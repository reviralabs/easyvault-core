import Crypto
import Foundation

/// Owns the vaults on this device: the primary vault and an optional decoy. Creating,
/// unlocking and changing passcodes go through here; everything else through `Vault`.
///
/// Nothing on disk marks a vault as the decoy. The app remembers which one is primary.
public final class VaultManager: Sendable {
    public let root: URL
    private let slotKeys: SlotKeys

    /// Opens the vault folder at `root`, creating it and the device settings if needed.
    /// `argon2` only applies when the folder is new; afterwards the stored settings win.
    /// `binding` must match the scheme the folder was created with (see `bindingKind(at:)`).
    public init(root: URL, binding: any DeviceBinding, argon2: Argon2Parameters = .standard) throws {
        self.root = root
        let configURL = root.appendingPathComponent("device.json")
        let config: DeviceConfig
        if FileManager.default.fileExists(atPath: configURL.path) {
            config = try Storage.decoder.decode(DeviceConfig.self, from: Data(contentsOf: configURL))
            guard config.version <= DeviceConfig.currentVersion else { throw VaultError.unsupportedVersion(config.version) }
            guard config.bindingKind == binding.kind else { throw VaultError.deviceBindingMismatch(config.bindingKind.rawValue) }
        } else {
            try Storage.createDirectory(root)
            config = DeviceConfig(
                version: DeviceConfig.currentVersion,
                salt: KeyDerivation.randomBytes(KeyDerivation.saltLength),
                argon2: argon2,
                binding: binding.kind
            )
            try Storage.write(Storage.encoder.encode(config), to: configURL)
        }
        slotKeys = SlotKeys(config: config, binding: binding)
    }

    public convenience init(root: URL, deviceSecret: any DeviceSecretProvider, argon2: Argon2Parameters = .standard) throws {
        try self.init(root: root, binding: DeviceSecretBinding(deviceSecret), argon2: argon2)
    }

    /// The binding scheme an existing vault folder uses, or nil for a new device.
    public static func bindingKind(at root: URL) throws -> DeviceBindingKind? {
        let configURL = root.appendingPathComponent("device.json")
        guard FileManager.default.fileExists(atPath: configURL.path) else { return nil }
        return try Storage.decoder.decode(DeviceConfig.self, from: Data(contentsOf: configURL)).bindingKind
    }

    public func vaultIDs() throws -> [UUID] {
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: root.path)
            .compactMap(UUID.init(uuidString:))
            .filter { FileManager.default.fileExists(atPath: directory($0).appendingPathComponent("vault.json").path) }
            .sorted { $0.uuidString < $1.uuidString }
    }

    /// The lock type a vault's passcode uses, so the lock screen can show a keypad or grid.
    public func secretKind(of vaultID: UUID) throws -> LockSecret.Kind? {
        try Vault.readHeader(at: directory(vaultID)).slots.first { $0.kind == .passcode }?.secretKind
    }

    public func slotKinds(of vaultID: UUID) throws -> Set<Keyslot.Kind> {
        Set(try Vault.readHeader(at: directory(vaultID)).slots.map(\.kind))
    }

    /// Creates an empty vault that opens with `secret`, and returns it unlocked.
    public func createVault(secret: LockSecret, recoveryKey: RecoveryKey? = nil) throws -> Vault {
        try secret.validate()
        let stretched = try slotKeys.stretch(secret)
        if try openWithPasscode(stretched: stretched) != nil { throw VaultError.secretInUse }

        let id = UUID()
        let vaultKey = SymmetricKey(size: .bits256)
        let directory = directory(id)
        var slots = [try Keyslot.wrap(vaultKey, with: slotKeys.passcodeKEK(stretched: stretched, vaultID: id), kind: .passcode, secretKind: secret.kind, vaultID: id)]
        if let recoveryKey {
            slots.append(try Keyslot.wrap(vaultKey, with: slotKeys.recoveryKEK(recoveryKey, vaultID: id), kind: .recovery, vaultID: id))
        }

        // Write into a temporary folder and rename, so a half-created vault never appears.
        let staging = root.appendingPathComponent(".creating-\(id.uuidString)")
        do {
            try Storage.createDirectory(staging)
            try Storage.createDirectory(staging.appendingPathComponent("items"))
            try Storage.createDirectory(staging.appendingPathComponent("thumbs"))
            try Vault.writeIndex(VaultIndex(), at: staging, vaultID: id, key: vaultKey)
            try Vault.writeHeader(VaultHeader(version: VaultHeader.currentVersion, id: id, createdAt: Date(), slots: slots), at: staging)
            try FileManager.default.moveItem(at: staging, to: directory)
        } catch {
            try? Storage.removeIfPresent(staging)
            throw error
        }
        return try Vault(id: id, directory: directory, header: Vault.readHeader(at: directory), vaultKey: vaultKey, slotKeys: slotKeys)
    }

    /// Opens whichever vault uses this secret.
    /// The length rules only apply when choosing a secret, so tightening them never locks
    /// anyone out of an existing vault.
    public func unlock(_ secret: LockSecret) throws -> Vault {
        guard let vault = try openWithPasscode(stretched: slotKeys.stretch(secret)) else { throw VaultError.wrongSecret }
        return vault
    }

    public func unlock(_ vaultID: UUID, biometricKey: Data) throws -> Vault {
        try open(vaultID, kind: .biometric) { _ in SymmetricKey(data: biometricKey) }
    }

    public func unlock(_ vaultID: UUID, recoveryKey: RecoveryKey) throws -> Vault {
        try open(vaultID, kind: .recovery) { slotKeys.recoveryKEK(recoveryKey, vaultID: $0) }
    }

    /// Replaces the vault's passcode. Fails if another vault already opens with the new secret.
    public func changePasscode(of vault: Vault, to secret: LockSecret) async throws {
        try secret.validate()
        let stretched = try slotKeys.stretch(secret)
        if let other = try openWithPasscode(stretched: stretched), other.id != vault.id {
            throw VaultError.secretInUse
        }
        try await vault.setPasscode(stretched: stretched, secretKind: secret.kind)
    }

    /// Permanently deletes a vault and everything in it.
    public func deleteVault(_ vaultID: UUID) throws {
        let directory = directory(vaultID)
        guard FileManager.default.fileExists(atPath: directory.path) else { throw VaultError.vaultNotFound(vaultID) }
        try FileManager.default.removeItem(at: directory)
    }

    /// Permanently deletes every vault except `keep`. Used when a duress vault is opened.
    public func deleteVaults(except keep: UUID) throws {
        for id in try vaultIDs() where id != keep {
            try deleteVault(id)
        }
    }

    // MARK: Backup

    /// Uploads whatever changed since the last backup. Needs a recovery key slot. Throws
    /// `BackupError.differentVault` if the store holds another vault's backup, unless `replacing`.
    public func backUp(
        _ vaultID: UUID, to store: any BackupStore, replacing: Bool = false,
        progress: @Sendable (BackupProgress) -> Void = { _ in }
    ) async throws {
        let directory = directory(vaultID)
        guard FileManager.default.fileExists(atPath: directory.path) else { throw VaultError.vaultNotFound(vaultID) }
        try await BackupEngine.backUp(directory: directory, vaultID: vaultID, to: store, replacing: replacing, progress: progress)
    }

    /// The vault a store holds a backup of, or nil if it's empty.
    public func backupVaultID(in store: any BackupStore) async throws -> UUID? {
        do {
            return try await BackupEngine.remoteHeader(in: store).id
        } catch BackupError.noBackup {
            return nil
        }
    }

    /// Checks a recovery key against the backup before downloading anything.
    public func verifyBackup(in store: any BackupStore, recoveryKey: RecoveryKey) async throws {
        let header = try await BackupEngine.remoteHeader(in: store)
        _ = try recoveryVaultKey(header, recoveryKey)
    }

    /// Checks that the backup in `store` has everything this vault holds, and, if a recovery
    /// key is given, that it opens the backup. Throws `BackupError.noBackup` if there isn't
    /// one, or `.differentVault` if it belongs to another vault.
    public func checkBackup(_ vaultID: UUID, in store: any BackupStore, recoveryKey: RecoveryKey? = nil) async throws -> BackupStatus {
        let directory = directory(vaultID)
        guard FileManager.default.fileExists(atPath: directory.path) else { throw VaultError.vaultNotFound(vaultID) }
        var status = try await BackupEngine.check(directory: directory, vaultID: vaultID, in: store)
        if let recoveryKey {
            let header = try await BackupEngine.remoteHeader(in: store)
            status.recoveryKeyWorks = (try? recoveryVaultKey(header, recoveryKey)) != nil
        }
        return status
    }

    /// Downloads the backup, sets `newSecret` as this device's passcode and returns the vault
    /// unlocked. Nothing appears in the vault folder until everything has arrived.
    public func restore(
        from store: any BackupStore, recoveryKey: RecoveryKey, newSecret: LockSecret,
        progress: @Sendable (BackupProgress) -> Void = { _ in }
    ) async throws -> Vault {
        try newSecret.validate()
        let remoteHeader = try await BackupEngine.remoteHeader(in: store)
        let id = remoteHeader.id
        let vaultKey = try recoveryVaultKey(remoteHeader, recoveryKey)
        guard !FileManager.default.fileExists(atPath: directory(id).path) else { throw BackupError.alreadyOnDevice }
        let stretched = try slotKeys.stretch(newSecret)
        if try openWithPasscode(stretched: stretched) != nil { throw VaultError.secretInUse }

        let staging = root.appendingPathComponent(".restoring-\(id.uuidString)")
        try Storage.removeIfPresent(staging)
        do {
            try await BackupEngine.download(from: store, into: staging, progress: progress)
            var header = try Vault.readHeader(at: staging)
            guard header.id == id else { throw BackupError.incomplete(BackupEngine.headerPath) }
            let index = try Vault.readIndex(at: staging, vaultID: id, key: vaultKey) // fails if the index doesn't match
            try Self.verifyRestoredItems(index, at: staging)
            let passcode = try Keyslot.wrap(vaultKey, with: slotKeys.passcodeKEK(stretched: stretched, vaultID: id), kind: .passcode, secretKind: newSecret.kind, vaultID: id)
            header.slots = [passcode] + header.slots.filter { $0.kind == .recovery }
            try Vault.writeHeader(header, at: staging)
            try FileManager.default.moveItem(at: staging, to: directory(id))
        } catch {
            try? Storage.removeIfPresent(staging)
            throw error
        }
        return try open(id, kind: .passcode) { slotKeys.passcodeKEK(stretched: stretched, vaultID: $0) }
    }

    /// The store's checksums only catch accidents, since whoever controls the store could
    /// change them too. Real integrity comes from AES-GCM: thumbnails and small items are
    /// decrypted in full, large items have their header checked here and every chunk checked
    /// when opened. An item file missing from the backup isn't fatal; it just won't open.
    private static func verifyRestoredItems(_ index: VaultIndex, at directory: URL) throws {
        for item in index.items {
            let key = SymmetricKey(data: item.key)
            let itemURL = directory.appendingPathComponent("items/\(item.id.uuidString).evf")
            if let size = try? FileManager.default.attributesOfItem(atPath: itemURL.path)[.size] as? Int {
                if size <= 2 << 20 {
                    _ = try ItemCipher.decrypt(Data(contentsOf: itemURL), itemID: item.id, key: key)
                } else {
                    let handle = try FileHandle(forReadingFrom: itemURL)
                    defer { try? handle.close() }
                    _ = try ItemCipher.Header(handle.read(upToCount: ItemCipher.headerLength) ?? Data(), expectedItemID: item.id)
                }
            }
            let thumbURL = directory.appendingPathComponent("thumbs/\(item.id.uuidString).evf")
            if item.hasThumbnail, FileManager.default.fileExists(atPath: thumbURL.path) {
                _ = try ItemCipher.decrypt(Data(contentsOf: thumbURL), itemID: item.id, key: key)
            }
        }
    }

    private func recoveryVaultKey(_ header: VaultHeader, _ recoveryKey: RecoveryKey) throws -> SymmetricKey {
        guard let slot = header.slots.first(where: { $0.kind == .recovery }) else { throw BackupError.noRecoveryKey }
        return try slot.unwrap(with: slotKeys.recoveryKEK(recoveryKey, vaultID: header.id), vaultID: header.id)
    }

    // MARK: Private

    private func directory(_ vaultID: UUID) -> URL {
        root.appendingPathComponent(vaultID.uuidString, isDirectory: true)
    }

    /// Tries every vault's passcode slot. Each try is one HKDF and one AES-GCM open, so
    /// the expensive Argon2id step runs once however many vaults exist.
    private func openWithPasscode(stretched: SymmetricKey) throws -> Vault? {
        for id in try vaultIDs() {
            do {
                return try open(id, kind: .passcode) { slotKeys.passcodeKEK(stretched: stretched, vaultID: $0) }
            } catch VaultError.wrongSecret {
                continue
            }
        }
        return nil
    }

    private func open(_ vaultID: UUID, kind: Keyslot.Kind, kek: (UUID) -> SymmetricKey) throws -> Vault {
        let directory = directory(vaultID)
        guard FileManager.default.fileExists(atPath: directory.path) else { throw VaultError.vaultNotFound(vaultID) }
        let header = try Vault.readHeader(at: directory)
        guard header.id == vaultID, let slot = header.slots.first(where: { $0.kind == kind }) else {
            throw VaultError.wrongSecret
        }
        let vaultKey = try slot.unwrap(with: kek(vaultID), vaultID: vaultID)
        return try Vault(id: vaultID, directory: directory, header: header, vaultKey: vaultKey, slotKeys: slotKeys)
    }
}
