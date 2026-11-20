import Crypto
import Foundation

/// An unlocked vault. Holds the vault key in memory until `lock()` is called.
public actor Vault {
    public nonisolated let id: UUID
    nonisolated let directory: URL
    private let slotKeys: SlotKeys
    private var vaultKey: SymmetricKey?
    private var header: VaultHeader
    private var index: VaultIndex

    /// `upgrade`: bring older files up to date (see `upgradeThumbnails`). Off for read-only use.
    init(id: UUID, directory: URL, header: VaultHeader, vaultKey: SymmetricKey, slotKeys: SlotKeys, upgrade: Bool = true) throws {
        self.id = id
        self.directory = directory
        self.header = header
        self.vaultKey = vaultKey
        self.slotKeys = slotKeys
        var index = try Self.readIndex(at: directory, vaultID: id, key: vaultKey)
        if upgrade, index.thumbnailKeys != true, Self.upgradeThumbnails(index, at: directory) {
            index.thumbnailKeys = true
            try? Self.writeIndex(index, at: directory, vaultID: id, key: vaultKey)
        }
        self.index = index
    }

    // MARK: Reading

    /// Newest first.
    public var items: [VaultItem] {
        index.items.sorted { $0.addedAt > $1.addedAt }
    }

    public var albums: [Album] {
        index.albums.sorted { $0.createdAt < $1.createdAt }
    }

    public var isLocked: Bool { vaultKey == nil }

    public var slotKinds: Set<Keyslot.Kind> { Set(header.slots.map(\.kind)) }

    /// See `VaultIndex.isDuress`. The app acts on it after unlocking, through
    /// `VaultManager.deleteVaults(except:)`.
    public var isDuress: Bool { index.isDuress == true }

    public func setDuress(_ isDuress: Bool) throws {
        _ = try unlockedKey()
        index.isDuress = isDuress ? true : nil
        try saveIndex()
    }

    /// See `VaultIndex.decoyIsDuress`. A note for display; `isDuress` on the decoy is what acts.
    public var decoyIsDuress: Bool { index.decoyIsDuress == true }

    public func setDecoyIsDuress(_ isDuress: Bool) throws {
        _ = try unlockedKey()
        index.decoyIsDuress = isDuress ? true : nil
        try saveIndex()
    }

    public var secretKind: LockSecret.Kind? {
        header.slots.first { $0.kind == .passcode }?.secretKind
    }

    public func data(for itemID: UUID) throws -> Data {
        let item = try item(itemID)
        let file = try Data(contentsOf: itemURL(itemID))
        return try ItemCipher.decrypt(file, itemID: itemID, key: SymmetricKey(data: item.key))
    }

    public func thumbnail(for itemID: UUID) throws -> Data? {
        let item = try item(itemID)
        guard item.hasThumbnail else { return nil }
        return try Self.readThumbnail(Data(contentsOf: thumbnailURL(itemID)), item: item).data
    }

    /// Decrypts an item to a file, chunk by chunk. Use for videos and large files.
    public func export(_ itemID: UUID, to destination: URL) throws {
        let item = try item(itemID)
        try ItemCipher.decryptFile(at: itemURL(itemID), to: destination, itemID: itemID, key: SymmetricKey(data: item.key))
    }

    // MARK: Adding

    @discardableResult
    public func add(
        _ data: Data,
        name: String,
        kind: VaultItem.Kind,
        contentType: String,
        createdAt: Date? = nil,
        albumID: UUID? = nil,
        thumbnail: Data? = nil
    ) throws -> VaultItem {
        try add(name: name, kind: kind, contentType: contentType, byteCount: Int64(data.count), createdAt: createdAt, albumID: albumID, thumbnail: thumbnail) { id, key, url in
            try Storage.write(ItemCipher.encrypt(data, itemID: id, key: key), to: url)
        }
    }

    /// Encrypts a file chunk by chunk without loading it into memory. The source is left
    /// in place; the caller deletes it.
    @discardableResult
    public func addFile(
        at source: URL,
        name: String,
        kind: VaultItem.Kind,
        contentType: String,
        createdAt: Date? = nil,
        albumID: UUID? = nil,
        thumbnail: Data? = nil
    ) throws -> VaultItem {
        let size = try FileManager.default.attributesOfItem(atPath: source.path)[.size] as? NSNumber
        return try add(name: name, kind: kind, contentType: contentType, byteCount: size?.int64Value ?? 0, createdAt: createdAt, albumID: albumID, thumbnail: thumbnail) { id, key, url in
            try ItemCipher.encryptFile(at: source, to: url, itemID: id, key: key)
        }
    }

    private func add(
        name: String,
        kind: VaultItem.Kind,
        contentType: String,
        byteCount: Int64,
        createdAt: Date?,
        albumID: UUID?,
        thumbnail: Data?,
        write: (UUID, SymmetricKey, URL) throws -> Void
    ) throws -> VaultItem {
        _ = try unlockedKey()
        if let albumID, !index.albums.contains(where: { $0.id == albumID }) {
            throw VaultError.albumNotFound(albumID)
        }
        let id = UUID()
        let key = SymmetricKey(size: .bits256)
        let item = VaultItem(
            id: id, name: name, kind: kind, contentType: contentType, byteCount: byteCount,
            createdAt: createdAt, addedAt: Date(), albumID: albumID, hasThumbnail: thumbnail != nil, key: key.data
        )
        do {
            try write(id, key, itemURL(id))
            if let thumbnail {
                try Storage.write(ItemCipher.encrypt(thumbnail, itemID: id, key: ItemCipher.thumbnailKey(key, itemID: id)), to: thumbnailURL(id))
            }
            index.items.append(item)
            try saveIndex()
        } catch {
            index.items.removeAll { $0.id == id }
            try? Storage.removeIfPresent(itemURL(id))
            try? Storage.removeIfPresent(thumbnailURL(id))
            throw error
        }
        return item
    }

    // MARK: Organising

    public func delete(_ itemIDs: [UUID]) throws {
        _ = try unlockedKey()
        let ids = Set(itemIDs)
        index.items.removeAll { ids.contains($0.id) }
        try saveIndex()
        for id in ids {
            try? Storage.removeIfPresent(itemURL(id))
            try? Storage.removeIfPresent(thumbnailURL(id))
        }
    }

    public func rename(_ itemID: UUID, to name: String) throws {
        try update(itemID) { $0.name = name }
    }

    public func move(_ itemIDs: [UUID], toAlbum albumID: UUID?) throws {
        _ = try unlockedKey()
        if let albumID, !index.albums.contains(where: { $0.id == albumID }) {
            throw VaultError.albumNotFound(albumID)
        }
        for id in itemIDs {
            guard let i = index.items.firstIndex(where: { $0.id == id }) else { throw VaultError.itemNotFound(id) }
            index.items[i].albumID = albumID
        }
        try saveIndex()
    }

    @discardableResult
    public func createAlbum(named name: String) throws -> Album {
        _ = try unlockedKey()
        let album = Album(id: UUID(), name: name, createdAt: Date())
        index.albums.append(album)
        try saveIndex()
        return album
    }

    public func renameAlbum(_ albumID: UUID, to name: String) throws {
        _ = try unlockedKey()
        guard let i = index.albums.firstIndex(where: { $0.id == albumID }) else { throw VaultError.albumNotFound(albumID) }
        index.albums[i].name = name
        try saveIndex()
    }

    /// Removes the album. Its items stay in the vault, outside any album.
    public func deleteAlbum(_ albumID: UUID) throws {
        _ = try unlockedKey()
        index.albums.removeAll { $0.id == albumID }
        for i in index.items.indices where index.items[i].albumID == albumID {
            index.items[i].albumID = nil
        }
        try saveIndex()
    }

    // MARK: Unlock methods

    /// Creates a new 32-byte Face ID key and returns it. The app stores it in the Keychain
    /// behind biometry, then passes it to `VaultManager.unlock(_:biometricKey:)`.
    public func enableBiometricUnlock() throws -> Data {
        let biometricKey = SymmetricKey(size: .bits256)
        try replaceSlot(Keyslot.wrap(unlockedKey(), with: biometricKey, kind: .biometric, vaultID: id))
        return biometricKey.data
    }

    public func disableBiometricUnlock() throws {
        try removeSlot(.biometric)
    }

    /// Adds or replaces the recovery key, the only way to open this vault on another phone.
    public func setRecoveryKey(_ recoveryKey: RecoveryKey) throws {
        let kek = slotKeys.recoveryKEK(recoveryKey, vaultID: id)
        try replaceSlot(Keyslot.wrap(unlockedKey(), with: kek, kind: .recovery, vaultID: id))
    }

    /// Whether `recoveryKey` opens this vault. Changes nothing; for "check your recovery key".
    public func checkRecoveryKey(_ recoveryKey: RecoveryKey) -> Bool {
        guard let slot = header.slots.first(where: { $0.kind == .recovery }) else { return false }
        return (try? slot.unwrap(with: slotKeys.recoveryKEK(recoveryKey, vaultID: id), vaultID: id)) != nil
    }

    public func removeRecoveryKey() throws {
        try removeSlot(.recovery)
    }

    /// Called by `VaultManager.changePasscode`, which first checks no other vault uses the secret.
    func setPasscode(stretched: SymmetricKey, secretKind: LockSecret.Kind) throws {
        let kek = slotKeys.passcodeKEK(stretched: stretched, vaultID: id)
        try replaceSlot(Keyslot.wrap(unlockedKey(), with: kek, kind: .passcode, secretKind: secretKind, vaultID: id))
    }

    /// Forgets the vault key and the decrypted index. The vault must be unlocked again.
    public func lock() {
        vaultKey = nil
        index = VaultIndex()
    }

    /// For tests only.
    var keyForTesting: Data? { vaultKey?.data }

    // MARK: Private

    private func unlockedKey() throws -> SymmetricKey {
        guard let vaultKey else { throw VaultError.locked }
        return vaultKey
    }

    private func item(_ itemID: UUID) throws -> VaultItem {
        _ = try unlockedKey()
        guard let item = index.items.first(where: { $0.id == itemID }) else { throw VaultError.itemNotFound(itemID) }
        return item
    }

    private func update(_ itemID: UUID, _ change: (inout VaultItem) -> Void) throws {
        _ = try unlockedKey()
        guard let i = index.items.firstIndex(where: { $0.id == itemID }) else { throw VaultError.itemNotFound(itemID) }
        change(&index.items[i])
        try saveIndex()
    }

    private func replaceSlot(_ slot: Keyslot) throws {
        var updated = header
        updated.slots.removeAll { $0.kind == slot.kind }
        updated.slots.append(slot)
        try Self.writeHeader(updated, at: directory)
        header = updated
    }

    private func removeSlot(_ kind: Keyslot.Kind) throws {
        _ = try unlockedKey()
        var updated = header
        updated.slots.removeAll { $0.kind == kind }
        try Self.writeHeader(updated, at: directory)
        header = updated
    }

    private func saveIndex() throws {
        try Self.writeIndex(index, at: directory, vaultID: id, key: unlockedKey())
    }

    private func itemURL(_ id: UUID) -> URL {
        directory.appendingPathComponent("items/\(id.uuidString).evf")
    }

    private func thumbnailURL(_ id: UUID) -> URL {
        directory.appendingPathComponent("thumbs/\(id.uuidString).evf")
    }

    // MARK: On-disk layout

    /// Decrypts a thumbnail file. `legacy` is true for one written under the item key itself,
    /// before thumbnails had their own key.
    static func readThumbnail(_ file: Data, item: VaultItem) throws -> (data: Data, legacy: Bool) {
        let itemKey = SymmetricKey(data: item.key)
        do {
            return (try ItemCipher.decrypt(file, itemID: item.id, key: ItemCipher.thumbnailKey(itemKey, itemID: item.id)), false)
        } catch {
            return (try ItemCipher.decrypt(file, itemID: item.id, key: itemKey), true)
        }
    }

    /// Re-encrypts thumbnails still under their item key with their own key. Each file is
    /// replaced atomically and readable either way, so an interrupted run is safe and resumes
    /// next time. Returns whether every thumbnail now has its own key.
    static func upgradeThumbnails(_ index: VaultIndex, at directory: URL) -> Bool {
        var done = true
        for item in index.items where item.hasThumbnail {
            let url = directory.appendingPathComponent("thumbs/\(item.id.uuidString).evf")
            guard let file = try? Data(contentsOf: url) else { continue } // nothing to upgrade
            guard let (data, legacy) = try? readThumbnail(file, item: item) else { continue } // damaged either way
            guard legacy else { continue }
            let key = ItemCipher.thumbnailKey(SymmetricKey(data: item.key), itemID: item.id)
            do {
                try Storage.write(ItemCipher.encrypt(data, itemID: item.id, key: key), to: url)
            } catch {
                done = false
            }
        }
        return done
    }

    static func indexAAD(_ vaultID: UUID) -> Data {
        Data("ev/index".utf8) + vaultID.data
    }

    static func writeIndex(_ index: VaultIndex, at directory: URL, vaultID: UUID, key: SymmetricKey) throws {
        let json = try Storage.encoder.encode(index)
        let sealed = try AES.GCM.seal(json, using: key, authenticating: indexAAD(vaultID)).combined!
        try Storage.write(sealed, to: directory.appendingPathComponent("index.evi"))
    }

    static func readIndex(at directory: URL, vaultID: UUID, key: SymmetricKey) throws -> VaultIndex {
        let sealed = try Data(contentsOf: directory.appendingPathComponent("index.evi"))
        let json: Data
        do {
            json = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key, authenticating: indexAAD(vaultID))
        } catch {
            throw VaultError.corrupted("The vault index was damaged or modified.")
        }
        let index = try Storage.decoder.decode(VaultIndex.self, from: json)
        guard index.version <= VaultIndex.currentVersion else { throw VaultError.unsupportedVersion(index.version) }
        return index
    }

    static func writeHeader(_ header: VaultHeader, at directory: URL) throws {
        try Storage.write(Storage.encoder.encode(header), to: directory.appendingPathComponent("vault.json"))
    }

    static func readHeader(at directory: URL) throws -> VaultHeader {
        let header = try Storage.decoder.decode(VaultHeader.self, from: Data(contentsOf: directory.appendingPathComponent("vault.json")))
        guard header.version <= VaultHeader.currentVersion else { throw VaultError.unsupportedVersion(header.version) }
        return header
    }
}

extension Vault {
    /// Opens one vault folder with its recovery key, without the device it was made on: the
    /// recovery keyslot isn't bound to a device. For reading a downloaded backup or exported
    /// folder (the `evdecrypt` tool). Passcode and Face ID changes fail on a vault opened this way.
    public static func open(folder: URL, recoveryKey: RecoveryKey) throws -> Vault {
        let header = try readHeader(at: folder)
        guard let slot = header.slots.first(where: { $0.kind == .recovery }) else { throw VaultError.wrongSecret }
        let slotKeys = SlotKeys(
            config: DeviceConfig(version: DeviceConfig.currentVersion, salt: Data(count: KeyDerivation.saltLength), argon2: .standard, binding: nil),
            binding: DeviceSecretBinding(NoDevice())
        )
        let vaultKey = try slot.unwrap(with: slotKeys.recoveryKEK(recoveryKey, vaultID: header.id), vaultID: header.id)
        return try Vault(id: header.id, directory: folder, header: header, vaultKey: vaultKey, slotKeys: slotKeys, upgrade: false)
    }
}

/// No device secret: a vault opened by recovery key alone can't derive passcode keys.
private struct NoDevice: DeviceSecretProvider {
    func deviceSecret() throws -> SymmetricKey { throw VaultError.locked }
}
