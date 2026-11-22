import Crypto
import Foundation
import XCTest
@testable import VaultCore

struct FixedDeviceSecret: DeviceSecretProvider {
    var bytes = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    func deviceSecret() throws -> SymmetricKey { SymmetricKey(data: bytes) }
}

final class VaultTests: XCTestCase {
    private var root: URL!
    private let device = FixedDeviceSecret()
    private let fast = Argon2Parameters(opsLimit: 1, memLimitBytes: 8 << 20)

    override func setUp() {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("vaults-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    private func manager(device: FixedDeviceSecret? = nil) throws -> VaultManager {
        try VaultManager(root: root, deviceSecret: device ?? self.device, argon2: fast)
    }

    func testCreateUnlockAndPersist() async throws {
        let vault = try manager().createVault(secret: .password("pw-246802-vault"))
        let photo = Data("pretend jpeg".utf8)
        let item = try await vault.add(photo, name: "IMG_0001.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("thumb".utf8))

        // A fresh manager, as after relaunching the app.
        let reopened = try manager().unlock(.password("pw-246802-vault"))
        XCTAssertEqual(reopened.id, vault.id)
        let items = await reopened.items
        XCTAssertEqual(items.map(\.name), ["IMG_0001.jpg"])
        let data = try await reopened.data(for: item.id)
        let thumbnail = try await reopened.thumbnail(for: item.id)
        XCTAssertEqual(data, photo)
        XCTAssertEqual(thumbnail, Data("thumb".utf8))
        XCTAssertThrowsError(try ItemCipher.decrypt(
            Data(contentsOf: vault.directory.appendingPathComponent("thumbs/\(item.id.uuidString).evf")),
            itemID: item.id, key: SymmetricKey(data: item.key)
        ), "a thumbnail never shares its item's key (same item ID, so same nonces)")
        XCTAssertEqual(try manager().secretKind(of: vault.id), .password)
    }

    func testCheckRecoveryKey() async throws {
        let key = RecoveryKey.generate()
        let vault = try manager().createVault(secret: .password("pw-check-recovery"), recoveryKey: key)
        let parsed = try RecoveryKey(key.description.lowercased())
        let right = await vault.checkRecoveryKey(parsed)
        let wrong = await vault.checkRecoveryKey(.generate())
        XCTAssertTrue(right, "the key as typed, any case, opens the vault")
        XCTAssertFalse(wrong)
        try await vault.removeRecoveryKey()
        let afterRemoval = await vault.checkRecoveryKey(key)
        XCTAssertFalse(afterRemoval, "no recovery slot, nothing to open")
    }

    func testNothingReadableOnDisk() async throws {
        let vault = try manager().createVault(secret: .password("correct horse"))
        let marker = "SECRET-MARKER-\(UUID().uuidString)"
        try await vault.add(Data(marker.utf8), name: "\(marker).txt", kind: .file, contentType: "public.plain-text")
        _ = try await vault.createAlbum(named: marker)

        let files = Self.files(under: root)
        for url in files {
            let contents = try Data(contentsOf: url)
            XCTAssertNil(contents.range(of: Data(marker.utf8)), "plaintext found in \(url.lastPathComponent)")
        }
        XCTAssertGreaterThanOrEqual(files.count, 4)
    }

    /// Every file under a folder. Synchronous, because newer Swift doesn't allow iterating a
    /// directory enumerator inside an async function.
    private static func files(under folder: URL) -> [URL] {
        var urls: [URL] = []
        let enumerator = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil)
        while let url = enumerator?.nextObject() as? URL {
            if !url.hasDirectoryPath { urls.append(url) }
        }
        return urls
    }

    func testWrongSecretFails() throws {
        _ = try manager().createVault(secret: .password("pw-246802-vault"))
        XCTAssertThrowsError(try manager().unlock(.password("pw-135791-vault"))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }
        XCTAssertThrowsError(try manager().unlock(.pattern([2, 4, 6, 8, 10, 12]))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }
    }

    func testDecoyVaultOpensSeparately() async throws {
        let manager = try manager()
        let primary = try manager.createVault(secret: .pattern([0, 1, 2, 3, 4, 9, 14]))
        let decoy = try manager.createVault(secret: .pattern([20, 16, 12, 8, 4, 9]))
        try await primary.add(Data("real".utf8), name: "real.jpg", kind: .photo, contentType: "public.jpeg")
        try await decoy.add(Data("cat".utf8), name: "cat.jpg", kind: .photo, contentType: "public.jpeg")

        XCTAssertEqual(try manager.vaultIDs().count, 2)
        let openedPrimary = try manager.unlock(.pattern([0, 1, 2, 3, 4, 9, 14]))
        let openedDecoy = try manager.unlock(.pattern([20, 16, 12, 8, 4, 9]))
        XCTAssertEqual(openedPrimary.id, primary.id)
        XCTAssertEqual(openedDecoy.id, decoy.id)
        let decoyNames = await openedDecoy.items.map(\.name)
        XCTAssertEqual(decoyNames, ["cat.jpg"])
    }

    func testDuressVaultIsHiddenUntilOpenedAndRemovesTheOthers() async throws {
        let manager = try manager()
        let primary = try manager.createVault(secret: .pattern([0, 1, 2, 3, 4, 9, 14]))
        let duress = try manager.createVault(secret: .pattern([20, 16, 12, 8, 4, 9]))
        try await primary.add(Data("real".utf8), name: "real.jpg", kind: .photo, contentType: "public.jpeg")
        try await duress.setDuress(true)
        await duress.lock()

        try await primary.setDecoyIsDuress(true)
        await primary.lock()

        let reopenedPrimary = try manager.unlock(.pattern([0, 1, 2, 3, 4, 9, 14]))
        let primaryIsDuress = await reopenedPrimary.isDuress
        XCTAssertFalse(primaryIsDuress)
        let noteSurvivesLock = await reopenedPrimary.decoyIsDuress
        XCTAssertTrue(noteSurvivesLock)
        let opened = try manager.unlock(.pattern([20, 16, 12, 8, 4, 9]))
        let openedIsDuress = await opened.isDuress
        XCTAssertTrue(openedIsDuress)

        try manager.deleteVaults(except: opened.id)
        XCTAssertEqual(try manager.vaultIDs(), [duress.id])
        XCTAssertThrowsError(try manager.unlock(.pattern([0, 1, 2, 3, 4, 9, 14])))
    }

    func testSecretCannotBeShared() async throws {
        let manager = try manager()
        let primary = try manager.createVault(secret: .password("pw-111111-vault"))
        let decoy = try manager.createVault(secret: .password("pw-222222-vault"))
        XCTAssertThrowsError(try manager.createVault(secret: .password("pw-111111-vault"))) { XCTAssertEqual($0 as? VaultError, .secretInUse) }
        do {
            try await manager.changePasscode(of: decoy, to: .password("pw-111111-vault"))
            XCTFail("expected secretInUse")
        } catch {
            XCTAssertEqual(error as? VaultError, .secretInUse)
        }
        // Re-setting a vault's own secret is fine.
        try await manager.changePasscode(of: primary, to: .password("pw-111111-vault"))
    }

    func testChangePasscode() async throws {
        let manager = try manager()
        let vault = try manager.createVault(secret: .password("pw-123456-vault"))
        try await vault.add(Data("x".utf8), name: "x", kind: .file, contentType: "public.data")
        try await manager.changePasscode(of: vault, to: .pattern([5, 6, 7, 8, 13, 18]))

        XCTAssertThrowsError(try manager.unlock(.password("pw-123456-vault")))
        let reopened = try manager.unlock(.pattern([5, 6, 7, 8, 13, 18]))
        let count = await reopened.items.count
        XCTAssertEqual(count, 1)
        XCTAssertEqual(try manager.secretKind(of: vault.id), .pattern)
    }

    func testBiometricUnlock() async throws {
        let manager = try manager()
        let vault = try manager.createVault(secret: .password("pw-123456-vault"))
        let biometricKey = try await vault.enableBiometricUnlock()

        XCTAssertEqual(try manager.unlock(vault.id, biometricKey: biometricKey).id, vault.id)
        XCTAssertThrowsError(try manager.unlock(vault.id, biometricKey: Data(repeating: 7, count: 32)))

        try await vault.disableBiometricUnlock()
        XCTAssertThrowsError(try manager.unlock(vault.id, biometricKey: biometricKey))
        XCTAssertEqual(try manager.slotKinds(of: vault.id), [.passcode])
    }

    func testUnlockDoesNotApplyCreationRules() throws {
        let manager = try manager()
        _ = try manager.createVault(secret: .password("pw-123456-vault"))
        // A too-short password is just a wrong secret, so rules can tighten without lockouts.
        XCTAssertThrowsError(try manager.unlock(.password("short"))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }
    }

    func testCopiedVaultNeedsRecoveryKeyOnAnotherPhone() async throws {
        let recoveryKey = RecoveryKey.generate()
        let vault = try manager().createVault(secret: .password("pw-123456-vault"), recoveryKey: recoveryKey)
        try await vault.add(Data("passport".utf8), name: "passport.jpg", kind: .photo, contentType: "public.jpeg")

        // Same files, different device secret: the PIN alone is not enough.
        let otherPhone = try manager(device: FixedDeviceSecret())
        XCTAssertThrowsError(try otherPhone.unlock(.password("pw-123456-vault"))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }

        let restored = try otherPhone.unlock(vault.id, recoveryKey: try RecoveryKey(recoveryKey.description))
        let restoredItems = await restored.items
        let item = try XCTUnwrap(restoredItems.first)
        let restoredData = try await restored.data(for: item.id)
        XCTAssertEqual(restoredData, Data("passport".utf8))

        // Set a passcode for the new phone.
        try await otherPhone.changePasscode(of: restored, to: .password("pw-567890-vault"))
        XCTAssertEqual(try otherPhone.unlock(.password("pw-567890-vault")).id, vault.id)

        XCTAssertThrowsError(try otherPhone.unlock(vault.id, recoveryKey: RecoveryKey.generate()))
    }

    func testRecoveryKeyCanBeAddedAndRemoved() async throws {
        let manager = try manager()
        let vault = try manager.createVault(secret: .password("pw-123456-vault"))
        XCTAssertThrowsError(try manager.unlock(vault.id, recoveryKey: RecoveryKey.generate()))

        let recoveryKey = RecoveryKey.generate()
        try await vault.setRecoveryKey(recoveryKey)
        XCTAssertEqual(try manager.unlock(vault.id, recoveryKey: recoveryKey).id, vault.id)

        try await vault.removeRecoveryKey()
        XCTAssertThrowsError(try manager.unlock(vault.id, recoveryKey: recoveryKey))
    }

    func testAlbumsAndOrganising() async throws {
        let vault = try manager().createVault(secret: .password("pw-123456-vault"))
        let album = try await vault.createAlbum(named: "Travel")
        let a = try await vault.add(Data("a".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg", albumID: album.id)
        let b = try await vault.add(Data("b".utf8), name: "b.pdf", kind: .file, contentType: "com.adobe.pdf")

        try await vault.move([b.id], toAlbum: album.id)
        try await vault.rename(a.id, to: "passport.jpg")
        try await vault.renameAlbum(album.id, to: "Documents")
        var items = await vault.items
        XCTAssertEqual(Set(items.map(\.albumID)), [album.id])
        XCTAssertTrue(items.contains { $0.name == "passport.jpg" })
        let albumNames = await vault.albums.map(\.name)
        XCTAssertEqual(albumNames, ["Documents"])

        try await vault.deleteAlbum(album.id)
        items = await vault.items
        XCTAssertEqual(Set(items.map(\.albumID)), [nil])

        try await vault.delete([a.id])
        let remaining = await vault.items.map(\.id)
        XCTAssertEqual(remaining, [b.id])
        let files = try FileManager.default.contentsOfDirectory(atPath: vault.directory.appendingPathComponent("items").path)
        XCTAssertEqual(files, ["\(b.id.uuidString).evf"])

        do {
            try await vault.add(Data(), name: "x", kind: .file, contentType: "public.data", albumID: UUID())
            XCTFail("expected albumNotFound")
        } catch {
            guard case .albumNotFound = error as? VaultError else { return XCTFail("\(error)") }
        }
    }

    func testLargeFileStreams() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = dir.appendingPathComponent("video.mov")
        let video = Data((0..<(2_500_000)).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        try video.write(to: source)

        let vault = try manager().createVault(secret: .password("pw-123456-vault"))
        let item = try await vault.addFile(at: source, name: "video.mov", kind: .video, contentType: "com.apple.quicktime-movie")
        XCTAssertEqual(item.byteCount, Int64(video.count))

        let exported = dir.appendingPathComponent("exported.mov")
        try await vault.export(item.id, to: exported)
        XCTAssertEqual(try Data(contentsOf: exported), video)
    }

    func testLockForgetsKeys() async throws {
        let vault = try manager().createVault(secret: .password("pw-123456-vault"))
        let item = try await vault.add(Data("x".utf8), name: "x", kind: .file, contentType: "public.data")
        await vault.lock()
        let isLocked = await vault.isLocked
        let lockedCount = await vault.items.count
        XCTAssertTrue(isLocked)
        XCTAssertEqual(lockedCount, 0)
        do {
            _ = try await vault.data(for: item.id)
            XCTFail("expected locked")
        } catch {
            XCTAssertEqual(error as? VaultError, .locked)
        }
        do {
            try await vault.createAlbum(named: "x")
            XCTFail("expected locked")
        } catch {
            XCTAssertEqual(error as? VaultError, .locked)
        }
    }

    func testTamperedIndexIsRejected() async throws {
        let vault = try manager().createVault(secret: .password("pw-123456-vault"))
        let indexURL = vault.directory.appendingPathComponent("index.evi")
        var index = try Data(contentsOf: indexURL)
        index[index.count - 1] ^= 1
        try index.write(to: indexURL)
        XCTAssertThrowsError(try manager().unlock(.password("pw-123456-vault"))) {
            guard case .corrupted = $0 as? VaultError else { return XCTFail("\($0)") }
        }
    }

    /// An exported copy opens with the recovery key alone and carries nothing device-bound
    /// and nothing about a second vault.
    func testExportEncryptedOpensWithRecoveryKeyAlone() async throws {
        let key = RecoveryKey.generate()
        let vault = try manager().createVault(secret: .password("pw-export-vault"), recoveryKey: key)
        _ = try await vault.enableBiometricUnlock()
        try await vault.setDecoyIsDuress(true)
        let album = try await vault.createAlbum(named: "Trips")
        let photo = try await vault.add(Data("photo".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg", albumID: album.id, thumbnail: Data("thumb".utf8))
        let document = try await vault.add(Data(), name: "empty.pdf", kind: .file, contentType: "com.adobe.pdf")

        let out = root.appendingPathComponent("export")
        try await vault.exportEncrypted(to: out)

        let header = try Vault.readHeader(at: out)
        XCTAssertEqual(header.slots.map(\.kind), [.recovery])
        let copy = try Vault.open(folder: out, recoveryKey: key)
        XCTAssertEqual(copy.id, vault.id)
        let items = await copy.items
        XCTAssertEqual(Set(items.map(\.name)), ["a.jpg", "empty.pdf"])
        let photoData = try await copy.data(for: photo.id)
        let thumb = try await copy.thumbnail(for: photo.id)
        let documentData = try await copy.data(for: document.id)
        XCTAssertEqual(photoData, Data("photo".utf8))
        XCTAssertEqual(thumb, Data("thumb".utf8))
        XCTAssertEqual(documentData, Data())
        let albums = await copy.albums
        XCTAssertEqual(albums.map(\.name), ["Trips"])
        let decoyIsDuress = await copy.decoyIsDuress
        XCTAssertFalse(decoyIsDuress)
        XCTAssertThrowsError(try Vault.open(folder: out, recoveryKey: .generate()))

        // Never over an existing folder, and never without a recovery key.
        do { try await vault.exportEncrypted(to: out); XCTFail("exported over an existing folder") } catch {}
        try await vault.removeRecoveryKey()
        let second = root.appendingPathComponent("export-2")
        do {
            try await vault.exportEncrypted(to: second)
            XCTFail("exported without a recovery key")
        } catch {
            XCTAssertEqual(error as? BackupError, .noRecoveryKey)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: second.path))
    }

    /// A damaged vault still exports: an item whose file is gone is left out, everything else
    /// gets out, and the copy still lists it so the opener can say it's missing.
    func testExportSkipsMissingItemFiles() async throws {
        let key = RecoveryKey.generate()
        let vault = try manager().createVault(secret: .password("pw-damaged-vault"), recoveryKey: key)
        let kept = try await vault.add(Data("kept".utf8), name: "kept.jpg", kind: .photo, contentType: "public.jpeg")
        let lost = try await vault.add(Data("lost".utf8), name: "lost.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("t".utf8))
        try FileManager.default.removeItem(at: vault.directory.appendingPathComponent("items/\(lost.id.uuidString).evf"))

        let out = root.appendingPathComponent("export")
        let missing = try await vault.exportEncrypted(to: out)
        XCTAssertEqual(missing, 1)
        let copy = try Vault.open(folder: out, recoveryKey: key)
        let names = await copy.items.map(\.name)
        XCTAssertEqual(Set(names), ["kept.jpg", "lost.jpg"])
        let keptData = try await copy.data(for: kept.id)
        XCTAssertEqual(keptData, Data("kept".utf8))
        do { _ = try await copy.data(for: lost.id); XCTFail("a missing file opened") } catch {}
    }

    /// The inbox's private key is sealed inside the vault, not left on the device: pending
    /// entries open only once the vault is unlocked, and only on the vault that holds the key.
    func testInboxKeyLivesInTheVault() async throws {
        let key = RecoveryKey.generate()
        let vault = try manager().createVault(secret: .password("pw-inbox-vault"), recoveryKey: key)
        let first = try await vault.inboxKey()
        let again = try await vault.inboxKey()
        XCTAssertEqual(first, again)

        // Survives locking, and comes from the encrypted index.
        await vault.lock()
        let reopened = try manager().unlock(.password("pw-inbox-vault"))
        let stored = try await reopened.inboxKey()
        XCTAssertEqual(stored, first)
        let onDisk = try Data(contentsOf: vault.directory.appendingPathComponent("index.evi"))
        XCTAssertNil(onDisk.range(of: first), "never in the clear")

        // A key kept elsewhere before (the app's Keychain) is adopted, so its entries still open.
        let legacy = Inbox.makeKey()
        let other = try manager().createVault(secret: .password("pw-inbox-other"))
        let adopted = try await other.inboxKey(migrating: legacy.rawRepresentation)
        XCTAssertEqual(adopted, legacy.rawRepresentation)
        let kept = try await other.inboxKey(migrating: Inbox.makeKey().rawRepresentation)
        XCTAssertEqual(kept, legacy.rawRepresentation, "an existing key is never replaced")

        // Not in an export: it only matters on this device.
        let out = root.appendingPathComponent("export")
        try await reopened.exportEncrypted(to: out)
        let rawVaultKey = await reopened.keyForTesting
        let vaultKey = try XCTUnwrap(rawVaultKey)
        XCTAssertNil(try Vault.readIndex(at: out, vaultID: reopened.id, key: SymmetricKey(data: vaultKey)).inboxKey)

        let locked = try manager().createVault(secret: .password("pw-inbox-locked"))
        await locked.lock()
        do { _ = try await locked.inboxKey(); XCTFail("read while locked") } catch {
            XCTAssertEqual(error as? VaultError, .locked)
        }
    }

    /// Once every thumbnail has its own key, a thumbnail under the item key no longer opens.
    func testOldThumbnailKeyRefusedAfterUpgrade() async throws {
        let vault = try manager().createVault(secret: .password("pw-thumb-vault"))
        let item = try await vault.add(Data("photo".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("new".utf8))
        let oldStyle = try ItemCipher.encrypt(Data("old".utf8), itemID: item.id, key: SymmetricKey(data: item.key))
        XCTAssertEqual(try Vault.readThumbnail(oldStyle, item: item, legacyAllowed: true).data, Data("old".utf8))
        XCTAssertThrowsError(try Vault.readThumbnail(oldStyle, item: item, legacyAllowed: false))

        try oldStyle.write(to: vault.directory.appendingPathComponent("thumbs/\(item.id.uuidString).evf"))
        do { _ = try await vault.thumbnail(for: item.id); XCTFail("old-style thumbnail opened") } catch {}
    }

    func testRejectsInvalidSecretsBeforeDoingWork() {
        XCTAssertThrowsError(try manager().createVault(secret: .password("short"))) {
            guard case .invalidSecret = $0 as? VaultError else { return XCTFail("\($0)") }
        }
    }
}

/// Stands in for the Secure Enclave: a private key the vault code never sees.
struct FakeEnclave {
    let raw = P256.KeyAgreement.PrivateKey().rawRepresentation
    var binding: KeyAgreementBinding {
        let raw = self.raw
        return KeyAgreementBinding { try P256.KeyAgreement.PrivateKey(rawRepresentation: raw).sharedSecretFromKeyAgreement(with: $0) }
    }
}

final class DeviceBindingTests: XCTestCase {
    private var root: URL!
    private let fast = Argon2Parameters(opsLimit: 1, memLimitBytes: 8 << 20)

    override func setUp() {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("vaults-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: root)
    }

    func testEnclaveBoundVaultUnlocksOnlyWithSameEnclave() async throws {
        let enclave = FakeEnclave()
        let recoveryKey = RecoveryKey.generate()
        let manager = try VaultManager(root: root, binding: enclave.binding, argon2: fast)
        let vault = try manager.createVault(secret: .password("pw-123456-vault"), recoveryKey: recoveryKey)
        try await vault.add(Data("id card".utf8), name: "id.jpg", kind: .photo, contentType: "public.jpeg")
        XCTAssertEqual(try VaultManager.bindingKind(at: root), .secureEnclave)

        // Relaunch with the same enclave: the PIN works, a wrong one doesn't.
        let reopened = try VaultManager(root: root, binding: enclave.binding, argon2: fast)
        XCTAssertEqual(try reopened.unlock(.password("pw-123456-vault")).id, vault.id)
        XCTAssertThrowsError(try reopened.unlock(.password("pw-123457-vault"))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }

        // Files copied to a phone with a different enclave: the right PIN fails, the recovery key works.
        let otherPhone = try VaultManager(root: root, binding: FakeEnclave().binding, argon2: fast)
        XCTAssertThrowsError(try otherPhone.unlock(.password("pw-123456-vault"))) { XCTAssertEqual($0 as? VaultError, .wrongSecret) }
        let restored = try otherPhone.unlock(vault.id, recoveryKey: recoveryKey)
        let restoredItems = await restored.items
        let restoredData = try await restored.data(for: XCTUnwrap(restoredItems.first).id)
        XCTAssertEqual(restoredData, Data("id card".utf8))
    }

    func testBindingIsDeterministicAndDependsOnPasscode() throws {
        let binding = FakeEnclave().binding
        let a = SymmetricKey(data: Data(repeating: 1, count: 32))
        let b = SymmetricKey(data: Data(repeating: 2, count: 32))
        XCTAssertEqual(try binding.bind(a), try binding.bind(a))
        XCTAssertNotEqual(try binding.bind(a), try binding.bind(b))
        XCTAssertEqual(try binding.bind(a).data.count, 64)
    }

    func testFolderRefusesADifferentBindingScheme() throws {
        _ = try VaultManager(root: root, deviceSecret: FixedDeviceSecret(), argon2: fast).createVault(secret: .password("pw-123456-vault"))
        XCTAssertEqual(try VaultManager.bindingKind(at: root), .keychainSecret)
        XCTAssertThrowsError(try VaultManager(root: root, binding: FakeEnclave().binding, argon2: fast)) {
            XCTAssertEqual($0 as? VaultError, .deviceBindingMismatch("keychainSecret"))
        }
    }

    func testFoldersWithoutABindingFieldAreKeychainSecret() throws {
        let device = FixedDeviceSecret()
        _ = try VaultManager(root: root, deviceSecret: device, argon2: fast).createVault(secret: .password("pw-123456-vault"))
        // Strip the field, as in folders written before it existed.
        let url = root.appendingPathComponent("device.json")
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        json["binding"] = nil
        try JSONSerialization.data(withJSONObject: json).write(to: url)

        XCTAssertEqual(try VaultManager.bindingKind(at: root), .keychainSecret)
        XCTAssertNoThrow(try VaultManager(root: root, deviceSecret: device, argon2: fast).unlock(.password("pw-123456-vault")))
    }

    func testPasscodeScalarIsAlwaysValid() throws {
        for _ in 0..<200 {
            XCTAssertNoThrow(try KeyAgreementBinding.passcodeKey(from: SymmetricKey(size: .bits256)))
        }
    }
}

#if canImport(CryptoKit)
import CryptoKit

/// Runs the real Secure Enclave where there is one (Apple silicon Macs, iPhones), with the
/// same calls the app makes. Skipped on Linux and the simulator.
final class SecureEnclaveBindingTests: XCTestCase {
    func testRealSecureEnclaveBinding() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "No Secure Enclave here")
        let blob = try SecureEnclave.P256.KeyAgreement.PrivateKey().dataRepresentation
        let binding = KeyAgreementBinding {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob).sharedSecretFromKeyAgreement(with: $0)
        }
        let stretched = SymmetricKey(size: .bits256)
        let first = try binding.bind(stretched)
        XCTAssertEqual(first, try binding.bind(stretched), "Same passcode, same key")
        XCTAssertNotEqual(first, try binding.bind(SymmetricKey(size: .bits256)))

        let otherEnclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey().dataRepresentation
        let other = KeyAgreementBinding {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: otherEnclaveKey).sharedSecretFromKeyAgreement(with: $0)
        }
        XCTAssertNotEqual(first, try other.bind(stretched), "A different enclave key gives a different result")
    }
}
#endif
