import Crypto
import Foundation
import XCTest
@testable import VaultCore

/// Counts uploads, to check that backups only send what changed.
actor CountingStore: BackupStore {
    let inner = MemoryBackupStore()
    private(set) var puts: [String] = []

    func list() async throws -> [String: String] { await inner.list() }
    func put(_ key: String, data: Data, sha256: String) async throws {
        puts.append(key)
        await inner.put(key, data: data, sha256: sha256)
    }
    func get(_ key: String) async throws -> Data { try await inner.get(key) }
    func delete(_ keys: [String]) async throws { await inner.delete(keys) }
    func resetCount() { puts = [] }
}

final class BackupTests: XCTestCase {
    private var roots: [URL] = []
    private let fast = Argon2Parameters(opsLimit: 1, memLimitBytes: 8 << 20)

    override func tearDown() {
        for root in roots { try? FileManager.default.removeItem(at: root) }
    }

    /// A separate phone: its own folder and its own device secret.
    private func phone() throws -> VaultManager {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("backup-\(UUID().uuidString)")
        roots.append(root)
        return try VaultManager(root: root, deviceSecret: FixedDeviceSecret(), argon2: fast)
    }

    private func directory(_ manager: VaultManager, _ id: UUID) -> URL {
        manager.root.appendingPathComponent(id.uuidString)
    }

    func testBackUpAndRestoreOnANewPhone() async throws {
        let oldPhone = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try oldPhone.createVault(secret: .password("old phone pass"), recoveryKey: recoveryKey)
        let photo = try await vault.add(Data("holiday photo".utf8), name: "beach.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("thumb".utf8))
        let video = Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let movie = try await vault.add(video, name: "clip.mov", kind: .video, contentType: "com.apple.quicktime-movie")

        let store = MemoryBackupStore()
        // Small parts so the video spans several of them.
        try await BackupEngine.backUp(directory: directory(oldPhone, vault.id), vaultID: vault.id, to: store, replacing: false, partSize: 64 * 1024)
        let keys = await store.list().keys
        XCTAssertTrue(keys.contains { $0.contains("of") && !$0.hasSuffix("of1") }, "the video should be split into parts")

        let newPhone = try phone()
        let backedUp = try await newPhone.backupVaultID(in: store)
        XCTAssertEqual(backedUp, vault.id)
        try await newPhone.verifyBackup(in: store, recoveryKey: recoveryKey)
        let restored = try await newPhone.restore(from: store, recoveryKey: recoveryKey, newSecret: .pattern([0, 1, 2, 7, 12, 17]))

        XCTAssertEqual(restored.id, vault.id)
        let items = await restored.items
        XCTAssertEqual(Set(items.map(\.name)), ["beach.jpg", "clip.mov"])
        let restoredPhoto = try await restored.data(for: photo.id)
        let restoredVideo = try await restored.data(for: movie.id)
        let restoredThumb = try await restored.thumbnail(for: photo.id)
        XCTAssertEqual(restoredPhoto, Data("holiday photo".utf8))
        XCTAssertEqual(restoredVideo, video)
        XCTAssertEqual(restoredThumb, Data("thumb".utf8))

        // The new phone opens with its new pattern; the old password means nothing there.
        XCTAssertEqual(try newPhone.unlock(.pattern([0, 1, 2, 7, 12, 17])).id, vault.id)
        XCTAssertThrowsError(try newPhone.unlock(.password("old phone pass")))
        XCTAssertEqual(try newPhone.slotKinds(of: vault.id), [.passcode, .recovery])
        // The recovery key still works for the next phone.
        XCTAssertEqual(try newPhone.unlock(vault.id, recoveryKey: recoveryKey).id, vault.id)
    }

    func testBackupHoldsNoDeviceSlotsAndNoPlaintext() async throws {
        let manager = try phone()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: .generate())
        _ = try await vault.enableBiometricUnlock()
        try await vault.add(Data("SECRET-PASSPORT-NUMBER".utf8), name: "passport-scan.jpg", kind: .photo, contentType: "public.jpeg")

        let store = MemoryBackupStore()
        try await manager.backUp(vault.id, to: store)

        let header = try await BackupEngine.remoteHeader(in: store)
        XCTAssertEqual(header.slots.map(\.kind), [.recovery])
        for (_, data) in await store.objects {
            XCTAssertNil(data.range(of: Data("SECRET-PASSPORT-NUMBER".utf8)), "file content leaked")
            XCTAssertNil(data.range(of: Data("passport-scan".utf8)), "file name leaked")
        }
    }

    func testBackupsOnlySendWhatChanged() async throws {
        let manager = try phone()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: .generate())
        let first = try await vault.add(Data("one".utf8), name: "1.jpg", kind: .photo, contentType: "public.jpeg")
        let store = CountingStore()
        try await manager.backUp(vault.id, to: store)
        let initial = await store.puts
        XCTAssertEqual(initial.count, 3, "item, header, index")

        await store.resetCount()
        try await manager.backUp(vault.id, to: store)
        let unchanged = await store.puts
        XCTAssertEqual(unchanged, [], "nothing changed, nothing sent")

        try await vault.add(Data("two".utf8), name: "2.jpg", kind: .photo, contentType: "public.jpeg")
        await store.resetCount()
        try await manager.backUp(vault.id, to: store)
        let added = await store.puts
        XCTAssertEqual(added.count, 2, "the new item and the index")
        XCTAssertTrue(added.contains("index.evi#0of1"))

        try await vault.delete([first.id])
        await store.resetCount()
        try await manager.backUp(vault.id, to: store)
        let afterDelete = await store.puts
        XCTAssertEqual(afterDelete, ["index.evi#0of1"])
        let remaining = try await store.list().keys
        XCTAssertFalse(remaining.contains { $0.contains(first.id.uuidString) }, "deleted items are removed from the backup")
    }

    func testWrongRecoveryKeyIsRejectedBeforeDownloading() async throws {
        let manager = try phone()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: .generate())
        let store = MemoryBackupStore()
        try await manager.backUp(vault.id, to: store)

        let newPhone = try phone()
        do {
            try await newPhone.verifyBackup(in: store, recoveryKey: .generate())
            XCTFail("should reject")
        } catch { XCTAssertEqual(error as? VaultError, .wrongSecret) }
        do {
            _ = try await newPhone.restore(from: store, recoveryKey: .generate(), newSecret: .password("new phone pass"))
            XCTFail("should reject")
        } catch { XCTAssertEqual(error as? VaultError, .wrongSecret) }
        XCTAssertEqual(try newPhone.vaultIDs(), [])
    }

    func testAnotherVaultsBackupIsNotOverwrittenSilently() async throws {
        let store = MemoryBackupStore()
        let first = try phone()
        let a = try first.createVault(secret: .password("first phone 1"), recoveryKey: .generate())
        try await first.backUp(a.id, to: store)

        let second = try phone()
        let b = try second.createVault(secret: .password("second phone 1"), recoveryKey: .generate())
        do {
            try await second.backUp(b.id, to: store)
            XCTFail("should ask before replacing")
        } catch { XCTAssertEqual(error as? BackupError, .differentVault(a.id)) }

        try await second.backUp(b.id, to: store, replacing: true)
        let replaced = try await second.backupVaultID(in: store)
        XCTAssertEqual(replaced, b.id)
        let keys = await store.list().keys
        XCTAssertEqual(keys.count, 2, "only b's header and index remain")
    }

    func testBackupNeedsARecoveryKey() async throws {
        let manager = try phone()
        let vault = try manager.createVault(secret: .password("device pass 1"))
        do {
            try await manager.backUp(vault.id, to: MemoryBackupStore())
            XCTFail("should need a recovery key")
        } catch { XCTAssertEqual(error as? BackupError, .noRecoveryKey) }
    }

    /// Whoever controls the store can rewrite its checksums too, so this relies on AES-GCM.
    func testTamperedBackupFailsAndLeavesNothingBehind() async throws {
        let manager = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: recoveryKey)
        let item = try await vault.add(Data("photo".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg")
        let store = MemoryBackupStore()
        try await manager.backUp(vault.id, to: store)
        await store.tamper("items/\(item.id.uuidString).evf#0of1", with: Data("swapped".utf8))

        let newPhone = try phone()
        do {
            _ = try await newPhone.restore(from: store, recoveryKey: recoveryKey, newSecret: .password("new phone pass"))
            XCTFail("should fail")
        } catch {
            guard case .corrupted = error as? VaultError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(try newPhone.vaultIDs(), [])
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: newPhone.root.path).filter { $0.hasPrefix(".restoring") }
        XCTAssertEqual(leftovers, [])
    }

    func testInterruptedUploadIsIgnoredOnRestoreAndRedoneNextTime() async throws {
        let manager = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: recoveryKey)
        try await vault.add(Data("photo".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg")
        let store = CountingStore()
        try await manager.backUp(vault.id, to: store)

        // Half an upload of an item that isn't in the index, plus junk outside the format.
        let orphan = "items/\(UUID().uuidString).evf"
        try await store.put("\(orphan)#0of2", data: Data("half".utf8), sha256: BackupEngine.sha256(Data("half".utf8)))
        try await store.put("../escape#0of1", data: Data("x".utf8), sha256: BackupEngine.sha256(Data("x".utf8)))

        let newPhone = try phone()
        let restored = try await newPhone.restore(from: store, recoveryKey: recoveryKey, newSecret: .password("new phone pass"))
        let restoredItems = await restored.items
        XCTAssertEqual(restoredItems.count, 1)
        let escaped = newPhone.root.deletingLastPathComponent().appendingPathComponent("escape")
        XCTAssertFalse(FileManager.default.fileExists(atPath: escaped.path))

        // The next backup from the old phone cleans up the half-uploaded file.
        try await manager.backUp(vault.id, to: store)
        let keys = try await store.list().keys
        XCTAssertFalse(keys.contains { $0.hasPrefix(orphan) })
    }

    func testRestoringAVaultAlreadyOnThisPhoneIsRefused() async throws {
        let manager = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: recoveryKey)
        let store = MemoryBackupStore()
        try await manager.backUp(vault.id, to: store)
        do {
            _ = try await manager.restore(from: store, recoveryKey: recoveryKey, newSecret: .password("another pass 1"))
            XCTFail("should refuse")
        } catch { XCTAssertEqual(error as? BackupError, .alreadyOnDevice) }
    }

    func testCheckBackupFindsMissingItemsAndAStaleIndex() async throws {
        let phone = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try phone.createVault(secret: .password("check my backup"), recoveryKey: recoveryKey)
        _ = try await vault.add(Data("one".utf8), name: "1.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("t1".utf8))
        _ = try await vault.add(Data("two".utf8), name: "2.jpg", kind: .photo, contentType: "public.jpeg")
        let store = MemoryBackupStore()
        try await phone.backUp(vault.id, to: store)

        var status = try await phone.checkBackup(vault.id, in: store, recoveryKey: recoveryKey)
        XCTAssertEqual(status, BackupStatus(itemCount: 2, missingCount: 0, indexIsCurrent: true, recoveryKeyWorks: true))
        XCTAssertTrue(status.isComplete)

        status = try await phone.checkBackup(vault.id, in: store, recoveryKey: .generate())
        XCTAssertEqual(status.recoveryKeyWorks, false, "another key doesn't open the backup")
        status = try await phone.checkBackup(vault.id, in: store)
        XCTAssertNil(status.recoveryKeyWorks)

        // Added since the last backup: the item is missing and the stored index is out of date.
        _ = try await vault.add(Data("three".utf8), name: "3.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Data("t3".utf8))
        status = try await phone.checkBackup(vault.id, in: store)
        XCTAssertEqual(status.itemCount, 3)
        XCTAssertEqual(status.missingCount, 1, "an item and its thumbnail count once")
        XCTAssertFalse(status.indexIsCurrent)
        XCTAssertFalse(status.isComplete)

        try await phone.backUp(vault.id, to: store)
        status = try await phone.checkBackup(vault.id, in: store)
        XCTAssertTrue(status.isComplete)
    }

    func testCheckBackupNeedsThisVaultsBackup() async throws {
        let phone = try phone()
        let vault = try phone.createVault(secret: .password("first vault"), recoveryKey: .generate())
        let store = MemoryBackupStore()
        do {
            _ = try await phone.checkBackup(vault.id, in: store)
            XCTFail("an empty store has no backup")
        } catch BackupError.noBackup {}

        let other = try phone.createVault(secret: .password("second vault"), recoveryKey: .generate())
        try await phone.backUp(other.id, to: store)
        do {
            _ = try await phone.checkBackup(vault.id, in: store)
            XCTFail("another vault's backup isn't this one's")
        } catch BackupError.differentVault(let id) {
            XCTAssertEqual(id, other.id)
        }
    }

    func testDirectoryStoreRoundTrip() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("store-\(UUID().uuidString)")
        roots.append(root)
        let store = try DirectoryBackupStore(root: root)
        let manager = try phone()
        let recoveryKey = RecoveryKey.generate()
        let vault = try manager.createVault(secret: .password("device pass 1"), recoveryKey: recoveryKey)
        try await vault.add(Data("photo".utf8), name: "a.jpg", kind: .photo, contentType: "public.jpeg")
        try await manager.backUp(vault.id, to: store)
        let restored = try await phone().restore(from: store, recoveryKey: recoveryKey, newSecret: .password("new phone pass"))
        let restoredItems = await restored.items
        XCTAssertEqual(restoredItems.map(\.name), ["a.jpg"])
    }
}
