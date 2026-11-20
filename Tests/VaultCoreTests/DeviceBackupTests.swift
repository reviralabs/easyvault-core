import Foundation
import XCTest
@testable import VaultCore

/// Two devices on one Apple Account share one iCloud store; each keeps its own backup in it.
final class DeviceBackupTests: XCTestCase {
    private var roots: [URL] = []
    private let fast = Argon2Parameters(opsLimit: 1, memLimitBytes: 8 << 20)

    override func tearDown() {
        for root in roots { try? FileManager.default.removeItem(at: root) }
    }

    private func phone() throws -> VaultManager {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("devices-\(UUID().uuidString)")
        roots.append(root)
        return try VaultManager(root: root, deviceSecret: FixedDeviceSecret(), argon2: fast)
    }

    private func names(_ vault: Vault) async -> Set<String> {
        Set(await vault.items.map(\.name))
    }

    func testTwoDevicesKeepTheirOwnBackups() async throws {
        let icloud = MemoryBackupStore()
        let iPhone = try phone(), iPad = try phone()
        let iPhoneKey = RecoveryKey.generate(), iPadKey = RecoveryKey.generate()
        let a = try iPhone.createVault(secret: .password("iphone pass 1"), recoveryKey: iPhoneKey)
        try await a.add(Data("a".utf8), name: "from-iphone.jpg", kind: .photo, contentType: "public.jpeg")
        let b = try iPad.createVault(secret: .password("ipad pass 1"), recoveryKey: iPadKey)
        try await b.add(Data("b".utf8), name: "from-ipad.jpg", kind: .photo, contentType: "public.jpeg")

        // Neither asks to replace the other, and both stay.
        try await iPhone.backUp(a.id, to: DeviceBackupStore(icloud, deviceID: UUID()))
        try await iPad.backUp(b.id, to: DeviceBackupStore(icloud, deviceID: UUID()))
        let keys = await icloud.list().keys
        XCTAssertTrue(keys.allSatisfy { $0.hasPrefix("devices/") })

        // The recovery key finds its own vault.
        let restoredA = try await phone().restore(from: icloud, recoveryKey: iPhoneKey, newSecret: .password("new phone 1"))
        let restoredB = try await phone().restore(from: icloud, recoveryKey: iPadKey, newSecret: .password("new phone 2"))
        XCTAssertEqual(restoredA.id, a.id)
        XCTAssertEqual(restoredB.id, b.id)
        let namesA = await names(restoredA), namesB = await names(restoredB)
        XCTAssertEqual(namesA, ["from-iphone.jpg"])
        XCTAssertEqual(namesB, ["from-ipad.jpg"])

        do {
            try await phone().verifyBackup(in: icloud, recoveryKey: .generate())
            XCTFail("a key for neither vault")
        } catch { XCTAssertEqual(error as? VaultError, .wrongSecret) }
        do {
            try await phone().verifyBackup(in: MemoryBackupStore(), recoveryKey: iPhoneKey)
            XCTFail("an empty iCloud")
        } catch { XCTAssertEqual(error as? BackupError, .noBackup) }
    }

    /// Restored onto an iPad and used on both: two backups of one vault. Restoring takes the one
    /// that changed last.
    func testSameVaultOnTwoDevicesRestoresTheNewest() async throws {
        let icloud = MemoryBackupStore()
        let key = RecoveryKey.generate()
        let iPhone = try phone(), iPhoneID = UUID()
        let vault = try iPhone.createVault(secret: .password("iphone pass 1"), recoveryKey: key)
        try await vault.add(Data("1".utf8), name: "first.jpg", kind: .photo, contentType: "public.jpeg")
        try await iPhone.backUp(vault.id, to: DeviceBackupStore(icloud, deviceID: iPhoneID))

        let iPad = try phone(), iPadID = UUID()
        let onIPad = try await iPad.restore(from: icloud, recoveryKey: key, newSecret: .password("ipad pass 1"))
        try await onIPad.add(Data("2".utf8), name: "added-on-ipad.jpg", kind: .photo, contentType: "public.jpeg")
        try await Task.sleep(for: .seconds(1.1))   // backup.json keeps whole seconds
        try await iPad.backUp(vault.id, to: DeviceBackupStore(icloud, deviceID: iPadID))
        let fromIPad = try await phone().restore(from: icloud, recoveryKey: key, newSecret: .password("new phone 1"))
        let fromIPadNames = await names(fromIPad)
        XCTAssertEqual(fromIPadNames, ["first.jpg", "added-on-ipad.jpg"])

        // The iPhone's backup is untouched by the iPad's, and wins once it changes again.
        try await vault.add(Data("3".utf8), name: "added-on-iphone.jpg", kind: .photo, contentType: "public.jpeg")
        try await Task.sleep(for: .seconds(1.1))
        try await iPhone.backUp(vault.id, to: DeviceBackupStore(icloud, deviceID: iPhoneID))
        let fromIPhone = try await phone().restore(from: icloud, recoveryKey: key, newSecret: .password("new phone 2"))
        let fromIPhoneNames = await names(fromIPhone)
        XCTAssertEqual(fromIPhoneNames, ["first.jpg", "added-on-iphone.jpg"])
    }

    /// Backups made before 1.3 sit at the top of the store. They still restore, and each device
    /// removes its own once its per-device backup is complete, never another vault's.
    func testBackupsFromBeforeKeepWorkingAndMoveOver() async throws {
        let icloud = MemoryBackupStore()
        let key = RecoveryKey.generate()
        let device = try phone()
        let vault = try device.createVault(secret: .password("device pass 1"), recoveryKey: key)
        try await vault.add(Data("old".utf8), name: "old.jpg", kind: .photo, contentType: "public.jpeg")
        try await device.backUp(vault.id, to: icloud)   // the old, shared layout

        let restored = try await phone().restore(from: icloud, recoveryKey: key, newSecret: .password("new phone 1"))
        let restoredNames = await names(restored)
        XCTAssertEqual(restoredNames, ["old.jpg"])

        // Another device's vault in the old layout: left alone.
        let other = try phone()
        let otherVault = try other.createVault(secret: .password("other pass 1"), recoveryKey: .generate())
        try await other.removeLegacyBackup(of: otherVault.id, in: icloud)
        let untouched = await icloud.list().keys
        XCTAssertFalse(untouched.isEmpty)

        // This vault's device moves to its own backup, then drops the old one.
        let own = DeviceBackupStore(icloud, deviceID: UUID())
        try await device.backUp(vault.id, to: own)
        try await device.removeLegacyBackup(of: vault.id, in: icloud)
        let keys = await icloud.list().keys
        XCTAssertTrue(keys.allSatisfy { $0.hasPrefix("devices/") }, "only the per-device backup is left")
        let status = try await device.checkBackup(vault.id, in: own, recoveryKey: key)
        XCTAssertTrue(status.isComplete)
        XCTAssertEqual(status.recoveryKeyWorks, true)
        let again = try await phone().restore(from: icloud, recoveryKey: key, newSecret: .password("new phone 2"))
        let againNames = await names(again)
        XCTAssertEqual(againNames, ["old.jpg"])
    }

    func testDevicesOnlySeeTheirOwnBackup() async throws {
        let icloud = MemoryBackupStore()
        let first = DeviceBackupStore(icloud, deviceID: UUID()), second = DeviceBackupStore(icloud, deviceID: UUID())
        try await first.put("index.evi#0of1", data: Data("1".utf8), sha256: "x")
        try await second.put("index.evi#0of1", data: Data("2".utf8), sha256: "y")
        await icloud.put("vault.json#0of1", data: Data("old".utf8), sha256: "z")

        let firstKeys = try await first.list()
        XCTAssertEqual(Array(firstKeys.keys), ["index.evi#0of1"])
        let firstData = try await first.get("index.evi#0of1")
        XCTAssertEqual(firstData, Data("1".utf8))
        let legacyKeys = try await DeviceBackupStore.legacy(icloud).list()
        XCTAssertEqual(Array(legacyKeys.keys), ["vault.json#0of1"])

        try await second.delete(["index.evi#0of1"])
        let left = await icloud.list().count
        XCTAssertEqual(left, 2, "deleting in one device's backup touches nothing else")
        let all = try await DeviceBackupStore.all(in: icloud)
        XCTAssertEqual(all.count, 2, "the first device's and the old one")
    }
}
