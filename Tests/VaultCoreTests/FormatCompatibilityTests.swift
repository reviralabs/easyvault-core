import Crypto
import Foundation
import XCTest
@testable import VaultCore

/// Every released vault format must keep opening. `Fixtures/format-v<n>` holds a vault folder
/// written by the code that shipped format n, with fixed secrets; these tests open it with
/// today's code. Before changing the format, add a new fixture with the old code:
///
///   WRITE_FORMAT_FIXTURE=$PWD/Tests/VaultCoreTests/Fixtures/format-v1 swift test --filter testWriteFixture
///
/// and never edit or delete an existing one.
final class FormatCompatibilityTests: XCTestCase {
    static let password = LockSecret.password("format fixture main")
    static let decoyPassword = LockSecret.password("format fixture decoy")
    static let device = FixedDeviceSecret(bytes: Data(repeating: 7, count: 32))
    static let recoveryKey = RecoveryKey(bytes: Data(repeating: 9, count: 15))
    static let photo = Data("a photo from format v1".utf8)
    static let thumbnail = Data("its thumbnail".utf8)
    static let document = Data((0..<5_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })

    private var root: URL!

    override func tearDown() {
        if let root { try? FileManager.default.removeItem(at: root) }
    }

    /// Opens a copy, so the fixture itself is never changed by a test.
    private func openFixture(_ name: String) throws -> VaultManager {
        guard let fixture = Bundle.module.resourceURL?.appendingPathComponent("Fixtures/\(name)"),
              FileManager.default.fileExists(atPath: fixture.path) else {
            throw XCTSkip("no fixture \(name)")
        }
        root = FileManager.default.temporaryDirectory.appendingPathComponent("fixture-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: fixture, to: root)
        return try VaultManager(root: root, deviceSecret: Self.device)
    }

    func testFormatV1StillOpens() async throws {
        let manager = try openFixture("format-v1")
        XCTAssertEqual(try manager.vaultIDs().count, 2, "main vault and decoy")

        let vault = try manager.unlock(Self.password)
        let items = await vault.items
        XCTAssertEqual(Set(items.map(\.name)), ["beach.jpg", "passport.pdf"])
        let photo = try XCTUnwrap(items.first { $0.name == "beach.jpg" })
        let document = try XCTUnwrap(items.first { $0.name == "passport.pdf" })
        XCTAssertEqual(photo.kind, .photo)
        XCTAssertEqual(document.kind, .file)
        let photoData = try await vault.data(for: photo.id)
        let thumb = try await vault.thumbnail(for: photo.id)
        let documentData = try await vault.data(for: document.id)
        XCTAssertEqual(photoData, Self.photo)
        XCTAssertEqual(thumb, Self.thumbnail)
        XCTAssertEqual(documentData, Self.document)

        let albums = await vault.albums
        XCTAssertEqual(albums.map(\.name), ["Holiday"])
        XCTAssertEqual(photo.albumID, albums.first?.id)
        XCTAssertNil(document.albumID)

        let keyWorks = await vault.checkRecoveryKey(Self.recoveryKey)
        XCTAssertTrue(keyWorks)
        let decoyIsDuress = await vault.decoyIsDuress
        XCTAssertFalse(decoyIsDuress)

        // The other ways in: the recovery key, and the decoy's own passcode.
        let viaRecovery = try manager.unlock(vault.id, recoveryKey: Self.recoveryKey)
        let recoveredCount = await viaRecovery.items.count
        XCTAssertEqual(recoveredCount, 2)
        let decoy = try manager.unlock(Self.decoyPassword)
        XCTAssertNotEqual(decoy.id, vault.id)
        let decoyItems = await decoy.items
        XCTAssertEqual(decoyItems.map(\.name), ["harmless.jpg"])
    }

    /// A single vault folder opens with only its recovery key, as `evdecrypt` does: no
    /// device.json, no device secret.
    func testFormatV1OpensWithRecoveryKeyAlone() async throws {
        _ = try openFixture("format-v1")
        let mainID = UUID(uuidString: "9E2D3225-CF4F-4C3F-A460-245A94A610EB")!
        let folder = root.appendingPathComponent(mainID.uuidString)
        let key = try RecoveryKey(Self.recoveryKey.description)
        let vault = try Vault.open(folder: folder, recoveryKey: key)
        XCTAssertEqual(vault.id, mainID)
        let items = await vault.items
        let photo = try XCTUnwrap(items.first { $0.name == "beach.jpg" })
        let photoData = try await vault.data(for: photo.id)
        XCTAssertEqual(photoData, Self.photo)

        let out = root.appendingPathComponent("out.pdf")
        let document = try XCTUnwrap(items.first { $0.name == "passport.pdf" })
        try await vault.export(document.id, to: out)
        XCTAssertEqual(try Data(contentsOf: out), Self.document)

        XCTAssertThrowsError(try Vault.open(folder: folder, recoveryKey: RecoveryKey.generate())) {
            XCTAssertEqual($0 as? VaultError, .wrongSecret)
        }
    }

    /// Format v1 thumbnails shared their item's key and nonces. Unlocking re-encrypts them under
    /// their own key, once; opening read-only (evdecrypt) changes nothing.
    func testFormatV1ThumbnailsGetTheirOwnKey() async throws {
        let manager = try openFixture("format-v1")
        let mainID = UUID(uuidString: "9E2D3225-CF4F-4C3F-A460-245A94A610EB")!
        let folder = root.appendingPathComponent(mainID.uuidString)
        let thumbs = try FileManager.default.contentsOfDirectory(atPath: folder.appendingPathComponent("thumbs").path)
        let thumbURL = folder.appendingPathComponent("thumbs").appendingPathComponent(try XCTUnwrap(thumbs.first))
        let before = try Data(contentsOf: thumbURL)

        _ = try Vault.open(folder: folder, recoveryKey: Self.recoveryKey)
        XCTAssertEqual(try Data(contentsOf: thumbURL), before, "read-only open doesn't rewrite")

        let vault = try manager.unlock(Self.password)
        let items = await vault.items
        let photo = try XCTUnwrap(items.first { $0.name == "beach.jpg" })
        let after = try Data(contentsOf: thumbURL)
        XCTAssertNotEqual(after, before)
        let itemKey = SymmetricKey(data: photo.key)
        XCTAssertThrowsError(try ItemCipher.decrypt(after, itemID: photo.id, key: itemKey))
        XCTAssertEqual(try ItemCipher.decrypt(after, itemID: photo.id, key: ItemCipher.thumbnailKey(itemKey, itemID: photo.id)), Self.thumbnail)
        let thumb = try await vault.thumbnail(for: photo.id)
        XCTAssertEqual(thumb, Self.thumbnail)
        let vaultKey = await vault.keyForTesting
        let index = try Vault.readIndex(at: folder, vaultID: mainID, key: SymmetricKey(data: try XCTUnwrap(vaultKey)))
        XCTAssertEqual(index.thumbnailKeys, true)

        _ = try manager.unlock(Self.password)
        XCTAssertEqual(try Data(contentsOf: thumbURL), after, "upgrades once")
    }

    /// Writes the fixture for the current format. Skipped unless WRITE_FORMAT_FIXTURE is set.
    func testWriteFixture() async throws {
        guard let path = ProcessInfo.processInfo.environment["WRITE_FORMAT_FIXTURE"] else {
            throw XCTSkip("set WRITE_FORMAT_FIXTURE to write a fixture")
        }
        let destination = URL(fileURLWithPath: path)
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            XCTFail("\(path) exists; fixtures are never overwritten")
            return
        }
        // Light settings so the fixture opens quickly; they're stored in the folder.
        let manager = try VaultManager(root: destination, deviceSecret: Self.device, argon2: Argon2Parameters(opsLimit: 1, memLimitBytes: 8 << 20))
        let vault = try manager.createVault(secret: Self.password, recoveryKey: Self.recoveryKey)
        let photo = try await vault.add(Self.photo, name: "beach.jpg", kind: .photo, contentType: "public.jpeg", thumbnail: Self.thumbnail)
        _ = try await vault.add(Self.document, name: "passport.pdf", kind: .file, contentType: "com.adobe.pdf")
        let album = try await vault.createAlbum(named: "Holiday")
        try await vault.move([photo.id], toAlbum: album.id)
        try await vault.setDecoyIsDuress(false)
        let decoy = try manager.createVault(secret: Self.decoyPassword)
        _ = try await decoy.add(Data("nothing to see".utf8), name: "harmless.jpg", kind: .photo, contentType: "public.jpeg")
    }
}
