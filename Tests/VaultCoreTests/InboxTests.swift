import Crypto
import Foundation
import XCTest
@testable import VaultCore

final class InboxTests: XCTestCase {
    private var folder: URL!

    override func setUp() {
        folder = FileManager.default.temporaryDirectory.appendingPathComponent("inbox-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: folder)
    }

    private func source(_ bytes: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try bytes.write(to: url)
        return url
    }

    func testSealedEntryOpensOnlyWithThePrivateKey() throws {
        let key = Inbox.makeKey()
        let plaintext = Data((0..<3_000_000).map { UInt8($0 % 251) }) // spans several chunks
        let meta = Inbox.Metadata(name: "beach.jpg", contentType: "public.jpeg")
        try Inbox.seal(fileAt: source(plaintext), metadata: meta, to: key.publicKey, in: folder)

        XCTAssertTrue(Inbox.entries(in: folder, key: Inbox.makeKey()).isEmpty, "another key opens nothing")
        let entries = Inbox.entries(in: folder, key: key)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].metadata, meta)

        let out = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Inbox.decrypt(entries[0], to: out)
        XCTAssertEqual(try Data(contentsOf: out), plaintext)

        Inbox.remove(entries[0])
        XCTAssertTrue(Inbox.entries(in: folder, key: key).isEmpty)
    }

    func testNothingReadableOnDisk() throws {
        let key = Inbox.makeKey()
        let secret = Data("my seed phrase words".utf8)
        try Inbox.seal(fileAt: source(secret), metadata: .init(name: "seed-phrase.txt", contentType: "public.plain-text"), to: key.publicKey, in: folder)
        for file in try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil) {
            let bytes = try Data(contentsOf: file)
            XCTAssertNil(bytes.range(of: secret))
            XCTAssertNil(bytes.range(of: Data("seed-phrase".utf8)), "the file name is encrypted too")
        }
    }

    func testHalfWrittenEntryIsSkipped() throws {
        let key = Inbox.makeKey()
        let id = try Inbox.seal(fileAt: source(Data("x".utf8)), metadata: .init(name: "a", contentType: "public.data"), to: key.publicKey, in: folder)
        try FileManager.default.removeItem(at: folder.appendingPathComponent("\(id.uuidString).evf"))
        XCTAssertTrue(Inbox.entries(in: folder, key: key).isEmpty)
    }
}
