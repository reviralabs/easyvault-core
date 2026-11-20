import Crypto
import Foundation
import XCTest
@testable import VaultCore

final class KeyDerivationTests: XCTestCase {
    private let salt = Data(0..<16)
    private let params = Argon2Parameters(opsLimit: 2, memLimitBytes: 8 << 20)

    /// Expected values computed independently with argon2-cffi (Argon2id, t=2, m=8 MiB, p=1).
    func testArgon2idMatchesReferenceImplementation() throws {
        let pin = try KeyDerivation.argon2id(Array("pin:123456".utf8), salt: salt, parameters: params)
        XCTAssertEqual(pin.data.hex, "967126c93343b257cf0d5d20e2f4fe7ebbb285e3b12624764bcf626319b16611")

        // Non-ASCII bytes must not crash and must hash as UTF-8.
        let password = try KeyDerivation.argon2id(LockSecret.password("pässwörd🔒").derivationInput, salt: salt, parameters: params)
        XCTAssertEqual(password.data.hex, "de3f1be207d117109186a1963cbae0ad9fcf8b77bffd25a1caf54ac32abde148")
    }

    func testLockTypesProduceDifferentInputs() {
        let inputs = [
            LockSecret.pattern([1, 2, 3, 4, 5, 6]).derivationInput,
            LockSecret.password("1,2,3,4,5,6").derivationInput,
            LockSecret.password("123456").derivationInput,
        ]
        XCTAssertEqual(Set(inputs).count, 3)
    }

    func testTwoDigitPatternNodesDontCollide() {
        // Without a separator, [1, 2, ...] and [12, ...] would hash the same digits.
        XCTAssertNotEqual(
            LockSecret.pattern([1, 2, 3, 4, 5, 6]).derivationInput,
            LockSecret.pattern([12, 3, 4, 5, 6, 7]).derivationInput
        )
    }

    func testPasswordIsUnicodeNormalised() {
        // "é" precomposed vs "e" + combining accent.
        XCTAssertEqual(LockSecret.password("caf\u{E9}abc").derivationInput, LockSecret.password("cafe\u{301}abc").derivationInput)
    }

    func testSecretValidation() {
        XCTAssertNoThrow(try LockSecret.pattern([0, 6, 12, 18, 24, 19]).validate())
        XCTAssertNoThrow(try LockSecret.pattern(Array(0..<25)).validate(), "every dot")
        XCTAssertThrowsError(try LockSecret.pattern([0, 6, 12, 18, 24]).validate(), "needs 6 dots")
        XCTAssertThrowsError(try LockSecret.pattern([0, 6, 12, 18, 24, 0]).validate(), "repeated dot")
        XCTAssertThrowsError(try LockSecret.pattern([0, 6, 12, 18, 24, 25]).validate(), "off the 5×5 grid")
        XCTAssertNoThrow(try LockSecret.password("maple river 42").validate())
        XCTAssertThrowsError(try LockSecret.password("seven77").validate(), "needs 8 characters")
    }

    func testCommonPasswordsAreRejected() {
        XCTAssertGreaterThan(CommonPasswords.count, 40_000, "the bundled list loaded")
        for common in ["password", "Password1", "iloveyou", "12345678", "qwertyuiop", "sunshine"] {
            XCTAssertThrowsError(try LockSecret.password(common).validate(), common) {
                guard case .invalidSecret = $0 as? VaultError else { return XCTFail("\($0)") }
            }
        }
        XCTAssertNoThrow(try LockSecret.password("quiet harbor lantern").validate())
    }
}

final class RecoveryKeyTests: XCTestCase {
    func testRoundTripAndFormat() throws {
        for _ in 0..<200 {
            let key = RecoveryKey.generate()
            let text = key.description
            XCTAssertEqual(text.count, 24 + 6 + 1)
            XCTAssertNotNil(text.range(of: #"^([0-9A-HJKMNP-TV-Z]{4}-){6}[0-9A-HJKMNP-TV-Z]$"#, options: .regularExpression), text)
            XCTAssertEqual(try RecoveryKey(text), key)
            XCTAssertEqual(try RecoveryKey(text.lowercased().replacingOccurrences(of: "-", with: " ")), key)
        }
    }

    func testAcceptsLookalikes() throws {
        let key = RecoveryKey(bytes: Data(repeating: 0, count: 15))
        let text = key.description
        XCTAssertTrue(text.hasPrefix("0000-"))
        XCTAssertEqual(try RecoveryKey(text.replacingOccurrences(of: "0", with: "O")), key)
    }

    func testRejectsTypos() {
        let text = RecoveryKey.generate().description
        var rejected = 0
        // Change one character at a time; the check character catches most single typos.
        for position in text.indices where text[position] != "-" {
            var changed = text
            changed.replaceSubrange(position...position, with: text[position] == "A" ? "B" : "A")
            if (try? RecoveryKey(changed)) == nil { rejected += 1 }
        }
        XCTAssertGreaterThan(rejected, 20)
        XCTAssertThrowsError(try RecoveryKey("ABCD"))
        XCTAssertThrowsError(try RecoveryKey(String(text.dropLast())))
    }
}

final class ItemCipherTests: XCTestCase {
    private let id = UUID()
    private let key = SymmetricKey(size: .bits256)
    /// 4 KiB chunks so multi-chunk cases stay small.
    private let log2: UInt8 = 12
    private var chunk: Int { 1 << Int(log2) }

    private func random(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    func testRoundTripAtChunkBoundaries() throws {
        for size in [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 3 * chunk + 17] {
            let plaintext = random(size)
            let sealed = try ItemCipher.encrypt(plaintext, itemID: id, key: key, chunkSizeLog2: log2)
            let chunks = max(1, (size + chunk - 1) / chunk)
            XCTAssertEqual(sealed.count, ItemCipher.headerLength + size + chunks * ItemCipher.tagLength, "size \(size)")
            XCTAssertEqual(try ItemCipher.decrypt(sealed, itemID: id, key: key), plaintext, "size \(size)")
        }
    }

    func testStreamingMatchesInMemoryFormat() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        for size in [0, chunk, 2 * chunk + 5] {
            let plaintext = random(size)
            let source = dir.appendingPathComponent("in-\(size)")
            let sealedURL = dir.appendingPathComponent("sealed-\(size)")
            let output = dir.appendingPathComponent("out-\(size)")
            try plaintext.write(to: source)

            try ItemCipher.encryptFile(at: source, to: sealedURL, itemID: id, key: key, chunkSizeLog2: log2)
            XCTAssertEqual(try Data(contentsOf: sealedURL), try ItemCipher.encrypt(plaintext, itemID: id, key: key, chunkSizeLog2: log2))

            try ItemCipher.decryptFile(at: sealedURL, to: output, itemID: id, key: key)
            XCTAssertEqual(try Data(contentsOf: output), plaintext)
        }
    }

    func testDetectsTampering() throws {
        let plaintext = random(3 * chunk + 10)
        let sealed = try ItemCipher.encrypt(plaintext, itemID: id, key: key, chunkSizeLog2: log2)
        let header = ItemCipher.headerLength
        let sealedChunk = chunk + ItemCipher.tagLength
        let chunks = (0..<4).map { i in sealed.subdata(in: (header + i * sealedChunk)..<min(header + (i + 1) * sealedChunk, sealed.count)) }

        var flipped = sealed
        flipped[header + 100] ^= 1
        XCTAssertThrowsError(try ItemCipher.decrypt(flipped, itemID: id, key: key), "flipped byte")

        let truncated = sealed.prefix(header + 3 * sealedChunk)
        XCTAssertThrowsError(try ItemCipher.decrypt(truncated, itemID: id, key: key), "last chunk dropped")

        let swapped = sealed.prefix(header) + chunks[1] + chunks[0] + chunks[2] + chunks[3]
        XCTAssertThrowsError(try ItemCipher.decrypt(swapped, itemID: id, key: key), "chunks reordered")

        let appended = sealed + chunks[0]
        XCTAssertThrowsError(try ItemCipher.decrypt(appended, itemID: id, key: key), "chunk appended")

        XCTAssertThrowsError(try ItemCipher.decrypt(sealed, itemID: UUID(), key: key), "wrong item")
        XCTAssertThrowsError(try ItemCipher.decrypt(sealed, itemID: id, key: SymmetricKey(size: .bits256)), "wrong key")

        var headerChanged = sealed
        headerChanged[6] = 1
        XCTAssertThrowsError(try ItemCipher.decrypt(headerChanged, itemID: id, key: key), "header modified")
    }
}

final class AttemptPolicyTests: XCTestCase {
    func testDelays() {
        XCTAssertEqual(AttemptPolicy.delay(afterFailures: 4), 0)
        XCTAssertEqual(AttemptPolicy.delay(afterFailures: 5), 60)
        XCTAssertEqual(AttemptPolicy.delay(afterFailures: 6), 300)
        XCTAssertEqual(AttemptPolicy.delay(afterFailures: 7), 900)
        XCTAssertEqual(AttemptPolicy.delay(afterFailures: 20), 3600)
        XCTAssertEqual(AttemptPolicy.nextAttemptAllowed(failures: 0, lastFailure: nil), .distantPast)
    }
}

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
