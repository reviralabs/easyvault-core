import Clibsodium
import Crypto
import Foundation

/// Argon2id settings, stored on disk so they can be raised in later versions.
public struct Argon2Parameters: Codable, Sendable, Equatable {
    public var opsLimit: Int
    public var memLimitBytes: Int

    /// 3 passes over 64 MiB: roughly half a second on a recent iPhone.
    public static let standard = Argon2Parameters(opsLimit: 3, memLimitBytes: 64 << 20)

    public init(opsLimit: Int, memLimitBytes: Int) {
        self.opsLimit = opsLimit
        self.memLimitBytes = memLimitBytes
    }
}

enum KeyDerivation {
    static let saltLength = 16

    static func argon2id(_ input: [UInt8], salt: Data, parameters: Argon2Parameters) throws -> SymmetricKey {
        precondition(salt.count == saltLength, "Argon2id salt must be \(saltLength) bytes")
        guard sodium_init() >= 0 else { throw VaultError.keyDerivationFailed }
        var output = [UInt8](repeating: 0, count: 32)
        var passwd = input.map { CChar(bitPattern: $0) }
        defer {
            for i in output.indices { output[i] = 0 }
            for i in passwd.indices { passwd[i] = 0 }
        }
        let result = crypto_pwhash(
            &output, UInt64(output.count),
            passwd, UInt64(passwd.count),
            [UInt8](salt),
            UInt64(parameters.opsLimit), Int(parameters.memLimitBytes),
            crypto_pwhash_ALG_ARGON2ID13
        )
        guard result == 0 else { throw VaultError.keyDerivationFailed }
        return SymmetricKey(data: output)
    }

    static func hkdf(_ inputKeyMaterial: SymmetricKey, vaultID: UUID, info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: vaultID.data,
            info: Data(info.utf8),
            outputByteCount: 32
        )
    }

    static func randomBytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}

extension UUID {
    var data: Data {
        withUnsafeBytes(of: uuid) { Data($0) }
    }

    init?(data: Data) {
        guard data.count == 16 else { return nil }
        var raw: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &raw) { $0.copyBytes(from: data) }
        self.init(uuid: raw)
    }
}

extension SymmetricKey {
    var data: Data { withUnsafeBytes { Data($0) } }
}
