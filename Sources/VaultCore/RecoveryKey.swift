import Crypto
import Foundation

/// 120 random bits shown to the user as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-C`:
/// 24 Crockford base32 characters plus one check character.
public struct RecoveryKey: Sendable, Equatable, CustomStringConvertible {
    static let byteCount = 15
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    let bytes: Data

    public static func generate() -> RecoveryKey {
        RecoveryKey(bytes: KeyDerivation.randomBytes(byteCount))
    }

    init(bytes: Data) {
        precondition(bytes.count == Self.byteCount)
        self.bytes = bytes
    }

    /// Accepts any case, with or without dashes and spaces, and the usual Crockford
    /// look-alikes (O for 0, I and L for 1).
    public init(_ text: String) throws {
        let symbols = text.uppercased().compactMap { character -> Character? in
            switch character {
            case "-", " ": nil
            case "O": "0"
            case "I", "L": "1"
            default: character
            }
        }
        guard symbols.count == 25 else { throw VaultError.invalidRecoveryKey }
        var values: [UInt8] = []
        for symbol in symbols {
            guard let index = Self.alphabet.firstIndex(of: symbol) else { throw VaultError.invalidRecoveryKey }
            values.append(UInt8(index))
        }
        let bytes = Self.unpack(Array(values.prefix(24)))
        guard Self.checkValue(bytes) == values[24] else { throw VaultError.invalidRecoveryKey }
        self.bytes = bytes
    }

    public var description: String {
        let symbols = Self.pack(bytes).map { Self.alphabet[Int($0)] } + [Self.alphabet[Int(Self.checkValue(bytes))]]
        return stride(from: 0, to: 24, by: 4)
            .map { String(symbols[$0..<$0 + 4]) }
            .joined(separator: "-") + "-" + String(symbols[24])
    }

    var key: SymmetricKey { SymmetricKey(data: bytes) }

    /// 120 bits → 24 five-bit values.
    private static func pack(_ bytes: Data) -> [UInt8] {
        var values: [UInt8] = []
        var buffer = 0
        var bits = 0
        for byte in bytes {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                values.append(UInt8((buffer >> bits) & 0x1F))
            }
        }
        return values
    }

    private static func unpack(_ values: [UInt8]) -> Data {
        var bytes = Data()
        var buffer = 0
        var bits = 0
        for value in values {
            buffer = (buffer << 5) | Int(value)
            bits += 5
            if bits >= 8 {
                bits -= 8
                bytes.append(UInt8((buffer >> bits) & 0xFF))
            }
        }
        return bytes
    }

    private static func checkValue(_ bytes: Data) -> UInt8 {
        Array(SHA256.hash(data: bytes))[0] & 0x1F
    }
}
