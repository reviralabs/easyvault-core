import Crypto
import Foundation

/// How passcode keys are tied to this device. Stored in `device.json`, so a vault never
/// silently switches scheme (which would make every passcode look wrong).
public enum DeviceBindingKind: String, Codable, Sendable {
    /// A random 32-byte secret in the Keychain. Used where there's no Secure Enclave
    /// (the simulator). Stops attacks on copied vault files, but forensic tools that can
    /// read the Keychain could take the secret and guess passcodes off the device.
    case keychainSecret
    /// A P-256 key that lives inside the Secure Enclave and can't be exported. Every
    /// passcode guess needs that chip, so guessing can only happen on this iPhone.
    case secureEnclave
}

/// Turns the Argon2id output for a passcode into key material only this device can produce.
/// The result feeds HKDF per vault, so it runs once per unlock attempt.
public protocol DeviceBinding: Sendable {
    var kind: DeviceBindingKind { get }
    func bind(_ stretched: SymmetricKey) throws -> SymmetricKey
}

/// Appends a device secret: `stretched ‖ secret`.
public struct DeviceSecretBinding: DeviceBinding {
    public let kind = DeviceBindingKind.keychainSecret
    let provider: any DeviceSecretProvider

    public init(_ provider: any DeviceSecretProvider) {
        self.provider = provider
    }

    public func bind(_ stretched: SymmetricKey) throws -> SymmetricKey {
        SymmetricKey(data: stretched.data + (try provider.deviceSecret()).data)
    }
}

/// Binds through an ECDH key agreement with a key the caller can't export (the Secure
/// Enclave in the app, a software key in tests):
///
/// 1. The Argon2id output is turned into a P-256 private scalar `p`, deterministically.
/// 2. The device key `d` agrees with `p·G`, giving the shared secret `d·p·G`.
///    Computing it needs both the passcode and `d`.
/// 3. Result: `stretched ‖ HKDF(shared secret)`.
public struct KeyAgreementBinding: DeviceBinding {
    public typealias Agree = @Sendable (P256.KeyAgreement.PublicKey) throws -> SharedSecret

    public let kind = DeviceBindingKind.secureEnclave
    let agree: Agree

    public init(agree: @escaping Agree) {
        self.agree = agree
    }

    public func bind(_ stretched: SymmetricKey) throws -> SymmetricKey {
        let passcodeKey = try Self.passcodeKey(from: stretched)
        let shared = try agree(passcodeKey.publicKey)
        let bound = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("ev/device-binding".utf8),
            sharedInfo: Data("ev/secure-enclave".utf8),
            outputByteCount: 32
        )
        return SymmetricKey(data: stretched.data + bound.data)
    }

    /// A P-256 private key derived from the stretched passcode. Not every 32-byte string is a
    /// valid scalar (zero, or ≥ the group order, about 1 in 2³² for random input), so hash
    /// with a counter until one is.
    static func passcodeKey(from stretched: SymmetricKey) throws -> P256.KeyAgreement.PrivateKey {
        for counter in UInt8(0)...UInt8.max {
            var hash = SHA256()
            hash.update(data: Data("ev/passcode-scalar".utf8))
            hash.update(data: stretched.data)
            hash.update(data: Data([counter]))
            if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: Data(hash.finalize())) {
                return key
            }
        }
        throw VaultError.keyDerivationFailed
    }
}
