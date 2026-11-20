import Crypto
import Foundation

/// One way of unlocking a vault: the vault key, wrapped with AES-256-GCM under a key
/// derived from a passcode, a biometric-gated Keychain key, or the recovery key.
public struct Keyslot: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case passcode, biometric, recovery
    }

    public var kind: Kind
    /// Only for passcode slots, so the lock screen knows whether to show a keypad or a grid.
    public var secretKind: LockSecret.Kind?
    /// nonce ‖ ciphertext ‖ tag
    var sealed: Data

    static func wrap(_ vaultKey: SymmetricKey, with kek: SymmetricKey, kind: Kind, secretKind: LockSecret.Kind? = nil, vaultID: UUID) throws -> Keyslot {
        let box = try AES.GCM.seal(vaultKey.data, using: kek, authenticating: aad(kind, vaultID))
        return Keyslot(kind: kind, secretKind: secretKind, sealed: box.combined!)
    }

    func unwrap(with kek: SymmetricKey, vaultID: UUID) throws -> SymmetricKey {
        do {
            let box = try AES.GCM.SealedBox(combined: sealed)
            return SymmetricKey(data: try AES.GCM.open(box, using: kek, authenticating: Self.aad(kind, vaultID)))
        } catch {
            throw VaultError.wrongSecret
        }
    }

    private static func aad(_ kind: Kind, _ vaultID: UUID) -> Data {
        Data("ev/slot/\(kind.rawValue)".utf8) + vaultID.data
    }
}

/// `vault.json`: everything needed to unlock a vault. Contains no plaintext secrets.
struct VaultHeader: Codable, Sendable {
    static let currentVersion = 1

    var version: Int
    var id: UUID
    var createdAt: Date
    var slots: [Keyslot]
}

/// `device.json`: settings shared by every vault on this device.
struct DeviceConfig: Codable, Sendable {
    static let currentVersion = 1

    var version: Int
    var salt: Data
    var argon2: Argon2Parameters
    /// Missing in folders created before Secure Enclave binding existed.
    var binding: DeviceBindingKind?

    var bindingKind: DeviceBindingKind { binding ?? .keychainSecret }
}

/// Supplies the 32-byte device secret for `DeviceSecretBinding`. The app keeps it in the
/// Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; tests use an in-memory value.
public protocol DeviceSecretProvider: Sendable {
    func deviceSecret() throws -> SymmetricKey
}

/// Derives slot keys. Shared by the vault manager and open vaults.
struct SlotKeys: Sendable {
    let config: DeviceConfig
    let binding: any DeviceBinding

    /// The expensive step, run once per unlock attempt however many vaults exist.
    func stretch(_ secret: LockSecret) throws -> SymmetricKey {
        let stretched = try KeyDerivation.argon2id(secret.derivationInput, salt: config.salt, parameters: config.argon2)
        return try binding.bind(stretched)
    }

    func passcodeKEK(stretched: SymmetricKey, vaultID: UUID) -> SymmetricKey {
        KeyDerivation.hkdf(stretched, vaultID: vaultID, info: "ev/passcode")
    }

    func recoveryKEK(_ recoveryKey: RecoveryKey, vaultID: UUID) -> SymmetricKey {
        KeyDerivation.hkdf(recoveryKey.key, vaultID: vaultID, info: "ev/recovery")
    }
}
