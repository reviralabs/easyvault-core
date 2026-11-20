import Foundation

public enum VaultError: Error, Equatable, Sendable {
    /// The PIN, pattern or password doesn't follow the rules for its lock type.
    case invalidSecret(String)
    /// No vault opens with this secret, recovery key or biometric key.
    case wrongSecret
    /// Another vault on this device already opens with this secret.
    case secretInUse
    /// The recovery key is malformed or its check character doesn't match.
    case invalidRecoveryKey
    /// A file is damaged, truncated or was modified.
    case corrupted(String)
    /// A format version this build doesn't understand.
    case unsupportedVersion(Int)
    /// The vault was locked; unlock it again through `VaultManager`.
    case locked
    case itemNotFound(UUID)
    case albumNotFound(UUID)
    case vaultNotFound(UUID)
    /// The vault folder was created with a different device binding than the one supplied.
    case deviceBindingMismatch(String)
    /// Argon2id failed, which in practice means it couldn't allocate memory.
    case keyDerivationFailed
}
