import Foundation

public struct VaultItem: Codable, Sendable, Identifiable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case photo, video, file
    }

    public let id: UUID
    public var name: String
    public var kind: Kind
    /// Uniform type identifier, e.g. `public.jpeg`.
    public var contentType: String
    public var byteCount: Int64
    /// When the photo or file was originally created, if known.
    public var createdAt: Date?
    public var addedAt: Date
    public var albumID: UUID?
    public var hasThumbnail: Bool
    /// The item's own encryption key. Only ever stored inside the encrypted index.
    var key: Data
}

public struct Album: Codable, Sendable, Identifiable, Equatable {
    public let id: UUID
    public var name: String
    public var createdAt: Date
}

/// Sealed with the vault key into `index.evi`.
struct VaultIndex: Codable, Sendable {
    static let currentVersion = 1

    var version = VaultIndex.currentVersion
    var items: [VaultItem] = []
    var albums: [Album] = []
    /// Duress vault: opening it removes every other vault on the device. Kept inside the
    /// encrypted index, so nothing on disk shows that a vault is one until it is opened.
    /// Optional so indexes written before this field still decode.
    var isDuress: Bool?
    /// On the main vault: whether its decoy is a duress vault, so the app can show the setting
    /// without the decoy's passcode. Also only readable once this vault is unlocked.
    var decoyIsDuress: Bool?
}
