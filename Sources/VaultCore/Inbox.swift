import Crypto
import Foundation

/// Files handed to Easy Vault while it's locked (the share extension). The sender only has the
/// inbox's public key, so it can encrypt but never read; the app opens entries with the private
/// key after the main vault is unlocked, then adds them to the vault.
///
/// Each entry is two files in the inbox folder, named by a fresh entry ID:
/// - `<id>.evf`: the content, in the item file format, under a per-entry key.
/// - `<id>.evm`: 32-byte ephemeral X25519 public key ‖ AES-GCM sealed JSON metadata.
///
/// Entry key = HKDF-SHA256(X25519(ephemeral, inbox), salt: entry ID, info: "EasyVault inbox v1").
/// The `.evm` file is written last, so a half-written entry has no metadata and is skipped.
public enum Inbox {
    public struct Metadata: Codable, Sendable, Equatable {
        public var name: String
        public var contentType: String
        public var createdAt: Date?

        public init(name: String, contentType: String, createdAt: Date? = nil) {
            self.name = name
            self.contentType = contentType
            self.createdAt = createdAt
        }
    }

    public struct Entry: Sendable {
        public let id: UUID
        public let metadata: Metadata
        let keyBytes: Data
        var key: SymmetricKey { SymmetricKey(data: keyBytes) }
        let contentURL: URL
        let metadataURL: URL
    }

    /// A new inbox key pair. The app keeps `rawRepresentation` private and shares `publicKey`.
    public static func makeKey() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }

    /// Encrypts a file into the inbox for `recipient`. Reads the source chunk by chunk, so large
    /// videos never sit in memory. The source is left in place.
    @discardableResult
    public static func seal(fileAt source: URL, metadata: Metadata, to recipient: Curve25519.KeyAgreement.PublicKey, in folder: URL) throws -> UUID {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: Storage.fileAttributes)
        let id = UUID()
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let key = try entryKey(ephemeral.sharedSecretFromKeyAgreement(with: recipient), id: id)
        let contentURL = folder.appendingPathComponent("\(id.uuidString).evf")
        let metadataURL = folder.appendingPathComponent("\(id.uuidString).evm")
        do {
            try ItemCipher.encryptFile(at: source, to: contentURL, itemID: id, key: key)
            var meta = ephemeral.publicKey.rawRepresentation
            meta.append(try AES.GCM.seal(JSONEncoder().encode(metadata), using: key, authenticating: id.data).combined!)
            try Storage.write(meta, to: metadataURL)
        } catch {
            try? FileManager.default.removeItem(at: contentURL)
            throw error
        }
        return id
    }

    /// Complete entries the private key can open, oldest first. Entries it can't open (another
    /// key, damaged) are left alone.
    public static func entries(in folder: URL, key privateKey: Curve25519.KeyAgreement.PrivateKey) -> [Entry] {
        let files = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.creationDateKey])) ?? []
        return files
            .filter { $0.pathExtension == "evm" }
            .sorted { (try? $0.resourceValues(forKeys: [.creationDateKey]).creationDate ?? .distantPast) ?? .distantPast
                    < (try? $1.resourceValues(forKeys: [.creationDateKey]).creationDate ?? .distantPast) ?? .distantPast }
            .compactMap { open($0, key: privateKey) }
    }

    /// Decrypts an entry's content to `destination`.
    public static func decrypt(_ entry: Entry, to destination: URL) throws {
        try ItemCipher.decryptFile(at: entry.contentURL, to: destination, itemID: entry.id, key: entry.key)
    }

    public static func remove(_ entry: Entry) {
        try? FileManager.default.removeItem(at: entry.metadataURL)
        try? FileManager.default.removeItem(at: entry.contentURL)
    }

    private static func open(_ metadataURL: URL, key privateKey: Curve25519.KeyAgreement.PrivateKey) -> Entry? {
        guard let id = UUID(uuidString: metadataURL.deletingPathExtension().lastPathComponent),
              let data = try? Data(contentsOf: metadataURL), data.count > 32,
              let ephemeral = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: data.prefix(32)),
              let secret = try? privateKey.sharedSecretFromKeyAgreement(with: ephemeral),
              let key = try? entryKey(secret, id: id),
              let box = try? AES.GCM.SealedBox(combined: data.dropFirst(32)),
              let json = try? AES.GCM.open(box, using: key, authenticating: id.data),
              let metadata = try? JSONDecoder().decode(Metadata.self, from: json) else { return nil }
        let contentURL = metadataURL.deletingPathExtension().appendingPathExtension("evf")
        guard FileManager.default.fileExists(atPath: contentURL.path) else { return nil }
        return Entry(id: id, metadata: metadata, keyBytes: key.withUnsafeBytes { Data($0) }, contentURL: contentURL, metadataURL: metadataURL)
    }

    private static func entryKey(_ secret: SharedSecret, id: UUID) throws -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: id.data, sharedInfo: Data("EasyVault inbox v1".utf8), outputByteCount: 32)
    }
}
