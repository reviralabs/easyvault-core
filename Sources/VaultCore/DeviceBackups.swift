import Foundation

/// `backup.json` in a backup: when it last changed. Plain JSON, like `vault.json`; the store
/// knows when objects were written anyway.
struct BackupInfo: Codable, Sendable {
    static let currentVersion = 1

    var version: Int
    var updatedAt: Date
}

/// One device's backup inside a store shared by every device on the same account (one iCloud
/// account, one CloudKit zone). Each device writes under `devices/<device ID>/`, so an iPhone
/// and an iPad never replace each other's backup. Backups made before backups were per device
/// sit at the top of the store; `legacy(_:)` reads those.
///
/// Keys inside look the same as in a store of their own, so `BackupEngine` doesn't know.
public struct DeviceBackupStore: BackupStore {
    static let folder = "devices/"

    let inner: any BackupStore
    /// nil: the top level, without anything under `devices/`.
    let prefix: String?

    public init(_ inner: any BackupStore, deviceID: UUID) {
        self.inner = inner
        prefix = Self.folder + deviceID.uuidString + "/"
    }

    private init(inner: any BackupStore, prefix: String?) {
        self.inner = inner
        self.prefix = prefix
    }

    /// The backup made before backups were per device, if there is one.
    public static func legacy(_ inner: any BackupStore) -> DeviceBackupStore {
        DeviceBackupStore(inner: inner, prefix: nil)
    }

    /// Every backup in `inner`: one per device that has backed up, plus the legacy one.
    static func all(in inner: any BackupStore) async throws -> [DeviceBackupStore] {
        var prefixes = Set<String>()
        var hasLegacy = false
        for key in try await inner.list().keys {
            if key.hasPrefix(folder) {
                let rest = key.dropFirst(folder.count)
                if let slash = rest.firstIndex(of: "/"), UUID(uuidString: String(rest[..<slash])) != nil {
                    prefixes.insert(folder + rest[..<slash] + "/")
                }
            } else {
                hasLegacy = true
            }
        }
        return prefixes.sorted().map { DeviceBackupStore(inner: inner, prefix: $0) }
            + (hasLegacy ? [legacy(inner)] : [])
    }

    private func owns(_ key: String) -> Bool {
        if let prefix { return key.hasPrefix(prefix) }
        return !key.hasPrefix(Self.folder)
    }

    private func full(_ key: String) -> String { (prefix ?? "") + key }

    public func list() async throws -> [String: String] {
        var result: [String: String] = [:]
        for (key, sha) in try await inner.list() where owns(key) {
            result[String(key.dropFirst(prefix?.count ?? 0))] = sha
        }
        return result
    }

    public func put(_ key: String, data: Data, sha256: String) async throws {
        try await inner.put(full(key), data: data, sha256: sha256)
    }

    public func get(_ key: String) async throws -> Data {
        try await inner.get(full(key))
    }

    public func delete(_ keys: [String]) async throws {
        try await inner.delete(keys.map(full))
    }
}
