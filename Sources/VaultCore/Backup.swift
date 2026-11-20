import Crypto
import Foundation

/// Somewhere to keep a vault backup: the user's private CloudKit database in the app,
/// a folder or memory in tests. It only ever receives data that is already encrypted.
///
/// Objects are small blobs (at most `BackupEngine.partSize`) addressed by a string key.
public protocol BackupStore: Sendable {
    /// Every key in the store with the SHA-256 (hex) of its data.
    func list() async throws -> [String: String]
    func put(_ key: String, data: Data, sha256: String) async throws
    func get(_ key: String) async throws -> Data
    func delete(_ keys: [String]) async throws
}

public enum BackupError: Error, Equatable, Sendable {
    /// Backups need a recovery key: it's the only way to open the vault on another phone.
    case noRecoveryKey
    /// The store holds a backup of a different vault. Replace it explicitly.
    case differentVault(UUID)
    case noBackup
    /// The vault in the backup already exists on this device.
    case alreadyOnDevice
    /// A file in the backup is missing parts or doesn't match its checksum.
    case incomplete(String)
}

/// What a backup check found. See `VaultManager.checkBackup`.
public struct BackupStatus: Sendable, Equatable {
    /// Items on this device.
    public var itemCount: Int
    /// Items (or their thumbnails) on this device that aren't fully in the backup yet.
    public var missingCount: Int
    /// Whether the backup's index matches this device's, so it lists every item and album.
    public var indexIsCurrent: Bool
    /// Whether the recovery key given opens the backup; nil when no key was given.
    public var recoveryKeyWorks: Bool?

    public var isComplete: Bool { missingCount == 0 && indexIsCurrent }

    public init(itemCount: Int, missingCount: Int, indexIsCurrent: Bool, recoveryKeyWorks: Bool? = nil) {
        self.itemCount = itemCount
        self.missingCount = missingCount
        self.indexIsCurrent = indexIsCurrent
        self.recoveryKeyWorks = recoveryKeyWorks
    }
}

public struct BackupProgress: Sendable, Equatable {
    public var done: Int
    public var total: Int

    public init(done: Int, total: Int) {
        self.done = done
        self.total = total
    }
}

/// Backs a vault folder up to a `BackupStore` and restores it on another device.
///
/// What's uploaded, all of it already encrypted:
/// - `vault.json` with only the recovery keyslot. Passcode and Face ID slots are bound to
///   this device and useless anywhere else.
/// - `index.evi`, and every file under `items/` and `thumbs/`.
///
/// Each file is stored as parts named `<path>#<n>of<total>`. Item files never change once
/// written, so an item counts as backed up when all its parts are present. Thumbnails can be
/// rewritten (see `Vault.upgradeThumbnails`), so theirs are compared by checksum. Items go up
/// before the index, so the index in the store never points at an item that isn't there.
enum BackupEngine {
    static let partSize = 32 << 20
    static let headerPath = "vault.json"
    static let indexPath = "index.evi"

    // MARK: Back up

    static func backUp(
        directory: URL, vaultID: UUID, to store: any BackupStore, replacing: Bool,
        partSize: Int = partSize, progress: @Sendable (BackupProgress) -> Void = { _ in }
    ) async throws {
        // Snapshot the small mutable files first. Items added after this are uploaded too and
        // simply aren't in this index yet; the next backup picks them up.
        let header = try backupHeader(directory: directory)
        let index = try Data(contentsOf: directory.appendingPathComponent(indexPath))

        var remote = try await store.list()
        if let existing = try await remoteVaultID(remote, store: store), existing != vaultID {
            guard replacing else { throw BackupError.differentVault(existing) }
            try await store.delete(Array(remote.keys))
            remote = [:]
        }

        let remoteFiles = files(in: remote)
        let localPaths = try itemPaths(in: directory)
        let toUpload = try localPaths.filter { try !isBackedUp($0, remote: remoteFiles[$0], directory: directory) }
        var report = BackupProgress(done: 0, total: toUpload.count + 2)
        progress(report)

        for path in toUpload {
            let url = directory.appendingPathComponent(path)
            guard FileManager.default.fileExists(atPath: url.path) else { continue } // deleted meanwhile
            let written = try await upload(contentsOf: url, path: path, to: store, partSize: partSize)
            try await deleteLeftovers(of: remoteFiles[path], keeping: written, in: store)
            report.done += 1
            progress(report)
        }

        // Written over in place (same key), so the store always has a header and an index.
        for (path, data) in [(headerPath, header), (indexPath, index)] {
            let file = remoteFiles[path]
            if file?.isComplete != true || file?.total != 1 || file?.parts[0]?.sha != sha256(data) {
                let key = "\(path)#0of1"
                try await store.put(key, data: data, sha256: sha256(data))
                try await deleteLeftovers(of: file, keeping: [key], in: store)
            }
            report.done += 1
            progress(report)
        }

        // Only now remove what was deleted locally, so the stored index never dangles.
        let keep = Set(localPaths + [headerPath, indexPath])
        let stale = remoteFiles.filter { !keep.contains($0.key) }.flatMap(\.value.keys)
        if !stale.isEmpty { try await store.delete(stale) }
    }

    // MARK: Check

    /// Compares the backup in `store` with the vault folder: which files are missing, and
    /// whether the stored index is this device's. Downloads only the header (to confirm it's
    /// this vault) and checks every part's checksum from the store's listing.
    static func check(directory: URL, vaultID: UUID, in store: any BackupStore) async throws -> BackupStatus {
        let remote = try await store.list()
        guard let existing = try await remoteVaultID(remote, store: store) else { throw BackupError.noBackup }
        guard existing == vaultID else { throw BackupError.differentVault(existing) }
        let remoteFiles = files(in: remote)
        let localPaths = try itemPaths(in: directory)
        let missing = Set(try localPaths.filter { try !isBackedUp($0, remote: remoteFiles[$0], directory: directory) }
            .map { String($0.split(separator: "/")[1]) })
        let items = localPaths.filter { $0.hasPrefix("items/") }.count
        let index = try Data(contentsOf: directory.appendingPathComponent(indexPath))
        let remoteIndex = remoteFiles[indexPath]
        let indexIsCurrent = remoteIndex?.isComplete == true && remoteIndex?.total == 1 && remoteIndex?.parts[0]?.sha == sha256(index)
        return BackupStatus(itemCount: items, missingCount: missing.count, indexIsCurrent: indexIsCurrent)
    }

    // MARK: Restore

    /// The vault ID and header of the backup in `store`.
    static func remoteHeader(in store: any BackupStore) async throws -> VaultHeader {
        let remote = try await store.list()
        guard let file = files(in: remote)[headerPath], file.isComplete else { throw BackupError.noBackup }
        let data = try await download(headerPath, file: file, from: store)
        return try Storage.decoder.decode(VaultHeader.self, from: data)
    }

    /// Downloads every complete file into `directory`, which must not exist yet.
    static func download(
        from store: any BackupStore, into directory: URL,
        progress: @Sendable (BackupProgress) -> Void = { _ in }
    ) async throws {
        let remote = files(in: try await store.list())
        guard remote[headerPath]?.isComplete == true, remote[indexPath]?.isComplete == true else { throw BackupError.noBackup }
        try Storage.createDirectory(directory)
        try Storage.createDirectory(directory.appendingPathComponent("items"))
        try Storage.createDirectory(directory.appendingPathComponent("thumbs"))

        // An interrupted upload can leave partial items behind; they aren't in the index.
        let complete = remote.filter { $0.value.isComplete && isAllowed($0.key) }
        var report = BackupProgress(done: 0, total: complete.count)
        progress(report)
        for (path, file) in complete.sorted(by: { $0.key < $1.key }) {
            try await download(path, file: file, from: store, to: directory.appendingPathComponent(path))
            report.done += 1
            progress(report)
        }
    }

    // MARK: Helpers

    struct RemoteFile {
        var total: Int
        /// part number → (key, sha)
        var parts: [Int: (key: String, sha: String)] = [:]
        var isComplete: Bool { parts.count == total && (0..<total).allSatisfy { parts[$0] != nil } }
        var keys: [String] { parts.values.map(\.key) }
    }

    static func files(in remote: [String: String]) -> [String: RemoteFile] {
        var files: [String: RemoteFile] = [:]
        for (key, sha) in remote {
            guard let hash = key.lastIndex(of: "#") else { continue }
            let path = String(key[..<hash])
            let counts = key[key.index(after: hash)...].split(separator: "o", maxSplits: 1)
            guard counts.count == 2, counts[1].hasPrefix("f"),
                  let n = Int(counts[0]), let total = Int(counts[1].dropFirst()), total > 0, n < total else { continue }
            var file = files[path] ?? RemoteFile(total: total)
            guard file.total == total else { continue }
            file.parts[n] = (key, sha)
            files[path] = file
        }
        return files
    }

    /// Items: all parts present. Thumbnails (small, single part, rewritable): same checksum.
    private static func isBackedUp(_ path: String, remote: RemoteFile?, directory: URL) throws -> Bool {
        guard let remote, remote.isComplete else { return false }
        guard path.hasPrefix("thumbs/") else { return true }
        let local = try Data(contentsOf: directory.appendingPathComponent(path))
        return remote.total == 1 && remote.parts[0]?.sha == sha256(local)
    }

    /// Reads and uploads one part at a time, so a large video never sits in memory whole.
    /// Returns the keys written.
    private static func upload(contentsOf url: URL, path: String, to store: any BackupStore, partSize: Int) async throws -> Set<String> {
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int ?? 0
        let total = max(1, (size + partSize - 1) / partSize)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var keys = Set<String>()
        for n in 0..<total {
            let part = try handle.read(upToCount: partSize) ?? Data()
            let key = "\(path)#\(n)of\(total)"
            try await store.put(key, data: part, sha256: sha256(part))
            keys.insert(key)
        }
        return keys
    }

    private static func deleteLeftovers(of file: RemoteFile?, keeping written: Set<String>, in store: any BackupStore) async throws {
        let leftovers = (file?.keys ?? []).filter { !written.contains($0) }
        if !leftovers.isEmpty { try await store.delete(leftovers) }
    }

    /// Writes part by part into a file at `url`.
    private static func download(_ path: String, file: RemoteFile, from store: any BackupStore, to url: URL) async throws {
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: Storage.fileAttributes) else {
            throw BackupError.incomplete(path)
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        for n in 0..<file.total {
            guard let part = file.parts[n] else { throw BackupError.incomplete(path) }
            let bytes = try await store.get(part.key)
            guard sha256(bytes) == part.sha else { throw BackupError.incomplete(path) }
            try handle.write(contentsOf: bytes)
        }
    }

    private static func download(_ path: String, file: RemoteFile, from store: any BackupStore) async throws -> Data {
        var data = Data()
        for n in 0..<file.total {
            guard let part = file.parts[n] else { throw BackupError.incomplete(path) }
            let bytes = try await store.get(part.key)
            guard sha256(bytes) == part.sha else { throw BackupError.incomplete(path) }
            data.append(bytes)
        }
        return data
    }

    private static func remoteVaultID(_ remote: [String: String], store: any BackupStore) async throws -> UUID? {
        guard let file = files(in: remote)[headerPath], file.isComplete else { return nil }
        let data = try await download(headerPath, file: file, from: store)
        return try Storage.decoder.decode(VaultHeader.self, from: data).id
    }

    private static func backupHeader(directory: URL) throws -> Data {
        var header = try Vault.readHeader(at: directory)
        header.slots = header.slots.filter { $0.kind == .recovery }
        guard !header.slots.isEmpty else { throw BackupError.noRecoveryKey }
        return try Storage.encoder.encode(header)
    }

    private static func itemPaths(in directory: URL) throws -> [String] {
        try ["items", "thumbs"].flatMap { folder in
            let url = directory.appendingPathComponent(folder)
            guard FileManager.default.fileExists(atPath: url.path) else { return [String]() }
            return try FileManager.default.contentsOfDirectory(atPath: url.path)
                .filter { $0.hasSuffix(".evf") }
                .map { "\(folder)/\($0)" }
        }
        .sorted()
    }

    /// Only paths the vault format uses, so a tampered store can't write elsewhere.
    private static func isAllowed(_ path: String) -> Bool {
        if path == headerPath || path == indexPath { return true }
        let parts = path.split(separator: "/")
        guard parts.count == 2, ["items", "thumbs"].contains(parts[0]), parts[1].hasSuffix(".evf") else { return false }
        return UUID(uuidString: String(parts[1].dropLast(4))) != nil
    }

    static func sha256<D: DataProtocol>(_ data: D) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

/// Keeps backups in memory. For tests and previews.
public actor MemoryBackupStore: BackupStore {
    public private(set) var objects: [String: Data] = [:]
    public init() {}

    public func list() -> [String: String] { objects.mapValues { BackupEngine.sha256($0) } }
    public func put(_ key: String, data: Data, sha256: String) { objects[key] = data }
    public func get(_ key: String) throws -> Data {
        guard let data = objects[key] else { throw BackupError.incomplete(key) }
        return data
    }
    public func delete(_ keys: [String]) { for key in keys { objects[key] = nil } }

    /// For tests: change stored bytes.
    public func tamper(_ key: String, with data: Data) { objects[key] = data }
}

/// Keeps backups as files in a folder. Used by debug builds to test restore without iCloud.
public struct DirectoryBackupStore: BackupStore {
    let root: URL

    public init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    private func url(_ key: String) -> URL {
        // Keys contain "/", which isn't allowed in a file name.
        root.appendingPathComponent(key.replacingOccurrences(of: "/", with: "|"))
    }

    public func list() throws -> [String: String] {
        var result: [String: String] = [:]
        for name in try FileManager.default.contentsOfDirectory(atPath: root.path) {
            let data = try Data(contentsOf: root.appendingPathComponent(name))
            result[name.replacingOccurrences(of: "|", with: "/")] = BackupEngine.sha256(data)
        }
        return result
    }

    public func put(_ key: String, data: Data, sha256: String) throws { try data.write(to: url(key), options: .atomic) }
    public func get(_ key: String) throws -> Data { try Data(contentsOf: url(key)) }
    public func delete(_ keys: [String]) throws {
        for key in keys { try? FileManager.default.removeItem(at: url(key)) }
    }
}
