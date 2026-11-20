import Crypto
import Foundation

/// The `.evf` item file: a 24-byte header followed by AES-256-GCM chunks (STREAM construction).
///
/// ```
/// 0   4   magic "EVF1"
/// 4   1   format version (1)
/// 5   1   log2(chunk size)
/// 6   2   reserved (0)
/// 8   16  item ID
/// 24  …   chunks: ciphertext ‖ 16-byte tag
/// ```
///
/// Nonce = 11-byte big-endian chunk index ‖ final flag. Every item has its own key, so
/// nonces never repeat under a key, and reordering, dropping or appending chunks fails.
enum ItemCipher {
    static let magic = Data("EVF1".utf8)
    static let version: UInt8 = 1
    static let headerLength = 24
    static let tagLength = 16
    static let defaultChunkSizeLog2: UInt8 = 20

    struct Header {
        var chunkSizeLog2: UInt8
        var itemID: UUID

        var chunkSize: Int { 1 << Int(chunkSizeLog2) }

        var encoded: Data {
            var data = ItemCipher.magic
            data.append(ItemCipher.version)
            data.append(chunkSizeLog2)
            data.append(contentsOf: [0, 0])
            data.append(itemID.data)
            return data
        }

        init(chunkSizeLog2: UInt8, itemID: UUID) {
            self.chunkSizeLog2 = chunkSizeLog2
            self.itemID = itemID
        }

        init(_ data: Data, expectedItemID: UUID) throws {
            guard data.count == ItemCipher.headerLength, data.prefix(4) == ItemCipher.magic else {
                throw VaultError.corrupted("Not an Easy Vault item file.")
            }
            let bytes = [UInt8](data)
            guard bytes[4] == ItemCipher.version else { throw VaultError.unsupportedVersion(Int(bytes[4])) }
            guard (12...24).contains(bytes[5]), bytes[6] == 0, bytes[7] == 0 else {
                throw VaultError.corrupted("Invalid item header.")
            }
            guard UUID(data: data.subdata(in: 8..<24)) == expectedItemID else {
                throw VaultError.corrupted("Item file belongs to a different item.")
            }
            self.init(chunkSizeLog2: bytes[5], itemID: expectedItemID)
        }
    }

    /// The key for an item's thumbnail. An item and its thumbnail share an item ID, so their
    /// chunk nonces are the same; a separate key keeps nonces from ever repeating under one key.
    static func thumbnailKey(_ itemKey: SymmetricKey, itemID: UUID) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: itemKey, salt: itemID.data, info: Data("ev/thumbnail".utf8), outputByteCount: 32)
    }

    static func nonce(index: UInt64, final: Bool) -> AES.GCM.Nonce {
        var bytes = [UInt8](repeating: 0, count: 12)
        withUnsafeBytes(of: index.bigEndian) { indexBytes in
            for (offset, byte) in indexBytes.enumerated() { bytes[3 + offset] = byte }
        }
        bytes[11] = final ? 1 : 0
        return try! AES.GCM.Nonce(data: bytes)
    }

    static func sealChunk(_ plaintext: Data, index: UInt64, final: Bool, key: SymmetricKey, header: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, nonce: nonce(index: index, final: final), authenticating: header)
        return box.ciphertext + box.tag
    }

    static func openChunk(_ sealed: Data, index: UInt64, final: Bool, key: SymmetricKey, header: Data) throws -> Data {
        guard sealed.count >= tagLength else { throw VaultError.corrupted("Item file is truncated.") }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: nonce(index: index, final: final),
                ciphertext: sealed.prefix(sealed.count - tagLength),
                tag: sealed.suffix(tagLength)
            )
            return try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw VaultError.corrupted("Item file was damaged or modified.")
        }
    }

    // MARK: In memory (photos, thumbnails)

    static func encrypt(_ plaintext: Data, itemID: UUID, key: SymmetricKey, chunkSizeLog2: UInt8 = defaultChunkSizeLog2) throws -> Data {
        let header = Header(chunkSizeLog2: chunkSizeLog2, itemID: itemID)
        let headerData = header.encoded
        var output = headerData
        var index: UInt64 = 0
        var offset = plaintext.startIndex
        repeat {
            let end = min(offset + header.chunkSize, plaintext.endIndex)
            let final = end == plaintext.endIndex
            output += try sealChunk(plaintext[offset..<end], index: index, final: final, key: key, header: headerData)
            offset = end
            index += 1
        } while offset < plaintext.endIndex
        return output
    }

    static func decrypt(_ file: Data, itemID: UUID, key: SymmetricKey) throws -> Data {
        guard file.count >= headerLength + tagLength else { throw VaultError.corrupted("Item file is truncated.") }
        let headerData = file.prefix(headerLength)
        let header = try Header(Data(headerData), expectedItemID: itemID)
        let sealedChunkSize = header.chunkSize + tagLength
        var output = Data()
        var index: UInt64 = 0
        var offset = file.startIndex + headerLength
        while true {
            let end = min(offset + sealedChunkSize, file.endIndex)
            let final = end == file.endIndex
            output += try openChunk(Data(file[offset..<end]), index: index, final: final, key: key, header: Data(headerData))
            if final { return output }
            offset = end
            index += 1
        }
    }

    // MARK: Streaming (videos, large files)

    static func encryptFile(at source: URL, to destination: URL, itemID: UUID, key: SymmetricKey, chunkSizeLog2: UInt8 = defaultChunkSizeLog2) throws {
        let header = Header(chunkSizeLog2: chunkSizeLog2, itemID: itemID)
        let headerData = header.encoded
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = try FileWriter(destination)
        try output.write(headerData)

        var index: UInt64 = 0
        var current = try input.readFully(header.chunkSize)
        while true {
            let next = current.count == header.chunkSize ? (try input.readFully(header.chunkSize)) : Data()
            let final = next.isEmpty
            try output.write(sealChunk(current, index: index, final: final, key: key, header: headerData))
            if final { break }
            current = next
            index += 1
        }
        try output.commit()
    }

    static func decryptFile(at source: URL, to destination: URL, itemID: UUID, key: SymmetricKey) throws {
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        guard let headerData = try input.read(upToCount: headerLength), headerData.count == headerLength else {
            throw VaultError.corrupted("Item file is truncated.")
        }
        let header = try Header(headerData, expectedItemID: itemID)
        let sealedChunkSize = header.chunkSize + tagLength
        let output = try FileWriter(destination)

        var index: UInt64 = 0
        var current = try input.readFully(sealedChunkSize)
        while true {
            let next = current.count == sealedChunkSize ? (try input.readFully(sealedChunkSize)) : Data()
            let final = next.isEmpty
            try output.write(openChunk(current, index: index, final: final, key: key, header: headerData))
            if final { break }
            current = next
            index += 1
        }
        try output.commit()
    }
}

/// Writes to a temporary file next to the destination and moves it into place on commit,
/// so a crash never leaves a half-written file behind.
final class FileWriter {
    private let destination: URL
    private let temporary: URL
    private let handle: FileHandle
    private var committed = false

    init(_ destination: URL) throws {
        self.destination = destination
        temporary = destination.deletingLastPathComponent()
            .appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil, attributes: Storage.fileAttributes) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        handle = try FileHandle(forWritingTo: temporary)
    }

    func write(_ data: Data) throws {
        try handle.write(contentsOf: data)
    }

    func commit() throws {
        try handle.synchronize()
        try handle.close()
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try FileManager.default.moveItem(at: temporary, to: destination)
        }
        committed = true
    }

    deinit {
        if !committed {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
        }
    }
}

extension FileHandle {
    /// Reads `count` bytes, or fewer only at end of file.
    func readFully(_ count: Int) throws -> Data {
        var data = Data()
        while data.count < count, let more = try read(upToCount: count - data.count), !more.isEmpty {
            data += more
        }
        return data
    }
}
