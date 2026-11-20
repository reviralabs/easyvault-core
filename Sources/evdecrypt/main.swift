import Foundation
import VaultCore

// evdecrypt: decrypts an Easy Vault folder with its recovery key, without the app.
//
//   swift run evdecrypt <vault-folder> <recovery-key> <output-folder>
//
// <vault-folder> holds vault.json, index.evi, items/ and thumbs/. Every item is written to
// <output-folder> under its original name, inside a folder per album. Nothing leaves this machine.

let args = CommandLine.arguments
guard args.count == 4 else {
    FileHandle.standardError.write(Data("usage: evdecrypt <vault-folder> <recovery-key> <output-folder>\n".utf8))
    exit(2)
}
let folder = URL(fileURLWithPath: args[1], isDirectory: true)
let output = URL(fileURLWithPath: args[3], isDirectory: true)

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("evdecrypt: \(message)\n".utf8))
    exit(1)
}

/// File names come from the encrypted index; keep them to a plain last path component.
func safeName(_ name: String) -> String {
    let cleaned = name.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
    return cleaned.isEmpty || cleaned.hasPrefix(".") ? "item\(cleaned)" : cleaned
}

/// `name`, or `name (2)`, `name (3)`… if that's taken.
func freeURL(in directory: URL, name: String) -> URL {
    var url = directory.appendingPathComponent(name)
    let base = url.deletingPathExtension().lastPathComponent, ext = url.pathExtension
    var n = 2
    while FileManager.default.fileExists(atPath: url.path) {
        url = directory.appendingPathComponent(ext.isEmpty ? "\(base) (\(n))" : "\(base) (\(n)).\(ext)")
        n += 1
    }
    return url
}

let recoveryKey: RecoveryKey
do { recoveryKey = try RecoveryKey(args[2]) } catch { fail("that isn't a valid recovery key (25 characters, like XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-X)") }

let vault: Vault
do { vault = try Vault.open(folder: folder, recoveryKey: recoveryKey) } catch VaultError.wrongSecret {
    fail("this recovery key doesn't open the vault in \(folder.path)")
} catch {
    fail("can't open \(folder.path): \(error)")
}

let items = await vault.items
let albums = Dictionary(uniqueKeysWithValues: await vault.albums.map { ($0.id, $0.name) })
var written = 0, failed = 0
for item in items {
    var directory = output
    if let albumID = item.albumID, let album = albums[albumID] { directory.appendPathComponent(safeName(album), isDirectory: true) }
    do {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let destination = freeURL(in: directory, name: safeName(item.name))
        try await vault.export(item.id, to: destination)
        print(destination.path)
        written += 1
    } catch {
        FileHandle.standardError.write(Data("evdecrypt: \(item.name): \(error)\n".utf8))
        failed += 1
    }
}
print("\(written) of \(items.count) items decrypted to \(output.path)" + (failed > 0 ? ", \(failed) failed" : ""))
exit(failed > 0 ? 1 : 0)
