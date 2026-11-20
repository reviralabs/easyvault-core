import Foundation

/// What the user enters to unlock a vault. The lock type is part of the derived bytes,
/// so a password can never collide with a pattern.
public enum LockSecret: Sendable, Equatable {
    /// Nodes of a 5×5 grid, numbered 0–24 left to right, top to bottom, in the order drawn.
    case pattern([Int])
    case password(String)

    public static let patternGridSize = 5
    public static var patternNodeCount: Int { patternGridSize * patternGridSize }
    /// 6 of 25 dots already allows over 100 million patterns.
    public static var patternLength: ClosedRange<Int> { 6...patternNodeCount }
    public static let passwordMinimumLength = 8

    public var kind: Kind {
        switch self {
        case .pattern: .pattern
        case .password: .password
        }
    }

    public enum Kind: String, Codable, Sendable {
        case pattern, password
    }

    /// Rules for choosing a new secret. Unlocking doesn't apply them.
    public func validate() throws {
        switch self {
        case .pattern(let nodes):
            guard Self.patternLength.contains(nodes.count) else {
                throw VaultError.invalidSecret("Connect at least \(Self.patternLength.lowerBound) dots.")
            }
            guard nodes.allSatisfy((0..<Self.patternNodeCount).contains), Set(nodes).count == nodes.count else {
                throw VaultError.invalidSecret("A pattern uses each dot at most once.")
            }
        case .password(let text):
            guard text.count >= Self.passwordMinimumLength else {
                throw VaultError.invalidSecret("Use at least \(Self.passwordMinimumLength) characters.")
            }
            guard !CommonPasswords.contains(text) else {
                throw VaultError.invalidSecret("That's one of the most common passwords. Try something more personal, like a few words together.")
            }
        }
    }

    /// Canonical bytes fed to the key derivation function. Pattern nodes are comma-separated
    /// because they can have two digits.
    var derivationInput: [UInt8] {
        switch self {
        case .pattern(let nodes):
            Array("pattern5x5:\(nodes.map(String.init).joined(separator: ","))".utf8)
        case .password(let text):
            Array("password:".utf8) + Array(text.precomposedStringWithCanonicalMapping.utf8)
        }
    }
}

/// About 46,000 passwords of 8+ characters from the UK NCSC's list of the 100,000 most used
/// passwords in breaches, lowercased. Bundled, so checking never touches the network.
enum CommonPasswords {
    private static let list: Set<String> = {
        guard let url = Bundle.module.url(forResource: "common-passwords", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return Set(text.split(separator: "\n").map(String.init))
    }()

    static var count: Int { list.count }

    static func contains(_ password: String) -> Bool {
        list.contains(password.lowercased())
    }
}
