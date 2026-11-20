import Foundation

/// How long the lock screen waits after repeated wrong secrets. The app stores the
/// failure count in the Keychain so deleting and reinstalling doesn't reset it.
public enum AttemptPolicy {
    public static let freeAttempts = 5

    /// The wait before the next attempt is allowed, given the number of failures so far.
    public static func delay(afterFailures failures: Int) -> TimeInterval {
        switch failures - freeAttempts {
        case ..<0: 0
        case 0: 60
        case 1: 5 * 60
        case 2: 15 * 60
        default: 60 * 60
        }
    }

    public static func nextAttemptAllowed(failures: Int, lastFailure: Date?) -> Date {
        guard let lastFailure else { return .distantPast }
        return lastFailure.addingTimeInterval(delay(afterFailures: failures))
    }
}
