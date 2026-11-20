// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VaultCore",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .executable(name: "evdecrypt", targets: ["evdecrypt"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.10.0"),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
    ],
    targets: [
        .target(
            name: "VaultCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Clibsodium", package: "swift-sodium"),
            ],
            resources: [.copy("Resources/common-passwords.txt")]
        ),
        .executableTarget(name: "evdecrypt", dependencies: ["VaultCore"]),
        .testTarget(name: "VaultCoreTests", dependencies: ["VaultCore"], resources: [.copy("Fixtures")]),
    ]
)
