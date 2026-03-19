// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "NobleClientCrypto",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleClientCrypto", targets: ["NobleClientCrypto"]),
    ],
    dependencies: [
        .package(path: "../NobleClientCore"),
        .package(path: "../../noble-tx-core"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift", from: "0.18.0"),
    ],
    targets: [
        .target(
            name: "NobleClientCrypto",
            dependencies: [
                "NobleClientCore",
                .product(name: "NobleTxCore", package: "noble-tx-core"),
                .product(name: "P256K", package: "secp256k1.swift"),
            ]
        ),
        .testTarget(
            name: "NobleClientCryptoTests",
            dependencies: ["NobleClientCrypto"]
        ),
    ]
)
