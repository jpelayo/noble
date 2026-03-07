// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NobleClientCore",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleClientCore", targets: ["NobleClientCore"]),
    ],
    targets: [
        .target(name: "NobleClientCore"),
        .testTarget(name: "NobleClientCoreTests", dependencies: ["NobleClientCore"]),
    ]
)
