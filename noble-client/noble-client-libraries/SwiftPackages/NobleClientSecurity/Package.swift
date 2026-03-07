// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NobleClientSecurity",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleClientSecurity", targets: ["NobleClientSecurity"]),
    ],
    dependencies: [
        .package(path: "../NobleClientCore"),
    ],
    targets: [
        .target(
            name: "NobleClientSecurity",
            dependencies: ["NobleClientCore"]
        ),
        .testTarget(
            name: "NobleClientSecurityTests",
            dependencies: ["NobleClientSecurity"]
        ),
    ]
)
