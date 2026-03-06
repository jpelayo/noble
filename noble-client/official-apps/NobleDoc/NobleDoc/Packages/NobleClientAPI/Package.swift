// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NobleClientAPI",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleClientAPI", targets: ["NobleClientAPI"]),
    ],
    dependencies: [
        .package(path: "../NobleClientCore"),
    ],
    targets: [
        .target(
            name: "NobleClientAPI",
            dependencies: ["NobleClientCore"]
        ),
        .testTarget(
            name: "NobleClientAPITests",
            dependencies: ["NobleClientAPI"]
        ),
    ]
)
