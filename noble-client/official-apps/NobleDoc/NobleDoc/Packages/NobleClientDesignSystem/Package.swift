// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NobleClientDesignSystem",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleClientDesignSystem", targets: ["NobleClientDesignSystem"]),
    ],
    targets: [
        .target(name: "NobleClientDesignSystem"),
        .testTarget(
            name: "NobleClientDesignSystemTests",
            dependencies: ["NobleClientDesignSystem"]
        ),
    ]
)
