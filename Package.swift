// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ACJFirmaIOS",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "ACJFirmaIOS",
            targets: ["ACJFirmaIOS"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/krzyzanowskim/OpenSSL.git",
            from: "3.0.0"
        ),
    ],
    targets: [
        .target(
            name: "ACJFirmaIOS",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL"),
            ],
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "ACJFirmaIOSTests",
            dependencies: ["ACJFirmaIOS"]
        ),
    ]
)
