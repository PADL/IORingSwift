// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "IORingSwift",
    products: [
        // Products define the executables and libraries a package produces, making them visible to
        // other packages.
        .library(
            name: "IORing",
            targets: ["IORing"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-async-algorithms", from: "0.1.0"),
        .package(url: "https://github.com/lhoward/AsyncExtensions", branch: "linux"),
    ],
    targets: [
        .systemLibrary(
            name: "CIOURing"
            // providers: .apt(["liburing-dev"])
        ),
        .target(
            name: "CIORingShims",
            dependencies: ["CIOURing"]
        ),
        .target(
            name: "IORing",
            dependencies: ["CIORingShims",
                           "AsyncExtensions",
                           .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")]
        ),
        .testTarget(
            name: "IORingTests",
            dependencies: ["IORing"]
        ),
        .target(
            name: "IORingUtils",
            dependencies: ["IORing",
                           "AsyncExtensions",
                           .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")]
        ),
        .executableTarget(
            name: "IORingCat",
            dependencies: ["IORing", "IORingUtils"],
            path: "Examples/IORingCat"
        ),
        .executableTarget(
            name: "IORingCopy",
            dependencies: ["IORing", "IORingUtils"],
            path: "Examples/IORingCopy"
        ),
        .executableTarget(
            name: "IORingTCPEcho",
            dependencies: ["IORing", "IORingUtils"],
            path: "Examples/IORingTCPEcho"
        ),
    ],
    cLanguageStandard: .c18,
    cxxLanguageStandard: .cxx20
)
