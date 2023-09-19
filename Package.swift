// swift-tools-version: 5.8

import Foundation
import PackageDescription

func tryGuessSwiftLibRoot() -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sh")
    task.arguments = ["-c", "which swift"]
    task.standardOutput = Pipe()
    do {
        try task.run()
        let outputData = (task.standardOutput as! Pipe).fileHandleForReading.readDataToEndOfFile()
        let path = URL(fileURLWithPath: String(decoding: outputData, as: UTF8.self))
        return path.deletingLastPathComponent().path + "/../lib/swift"
    } catch {
        return "/usr/lib/swift"
    }
}

let SwiftLibRoot = tryGuessSwiftLibRoot()

let package = Package(
    name: "IORingSwift",
    products: [
        .library(
            name: "IORing",
            targets: ["IORing"]
        ),
        .library(
            name: "IORingUtils",
            targets: ["IORingUtils"]
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
            dependencies: ["CIOURing"],
            cSettings: [
                .unsafeFlags(["-I", SwiftLibRoot]),
            ],
            cxxSettings: [
                .unsafeFlags(["-I", SwiftLibRoot]),
            ]
        ),
        .target(
            name: "IORing",
            dependencies: ["CIORingShims",
                           "AsyncExtensions",
                           .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")],
            cSettings: [
                .define("_XOPEN_SOURCE=500"),
            ],
            cxxSettings: [
                .define("_XOPEN_SOURCE=500"),
            ]
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
        .executableTarget(
            name: "IORingUDPClient",
            dependencies: ["IORing", "IORingUtils"],
            path: "Examples/IORingUDPClient"
        ),
    ],
    cLanguageStandard: .c18,
    cxxLanguageStandard: .cxx20
)
