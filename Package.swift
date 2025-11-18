// swift-tools-version: 6.2

import Foundation
import PackageDescription

let EnvSysRoot = ProcessInfo.processInfo.environment["SYSROOT"]

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

let SwiftLibRoot = EnvSysRoot != nil ? "\(EnvSysRoot!)/usr/lib/swift" : tryGuessSwiftLibRoot()

enum CQHandlerType: String {
  case dispatch = "DISPATCH_IO_URING"
  case pthread = "PTHREAD_IO_URING"
}

let cqHandlerType: CQHandlerType = .dispatch

let package = Package(
  name: "IORingSwift",
  platforms: [
    .macOS(.v13),
  ],
  products: [
    .library(
      name: "IORing",
      targets: ["IORing"]
    ),
    .library(
      name: "IORingUtils",
      targets: ["IORingUtils"]
    ),
    .library(
      name: "IORingFoundation",
      targets: ["IORingFoundation"]
    ),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-async-algorithms", from: "1.0.0"),
    .package(url: "https://github.com/lhoward/AsyncExtensions", from: "0.9.0"),
    .package(url: "https://github.com/dfed/swift-async-queue", from: "0.7.0"),
    .package(url: "https://github.com/apple/swift-log", from: "1.6.2"),
    .package(url: "https://github.com/apple/swift-system", from: "1.0.0"),
    .package(url: "https://github.com/PADL/SocketAddress", from: "0.1.0"),
  ],
  targets: [
    .systemLibrary(
      name: "CIOURing",
      providers: [.apt(["liburing-dev"])]
    ),
    .target(
      name: "CIORingShims",
      dependencies: ["CIOURing"],
      cSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
        .define("\(cqHandlerType.rawValue)=1"),
      ],
      cxxSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
        .define("\(cqHandlerType.rawValue)=1"),
      ]
    ),
    .target(
      name: "IORing",
      dependencies: ["CIORingShims",
                     "AsyncExtensions",
                     .product(name: "SystemPackage", package: "swift-system"),
                     .product(name: "AsyncQueue", package: "swift-async-queue"),
                     .product(name: "Logging", package: "swift-log"),
                     .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")],
      cSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
      ],
      cxxSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
      ],
      swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency"),
        .enableExperimentalFeature("NonisolatedNonsendingByDefault"),
      ]
    ),
    .testTarget(
      name: "IORingTests",
      dependencies: ["IORing", "IORingUtils"]
    ),
    .target(
      name: "IORingUtils",
      dependencies: ["IORing",
                     "AsyncExtensions",
                     "SocketAddress",
                     .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")],
      swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency"),
      ]
    ),
    .target(
      name: "IORingFoundation",
      dependencies: ["IORingUtils"],
      swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency"),
      ]
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
      name: "IORingDatagramClient",
      dependencies: ["IORing", "IORingUtils", "IORingFoundation"],
      path: "Examples/IORingDatagramClient"
    ),
    .executableTarget(
      name: "IORingDatagramServer",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingDatagramServer"
    ),
    .executableTarget(
      name: "IORingDeviceSpy",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingDeviceSpy"
    ),
  ],
  swiftLanguageModes: [.v5],
  cLanguageStandard: .c18,
  cxxLanguageStandard: .cxx20
)
