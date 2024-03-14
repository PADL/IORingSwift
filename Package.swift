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
let EnableASAN = false
var ASANCFlags: [String] = []
var ASANSwiftFlags: [String] = []
var ASANLinkerSettings: [LinkerSetting] = []

if EnableASAN {
  ASANCFlags.append("-fsanitize=address")
  ASANSwiftFlags.append("-sanitize=address")
  ASANLinkerSettings.append(LinkerSetting.linkedLibrary("asan"))
}

enum CQHandlerType: String {
  case dispatch = "DISPATCH_IO_URING"
  case pthread = "PTHREAD_IO_URING"
}

let cqHandlerType: CQHandlerType = .dispatch

let package = Package(
  name: "IORingSwift",
  platforms: [
    .macOS(.v10_15),
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
    .library(
      name: "CLinuxSockAddr",
      targets: ["CLinuxSockAddr"]
    ),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-async-algorithms", from: "0.1.0"),
    .package(url: "https://github.com/lhoward/AsyncExtensions", branch: "linux"),
    .package(url: "https://github.com/dfed/swift-async-queue", from: "0.4.0"),
    .package(url: "https://github.com/apple/swift-log", from: "1.5.4"),
  ],
  targets: [
    .systemLibrary(
      name: "CIOURing",
      providers: [.apt(["liburing-dev"])]
    ),
    .systemLibrary(
      name: "CLinuxSockAddr"
    ),
    .target(
      name: "CIORingShims",
      dependencies: ["CIOURing"],
      cSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
        .define("\(cqHandlerType.rawValue)=1"),
        .unsafeFlags(["-I", SwiftLibRoot] + ASANCFlags),
      ],
      cxxSettings: [
        .define("_XOPEN_SOURCE=700"),
        .define("_DEFAULT_SOURCE"),
        .define("\(cqHandlerType.rawValue)=1"),
        .unsafeFlags(["-I", SwiftLibRoot] + ASANCFlags),
      ]
    ),
    .target(
      name: "IORing",
      dependencies: ["CIORingShims",
                     "AsyncExtensions",
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
        .unsafeFlags(ASANSwiftFlags),
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
                     "CLinuxSockAddr",
                     .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")],
      swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency"),
        .unsafeFlags(ASANSwiftFlags),
      ]
    ),
    .target(
      name: "IORingFoundation",
      dependencies: ["IORingUtils"],
      swiftSettings: [
        .enableExperimentalFeature("StrictConcurrency"),
        .unsafeFlags(ASANSwiftFlags),
      ]
    ),
    .executableTarget(
      name: "IORingCat",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingCat",
      linkerSettings: [] + ASANLinkerSettings
    ),
    .executableTarget(
      name: "IORingCopy",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingCopy",
      linkerSettings: [] + ASANLinkerSettings
    ),
    .executableTarget(
      name: "IORingTCPEcho",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingTCPEcho",
      linkerSettings: [] + ASANLinkerSettings
    ),
    .executableTarget(
      name: "IORingUDPClient",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingUDPClient",
      linkerSettings: [] + ASANLinkerSettings
    ),
    .executableTarget(
      name: "IORingUDPServer",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingUDPServer",
      linkerSettings: [] + ASANLinkerSettings
    ),
    .executableTarget(
      name: "IORingDeviceSpy",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingDeviceSpy",
      linkerSettings: [] + ASANLinkerSettings
    ),
  ],
  cLanguageStandard: .c18,
  cxxLanguageStandard: .cxx20
)
