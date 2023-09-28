// swift-tools-version: 5.7.1

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

enum CQHandlerType: String {
  case dispatch = "DISPATCH_IO_URING"
  case pthread = "PTHREAD_IO_URING"
}

let cqHandlerType: CQHandlerType = .pthread

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
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-async-algorithms", from: "0.1.0"),
    .package(url: "https://github.com/lhoward/AsyncExtensions", branch: "linux"),
    .package(url: "https://github.com/dfed/swift-async-queue", from: "0.4.0"),
  ],
  targets: [
    .target(
      name: "CIOURing",
      exclude: [
        "liburing/examples",
        "liburing/test",
        "liburing/man",
        "liburing/debian",
        "liburing/src/nolibc.c",
      ],
      cSettings: [
        .define("_GNU_SOURCE"),
        .define("_LARGEFILE_SOURCE"),
        .define("_FILE_OFFSET_BITS=64"),
        .define("_XOPEN_SOURCE=500"),
        .headerSearchPath("include"),
        .headerSearchPath("liburing/src/include")
      ]
    ),
    .target(
      name: "CIORingShims",
      dependencies: ["CIOURing"],
      cSettings: [
        .define("\(cqHandlerType.rawValue)=1"),
        .unsafeFlags(["-I", SwiftLibRoot]),
        .headerSearchPath("../CIOURing/include"),
        .headerSearchPath("../CIOURing/liburing/src/include")
      ],
      cxxSettings: [
        .define("\(cqHandlerType.rawValue)=1"),
        .unsafeFlags(["-I", SwiftLibRoot]),
        .headerSearchPath("../CIOURing/include"),
        .headerSearchPath("../CIOURing/liburing/src/include")
      ]
    ),
    .target(
      name: "IORing",
      dependencies: ["CIOURing",
                     "CIORingShims",
                     "AsyncExtensions",
                     .product(name: "AsyncQueue", package: "swift-async-queue"),
                     .product(name: "AsyncAlgorithms", package: "swift-async-algorithms")],
      cSettings: [
        .define("_XOPEN_SOURCE=500"),
        .headerSearchPath("../CIOURing/include"),
        .headerSearchPath("../CIOURing/liburing/src/include")
      ],
      cxxSettings: [
        .define("_XOPEN_SOURCE=500"),
        .headerSearchPath("../CIOURing/include"),
        .headerSearchPath("../CIOURing/liburing/src/include")
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
    .target(
      name: "IORingFoundation",
      dependencies: ["IORingUtils"]
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
    .executableTarget(
      name: "IORingUDPServer",
      dependencies: ["IORing", "IORingUtils"],
      path: "Examples/IORingUDPServer"
    ),
  ],
  cLanguageStandard: .c18,
  cxxLanguageStandard: .cxx20
)
