//
// Copyright (c) 2026 PADL Software Pty Ltd
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

@preconcurrency import Foundation
@preconcurrency import Glibc
@testable import IORing
import IORingUtils
import struct SystemPackage.Errno
import XCTest

// Load rings from many tasks, many rings and cancellation at once, checking every byte.
final class StressTests: XCTestCase {
  private static func makeStreamPair(ring: IORing) throws -> (Socket, Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    )
  }

  /// `count` round trips of varying sizes between the two ends of a pair, checking each byte.
  private static func roundTrips(_ count: Int, on ring: IORing, seed: Int) async throws {
    let (a, b) = try makeStreamPair(ring: ring)
    for i in 0..<count {
      let size = 1 + (seed &* 7919 &+ i &* 104_729) % 4096
      let payload = (0..<size).map { UInt8(truncatingIfNeeded: $0 &+ i &+ seed) }
      async let received = b.read(count: size, awaitingAllRead: true)
      let written = try await a.write(payload, count: size, awaitingAllWritten: true)
      XCTAssertEqual(written, size)
      let bytes = try await received
      guard bytes == payload else {
        XCTFail("pair \(seed) round trip \(i): payload corrupted")
        return
      }
    }
  }

  func testManyTasksShareOneRing() async throws {
    let ring = try IORing()
    try await withThrowingTaskGroup(of: Void.self) { group in
      for seed in 0..<64 {
        group.addTask { try await Self.roundTrips(1000, on: ring, seed: seed) }
      }
      try await group.waitForAll()
    }
  }

  func testManyRingsInParallel() async throws {
    let rings = try (0..<8).map { _ in try IORing() }
    try await withThrowingTaskGroup(of: Void.self) { group in
      for (index, ring) in rings.enumerated() {
        for pair in 0..<8 {
          group.addTask { try await Self.roundTrips(500, on: ring, seed: index * 8 + pair) }
        }
      }
      try await group.waitForAll()
    }
  }

  func testCancellationStorm() async throws {
    let ring = try IORing()
    // the peer stays open, so reads on `idle` wait rather than see EOF
    let (idle, peer) = try Self.makeStreamPair(ring: ring)
    defer { withExtendedLifetime(peer) {} }
    for round in 0..<50 {
      // reads that will never be satisfied, cancelled at staggered moments
      let reads = (0..<100).map { i in
        Task {
          try await Task.sleep(for: .microseconds(i * 37 % 500))
          _ = try await idle.read(count: 1, awaitingAllRead: true)
        }
      }
      // meanwhile the ring must keep serving other I/O
      async let traffic: () = Self.roundTrips(20, on: ring, seed: round)
      try await Task.sleep(for: .milliseconds(2))
      for read in reads {
        read.cancel()
      }
      for read in reads {
        do {
          try await read.value
          XCTFail("an unsatisfiable read completed")
        } catch is CancellationError {
        } catch let error as Errno where error == .canceled {}
      }
      try await traffic
    }
    // and it still works afterwards
    try await Self.roundTrips(10, on: ring, seed: 99)
  }
}
