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

import AsyncExtensions
@preconcurrency import Foundation
@preconcurrency import Glibc
@testable import IORing
import IORingUtils
import struct SystemPackage.Errno
import struct SystemPackage.FileDescriptor
import XCTest

final class RegressionTests: XCTestCase {
  private var tmpDir: String {
    ProcessInfo.processInfo.environment["RUNNER_TEMP"] ?? "/var/tmp"
  }

  private static func makePair(_ type: __socket_type, ring: IORing) throws -> (Socket, Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(type.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    )
  }

  // MessageHolder registered its provided buffers at the payload size, not the padded size
  // it computed for them, so a small `count` failed with EFAULT.
  func testSmallMessageBuffersReceive() async throws {
    let ring = try IORing()
    let (rx, tx) = try Self.makePair(SOCK_DGRAM, ring: ring)
    let payload = Array("small".utf8)
    try await tx.send(payload)
    for try await message in try await rx.receiveMessages(count: 64, capacity: 4) {
      XCTAssertEqual(message.buffer, payload)
      break
    }
  }

  // Multishot recv needs a provided-buffer group; without one the kernel rejects it.
  func testMultishotReceive() async throws {
    let ring = try IORing()
    let (rx, tx) = try Self.makePair(SOCK_STREAM, ring: ring)
    let chunks = (0..<8).map { Array(repeating: UInt8($0), count: 32) }
    let sender = Task {
      for chunk in chunks {
        try await tx.send(chunk)
        try await Task.sleep(for: .milliseconds(5))
      }
    }
    var received = [UInt8]()
    for try await chunk in try await rx.receive(count: 128) as AnyAsyncSequence<[UInt8]> {
      received += chunk
      if received.count >= chunks.count * 32 { break }
    }
    try await sender.value
    XCTAssertEqual(received, chunks.flatMap { $0 })
  }
}
