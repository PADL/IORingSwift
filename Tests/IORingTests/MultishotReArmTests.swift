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

final class MultishotReArmTests: XCTestCase {
  private func makeDatagramPair(ring: IORing) throws -> (rx: Socket, tx: Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let rx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let tx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    return (rx, tx)
  }

  // A capacity-1 pool plus a send burst reliably provokes -ENOBUFS; the sentinel
  // must still arrive, proving the multishot re-armed instead of terminating.
  func testMultishotSurvivesBufferExhaustion() async throws {
    let ring = try IORing()
    let (rx, tx) = try makeDatagramPair(ring: ring)
    let sentinel: UInt8 = 0xFF

    let gotSentinel = try await withThrowingTaskGroup(of: Bool.self) { group in
      group.addTask {
        let messages = try await rx.receiveMessages(count: 2048, capacity: 1)
        for try await message in messages where message.buffer.first == sentinel {
          return true
        }
        return false
      }
      group.addTask {
        try await Task.sleep(nanoseconds: 5_000_000_000)
        return false
      }
      try await Task.sleep(nanoseconds: 50_000_000) // let the receiver arm
      for _ in 0..<64 { try await tx.send([0x01]) }
      try await tx.send([sentinel])
      let result = try await group.next() ?? false
      group.cancelAll()
      return result
    }

    XCTAssertTrue(gotSentinel, "multishot stream did not survive buffer exhaustion")
  }

  // Sanity: a small (non-default) buffer capacity still delivers a paced stream.
  func testSmallCapacityDeliversPacedMessages() async throws {
    let ring = try IORing()
    let (rx, tx) = try makeDatagramPair(ring: ring)
    let count = 20

    let received = try await withThrowingTaskGroup(of: Int.self) { group in
      group.addTask {
        let messages = try await rx.receiveMessages(count: 2048, capacity: 4)
        var n = 0
        for try await _ in messages {
          n += 1
          if n == count { return n }
        }
        return n
      }
      group.addTask {
        try await Task.sleep(nanoseconds: 5_000_000_000)
        return -1
      }
      try await Task.sleep(nanoseconds: 50_000_000) // let the receiver arm
      for i in 0..<count {
        try await tx.send([UInt8(i & 0xff)])
        try await Task.sleep(nanoseconds: 2_000_000)
      }
      let result = try await group.next() ?? -1
      group.cancelAll()
      return result
    }

    XCTAssertEqual(received, count)
  }
}
