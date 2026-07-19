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

// Exercises the noncopyable `ProvidedBuffer` slot: each multishot recvmsg
// completion borrows a slot, copies the payload out, and the slot's deinit
// reprovides it to the ring. A slot pool smaller than the number of datagrams
// forces slots to be recycled, so correct contents prove copy-out-then-reprovide
// works over many borrow/return cycles.
final class ProvidedBufferTests: XCTestCase {
  private func makeDatagramPair(ring: IORing) throws -> (rx: Socket, tx: Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let rx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let tx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    return (rx, tx)
  }

  // Send N distinct datagrams through a pool of only `capacity` slots and assert
  // every payload arrives byte-for-byte. Since capacity < N, each delivered
  // message must have been copied out before its slot was reprovided and reused.
  func testProvidedBufferRecyclesWithoutCorruption() async throws {
    let ring = try IORing()
    let (rx, tx) = try makeDatagramPair(ring: ring)
    let messageCount = 40
    let capacity = 4

    // Each datagram carries a unique, self-identifying payload.
    func payload(_ i: Int) -> [UInt8] {
      Array("msg-\(i)-".utf8) + [UInt8(i & 0xff), UInt8((i >> 8) & 0xff)]
    }

    let received = try await withThrowingTaskGroup(of: [[UInt8]].self) { group in
      group.addTask {
        let messages = try await rx.receiveMessages(count: 2048, capacity: capacity)
        var collected = [[UInt8]]()
        for try await message in messages {
          collected.append(message.buffer)
          if collected.count == messageCount { break }
        }
        return collected
      }
      group.addTask {
        try await Task.sleep(nanoseconds: 5_000_000_000)
        return []
      }

      try await Task.sleep(nanoseconds: 50_000_000) // let the receiver arm
      for i in 0..<messageCount {
        try await tx.send(payload(i))
        try await Task.sleep(nanoseconds: 1_000_000) // pace so the pool keeps up
      }

      let result = try await group.next() ?? []
      group.cancelAll()
      return result
    }

    XCTAssertEqual(received.count, messageCount, "not all datagrams were delivered")

    // Datagrams are ordered on a stream-less DGRAM socketpair, so contents should
    // match the send order exactly.
    for i in 0..<received.count {
      XCTAssertEqual(received[i], payload(i), "payload \(i) corrupted across slot reuse")
    }
  }
}
