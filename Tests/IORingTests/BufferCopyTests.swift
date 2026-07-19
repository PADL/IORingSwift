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
import struct SystemPackage.FileDescriptor
import XCTest

// Covers the redundant-copy eliminations in `IORing.read(count:)` and
// `Socket.write(_:count:awaitingAllWritten:)`.
final class BufferCopyTests: XCTestCase {
  private var tmpDir: String {
    ProcessInfo.processInfo.environment["RUNNER_TEMP"] ?? "/var/tmp"
  }

  private func makeStreamPair(ring: IORing) throws -> (rx: Socket, tx: Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let rx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let tx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    return (rx, tx)
  }

  // read(count:) requests more bytes than the file holds; the result must be
  // trimmed to exactly the bytes read, not padded out to `count`. This exercises
  // the in-place `removeLast` path that replaced `Array(buffer.prefix(nread))`.
  func testReadCountTrimsToBytesRead() async throws {
    let ring = try IORing()
    let tempFile = "\(tmpDir)/ioring_trim_\(getpid()).txt"
    let payload = Array("short".utf8) // 5 bytes
    defer { unlink(tempFile) }

    let writeFd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))
    _ = try await ring.write(payload, to: writeFd)
    try? writeFd.close()

    let readFd = FileDescriptor(rawValue: open(tempFile, O_RDONLY))
    defer { try? readFd.close() }

    // ask for far more than exists in the file
    let result = try await ring.read(count: 4096, from: readFd)
    XCTAssertEqual(result.count, payload.count)
    XCTAssertEqual(result, payload)
  }

  // A full read (count == file size) must return every byte unchanged; the trim
  // branch must not fire when nread == count.
  func testReadCountExactReturnsAllBytes() async throws {
    let ring = try IORing()
    let tempFile = "\(tmpDir)/ioring_exact_\(getpid()).txt"
    let payload = Array(0..<UInt8(200))
    defer { unlink(tempFile) }

    let writeFd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))
    _ = try await ring.write(payload, to: writeFd)
    try? writeFd.close()

    let readFd = FileDescriptor(rawValue: open(tempFile, O_RDONLY))
    defer { try? readFd.close() }

    let result = try await ring.read(count: payload.count, from: readFd)
    XCTAssertEqual(result, payload)
  }

  // Socket.write with count == buffer.count takes the first-pass no-slice branch;
  // the receiver must see the whole buffer intact.
  func testSocketWriteWholeBufferRoundTrips() async throws {
    let ring = try IORing()
    let (rx, tx) = try makeStreamPair(ring: ring)
    let payload = Array("the quick brown fox jumps".utf8)

    let received = try await withThrowingTaskGroup(of: [UInt8].self) { group in
      group.addTask { try await rx.read(count: payload.count, awaitingAllRead: true) }
      let nwritten = try await tx.write(payload, count: payload.count, awaitingAllWritten: true)
      XCTAssertEqual(nwritten, payload.count)
      return try await group.next()!
    }

    XCTAssertEqual(received, payload)
  }

  // Socket.write with count < buffer.count must send only the first `count` bytes
  // from the start of the buffer (the no-slice first pass honours `count`).
  func testSocketWritePartialCountSendsPrefix() async throws {
    let ring = try IORing()
    let (rx, tx) = try makeStreamPair(ring: ring)
    let payload = Array("HELLOworldtrailing".utf8)
    let prefixCount = 5 // "HELLO"

    let received = try await withThrowingTaskGroup(of: [UInt8].self) { group in
      group.addTask { try await rx.read(count: prefixCount, awaitingAllRead: true) }
      let nwritten = try await tx.write(payload, count: prefixCount, awaitingAllWritten: true)
      XCTAssertEqual(nwritten, prefixCount)
      return try await group.next()!
    }

    XCTAssertEqual(received, Array(payload.prefix(prefixCount)))
  }
}
