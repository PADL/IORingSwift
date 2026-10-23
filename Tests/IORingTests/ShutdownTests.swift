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

@preconcurrency import Glibc
import IORing
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno
import XCTest

final class ShutdownTests: XCTestCase {
  private static func makePair(ring: IORing) throws -> (own: Socket, peer: Socket, ownFd: Int32) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)),
      fds[0]
    )
  }

  func testPeerReadsEOFAfterWriteShutdown() async throws {
    let ring = try IORing()
    let (own, peer, _) = try Self.makePair(ring: ring)
    try own.shutdown(.write)
    let bytes = try await peer.read(count: 1, awaitingAllRead: true)
    XCTAssertEqual(bytes, [])
    XCTAssertFalse(own.isClosed) // the descriptor stays the caller's to close
  }

  /// a read waiting for data ends at EOF when the socket's reading side is shut down, rather
  /// than waiting for a peer that stays open; so do reads after it
  func testPendingReadEndsAfterReadShutdown() async throws {
    let ring = try IORing()
    let (own, peer, _) = try Self.makePair(ring: ring)
    let read = Task { try await own.read(count: 1, awaitingAllRead: true) }
    let watchdog = Task { // so a read that outlives the shutdown fails the test, not the suite
      try await Task.sleep(for: .seconds(5))
      read.cancel()
    }
    defer { watchdog.cancel() }
    try await Task.sleep(for: .milliseconds(50))
    try own.shutdown(.read)
    let bytes = try await read.value
    XCTAssertEqual(bytes, [])
    let after = try await own.read(count: 1, awaitingAllRead: true)
    XCTAssertEqual(after, [])
    _ = peer // kept open: the read must end by the shutdown, not by a closed peer
  }

  /// a write waiting for buffer space fails when the socket is shut down under it, rather than
  /// waiting for a peer that has stopped reading
  func testPendingWriteFailsAfterShutdown() async throws {
    let ring = try IORing()
    let (own, peer, ownFd) = try Self.makePair(ring: ring)
    let filler = [UInt8](repeating: 0, count: 65536)
    while filler.withUnsafeBytes({ send(ownFd, $0.baseAddress, $0.count, Int32(MSG_DONTWAIT)) }) > 0 {}
    XCTAssertEqual(errno, EAGAIN)
    let write = Task { try await own.write(filler, count: filler.count, awaitingAllWritten: true) }
    let watchdog = Task { // so a write that outlives the shutdown fails the test, not the suite
      try await Task.sleep(for: .seconds(5))
      write.cancel()
    }
    defer { watchdog.cancel() }
    try await Task.sleep(for: .milliseconds(50))
    try own.shutdown(.write)
    do {
      _ = try await write.value
      XCTFail("written after shutdown")
    } catch let error as Errno {
      XCTAssertEqual(error, .brokenPipe)
    }
    _ = peer // kept open: the write must fail by the shutdown, not by a closed peer
  }
}
