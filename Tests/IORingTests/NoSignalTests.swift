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
import Synchronization
import struct SystemPackage.Errno
import XCTest

private let sigpipes = Atomic<Int>(0)

/// Socket writes and sends ask for MSG_NOSIGNAL unless told otherwise, so one to a peer that
/// has gone throws rather than raising SIGPIPE, which by default ends the process.
final class NoSignalTests: XCTestCase {
  /// SIGPIPE is counted rather than fatal for the test's duration; another test may have
  /// ignored it, which would hide a send that raised it.
  override func setUp() async throws {
    try await super.setUp()
    sigpipes.store(0, ordering: .relaxed)
    signal(SIGPIPE) { _ in sigpipes.add(1, ordering: .relaxed) }
  }

  override func tearDown() async throws {
    signal(SIGPIPE, SIG_DFL)
    try await super.tearDown()
  }

  /// A stream socket whose peer has been closed.
  private static func makeOrphan(ring: IORing) throws -> Socket {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    close(fds[1])
    return try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
  }

  private func assertBrokenPipe(_ body: () async throws -> ()) async {
    do {
      try await body()
      XCTFail("sent to a peer that has gone")
    } catch let error as Errno {
      XCTAssertEqual(error, .brokenPipe)
    } catch {
      XCTFail("unexpected error \(error)")
    }
  }

  func testWriteToGonePeerThrowsWithoutSignal() async throws {
    let socket = try Self.makeOrphan(ring: IORing())
    await assertBrokenPipe {
      _ = try await socket.write([1, 2, 3], count: 3, awaitingAllWritten: true)
    }
    XCTAssertEqual(sigpipes.load(ordering: .relaxed), 0)
  }

  func testSendToGonePeerThrowsWithoutSignal() async throws {
    let socket = try Self.makeOrphan(ring: IORing())
    await assertBrokenPipe { try await socket.send([1, 2, 3]) }
    XCTAssertEqual(sigpipes.load(ordering: .relaxed), 0)
  }

  /// What the ring's write op does, which is why `Socket.write` sends instead: the kernel
  /// raises SIGPIPE for it, having no flags to take. This also shows the counting sees one.
  func testRingWriteRaisesSignal() async throws {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    close(fds[1])
    let fileHandle = try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
    let ring = try IORing()
    await assertBrokenPipe { _ = try await ring.write([1, 2, 3], to: fileHandle) }
    XCTAssertEqual(sigpipes.load(ordering: .relaxed), 1)
  }

  /// The flags reach the kernel: MSG_DONTWAIT on a full socket fails at once.
  func testSendFlagsArePassed() async throws {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let ring = try IORing()
    let own = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let peer = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    let filler = [UInt8](repeating: 0, count: 65536)
    while filler.withUnsafeBytes({ send(fds[0], $0.baseAddress, $0.count, Int32(MSG_DONTWAIT)) }) > 0 {}
    do {
      try await own.send([1], flags: CInt(MSG_DONTWAIT | MSG_NOSIGNAL))
      XCTFail("sent to a full socket without waiting")
    } catch let error as Errno {
      XCTAssertEqual(error, .resourceTemporarilyUnavailable)
    }
    _ = peer // kept open, so the socket is full rather than orphaned
  }

  /// A partial write resumes through the same path, so its count still comes back.
  func testWriteReturnsCount() async throws {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let ring = try IORing()
    let own = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let peer = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    let payload = [UInt8](0..<200)
    let written = try await own.write(payload, count: 150, awaitingAllWritten: true)
    XCTAssertEqual(written, 150)
    let received = try await peer.read(count: 150, awaitingAllRead: true)
    XCTAssertEqual(received, Array(payload[0..<150]))
  }
}
