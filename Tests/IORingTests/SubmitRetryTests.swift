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

#if DEBUG
@preconcurrency import Glibc
@testable import IORing
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno
import struct SystemPackage.FileDescriptor
import XCTest

/// A submit whose enter fails, or consumes only a prefix, leaves SQEs flushed for the next
/// submit to carry; the ring makes sure there is one, and nothing awaiting them unwinds.
/// Each test strands requests on a ring of its own, so that no other I/O carries them.
final class SubmitRetryTests: XCTestCase {
  /// a socket pair whose ends are on different rings, so that I/O on `peer` cannot carry
  /// what is stranded on `ring`
  private static func makePair(ring: IORing) throws -> (own: Socket, peer: Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(
        ring: IORing.shared,
        fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
      )
    )
  }

  /// `body`, or `Errno.timedOut` after `limit`: a broken retry must not hang the suite
  private func within<T: Sendable>(
    _ limit: Duration,
    _ body: @escaping @Sendable () async throws -> T
  ) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
      group.addTask { try await body() }
      group.addTask {
        try await Task.sleep(for: limit)
        throw Errno.timedOut
      }
      let result = try await group.next()!
      group.cancelAll()
      return result
    }
  }

  func testStrandedRequestIsCarried() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable])
    let received = try await within(.seconds(2)) {
      async let receive: [UInt8] = own.receive(count: 1)
      try await peer.send([7])
      return try await receive
    }
    XCTAssertEqual(received, [7])
  }

  /// each retry may fail in turn; the request completes once, when one succeeds
  func testRepeatedFailuresAreRetried() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable, .noMemory, .interrupted])
    let start = ContinuousClock.now
    let received = try await within(.seconds(2)) {
      async let receive: [UInt8] = own.receive(count: 1)
      try await peer.send([8])
      return try await receive
    }
    XCTAssertEqual(received, [8])
    XCTAssertGreaterThanOrEqual(ContinuousClock.now - start, .milliseconds(30))
  }

  /// a group whose submit failed waits for its members' completions rather than unwinding
  /// from under them
  func testGroupWaitsForAStrandedSubmit() async throws {
    let ring = try IORing()
    try await ring.registerFixedBuffers(count: 1, size: 4096)
    var source = [Int32](repeating: -1, count: 2), sink = [Int32](repeating: -1, count: 2)
    guard pipe(&source) == 0, pipe(&sink) == 0 else { throw Errno(rawValue: errno) }
    defer { for fd in source + sink { close(fd) } }
    let bytes: [UInt8] = [1, 2, 3, 4, 5]
    XCTAssertEqual(bytes.withUnsafeBytes { write(source[1], $0.baseAddress, $0.count) }, 5)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable])
    let (from, to) = (FileDescriptor(rawValue: source[0]), FileDescriptor(rawValue: sink[1]))
    try await within(.seconds(2)) {
      try await ring.copy(count: bytes.count, bufferIndex: 0, from: from, to: to)
    }
    var copied = [UInt8](repeating: 0, count: bytes.count)
    XCTAssertEqual(copied.withUnsafeMutableBytes { read(sink[0], $0.baseAddress, $0.count) }, 5)
    XCTAssertEqual(copied, bytes)
  }

  /// a multishot request whose submit failed is armed by the retry, and is the one that
  /// ending the stream cancels
  func testMultishotArmsAfterAStrandedSubmit() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable])
    let first = try await within(.seconds(2)) {
      let stream = try await own.receive(count: 64, capacity: 4)
      try await peer.send([9])
      for try await bytes in stream {
        return bytes
      }
      return []
    }
    XCTAssertEqual(first, [9])
    // the stream is gone: its request is cancelled, and the ring can be torn down after it
    try await Task.sleep(for: .milliseconds(50))
  }
}
#endif
