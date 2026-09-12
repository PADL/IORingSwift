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
import Synchronization
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

  /// the first of two results, delivered once
  private final class Outcome<T: Sendable>: Sendable {
    private let state = Mutex<(
      result: Result<T, any Error>?,
      waiter: CheckedContinuation<T, any Error>?
    )>((nil, nil))

    func settle(_ result: Result<T, any Error>) {
      let waiter = state.withLock { state -> CheckedContinuation<T, any Error>? in
        guard state.result == nil else { return nil }
        state.result = result
        defer { state.waiter = nil }
        return state.waiter
      }
      waiter?.resume(with: result)
    }

    var value: T {
      get async throws {
        try await withCheckedThrowingContinuation { continuation in
          let settled = state.withLock { state -> Result<T, any Error>? in
            if let result = state.result { return result }
            state.waiter = continuation
            return nil
          }
          if let settled { continuation.resume(with: settled) }
        }
      }
    }
  }

  /// `body`, or `Errno.timedOut` after `limit` whether or not `body` can be cancelled: a
  /// broken retry must not hang the suite, so its task is left behind rather than awaited
  private func within<T: Sendable>(
    _ limit: Duration,
    _ body: @escaping @Sendable () async throws -> T
  ) async throws -> T {
    let outcome = Outcome<T>()
    Task {
      do { outcome.settle(.success(try await body())) } catch { outcome.settle(.failure(error)) }
    }
    Task {
      try? await Task.sleep(for: limit)
      outcome.settle(.failure(Errno.timedOut))
    }
    return try await outcome.value
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

  /// an enter that fails for good fails the requests the ring holds, once each and at once,
  /// and everything asked of the ring after
  func testTerminalFailureIsDeliveredOnce() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.permissionDenied])
    let start = ContinuousClock.now
    do {
      _ = try await within(.seconds(2)) { try await own.receive(count: 1) as [UInt8] }
      XCTFail("received")
    } catch let error as Errno {
      XCTAssertEqual(error, .permissionDenied)
    }
    XCTAssertLessThan(ContinuousClock.now - start, .milliseconds(100)) // no retry waited for
    do {
      _ = try await within(.seconds(2)) { try await own.receive(count: 1) as [UInt8] }
      XCTFail("received")
    } catch let error as Errno {
      XCTAssertEqual(error, .permissionDenied)
    }
    _ = peer
  }

  /// a caller cancelled while its group's members are pending has them cancelled and waits
  /// for that, so that the descriptors it lent them are its own again when it returns
  func testCancelledGroupWaitsForItsMembers() async throws {
    let ring = try IORing()
    try await ring.registerFixedBuffers(count: 1, size: 4096)
    var source = [Int32](repeating: -1, count: 2), sink = [Int32](repeating: -1, count: 2)
    guard pipe(&source) == 0, pipe(&sink) == 0 else { throw Errno(rawValue: errno) }
    defer { for fd in source + sink { close(fd) } }
    let (from, to) = (FileDescriptor(rawValue: source[0]), FileDescriptor(rawValue: sink[1]))
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable])
    // nothing to read: the copy waits until it is cancelled
    let copy = Task { try await ring.copy(count: 5, bufferIndex: 0, from: from, to: to) }
    try await Task.sleep(for: .milliseconds(2))
    copy.cancel()
    let outcome = try await within(.seconds(2)) { await copy.result }
    guard case let .failure(error) = outcome else { return XCTFail("copied nothing") }
    XCTAssert(error is CancellationError, "\(error)")
    // the ring, and the descriptors, are free for the next
    let bytes: [UInt8] = [1, 2, 3, 4, 5]
    XCTAssertEqual(bytes.withUnsafeBytes { write(source[1], $0.baseAddress, $0.count) }, 5)
    try await within(.seconds(2)) {
      try await ring.copy(count: bytes.count, bufferIndex: 0, from: from, to: to)
    }
    var copied = [UInt8](repeating: 0, count: bytes.count)
    XCTAssertEqual(copied.withUnsafeMutableBytes { read(sink[0], $0.baseAddress, $0.count) }, 5)
    XCTAssertEqual(copied, bytes)
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

  /// a multishot request whose own submit failed, after the one providing its buffers did, is
  /// armed by the retry
  func testMultishotArmsAfterAStrandedSubmit() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable, .resourceTemporarilyUnavailable])
    let first = try await within(.seconds(2)) {
      let stream = try await own.receive(count: 64, capacity: 4)
      try await peer.send([9])
      for try await bytes in stream {
        return bytes
      }
      return []
    }
    XCTAssertEqual(first, [9])
  }

  /// a stream let go while its request is still pending has that request cancelled, before
  /// its buffers go, so that data arriving later meets a closed request and not freed memory
  func testMultishotEndedWhilePendingIsCancelled() async throws {
    let ring = try IORing()
    let (own, peer) = try Self.makePair(ring: ring)
    await ring.injectSubmitErrors([.resourceTemporarilyUnavailable, .resourceTemporarilyUnavailable])
    do {
      let stream = try await own.receive(count: 64, capacity: 4)
      _ = stream // let go at once, while pending
    }
    try await Task.sleep(for: .milliseconds(50)) // the cancel and the retry have both run
    try await peer.send([1])
    try await Task.sleep(for: .milliseconds(50))
  }
}
#endif
