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
@testable import IORing
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno
import struct SystemPackage.FileDescriptor
import XCTest

@_silgen_name("malloc_usable_size")
private func malloc_usable_size(_ pointer: UnsafeMutableRawPointer?) -> Int

/// A request's `timeout` is a linked timeout: the kernel cancels the request when it passes.
final class TimeoutTests: XCTestCase {
  private static func makePair(ring: IORing) throws -> (Socket, Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    )
  }

  func testReceiveTimesOut() async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    let start = ContinuousClock.now
    do {
      _ = try await b.receive(count: 1, timeout: .milliseconds(50))
      XCTFail("received")
    } catch let error as Errno {
      XCTAssertEqual(error, .timedOut)
    }
    let elapsed = ContinuousClock.now - start
    XCTAssertGreaterThanOrEqual(elapsed, .milliseconds(50))
    XCTAssertLessThan(elapsed, .seconds(1))
    _ = a // open, so that the receive waits rather than seeing the end of the stream
  }

  /// a request that completes in time is unaffected, and so is the ring after it
  func testTimeoutLeavesACompletedRequestAlone() async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    try await a.send([7])
    let first = try await b.receive(count: 1, timeout: .seconds(5))
    XCTAssertEqual(first, [7])
    try await a.send([8], timeout: .seconds(5))
    let second = try await b.receive(count: 1, timeout: .seconds(5))
    XCTAssertEqual(second, [8])
    try await a.send([9])
    let third: [UInt8] = try await b.receive(count: 1)
    XCTAssertEqual(third, [9])
  }

  /// a request cancelled with its task, before its timeout, reports the cancellation
  func testCancellationIsNotATimeout() async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    let receiver = Task { try await b.receive(count: 1, timeout: .seconds(5)) }
    try await Task.sleep(for: .milliseconds(20))
    let start = ContinuousClock.now
    receiver.cancel()
    do {
      _ = try await receiver.value
      XCTFail("received")
    } catch let error as Errno {
      XCTAssertEqual(error, .canceled)
    }
    XCTAssertLessThan(ContinuousClock.now - start, .seconds(1))
    _ = a
  }

  func testNegativeTimeoutIsRejected() async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    do {
      _ = try await b.receive(count: 1, timeout: .seconds(-1))
      XCTFail("received")
    } catch let error as Errno {
      XCTAssertEqual(error, .invalidArgument)
    }
    _ = a
  }

  /// a duration survives the trip through the kernel's timespec, to the nanosecond
  func testTimespecRoundTrips() {
    let duration = Duration.seconds(3) + .nanoseconds(250)
    XCTAssertEqual(duration.kernelTimespec.duration, duration)
    XCTAssertEqual(Duration.zero.kernelTimespec.duration, .zero)
    XCTAssertNotEqual(Duration.nanoseconds(1).kernelTimespec.duration, .zero)
  }

  /// `SingleshotSubmission` is served from glibc's largest fastbin; see its declaration
  func testSingleshotSubmissionFitsAFastbin() async throws {
    let ring = try IORing()
    let size = try await ring.singleshotSubmissionUsableSize()
    XCTAssertLessThanOrEqual(size, 120, "SingleshotSubmission has outgrown the fastbin")
  }
}

private extension IORing {
  func singleshotSubmissionUsableSize() async throws -> Int {
    // never submitted: the ring's teardown releases its block without calling it
    let submission = try await SingleshotSubmission<()>(
      ring: self,
      .nop,
      fd: FileDescriptor(rawValue: -1),
      timeout: .seconds(1)
    ) { _ in }
    return malloc_usable_size(Unmanaged.passUnretained(submission).toOpaque())
  }
}
