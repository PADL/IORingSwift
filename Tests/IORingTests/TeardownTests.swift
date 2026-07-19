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

// Regression coverage for the completion-queue-handler teardown race: IORing.deinit
// running io_uring_queue_exit() while the (dispatch or pthread) CQ handler was still
// in io_uring_wait_cqe() on the same ring. Reliably reproduced by spinning up and
// immediately tearing down many short-lived rings that had a CQ handler active.
// A regression manifests as a SIGSEGV/SIGABRT or a teardown deadlock, not a failed
// assertion — so merely completing these loops is the pass condition.
final class TeardownTests: XCTestCase {
  private var tmpDir: String {
    ProcessInfo.processInfo.environment["RUNNER_TEMP"] ?? "/var/tmp"
  }

  private func makeDatagramPair(ring: IORing) throws -> (rx: Socket, tx: Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let rx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let tx = Socket(ring: ring, fileHandle: try FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    return (rx, tx)
  }

  // Rapidly create and drop rings that have just done I/O (so the CQ handler has
  // been active) — the pure-teardown analogue that produced the SIGABRT in
  // IORing.deinit.
  func testRapidRingCreateAndTeardown() async throws {
    let tempFile = "\(tmpDir)/ioring_teardown_\(getpid()).txt"
    defer { unlink(tempFile) }
    let payload = Array("teardown".utf8)

    for _ in 0..<50 {
      let ring = try IORing()
      let fd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_RDWR | O_TRUNC, 0o644))
      _ = try await ring.write(payload, to: fd)
      _ = try await ring.read(count: payload.count, from: fd)
      try? fd.close()
      // `ring` drops here -> deinit stops the CQ handler then queue_exit()s
    }

    XCTAssertTrue(true, "completed rapid ring teardown without crashing")
  }

  // Tear down rings while a multishot receive is still armed: the CQ handler is
  // most likely to be parked in io_uring_wait_cqe() at deinit, which is what
  // deadlocked the naive synchronous-cancel fix and crashed before any fix.
  func testTeardownWithArmedMultishotReceive() async throws {
    for _ in 0..<25 {
      let ring = try IORing()
      let (rx, tx) = try makeDatagramPair(ring: ring)

      try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
          let messages = try await rx.receiveMessages(count: 2048, capacity: 4)
          var n = 0
          for try await _ in messages {
            n += 1
            if n == 2 { break }
          }
        }
        try await Task.sleep(nanoseconds: 5_000_000) // let the receiver arm
        try await tx.send([0x01])
        try await tx.send([0x02])
        _ = try await group.next()
        group.cancelAll()
      }
      // ring/rx/tx drop here with the multishot potentially still armed
    }

    XCTAssertTrue(true, "completed teardown with armed multishot without hanging")
  }
}
