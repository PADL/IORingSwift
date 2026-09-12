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

  /// MessageHolder registered its provided buffers at the payload size, not the padded size
  /// it computed for them, so a small `count` failed with EFAULT.
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

  /// Multishot recv needs a provided-buffer group; without one the kernel rejects it.
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

  /// Leaving a multishot receive ended nothing: the request stayed armed on a provided-buffer
  /// group that had just been freed, re-armed itself on ENOBUFS, and kept consuming the socket.
  func testLeavingMultishotReceiveCancelsIt() async throws {
    let ring = try IORing()
    let (rx, tx) = try Self.makePair(SOCK_STREAM, ring: ring)
    let sender = Task {
      // few enough to fit the socket's send buffer once nothing reads
      for i in 0..<50 {
        try await tx.send(Array(repeating: UInt8(i), count: 32))
      }
    }
    for try await _ in try await rx.receive(count: 128, capacity: 2) as AnyAsyncSequence<[UInt8]> {
      break
    }
    try await sender.value
    // the stream cancelled, the rest of the data is still in the socket for a plain receive,
    // which is how a still-armed multishot would show: by eating it
    try await tx.send([0xFF])
    var chunks = 0
    while chunks < 100 { // the buffer comes back at its full size; look for the sentinel in it
      let chunk = try await rx.receive(count: 4096) as [UInt8]
      chunks += 1
      if chunk.contains(0xFF) { break }
    }
    XCTAssertLessThan(chunks, 100, "the sentinel never arrived: a receive is still armed")
  }

  /// A linked pair's SQEs were prepared in one actor job and their continuations registered in
  /// later ones, so another task's submit in between flushed them before anyone was waiting.
  func testLinkedSubmissionsUnderConcurrentSubmits() async throws {
    let ring = try IORing()
    try await ring.registerFixedBuffers(count: 1, size: 4096)
    let path = "\(tmpDir)/ioring_linked_\(getpid())"
    defer { unlink(path) }
    let fd = FileDescriptor(rawValue: open(path, O_CREAT | O_RDWR | O_TRUNC, 0o644))
    defer { try? fd.close() }
    let (a, b) = try Self.makePair(SOCK_STREAM, ring: ring)

    try await withThrowingTaskGroup(of: Void.self) { group in
      // unrelated submissions, as many as possible, while the linked pairs are being built
      group.addTask {
        for _ in 0..<2000 {
          try await a.send([1])
          _ = try await b.receive(count: 1) as [UInt8]
        }
      }
      group.addTask {
        var data = [UInt8](repeating: 0x42, count: 64)
        for _ in 0..<200 {
          try await ring.writeReadFixed(
            &data,
            writeCount: 64,
            readCount: 64,
            offset: 0,
            bufferIndex: 0,
            fd: fd
          )
        }
      }
      try await group.waitForAll()
    }
  }

  /// The SQE was given a pointer to the socket address that was only valid inside a closure.
  func testSendToAddress() async throws {
    let ring = try IORing()
    let path = "\(tmpDir)/ioring_sendto_\(getpid())"
    unlink(path)
    defer { unlink(path) }
    let rx = try Socket(ring: ring, domain: sa_family_t(AF_LOCAL), type: SOCK_DGRAM)
    try rx.bind(path: path)
    let tx = try Socket(ring: ring, domain: sa_family_t(AF_LOCAL), type: SOCK_DGRAM)
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_LOCAL)
    withUnsafeMutableBytes(of: &address.sun_path) { bytes in
      _ = path.utf8CString.withUnsafeBytes { memcpy(bytes.baseAddress!, $0.baseAddress!, $0.count) }
    }
    let payload = Array("addressed".utf8)
    try await tx.send(payload, to: address)
    let received = try await rx.receive(count: 64) as [UInt8]
    XCTAssertEqual(received.prefix(payload.count).map { $0 }, payload)
  }
}
