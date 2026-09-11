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
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno
import XCTest

// The kernel ties an io_uring request to the thread that submitted it, and completes one still
// waiting for readiness with -ECANCELED once that thread has exited. The default executor's
// cooperative pool retires threads after five idle seconds, which is why rings run on the
// executor's threads instead; each request here waits longer than that.
final class OrphanedRequestTests: XCTestCase {
  private static let longerThanPoolThreadIdleTimeout = Duration.seconds(8)

  private static func makeStreamPair(ring: IORing) throws -> (ioRing: Socket, plain: Int32) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let socket = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    return (socket, fds[1])
  }

  /// A read waiting for data.
  private static func read(on ring: IORing, after delay: Duration) async throws {
    let (socket, peer) = try makeStreamPair(ring: ring)
    defer { close(peer) }
    let payload = Array("late".utf8)
    let writer = Task.detached {
      try await Task.sleep(for: delay)
      _ = payload.withUnsafeBytes { Glibc.write(peer, $0.baseAddress, $0.count) }
    }
    let received = try await socket.read(count: payload.count, awaitingAllRead: true)
    try await writer.value
    XCTAssertEqual(received, payload)
  }

  /// A write waiting for socket buffer space.
  private static func write(on ring: IORing, after delay: Duration) async throws {
    let (socket, peer) = try makeStreamPair(ring: ring)
    defer { close(peer) }
    // far more than a socket buffer holds, so the write waits for the reader
    let payload = [UInt8](repeating: 0x5A, count: 8 * 1024 * 1024)
    let reader = Task.detached {
      try await Task.sleep(for: delay)
      var total = 0
      var buffer = [UInt8](repeating: 0, count: 1 << 16)
      while total < payload.count {
        let count = Glibc.read(peer, &buffer, buffer.count)
        guard count > 0 else { break }
        total += count
      }
      return total
    }
    let written = try await socket.write(payload, count: payload.count, awaitingAllWritten: true)
    let read = try await reader.value
    XCTAssertEqual(written, payload.count)
    XCTAssertEqual(read, payload.count)
  }

  /// A multishot message receive waiting for a datagram.
  private static func receive(on ring: IORing, after delay: Duration) async throws {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_DGRAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let socket = try Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    let peer = fds[1]
    defer { close(peer) }
    let payload = Array("later".utf8)
    let sender = Task.detached {
      try await Task.sleep(for: delay)
      _ = payload.withUnsafeBytes { Glibc.write(peer, $0.baseAddress, $0.count) }
    }
    var received = [UInt8]()
    for try await message in try await socket.receiveMessages(count: 2048, capacity: 4) {
      received = message.buffer
      break
    }
    try await sender.value
    XCTAssertEqual(received, payload)
  }

  /// An accept waiting for a connection.
  private static func accept(on ring: IORing, after delay: Duration) async throws {
    let path = "/tmp/ioring_orphaned_accept_\(getpid())"
    unlink(path)
    defer { unlink(path) }
    let listener = try Socket(ring: ring, domain: sa_family_t(AF_LOCAL), type: SOCK_STREAM)
    try listener.bind(path: path)
    try listener.listen()
    let connector = Task.detached {
      try await Task.sleep(for: delay)
      let fd = socket(AF_LOCAL, Int32(SOCK_STREAM.rawValue), 0)
      var address = sockaddr_un()
      address.sun_family = sa_family_t(AF_LOCAL)
      withUnsafeMutableBytes(of: &address.sun_path) { bytes in
        _ = path.utf8CString.withUnsafeBytes { memcpy(bytes.baseAddress!, $0.baseAddress!, $0.count) }
      }
      let result = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
      }
      return (fd, result)
    }
    let client = try await listener.accept() as Socket
    let (fd, result) = try await connector.value
    defer { close(fd) }
    XCTAssertEqual(result, 0)
    withExtendedLifetime(client) {}
  }

  /// A cancellation the kernel makes, here an `async_cancel` by descriptor rather than the
  /// request's own task, is reported as such.
  func testCancellationFromElsewhereIsReported() async throws {
    let ring = try IORing()
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    let handle = try FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
    let peer = fds[1]
    defer { close(peer) }

    let read = Task { try await ring.read(count: 4, from: handle) }
    try await Task.sleep(for: .milliseconds(50))
    try await ring.cancelRequests(on: handle)

    // bound the wait, in case it were waiting for data that never comes
    let outcome = await withTaskGroup(of: String.self) { group in
      group.addTask {
        do {
          _ = try await read.value
          return "completed"
        } catch let error as Errno {
          return error == .canceled ? "canceled" : "errno \(error)"
        } catch {
          return "\(error)"
        }
      }
      group.addTask {
        try? await Task.sleep(for: .seconds(2))
        return "timed out: the cancelled read was retried"
      }
      let first = await group.next()!
      group.cancelAll()
      return first
    }
    XCTAssertEqual(outcome, "canceled")
  }

  func testRequestsOutliveIdlePoolThreads() async throws {
    let ring = try IORing()
    let delay = Self.longerThanPoolThreadIdleTimeout
    try await withThrowingTaskGroup(of: Void.self) { group in
      group.addTask { try await Self.read(on: ring, after: delay) }
      group.addTask { try await Self.write(on: ring, after: delay) }
      group.addTask { try await Self.receive(on: ring, after: delay) }
      group.addTask { try await Self.accept(on: ring, after: delay) }
      try await group.waitForAll()
    }
  }
}
