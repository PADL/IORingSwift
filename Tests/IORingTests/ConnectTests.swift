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
import SocketAddress
import struct SystemPackage.Errno
import XCTest

/// The synchronous `Socket.connect(to:)` connects without blocking, and must leave the socket
/// in the mode it found it, whether or not it connected.
final class ConnectTests: XCTestCase {
  private static func makeSocket(ring: IORing) throws -> (Socket, FileHandle) {
    let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
    guard fd >= 0 else { throw Errno(rawValue: errno) }
    let fileHandle = try FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    return (Socket(ring: ring, fileHandle: fileHandle, domain: sa_family_t(AF_UNIX)), fileHandle)
  }

  private static func temporaryPath() -> String {
    "/tmp/IORingSwift-ConnectTests-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
  }

  func testSetBlockingRoundTrips() throws {
    let ring = try IORing()
    let (_, fileHandle) = try Self.makeSocket(ring: ring)
    XCTAssertTrue(try fileHandle.isBlocking)
    try fileHandle.setBlocking(false)
    XCTAssertFalse(try fileHandle.isBlocking)
    XCTAssertNotEqual(fcntl(fileHandle.fileDescriptor, F_GETFL, 0) & O_NONBLOCK, 0)
    try fileHandle.setBlocking(true)
    XCTAssertTrue(try fileHandle.isBlocking)
    XCTAssertEqual(fcntl(fileHandle.fileDescriptor, F_GETFL, 0) & O_NONBLOCK, 0)
  }

  func testFailedConnectLeavesSocketBlocking() throws {
    let ring = try IORing()
    let (socket, fileHandle) = try Self.makeSocket(ring: ring)
    let address = try sockaddr_un(
      family: sa_family_t(AF_UNIX),
      presentationAddress: Self.temporaryPath()
    )
    XCTAssertThrowsError(try socket.connect(to: address)) { error in
      XCTAssertEqual(error as? Errno, .noSuchFileOrDirectory)
    }
    XCTAssertTrue(try fileHandle.isBlocking)
  }

  func testFailedConnectLeavesSocketNonBlocking() throws {
    let ring = try IORing()
    let (socket, fileHandle) = try Self.makeSocket(ring: ring)
    try fileHandle.setBlocking(false)
    let address = try sockaddr_un(
      family: sa_family_t(AF_UNIX),
      presentationAddress: Self.temporaryPath()
    )
    XCTAssertThrowsError(try socket.connect(to: address))
    XCTAssertFalse(try fileHandle.isBlocking)
  }

  func testConnectLeavesSocketBlocking() throws {
    let ring = try IORing()
    let path = Self.temporaryPath()
    let (listener, _) = try Self.makeSocket(ring: ring)
    try listener.bind(path: path)
    defer { unlink(path) }
    try listener.listen()

    let (socket, fileHandle) = try Self.makeSocket(ring: ring)
    try socket.connect(to: sockaddr_un(family: sa_family_t(AF_UNIX), presentationAddress: path))
    XCTAssertTrue(try fileHandle.isBlocking)
    XCTAssertEqual(try socket.peerName, path)
  }
}
