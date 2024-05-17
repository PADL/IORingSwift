//
// Copyright (c) 2023 PADL Software Pty Ltd
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

import AsyncAlgorithms
@preconcurrency
import AsyncExtensions
import CLinuxSockAddr
import Glibc
import IORing
import SocketAddress
import SystemPackage

public struct Socket: CustomStringConvertible, Equatable, Hashable, Sendable {
  private let fileHandle: FileHandle!
  private let domain: sa_family_t
  private let ring: IORing

  public init(ring: IORing, fileHandle: FileHandle) {
    self.ring = ring
    self.fileHandle = fileHandle
    domain = sa_family_t(AF_UNSPEC)
  }

  public var description: String {
    let fileDescriptor = fileHandle?.fileDescriptor ?? -1
    if let localName = try? localName, let peerName = try? peerName {
      return "\(type(of: self))(fileDescriptor: \(fileDescriptor), localName: \(localName), peerName: \(peerName))"
    } else {
      return "\(type(of: self))(fileDescriptor: \(fileDescriptor))"
    }
  }

  public init(
    ring: IORing,
    domain: sa_family_t,
    type: __socket_type,
    protocol proto: CInt = 0
  ) throws {
    self.ring = ring
    let fileHandle = socket(CInt(domain), Int32(type.rawValue), proto)
    self.fileHandle = try FileHandle(fileDescriptor: fileHandle, closeOnDealloc: true)
    self.domain = sa_family_t(domain)
  }

  private func getName(_ body: @escaping (
    Int32,
    UnsafeMutablePointer<sockaddr>,
    UnsafeMutablePointer<socklen_t>
  ) -> CInt) throws -> sockaddr_storage {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    var ss = sockaddr_storage()
    var length = ss.size

    _ = try withUnsafeMutablePointer(to: &ss) { pointer in
      try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try Errno.throwingGlobalErrno {
          body(fileHandle.fileDescriptor, sa, &length)
        }
      }
    }

    return ss
  }

  public var localAddress: any SocketAddress {
    get throws {
      try getName { getsockname($0, $1, $2) }
    }
  }

  public var localName: String {
    get throws {
      try localAddress.presentationAddress
    }
  }

  public var peerAddress: any SocketAddress {
    get throws {
      try getName { getpeername($0, $1, $2) }
    }
  }

  public var peerName: String {
    get throws {
      try peerAddress.presentationAddress
    }
  }

  public func setBooleanOption(level: CInt = SOL_SOCKET, option: CInt, to value: Bool) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    var value: CInt = value ? 1 : 0
    try Errno.throwingGlobalErrno { setsockopt(
      fileHandle.fileDescriptor,
      level,
      option,
      &value,
      socklen_t(MemoryLayout<CInt>.size)
    ) }
  }

  public func setReuseAddr() throws {
    try setBooleanOption(option: SO_REUSEADDR, to: true)
  }

  public func setReusePort() throws {
    try setBooleanOption(option: SO_REUSEPORT, to: true)
  }

  public func setTcpNoDelay() throws {
    try setBooleanOption(level: CInt(IPPROTO_TCP), option: TCP_NODELAY, to: true)
  }

  public func bind(port: UInt16) throws {
    switch Int32(domain) {
    case AF_INET:
      var sin = sockaddr_in()
      sin.sin_family = domain
      sin.sin_port = port.bigEndian
      try bind(to: sin)
    case AF_INET6:
      var sin6 = sockaddr_in6()
      sin6.sin6_family = domain
      sin6.sin6_port = port.bigEndian
      try bind(to: sin6)
    default:
      throw Errno.addressFamilyNotSupported
    }
  }

  public func bind(path: String) throws {
    let sun = try sockaddr_un(family: sa_family_t(AF_LOCAL), presentationAddress: path)
    try bind(to: sun)
  }

  public func bind(to address: any SocketAddress) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    _ = try address.withSockAddr { sa in
      try Errno.throwingGlobalErrno {
        SwiftGlibc.bind(fileHandle.fileDescriptor, sa, address.size)
      }
    }
  }

  public func listen(backlog: Int = 128) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    _ = try Errno.throwingGlobalErrno {
      SwiftGlibc.listen(fileHandle.fileDescriptor, Int32(backlog))
    }
  }

  @IORingActor
  public func accept() async throws -> Socket {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    let clientFileHandle: FileDescriptorRepresentable = try await ring.accept(from: fileHandle)
    return Socket(ring: ring, fileHandle: clientFileHandle as! FileHandle)
  }

  @IORingActor
  public func accept() async throws -> AnyAsyncSequence<Socket> {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try ring.accept(from: fileHandle).map { Socket(
      ring: ring,
      fileHandle: $0 as! FileHandle
    ) }
    .eraseToAnyAsyncSequence()
  }

  public func connect(to address: any SocketAddress) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try fileHandle.setBlocking(false)
    _ = try address.withSockAddr { sa in
      try Errno.throwingGlobalErrno {
        SwiftGlibc.connect(fileHandle.fileDescriptor, sa, address.size)
      }
    }
    try fileHandle.setBlocking(true)
  }

  @IORingActor
  public func connect(to address: any SocketAddress) async throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try await ring.connect(fileHandle, to: address)
  }

  @IORingActor
  public func read(into buffer: inout [UInt8], count: Int) async throws -> Int {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    return try await ring.read(into: &buffer, count: count, from: fileHandle)
  }

  @IORingActor
  public func read(count: Int, awaitingAllRead: Bool) async throws -> [UInt8] {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    var buffer = [UInt8]()

    repeat {
      let _buffer = try await ring.read(count: count, from: fileHandle)
      if _buffer.count == 0 {
        break // EOF
      }
      buffer += _buffer
    } while awaitingAllRead && buffer.count < count

    return buffer
  }

  @IORingActor
  public func readFixed(
    count: Int,
    bufferIndex: UInt16,
    awaitingAllRead: Bool
  ) async throws -> [UInt8] {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    var buffer = [UInt8]()

    repeat {
      let _buffer = try await ring.readFixed(
        count: count,
        bufferIndex: bufferIndex,
        from: fileHandle
      ) {
        Array($0)
      }
      if _buffer.count == 0 {
        break // EOF
      }
      buffer += _buffer
    } while awaitingAllRead && buffer.count < count

    return buffer
  }

  @IORingActor
  public func write(_ buffer: [UInt8], count: Int, awaitingAllWritten: Bool) async throws -> Int {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    var nwritten = 0

    repeat {
      nwritten += try await ring.write(
        Array(buffer[nwritten..<count]),
        count: count - nwritten,
        to: fileHandle
      )
    } while awaitingAllWritten && nwritten < count

    return nwritten
  }

  @IORingActor
  public func writeFixed(
    _ buffer: [UInt8],
    bufferIndex: UInt16,
    awaitingAllWritten: Bool
  ) async throws -> Int {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    var nwritten = 0

    repeat {
      nwritten += try await ring.writeFixed(
        Array(buffer[nwritten..<buffer.count]),
        bufferIndex: bufferIndex,
        to: fileHandle
      )
    } while awaitingAllWritten && nwritten < buffer.count

    return nwritten
  }

  @IORingActor
  public func receive(count: Int) async throws -> [UInt8] {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try await ring.receive(
      count: count,
      from: fileHandle
    )
  }

  @IORingActor
  public func send(_ data: [UInt8]) async throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try await ring.send(
      data,
      to: fileHandle
    )
  }

  @IORingActor
  public func receiveMessages(count: Int) async throws -> AnyAsyncSequence<Message> {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try await ring.receiveMessages(
      count: count,
      from: fileHandle
    )
  }

  @IORingActor
  public func sendMessage(_ message: Message) async throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try await ring.send(
      message: message,
      to: fileHandle
    )
  }

  public var isClosed: Bool {
    guard let fileHandle else { return true }
    return fileHandle.fileDescriptor < 0
  }
}
