//
// Copyright (c) 2023-2026 PADL Software Pty Ltd
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
import struct SystemPackage.Errno

public struct Socket: CustomStringConvertible, Equatable, Hashable, Sendable {
  private let _fileHandle: FileHandle
  private let _domain: sa_family_t
  private let _ring: IORing

  private var fileHandle: FileHandle {
    get throws {
      guard _fileHandle.fileDescriptor >= 0 else { throw Errno.badFileDescriptor }
      return _fileHandle
    }
  }

  private var fileDescriptor: CInt {
    get throws {
      try fileHandle.fileDescriptor
    }
  }

  public init(ring: IORing, fileHandle: FileHandle, domain: sa_family_t = sa_family_t(AF_UNSPEC)) {
    _ring = ring
    _fileHandle = fileHandle
    _domain = domain
  }

  public var description: String {
    let fileDescriptor = (try? fileHandle.fileDescriptor) ?? -1
    let localName = (try? localName) ?? "<unknown>"
    let peerName = (try? peerName) ?? "<unknown>"

    return "\(type(of: self))(fileDescriptor: \(fileDescriptor), localName: \(localName), peerName: \(peerName))"
  }

  public init(
    ring: IORing,
    domain: sa_family_t,
    type: __socket_type,
    protocol proto: CInt = 0
  ) throws {
    let fileHandle = try FileHandle(fileDescriptor: socket(
      CInt(domain),
      Int32(type.rawValue),
      proto
    ))
    self.init(ring: ring, fileHandle: fileHandle, domain: domain)
  }

  private func getName(_ body: @escaping (
    Int32,
    UnsafeMutablePointer<sockaddr>,
    UnsafeMutablePointer<socklen_t>
  ) -> CInt) throws -> any SocketAddress {
    var ss = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)

    _ = try withUnsafeMutablePointer(to: &ss) { pointer in
      try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try Errno.throwingGlobalErrno {
          try body(fileDescriptor, sa, &length)
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

  public func setIntegerOption(level: CInt = SOL_SOCKET, option: CInt, to value: CInt) throws {
    var value = value
    try Errno.throwingGlobalErrno { try setsockopt(
      fileDescriptor,
      level,
      option,
      &value,
      socklen_t(MemoryLayout<CInt>.size)
    ) }
  }

  public func setBooleanOption(level: CInt = SOL_SOCKET, option: CInt, to value: Bool) throws {
    var value: CInt = value ? 1 : 0
    try Errno.throwingGlobalErrno { try setsockopt(
      fileDescriptor,
      level,
      option,
      &value,
      socklen_t(MemoryLayout<CInt>.size)
    ) }
  }

  public func setStringOption(level: CInt = SOL_SOCKET, option: CInt, to value: String) throws {
    try Errno.throwingGlobalErrno {
      try value.utf8CString.withUnsafeBytes {
        try setsockopt(
          fileDescriptor,
          level,
          option,
          UnsafeMutableRawPointer(mutating: $0.baseAddress),
          socklen_t(value.utf8.count)
        )
      }
    }
  }

  public func setOpaqueOption<T>(
    level: CInt = SOL_SOCKET,
    option: CInt,
    to value: UnsafePointer<T>
  ) throws {
    try Errno.throwingGlobalErrno {
      try setsockopt(
        fileDescriptor,
        level,
        option,
        UnsafeMutableRawPointer(mutating: value),
        socklen_t(MemoryLayout<T>.size)
      )
    }
  }

  public func getIntegerOption(level: CInt = SOL_SOCKET, option: CInt) throws -> CInt {
    var value = CInt(0)
    var length = socklen_t(MemoryLayout<CInt>.size)
    try Errno.throwingGlobalErrno { try getsockopt(
      fileDescriptor,
      level,
      option,
      &value,
      &length
    ) }
    return value
  }

  public func getBooleanOption(level: CInt = SOL_SOCKET, option: CInt) throws -> Bool {
    var value = CInt(0)
    var length = socklen_t(MemoryLayout<CInt>.size)
    try Errno.throwingGlobalErrno {
      try getsockopt(
        fileDescriptor,
        level,
        option,
        &value,
        &length
      )
    }
    return value != 0
  }

  public func getOpaqueOption<T>(
    level: CInt = SOL_SOCKET,
    option: CInt,
    value: UnsafePointer<T>
  ) throws {
    var len = socklen_t(MemoryLayout<T>.size)
    try Errno.throwingGlobalErrno {
      try getsockopt(
        fileDescriptor,
        level,
        option,
        UnsafeMutableRawPointer(mutating: value),
        &len
      )
    }
  }

  public func bindTo(device: String) throws {
    try setStringOption(option: SO_BINDTODEVICE, to: device)
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

  public func setIPv6Only() throws {
    try setBooleanOption(level: CInt(IPPROTO_IPV6), option: IPV6_V6ONLY, to: true)
  }

  private func _addOrDropMembership(
    _ add: Bool,
    address: sockaddr_ll
  ) throws {
    var address = address
    var mreq = packet_mreq()
    mreq.mr_ifindex = address.sll_ifindex
    mreq.mr_type = UInt16(PACKET_MR_MULTICAST)
    mreq.mr_alen = UInt16(address.sll_halen)
    withUnsafeMutablePointer(to: &mreq.mr_address) { dstAddress in
      withUnsafePointer(to: &address.sll_addr) { srcAddress in
        let dstAddressPtr = dstAddress.propertyBasePointer(to: \.0)!
        let srcAddressPtr = srcAddress.propertyBasePointer(to: \.0)!
        memcpy(dstAddressPtr, srcAddressPtr, Int(address.sll_halen))
      }
    }
    try Errno.throwingGlobalErrno {
      try setsockopt(
        fileDescriptor,
        SOL_PACKET,
        add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
        &mreq,
        socklen_t(MemoryLayout<packet_mreq>.size)
      )
    }
  }

  public func addMulticastMembership(for address: sockaddr_ll) throws {
    try _addOrDropMembership(true, address: address)
  }

  public func dropMulticastMembership(for address: sockaddr_ll) throws {
    try _addOrDropMembership(false, address: address)
  }

  public func bind(port: UInt16) throws {
    switch Int32(_domain) {
    case AF_INET:
      var sin = sockaddr_in()
      sin.sin_family = _domain
      sin.sin_port = port.bigEndian
      try bind(to: sin)
    case AF_INET6:
      var sin6 = sockaddr_in6()
      sin6.sin6_family = _domain
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
    _ = try address.withSockAddr { sa, size in
      try Errno.throwingGlobalErrno {
        try SwiftGlibc.bind(fileDescriptor, sa, size)
      }
    }
  }

  public func listen(backlog: Int = 128) throws {
    _ = try Errno.throwingGlobalErrno {
      try SwiftGlibc.listen(fileDescriptor, Int32(backlog))
    }
  }

  public func accept() async throws -> Socket {
    let clientFileHandle: FileDescriptorRepresentable = try await _ring.accept(from: fileHandle)
    return Socket(ring: _ring, fileHandle: clientFileHandle as! FileHandle)
  }

  public func accept() async throws -> AnyAsyncSequence<Socket> {
    try await _ring.accept(from: fileHandle).map { Socket(
      ring: _ring,
      fileHandle: $0 as! FileHandle
    ) }
    .eraseToAnyAsyncSequence()
  }

  public func connect(to address: any SocketAddress) throws {
    try fileHandle.setBlocking(false)
    _ = try address.withSockAddr { sa, size in
      try Errno.throwingGlobalErrno {
        try SwiftGlibc.connect(fileDescriptor, sa, size)
      }
    }
    try fileHandle.setBlocking(true)
  }

  public func connect(to address: any SocketAddress) async throws {
    try await _ring.connect(fileHandle, to: address)
  }

  public func read(into buffer: inout [UInt8], count: Int) async throws -> Int {
    try await _ring.read(into: &buffer, count: count, from: fileHandle)
  }

  public func read(count: Int, awaitingAllRead: Bool) async throws -> [UInt8] {
    var buffer = [UInt8]()

    repeat {
      let _buffer = try await _ring.read(count: count, from: fileHandle)
      if _buffer.count == 0 {
        break // EOF
      }
      buffer += _buffer
    } while awaitingAllRead && buffer.count < count

    return buffer
  }

  public func readFixed(
    count: Int,
    bufferIndex: UInt16,
    awaitingAllRead: Bool
  ) async throws -> [UInt8] {
    var buffer = [UInt8]()

    repeat {
      let _buffer = try await _ring.readFixed(
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

  public func write(_ buffer: [UInt8], count: Int, awaitingAllWritten: Bool) async throws -> Int {
    var nwritten = 0

    repeat {
      nwritten += try await _ring.write(
        Array(buffer[nwritten..<count]),
        count: count - nwritten,
        to: fileHandle
      )
    } while awaitingAllWritten && nwritten < count

    return nwritten
  }

  public func writeFixed(
    _ buffer: [UInt8],
    bufferIndex: UInt16,
    awaitingAllWritten: Bool
  ) async throws -> Int {
    var nwritten = 0

    repeat {
      nwritten += try await _ring.writeFixed(
        Array(buffer[nwritten..<buffer.count]),
        bufferIndex: bufferIndex,
        to: fileHandle
      )
    } while awaitingAllWritten && nwritten < buffer.count

    return nwritten
  }

  public func receive(count: Int) async throws -> [UInt8] {
    try await _ring.receive(
      count: count,
      from: fileHandle
    )
  }

  public func receive(count: Int) async throws -> AnyAsyncSequence<[UInt8]> {
    try await _ring.receive(
      count: count,
      from: fileHandle
    )
  }

  public func send(_ data: [UInt8]) async throws {
    try await _ring.send(
      data,
      to: fileHandle
    )
  }

  public func receiveMessages(
    count: Int,
    capacity: Int? = nil
  ) async throws -> AnyAsyncSequence<Message> {
    try await _ring.receiveMessages(
      count: count,
      capacity: capacity,
      from: fileHandle
    )
  }

  public func sendMessage(_ message: Message) async throws {
    try await _ring.send(
      message: message,
      to: fileHandle
    )
  }

  public var isClosed: Bool {
    do {
      try _ = fileHandle
      return false
    } catch {
      return true
    }
  }
}

struct in6_pktinfo {
  var ipi6_addr: in6_addr
  var ipi6_ifindex: CUnsignedInt
}

extension Message {
  static func withControlMessage(
    control: UnsafeRawPointer,
    controllen: Int,
    _ body: (cmsghdr, UnsafeRawBufferPointer) -> ()
  ) {
    let controlBuffer = UnsafeRawBufferPointer(start: control, count: Int(controllen))
    var cmsgHeaderIndex = 0

    while true {
      let cmsgDataIndex = cmsgHeaderIndex + MemoryLayout<cmsghdr>.stride

      if cmsgDataIndex > controllen {
        break
      }

      let header = controlBuffer.load(fromByteOffset: cmsgHeaderIndex, as: cmsghdr.self)
      if Int(header.cmsg_len) < MemoryLayout<cmsghdr>.stride {
        break
      }

      cmsgHeaderIndex = cmsgDataIndex
      cmsgHeaderIndex += Int(header.cmsg_len) - MemoryLayout<cmsghdr>.stride
      if cmsgHeaderIndex > controlBuffer.count {
        break
      }
      body(
        header,
        UnsafeRawBufferPointer(rebasing: controlBuffer[cmsgDataIndex..<cmsgHeaderIndex])
      )

      cmsgHeaderIndex += MemoryLayout<cmsghdr>.alignment - 1
      cmsgHeaderIndex &= ~(MemoryLayout<cmsghdr>.alignment - 1)
    }
  }

  static func getPacketInfoControl(
    msghdr: msghdr
  ) -> (UInt32?, (any SocketAddress)?) {
    var interfaceIndex: UInt32?
    var localAddress: (any SocketAddress)?

    withControlMessage(
      control: msghdr.msg_control,
      controllen: msghdr.msg_controllen
    ) { cmsghdr, cmsgdata in
      switch Int(cmsghdr.cmsg_level) {
      case IPPROTO_IP:
        guard cmsghdr.cmsg_type == IP_PKTINFO else { break }
        cmsgdata.baseAddress!
          .withMemoryRebound(to: in_pktinfo.self, capacity: 1) { pktinfo in
            var sin = sockaddr_in()
            sin.sin_addr = pktinfo.pointee.ipi_addr
            interfaceIndex = UInt32(pktinfo.pointee.ipi_ifindex)
            localAddress = sin
          }
      case IPPROTO_IPV6:
        guard cmsghdr.cmsg_type == IPV6_PKTINFO else { break }
        cmsgdata.baseAddress!
          .withMemoryRebound(to: in6_pktinfo.self, capacity: 1) { pktinfo in
            var sin6 = sockaddr_in6()
            sin6.sin6_addr = pktinfo.pointee.ipi6_addr
            interfaceIndex = UInt32(pktinfo.pointee.ipi6_ifindex)
            localAddress = sin6
          }
      default:
        break
      }
    }

    return (interfaceIndex, localAddress)
  }

  static func withPacketInfoControl<T>(
    family: sa_family_t,
    interfaceIndex: UInt32?,
    address: (some SocketAddress)?,
    _ body: (UnsafePointer<cmsghdr>?, Int) -> T
  ) -> T {
    switch Int32(family) {
    case AF_INET:
      let buffer = ManagedBuffer<cmsghdr, in_pktinfo>.create(minimumCapacity: 1) { buffer in
        buffer.withUnsafeMutablePointers { header, element in
          header.pointee
            .cmsg_len = Int(MemoryLayout<cmsghdr>.size + MemoryLayout<in_pktinfo>.size)
          header.pointee.cmsg_level = SOL_SOCKET
          header.pointee.cmsg_type = Int32(IPPROTO_IP)
          element.pointee.ipi_ifindex = Int32(interfaceIndex ?? 0)
          if let address {
            var address = address
            withUnsafePointer(to: &address) {
              $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                element.pointee.ipi_addr = $0.pointee.sin_addr
              }
            }
          } else {
            element.pointee.ipi_addr.s_addr = 0
          }

          return header.pointee
        }
      }

      return buffer.withUnsafeMutablePointerToHeader { body($0, Int($0.pointee.cmsg_len)) }
    case AF_INET6:
      let buffer = ManagedBuffer<cmsghdr, in6_pktinfo>.create(minimumCapacity: 1) { buffer in
        buffer.withUnsafeMutablePointers { header, element in
          header.pointee
            .cmsg_len = Int(MemoryLayout<cmsghdr>.size + MemoryLayout<in6_pktinfo>.size)
          header.pointee.cmsg_level = SOL_SOCKET
          header.pointee.cmsg_type = Int32(IPPROTO_IPV6)
          element.pointee.ipi6_ifindex = interfaceIndex ?? 0
          if let address {
            var address = address
            withUnsafePointer(to: &address) {
              $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                element.pointee.ipi6_addr = $0.pointee.sin6_addr
              }
            }
          } else {
            element.pointee.ipi6_addr = in6_addr()
          }

          return header.pointee
        }
      }

      return buffer.withUnsafeMutablePointerToHeader { body($0, Int($0.pointee.cmsg_len)) }
    default:
      return body(nil, 0)
    }
  }
}
