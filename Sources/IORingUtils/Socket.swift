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
        try Errno.throwingErrno {
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
    try Errno.throwingErrno { setsockopt(
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
      try Errno.throwingErrno {
        SwiftGlibc.bind(fileHandle.fileDescriptor, sa, address.size)
      }
    }
  }

  public func listen(backlog: Int = 128) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    _ = try Errno.throwingErrno {
      SwiftGlibc.listen(fileHandle.fileDescriptor, Int32(backlog))
    }
  }

  public func accept() async throws -> Socket {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    let clientFileHandle: FileDescriptorRepresentable = try await ring.accept(from: fileHandle)
    return Socket(ring: ring, fileHandle: clientFileHandle as! FileHandle)
  }

  public func accept() async throws -> AnyAsyncSequence<Socket> {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try await ring.accept(from: fileHandle).map { Socket(
      ring: ring,
      fileHandle: $0 as! FileHandle
    ) }
    .eraseToAnyAsyncSequence()
  }

  public func connect(to address: any SocketAddress) throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try fileHandle.setBlocking(false)
    _ = try address.withSockAddr { sa in
      try Errno.throwingErrno {
        SwiftGlibc.connect(fileHandle.fileDescriptor, sa, address.size)
      }
    }
    try fileHandle.setBlocking(true)
  }

  public func connect(to address: any SocketAddress) async throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try await ring.connect(fileHandle, to: address)
  }

  public func read(into buffer: inout [UInt8], count: Int) async throws -> Int {
    guard let fileHandle else { throw Errno.badFileDescriptor }

    return try await ring.read(into: &buffer, count: count, from: fileHandle)
  }

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

  public func receive(count: Int) async throws -> [UInt8] {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try await ring.receive(
      count: count,
      from: fileHandle
    )
  }

  public func send(_ data: [UInt8]) async throws {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    try await ring.send(
      data,
      to: fileHandle
    )
  }

  public func receiveMessages(count: Int) async throws -> AnyAsyncSequence<Message> {
    guard let fileHandle else { throw Errno.badFileDescriptor }
    return try await ring.receiveMessages(
      count: count,
      from: fileHandle
    )
  }

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

private func parseIPv4PresentationAddress(_ presentationAddress: String) -> (String, UInt16?) {
  var port: UInt16?
  let addressPort = presentationAddress.split(separator: ":", maxSplits: 2)
  if addressPort.count > 1 {
    port = UInt16(addressPort[1])
  }

  return (String(addressPort.first!), port)
}

public func parseIPv6PresentationAddress(_ presentationAddress: String) throws
  -> (String, UInt16?)
{
  let ipv6Regex: Regex = #/\[([0-9a-fA-F:]+)\](:(\d+))?/#
  let port: UInt16?
  let addressPort = presentationAddress.firstMatch(of: ipv6Regex)

  guard let address = addressPort?.1 else { throw Errno(rawValue: EINVAL) }
  if let portString = addressPort?.3 { port = UInt16(portString) }
  else { port = nil }

  return (String(address), port)
}

public protocol SocketAddress: Sendable {
  static var family: sa_family_t { get }

  init(family: sa_family_t, presentationAddress: String) throws
  func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T
  var presentationAddress: String { get throws }
  var port: UInt16 { get throws }
  var size: socklen_t { get }
}

public extension SocketAddress {
  var family: sa_family_t {
    withSockAddr { $0.pointee.sa_family }
  }
}

extension SocketAddress {
  func asStorage() -> sockaddr_storage {
    var ss = sockaddr_storage()
    withSockAddr {
      _ = memcpy(&ss, $0, Int(size))
    }
    return ss
  }
}

extension sockaddr: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_UNSPEC)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    throw Errno.invalidArgument
  }

  public var size: socklen_t {
    switch Int32(sa_family) {
    case AF_INET:
      return socklen_t(MemoryLayout<sockaddr_in>.size)
    case AF_INET6:
      return socklen_t(MemoryLayout<sockaddr_in6>.size)
    case AF_LOCAL:
      return socklen_t(MemoryLayout<sockaddr_un>.size)
    case AF_PACKET:
      return socklen_t(MemoryLayout<sockaddr_ll>.size)
    case AF_NETLINK:
      return socklen_t(MemoryLayout<sockaddr_nl>.size)
    default:
      return 0
    }
  }

  private var _storage: sockaddr_storage {
    var storage = sockaddr_storage()
    let size = Int(size)
    withUnsafePointer(to: self) { _ = memcpy(&storage, $0, size) }
    return storage
  }

  public var presentationAddress: String {
    get throws {
      let storage = _storage

      return try withUnsafePointer(to: storage) {
        switch Int32(sa_family) {
        case AF_INET:
          try $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
            try $0.pointee.presentationAddress
          }
        case AF_INET6:
          try $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
            try $0.pointee.presentationAddress
          }
        case AF_LOCAL:
          try $0.withMemoryRebound(to: sockaddr_un.self, capacity: 1) {
            try $0.pointee.presentationAddress
          }
        case AF_PACKET:
          try $0.withMemoryRebound(to: sockaddr_ll.self, capacity: 1) {
            try $0.pointee.presentationAddress
          }
        case AF_NETLINK:
          try $0.withMemoryRebound(to: sockaddr_nl.self, capacity: 1) {
            try $0.pointee.presentationAddress
          }
        default:
          throw Errno.addressFamilyNotSupported
        }
      }
    }
  }

  public var port: UInt16 {
    get throws {
      let storage = _storage

      return try withUnsafePointer(to: storage) {
        switch Int32(sa_family) {
        case AF_INET:
          try $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
            try $0.pointee.port
          }
        case AF_INET6:
          try $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
            try $0.pointee.port
          }
        default:
          throw Errno.addressFamilyNotSupported
        }
      }
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sa in
      try body(sa)
    }
  }
}

extension sockaddr_in: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_INET)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    guard family == AF_INET else { throw Errno.invalidArgument }
    self = sockaddr_in()
    let (address, port) = parseIPv4PresentationAddress(presentationAddress)
    var sin_port = UInt16()
    var sin_addr = in_addr()
    _ = try Errno.throwingErrno {
      if let port { sin_port = port.bigEndian }
      return inet_pton(AF_INET, address, &sin_addr)
    }
    sin_family = family
    self.sin_port = sin_port
    self.sin_addr = sin_addr
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      var sin = self
      var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
      let size = socklen_t(buffer.count)
      guard let result = inet_ntop(AF_INET, &sin.sin_addr, &buffer, size) else {
        throw Errno.lastError
      }
      let port = UInt16(bigEndian: sin.sin_port)
      return "\(String(cString: result)):\(port)"
    }
  }

  public var port: UInt16 {
    get throws {
      UInt16(bigEndian: sin_port)
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sin in
      try sin.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

extension sockaddr_in6: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_INET6)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    guard family == AF_INET6 else { throw Errno.invalidArgument }
    self = sockaddr_in6()
    let (address, port) = try parseIPv6PresentationAddress(presentationAddress)
    var sin6_port = UInt16()
    var sin6_addr = in6_addr()
    _ = try Errno.throwingErrno {
      if let port { sin6_port = port.bigEndian }
      return inet_pton(AF_INET6, address, &sin6_addr)
    }
    sin6_family = family
    self.sin6_port = sin6_port
    self.sin6_addr = sin6_addr
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      var sin6 = self
      var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
      let size = socklen_t(buffer.count)
      guard let result = inet_ntop(AF_INET, &sin6.sin6_addr, &buffer, size) else {
        throw Errno.lastError
      }
      let port = UInt16(bigEndian: sin6.sin6_port)
      return "[\(String(cString: result))]:\(port)"
    }
  }

  public var port: UInt16 {
    get throws {
      UInt16(bigEndian: sin6_port)
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sin6 in
      try sin6.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

extension sockaddr_un: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_LOCAL)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    guard family == AF_LOCAL else { throw Errno.invalidArgument }

    self = sockaddr_un()
    var sun = self
    sun.sun_family = family

    try withUnsafeMutablePointer(to: &sun.sun_path) { path in
      let start = path.propertyBasePointer(to: \.0)!
      let capacity = MemoryLayout.size(ofValue: path.pointee)
      if capacity <= presentationAddress.utf8.count {
        throw Errno.outOfRange
      }
      start.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
        _ = memcpy(
          UnsafeMutableRawPointer(mutating: dst),
          presentationAddress,
          presentationAddress.utf8.count + 1
        )
      }
    }

    self = sun
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      var sun = self
      return withUnsafeMutablePointer(to: &sun.sun_path) { path in
        let start = path.propertyBasePointer(to: \.0)!
        let capacity = MemoryLayout.size(ofValue: path)
        return start
          .withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
            String(cString: dst)
          }
      }
    }
  }

  public var port: UInt16 {
    get throws {
      throw Errno.addressFamilyNotSupported
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sun in
      try sun.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

extension sockaddr_ll: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_PACKET)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    guard family == AF_PACKET else { throw Errno.invalidArgument }

    var sll = sockaddr_ll()
    sll.sll_family = family

    let bytes = try presentationAddress.split(separator: ":").map {
      guard let byte = UInt8($0) else { throw Errno.invalidArgument }
      return byte
    }

    guard bytes.count == 6 else { throw Errno.invalidArgument }

    try withUnsafeMutablePointer(to: &sll.sll_addr) { addr in
      let start = addr.propertyBasePointer(to: \.0)!
      let capacity = MemoryLayout.size(ofValue: addr.pointee)
      if capacity <= presentationAddress.utf8.count {
        throw Errno.outOfRange
      }
      _ = start.withMemoryRebound(to: UInt8.self, capacity: capacity) { dst in
        memcpy(UnsafeMutableRawPointer(mutating: dst), bytes, capacity)
      }
    }
    self = sll
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      String(
        format: "%02x:%02x:%02x:%02x:%02x:%02x",
        sll_addr.0,
        sll_addr.1,
        sll_addr.2,
        sll_addr.3,
        sll_addr.4,
        sll_addr.5
      )
    }
  }

  public var port: UInt16 {
    get throws {
      throw Errno.addressFamilyNotSupported
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sun in
      try sun.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

extension sockaddr_nl: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_NETLINK)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    guard let pid = UInt32(presentationAddress) else { throw Errno.invalidArgument }
    try self.init(family: family, pid: pid, groups: 0)
  }

  public init(family: sa_family_t, pid: UInt32, groups: UInt32) throws {
    guard family == AF_NETLINK else { throw Errno.invalidArgument }

    self.init()
    nl_family = family
    nl_pid = pid
    nl_groups = groups
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      String(describing: nl_pid)
    }
  }

  public var port: UInt16 {
    get throws {
      throw Errno.addressFamilyNotSupported
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { sun in
      try sun.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

extension sockaddr_storage: SocketAddress, @unchecked Sendable {
  public static var family: sa_family_t {
    sa_family_t(AF_UNSPEC)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    var ss = Self()
    switch Int32(family) {
    case AF_INET:
      var sin = try sockaddr_in(family: family, presentationAddress: presentationAddress)
      _ = memcpy(&ss, &sin, Int(sin.size))
    case AF_INET6:
      var sin6 = try sockaddr_in6(family: family, presentationAddress: presentationAddress)
      _ = memcpy(&ss, &sin6, Int(sin6.size))
    case AF_LOCAL:
      var sun = try sockaddr_un(family: family, presentationAddress: presentationAddress)
      _ = memcpy(&ss, &sun, Int(sun.size))
    case AF_PACKET:
      var sll = try sockaddr_ll(family: family, presentationAddress: presentationAddress)
      _ = memcpy(&ss, &sll, Int(sll.size))
    case AF_NETLINK:
      var snl = try sockaddr_nl(family: family, presentationAddress: presentationAddress)
      _ = memcpy(&ss, &snl, Int(snl.size))
    default:
      throw Errno.addressFamilyNotSupported
    }
    self = ss
  }

  public var size: socklen_t {
    socklen_t(MemoryLayout<Self>.size)
  }

  public var presentationAddress: String {
    get throws {
      try withSockAddr { sa in
        try sa.pointee.presentationAddress
      }
    }
  }

  public var port: UInt16 {
    get throws {
      try withSockAddr { sa in
        try sa.pointee.port
      }
    }
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try withUnsafePointer(to: self) { ss in
      try ss.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
        try body(sa)
      }
    }
  }
}

public extension sockaddr {
  init(bytes: [UInt8]) throws {
    guard bytes.count >= MemoryLayout<Self>.size else {
      throw Errno.outOfRange
    }
    var sa = sockaddr()
    memcpy(&sa, bytes, MemoryLayout<Self>.size)
    self = sa
  }
}

public extension sockaddr_storage {
  init(bytes: [UInt8]) throws {
    let sa = try sockaddr(bytes: bytes)
    var ss = Self()
    let bytesRequired: Int
    switch Int32(sa.sa_family) {
    case AF_INET:
      bytesRequired = MemoryLayout<sockaddr_in>.size
    case AF_INET6:
      bytesRequired = MemoryLayout<sockaddr_in6>.size
    case AF_LOCAL:
      bytesRequired = MemoryLayout<sockaddr_un>.size
    case AF_PACKET:
      bytesRequired = MemoryLayout<sockaddr_ll>.size
    case AF_NETLINK:
      bytesRequired = MemoryLayout<sockaddr_nl>.size
    default:
      throw Errno.addressFamilyNotSupported
    }
    guard bytes.count >= bytesRequired else {
      throw Errno.outOfRange
    }
    memcpy(&ss, bytes, bytesRequired)
    self = ss
  }
}

public struct AnySocketAddress: Sendable {
  private var storage: sockaddr_storage

  public init(_ sa: any SocketAddress) {
    storage = sa.asStorage()
  }

  public init(bytes: [UInt8]) throws {
    storage = try sockaddr_storage(bytes: bytes)
  }
}

extension AnySocketAddress: Equatable {
  public static func == (lhs: AnySocketAddress, rhs: AnySocketAddress) -> Bool {
    var lhs = lhs
    var rhs = rhs
    return lhs.storage.size == rhs.storage.size &&
      memcmp(&lhs.storage, &rhs.storage, Int(lhs.storage.size)) == 0
  }
}

extension AnySocketAddress: SocketAddress {
  public static var family: sa_family_t {
    sa_family_t(AF_UNSPEC)
  }

  public init(family: sa_family_t, presentationAddress: String) throws {
    storage = try sockaddr_storage(family: family, presentationAddress: presentationAddress)
  }

  public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
    try storage.withSockAddr(body)
  }

  public var presentationAddress: String {
    get throws {
      try storage.presentationAddress
    }
  }

  public var port: UInt16 {
    get throws {
      try storage.port
    }
  }

  public var size: socklen_t {
    storage.size
  }
}

extension AnySocketAddress: Hashable {
  public func hash(into hasher: inout Hasher) {
    withUnsafeBytes(of: storage) {
      hasher.combine(bytes: $0)
    }
  }
}
