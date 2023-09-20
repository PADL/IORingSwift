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
import AsyncExtensions
import Foundation
import Glibc
import IORing

public struct Socket: CustomStringConvertible, Equatable, Hashable {
    private let fd: IORingUtils.FileHandle
    private let domain: sa_family_t
    private let ring: IORing

    public init(ring: IORing, fd: IORingUtils.FileHandle) {
        self.ring = ring
        self.fd = fd
        domain = sa_family_t(AF_UNSPEC)
    }

    public var description: String {
        if let localName = try? localName, let peerName = try? peerName {
            return "\(type(of: self))(fd: \(fd), localName: \(localName), peerName: \(peerName))"
        } else {
            return "\(type(of: self))(fd: \(fd))"
        }
    }

    public init(
        ring: IORing,
        domain: sa_family_t,
        type: __socket_type,
        `protocol` proto: CInt = 0
    ) throws {
        self.ring = ring
        let fd = socket(CInt(domain), Int32(type.rawValue), proto)
        self.fd = try FileHandle(fd: fd)
        self.domain = sa_family_t(domain)
    }

    public func setNonBlocking() throws {
        try fd.setNonBlocking()
    }

    private func getName(_ body: @escaping (
        _ fd: IORing.FileDescriptor,
        UnsafeMutablePointer<sockaddr>,
        UnsafeMutablePointer<socklen_t>
    ) -> CInt) throws -> sockaddr_storage {
        var ss = sockaddr_storage()
        var length = ss.size

        _ = try withUnsafeMutablePointer(to: &ss) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                try fd.withDescriptor { fd in
                    try Errno.throwingErrno {
                        body(fd, sa, &length)
                    }
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
        try fd.withDescriptor { fd in
            var value: CInt = value ? 1 : 0
            try Errno.throwingErrno { setsockopt(
                fd,
                level,
                option,
                &value,
                socklen_t(MemoryLayout<CInt>.size)
            ) }
        }
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
            sin.sin_port = port.bigEndian
            try bind(to: sin)
        case AF_INET6:
            var sin6 = sockaddr_in6()
            sin6.sin6_port = port.bigEndian
            try bind(to: sin6)
        default:
            throw Errno(rawValue: EAFNOSUPPORT)
        }
    }

    public func bind(path: String) throws {
        let sun = try sockaddr_un(family: sa_family_t(AF_LOCAL), presentationAddress: path)
        try bind(to: sun)
    }

    public func bind(to address: any SocketAddress) throws {
        try fd.withDescriptor { fd in
            try address.withSockAddr { sa in
                try Errno.throwingErrno {
                    SwiftGlibc.bind(fd, sa, address.size)
                }
            }
        }
    }

    public func listen(backlog: Int = 128) throws {
        try fd.withDescriptor { fd in
            try Errno.throwingErrno {
                SwiftGlibc.listen(fd, Int32(backlog))
            }
        }
    }

    public func accept() async throws -> AnyAsyncSequence<Socket> {
        try await fd.withDescriptor { fd in
            try await ring.accept(from: fd).map { try Socket(ring: ring, fd: FileHandle(fd: $0)) }
                .eraseToAnyAsyncSequence()
        }
    }

    public func connect(to address: any SocketAddress) throws {
        try fd.withDescriptor { fd in
            try address.withSockAddr { sa in
                try Errno.throwingErrno {
                    SwiftGlibc.connect(fd, sa, address.size)
                }
            }
        }
    }

    public func connect(to address: any SocketAddress) async throws {
        try await fd.withDescriptor { fd in
            try await ring.connect(fd, to: address)
        }
    }

    public func read(into buffer: inout [UInt8], count: Int) async throws -> Bool {
        try await fd.withDescriptor { try await ring.read(
            into: &buffer,
            count: count,
            offset: 0,
            from: $0
        ) }
    }

    public func write(_ buffer: [UInt8], count: Int) async throws {
        try await fd.withDescriptor { try await ring.write(
            buffer,
            count: count,
            offset: 0,
            to: $0
        ) }
    }

    public func recv(count: Int) async throws -> [UInt8] {
        try await fd.withDescriptor { try await ring.recv(
            count: count,
            from: $0
        ) }
    }

    public func send(_ data: [UInt8]) async throws {
        try await fd.withDescriptor { try await ring.send(
            data,
            to: $0
        ) }
    }

    public func recvmsg(count: Int) async throws -> AnyAsyncSequence<Message> {
        try await fd.withDescriptor { try await ring.recvmsg(
            count: count,
            from: $0
        ) }
    }

    public func sendmsg(_ message: Message) async throws {
        try await fd.withDescriptor { try await ring.sendmsg(
            message,
            to: $0
        ) }
    }

    public func close() async throws {
        try await fd.withDescriptor { try await ring.close($0) }
        fd.invalidate()
    }

    public var isClosed: Bool {
        fd.isValid
    }
}

public protocol InternetSocketAddress {
    static func any(port: UInt16) -> Self
}

extension sockaddr_in: InternetSocketAddress {
    public static func any(port: UInt16) -> Self {
        var sin = Self()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = port.bigEndian
        sin.sin_addr = in_addr(s_addr: INADDR_ANY)
        return sin
    }
}

extension sockaddr_in6: InternetSocketAddress {
    public static func any(port: UInt16) -> Self {
        var sin6 = Self()
        sin6.sin6_family = sa_family_t(AF_INET6)
        sin6.sin6_port = port.bigEndian
        sin6.sin6_addr = in6_addr()
        return sin6
    }
}

private func parsePresentationAddress(_ presentationAddress: String) -> (String, UInt16?) {
    var port: UInt16?
    let addressPort = presentationAddress.split(separator: ":", maxSplits: 2)
    if addressPort.count > 1 {
        port = UInt16(addressPort[1])
    }

    return (String(addressPort.first!), port)
}

public protocol SocketAddress {
    static var family: sa_family_t { get }

    init(family: sa_family_t, presentationAddress: String) throws
    func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T
    var presentationAddress: String { get throws }
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

extension sockaddr: SocketAddress {
    public static var family: sa_family_t {
        sa_family_t(AF_UNSPEC)
    }

    public init(family: sa_family_t, presentationAddress: String) throws {
        throw Errno(rawValue: EINVAL)
    }

    public var size: socklen_t {
        switch Int32(sa_family) {
        case AF_INET:
            return socklen_t(MemoryLayout<sockaddr_in>.size)
        case AF_INET6:
            return socklen_t(MemoryLayout<sockaddr_in6>.size)
        case AF_LOCAL:
            return socklen_t(MemoryLayout<sockaddr_un>.size)
        default:
            return 0
        }
    }

    public var presentationAddress: String {
        get throws {
            switch Int32(sa_family) {
            case AF_INET:
                return try withUnsafePointer(to: self) {
                    try $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        try $0.pointee.presentationAddress
                    }
                }
            case AF_INET6:
                return try withUnsafePointer(to: self) {
                    try $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                        try $0.pointee.presentationAddress
                    }
                }
            case AF_LOCAL:
                return try withUnsafePointer(to: self) {
                    try $0.withMemoryRebound(to: sockaddr_un.self, capacity: 1) {
                        try $0.pointee.presentationAddress
                    }
                }
            default:
                throw Errno(rawValue: EAFNOSUPPORT)
            }
        }
    }

    public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) { sa in
            try body(sa)
        }
    }
}

extension sockaddr_in: SocketAddress {
    public static var family: sa_family_t {
        sa_family_t(AF_INET)
    }

    public init(family: sa_family_t, presentationAddress: String) throws {
        guard family == AF_INET else { throw Errno(rawValue: EINVAL) }
        self = sockaddr_in()
        let (address, port) = parsePresentationAddress(presentationAddress)
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

    public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) { sin in
            try sin.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                try body(sa)
            }
        }
    }
}

extension sockaddr_in6: SocketAddress {
    public static var family: sa_family_t {
        sa_family_t(AF_INET6)
    }

    public init(family: sa_family_t, presentationAddress: String) throws {
        guard family == AF_INET6 else { throw Errno(rawValue: EINVAL) }
        self = sockaddr_in6()
        let (address, port) = parsePresentationAddress(presentationAddress)
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
            return "\(String(cString: result)):\(port)"
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

extension sockaddr_un: SocketAddress {
    public static var family: sa_family_t {
        sa_family_t(AF_LOCAL)
    }

    public init(family: sa_family_t, presentationAddress: String) throws {
        guard family == AF_LOCAL else { throw Errno(rawValue: EINVAL) }

        self = sockaddr_un()
        var sun = self
        sun.sun_family = family

        try withUnsafeMutablePointer(to: &sun.sun_path) { path in
            let start = path.propertyBasePointer(to: \.0)!
            let capacity = MemoryLayout.size(ofValue: path)
            if capacity <= presentationAddress.utf8.count {
                throw Errno(rawValue: ERANGE)
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

    public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) { sun in
            try sun.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                try body(sa)
            }
        }
    }
}

extension sockaddr_storage: SocketAddress {
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
        default:
            throw Errno(rawValue: EAFNOSUPPORT)
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

    public func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) { ss in
            try ss.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                try body(sa)
            }
        }
    }
}

public extension Data {
    var socketAddress: any SocketAddress {
        get throws {
            try withUnsafeBytes { data -> (any SocketAddress) in
                var family = sa_family_t(AF_UNSPEC)

                try data.withMemoryRebound(to: sockaddr.self) {
                    let sa = $0.baseAddress!.pointee
                    family = sa.sa_family
                    guard sa.size <= self.count else { // ignores trailing bytes
                        throw Errno(rawValue: EAFNOSUPPORT)
                    }
                }

                switch Int32(family) {
                case AF_INET:
                    var sin = sockaddr_in()
                    memcpy(&sin, data.baseAddress!, Int(sin.size))
                    return sin
                case AF_INET6:
                    var sin6 = sockaddr_in6()
                    memcpy(&sin6, data.baseAddress!, Int(sin6.size))
                    return sin6
                case AF_LOCAL:
                    var sun = sockaddr_un()
                    memcpy(&sun, data.baseAddress!, Int(sun.size))
                    return sun
                default:
                    throw Errno(rawValue: EAFNOSUPPORT)
                }
            }
        }
    }
}

public extension sockaddr {
    init(bytes: [UInt8]) throws {
        guard bytes.count >= MemoryLayout<Self>.size else {
            throw Errno(rawValue: ERANGE)
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
        default:
            throw Errno(rawValue: EAFNOSUPPORT)
        }
        guard bytes.count >= bytesRequired else {
            throw Errno(rawValue: ERANGE)
        }
        memcpy(&ss, bytes, bytesRequired)
        self = ss
    }
}
