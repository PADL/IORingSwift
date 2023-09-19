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

public struct Socket: CustomStringConvertible {
    private let fd: IORingUtils.FileHandle

    public init(fd: IORingUtils.FileHandle) {
        self.fd = fd
    }

    public var description: String {
        if let peerNameString = try? peerNameString {
            return "\(type(of: self))(fd: \(fd), peerName: \(peerNameString))"
        } else {
            return "\(type(of: self))(fd: \(fd))"
        }
    }

    public init(domain: CInt, type: UInt32, protocol proto: CInt) throws {
        let fd = socket(domain, Int32(type), proto)
        self.fd = try FileHandle(fd: fd)
    }

    public func setNonBlocking() throws {
        try fd.setNonBlocking()
    }

    func getName(_ body: @escaping (
        _ fd: IORing.FileDescriptor,
        UnsafeMutablePointer<sockaddr>,
        UnsafeMutablePointer<socklen_t>
    ) -> CInt) throws -> sockaddr_storage {
        var ss = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)

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

    public var sockName: sockaddr_storage {
        get throws {
            try getName { getsockname($0, $1, $2) }
        }
    }

    public var sockNameString: String {
        get throws {
            try sockName.presentationAddress
        }
    }

    public var peerName: sockaddr_storage {
        get throws {
            try getName { getpeername($0, $1, $2) }
        }
    }

    public var peerNameString: String {
        get throws {
            try peerName.presentationAddress
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

    public func bind(to address: sockaddr, length: Int) throws {
        var address = address
        try fd.withDescriptor { fd in
            try Errno.throwingErrno {
                SwiftGlibc.bind(fd, &address, socklen_t(length))
            }
        }
    }

    public func bind(to address: sockaddr_in) throws {
        try withUnsafePointer(to: address) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try bind(to: $0.pointee, length: MemoryLayout<sockaddr_in>.size)
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

    public func accept(ring: IORing) async throws -> AnyAsyncSequence<Socket> {
        try await fd.withDescriptor { fd in
            try await ring.accept(from: fd).map { try Socket(fd: FileHandle(fd: $0)) }
                .eraseToAnyAsyncSequence()
        }
    }

    public func connect(to address: sockaddr, length: Int) throws {
        var address = address
        try fd.withDescriptor { fd in
            try Errno.throwingErrno {
                SwiftGlibc.connect(fd, &address, socklen_t(length))
            }
        }
    }

    public func connect(to address: sockaddr_in) throws {
        try withUnsafePointer(to: address) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try connect(to: $0.pointee, length: MemoryLayout<sockaddr_in>.size)
            }
        }
    }

    /*
     public func connect(to address: sockaddr_storage, ring: IORing) async throws {
         var address = address
         try await fd.withDescriptor { fd in
             try await ring.connect(fd, to: address)
         }
     }
     */

    public func read(into buffer: inout [UInt8], count: Int, ring: IORing) async throws -> Bool {
        try await fd.withDescriptor { try await ring.read(
            into: &buffer,
            count: count,
            offset: 0,
            from: $0
        ) }
    }

    public func write(_ buffer: [UInt8], count: Int, ring: IORing) async throws {
        try await fd.withDescriptor { try await ring.write(
            buffer,
            count: count,
            offset: 0,
            to: $0
        ) }
    }

    public func recv(count: Int, ring: IORing) async throws -> [UInt8] {
        try await fd.withDescriptor { try await ring.recv(
            count: count,
            from: $0
        ) }
    }

    public func send(_ data: [UInt8], ring: IORing) async throws {
        try await fd.withDescriptor { try await ring.send(
            data,
            to: $0
        ) }
    }

    public func recvmsg(count: Int, ring: IORing) async throws -> AnyAsyncSequence<IORing.Message> {
        try await fd.withDescriptor { try await ring.recvmsg(
            count: count,
            from: $0
        ) }
    }

    public func sendmsg(_ message: IORing.Message, ring: IORing) async throws {
        try await fd.withDescriptor { try await ring.sendmsg(
            message,
            to: $0
        ) }
    }
}

public extension sockaddr_in {
    static func any(port: UInt16) -> Self {
        var sin = Self()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = port.bigEndian
        sin.sin_addr = in_addr(s_addr: INADDR_ANY)
        return sin
    }
}

public extension sockaddr_storage {
    init(family: Int32, presentationAddress: String) throws {
        self.init()

        var port: UInt16?
        let addressPort = presentationAddress.split(separator: ":", maxSplits: 2)
        if addressPort.count > 1 {
            port = UInt16(addressPort[1])
        }

        ss_family = sa_family_t(family)
        try withUnsafeMutablePointer(to: &self) { pointer in
            switch Int32(family) {
            case AF_INET:
                try pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    _ = try Errno.throwingErrno {
                        if let port { sin.pointee.sin_port = port.bigEndian }
                        return inet_pton(AF_INET, String(addressPort.first!), &sin.pointee.sin_addr)
                    }
                }
            case AF_INET6:
                try pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    _ = try Errno.throwingErrno {
                        if let port { sin6.pointee.sin6_port = port.bigEndian }
                        return inet_pton(
                            AF_INET,
                            String(addressPort.first!),
                            &sin6.pointee.sin6_addr
                        )
                    }
                }
            case AF_LOCAL:
                try pointer.withMemoryRebound(to: sockaddr_un.self, capacity: 1) { sun in
                    try withUnsafeMutablePointer(to: &sun.pointee.sun_path) { path in
                        let start = path.propertyBasePointer(to: \.0)!
                        let capacity = MemoryLayout.size(ofValue: path)
                        if capacity <= addressPort.first!.utf8.count {
                            throw Errno(rawValue: ERANGE)
                        }
                        start.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                            _ = memcpy(
                                UnsafeMutableRawPointer(mutating: dst),
                                String(addressPort.first!),
                                addressPort.first!.utf8.count + 1
                            )
                        }
                    }
                }
            default:
                throw Errno(rawValue: EAFNOSUPPORT)
            }
        }
    }

    var presentationAddress: String {
        get throws {
            var ss = self
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let size = socklen_t(buffer.count)
            var port: UInt16 = 0

            let address = try withUnsafeMutablePointer(to: &ss) { pointer in
                switch Int32(pointer.pointee.ss_family) {
                case AF_INET:
                    return try pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                        guard let result = inet_ntop(AF_INET, &sin.pointee.sin_addr, &buffer, size)
                        else {
                            throw Errno.lastError
                        }
                        port = UInt16(bigEndian: sin.pointee.sin_port)
                        return String(cString: result)
                    }
                case AF_INET6:
                    return try pointer
                        .withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                            guard let result = inet_ntop(
                                AF_INET6,
                                &sin6.pointee.sin6_addr,
                                &buffer,
                                size
                            ) else {
                                throw Errno.lastError
                            }
                            port = UInt16(bigEndian: sin6.pointee.sin6_port)
                            return String(cString: result)
                        }
                case AF_LOCAL:
                    return pointer.withMemoryRebound(to: sockaddr_un.self, capacity: 1) { sun in
                        withUnsafeMutablePointer(to: &sun.pointee.sun_path) { path in
                            let start = path.propertyBasePointer(to: \.0)!
                            let capacity = MemoryLayout.size(ofValue: path)
                            return start
                                .withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                                    String(cString: dst)
                                }
                        }
                    }
                default:
                    throw Errno(rawValue: EAFNOSUPPORT)
                }
            }

            if port != 0 {
                return "\(address):\(port)"
            } else {
                return address
            }
        }
    }
}
