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
        "\(type(of: self))(fd: \(fd))"
    }

    public init(domain: CInt, type: UInt32, protocol proto: CInt) throws {
        let fd = socket(domain, Int32(type), proto)
        self.fd = try FileHandle(fd: fd)
    }

    public func setNonBlocking() throws {
        try fd.setNonBlocking()
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
