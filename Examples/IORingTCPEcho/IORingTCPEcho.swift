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

import Foundation
import Glibc
import IORing
import IORingUtils

public struct Socket {
    private let fd: IORingUtils.FileHandle

    public init(domain: CInt, type: UInt32, protocol proto: CInt) throws {
        let fd = socket(domain, Int32(type), proto)
        self.fd = try FileHandle(fd: fd)
    }

    public func setNonBlocking() throws {
        try fd.withDescriptor { fd in
            let flags = try Errno.throwingErrno { fcntl(fd, F_GETFL, 0) }
            try Errno.throwingErrno { fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
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

@main
public struct IORingTCPEcho {
    private let socket: Socket
    private let ring: IORing
    private let bufferSize: Int

    public static func main() async throws {
        guard CommandLine.arguments.count == 2,
              let port = UInt16(CommandLine.arguments[1])
        else {
            print("Usage: \(CommandLine.arguments[0]) [port]")
            exit(1)
        }

        let echo = try IORingTCPEcho(port: port)
        try await echo.run()
    }

    init(port: UInt16 = 10000, bufferSize: Int = 1024, backlog: Int = 128) throws {
        self.bufferSize = bufferSize
        ring = try IORing(depth: backlog)
        socket = try Socket(domain: AF_INET, type: SOCK_STREAM.rawValue, protocol: 0)
        try socket.setNonBlocking()
        try socket.setReuseAddr()
        try socket.bind(to: sockaddr_in.any(port: port))
        try socket.listen(backlog: backlog)
    }

    func run() async throws {
        repeat {
            // accept
            // recv
            // send
        } while true
    }
}
