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

@_implementationOnly
import CIORingShims
@_implementationOnly
import CIOURing
import ErrNo
import Glibc

// MARK: - iovec extensions

extension iovec {
    init(
        bufferPointer: UnsafeRawBufferPointer,
        offset: size_t? = nil,
        count: size_t? = nil
    ) throws {
        try self.init(
            mutableBufferPointer: UnsafeMutableRawBufferPointer(mutating: bufferPointer),
            offset: offset,
            count: count
        )
    }

    init(
        mutableBufferPointer: UnsafeMutableRawBufferPointer,
        offset: size_t? = nil, // offset into buffer pointer to start reading or writing
        count: size_t? = nil // number of bytes to read or write
    ) throws {
        let offset = offset ?? 0
        let count = count ?? mutableBufferPointer.count

        if offset + count > mutableBufferPointer.count {
            throw ErrNo.ERANGE
        }

        self.init(
            iov_base: mutableBufferPointer.baseAddress! + offset,
            iov_len: count
        )
    }
}

// MARK: - sockaddr extensions

extension sockaddr {
    var size: socklen_t {
        get throws {
            switch Int32(sa_family) {
            case AF_INET:
                return socklen_t(MemoryLayout<sockaddr_in>.size)
            case AF_INET6:
                return socklen_t(MemoryLayout<sockaddr_in6>.size)
            case AF_LOCAL:
                return socklen_t(MemoryLayout<sockaddr_un>.size)
            default:
                throw ErrNo.EAFNOSUPPORT
            }
        }
    }
}

extension sockaddr_storage {
    // FIXME: DRY IORingUtils
    func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try body($0)
            }
        }
    }

    var size: socklen_t {
        get throws {
            try withSockAddr {
                try $0.pointee.size
            }
        }
    }
}

extension sockaddr {
    init(bytes: [UInt8]) throws {
        guard bytes.count >= MemoryLayout<Self>.size else {
            throw ErrNo.ERANGE
        }
        var sa = sockaddr()
        memcpy(&sa, bytes, MemoryLayout<Self>.size)
        self = sa
    }
}

extension sockaddr_storage {
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
            throw ErrNo.EAFNOSUPPORT
        }
        guard bytes.count >= bytesRequired else {
            throw ErrNo.ERANGE
        }
        memcpy(&ss, bytes, bytesRequired)
        self = ss
    }
}

public extension ErrNo {
    @discardableResult
    static func throwingErrNo(_ body: @escaping () -> RawValue) throws -> RawValue {
        let result = body()
        if result < 0 {
            throw ErrNo(rawValue: result)
        }
        return result
    }
}

struct Queue<T> {
    private var storage = [T]()

    mutating func enqueue(_ element: T) {
        storage.append(element)
    }

    mutating func dequeue() -> T? {
        guard !storage.isEmpty else {
            return nil
        }

        return storage.removeFirst()
    }
}
