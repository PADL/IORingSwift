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
            throw Errno(rawValue: ERANGE)
        }

        self.init(
            iov_base: mutableBufferPointer.baseAddress! + offset,
            iov_len: count
        )
    }
}

extension sockaddr {
    var size: Int {
        get throws {
            switch Int32(sa_family) {
            case AF_INET:
                return MemoryLayout<sockaddr_in>.size
            case AF_INET6:
                return MemoryLayout<sockaddr_in6>.size
            case AF_LOCAL:
                return MemoryLayout<sockaddr_un>.size
            default:
                throw Errno(rawValue: EAFNOSUPPORT)
            }
        }
    }
}

// FIXME: DRY IORingUtils

extension sockaddr_storage {
    func withSockAddr<T>(_ body: (_ sa: UnsafePointer<sockaddr>) throws -> T) rethrows -> T {
        try withUnsafePointer(to: self) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try body($0)
            }
        }
    }

    var size: Int {
        get throws {
            try withSockAddr {
                try $0.pointee.size
            }
        }
    }
}
