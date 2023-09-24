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
import AsyncAlgorithms
import AsyncExtensions
@_implementationOnly
import CIORingShims
@_implementationOnly
import CIOURing
import Glibc

public final class Message {
    // FIXME: again, this is a workaround for _XOPEN_SOURCE=500 clang importer issues
    public var name: [UInt8] {
        get {
            withUnsafeBytes(of: address) {
                Array($0)
            }
        }
        set {
            address = try! sockaddr_storage(bytes: newValue)
        }
    }

    public var address: sockaddr_storage {
        didSet {
            Swift.withUnsafeMutablePointer(to: &address) { pointer in
                __storage.msg_name = UnsafeMutableRawPointer(pointer)
                __storage.msg_namelen = (try? pointer.pointee.size) ?? 0
            }
        }
    }

    public var buffer: [UInt8] {
        didSet {
            buffer.withUnsafeMutableBytes { bytes in
                __iov_storage.iov_base = bytes.baseAddress
                __iov_storage.iov_len = bytes.count
            }
        }
    }

    public struct Control {
        public var level: Int32
        public var type: Int32
        public var data: [UInt8]
    }

    public var control = [Control]()

    public var flags: Int32 {
        get {
            __storage.msg_flags
        }
        set {
            __storage.msg_flags = newValue
        }
    }

    private var __storage = msghdr()
    private var __iov_storage = iovec()

    func withUnsafeMutablePointer<T>(
        _ body: (UnsafeMutablePointer<msghdr>) async throws
            -> T
    ) async rethrows
        -> T
    {
        try await body(&__storage)
    }

    func withUnsafePointer<T>(
        _ body: (UnsafePointer<msghdr>) async throws
            -> T
    ) async rethrows
        -> T
    {
        var storage = __storage
        return try await body(&storage)
    }

    init(address: sockaddr_storage, buffer: [UInt8] = [], flags: Int32 = 0) {
        self.address = address
        self.buffer = buffer
        self.flags = flags
        __init_storage()
    }

    func copy() -> Self {
        Self(address: address, buffer: buffer, flags: flags)
    }

    // FIXME: see note below about _XOPEN_SOURCE=500 sockaddr clang importer issues
    public convenience init(
        name: [UInt8]? = nil,
        buffer: [UInt8] = [],
        flags: Int32 = 0
    ) throws {
        let ss: sockaddr_storage = if let name {
            try sockaddr_storage(bytes: name)
        } else {
            sockaddr_storage()
        }
        self.init(address: ss, buffer: buffer, flags: 0)
    }

    public convenience init(capacity: Int, flags: Int32 = 0) {
        self.init(
            address: sockaddr_storage(),
            buffer: [UInt8](repeating: 0, count: capacity),
            flags: flags
        )
        // special case for receiving messages
        __storage.msg_namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
    }

    /*
     private init(_ msg: UnsafePointer<msghdr>) throws {
         let name = UnsafeRawBufferPointer(
             start: msg.pointee.msg_name,
             count: Int(msg.pointee.msg_namelen)
         )
         address = try sockaddr_storage(bytes: Array(name))
         var buffer = [UInt8]()
         let iov = UnsafeBufferPointer(start: msg.pointee.msg_iov, count: msg.pointee.msg_iovlen)
         for iovec in iov {
             let ptr = unsafeBitCast(iovec.iov_base, to: UnsafePointer<UInt8>.self)
             let data = UnsafeBufferPointer(start: ptr, count: iovec.iov_len)
             buffer.append(contentsOf: data)
         }
         self.buffer = buffer
         var control = [Control]()
         CMSG_APPLY(msg) { cmsg, data, len in
             let data = UnsafeBufferPointer(start: data, count: len)
             control.append(Control(
                 level: cmsg.pointee.cmsg_level,
                 type: cmsg.pointee.cmsg_type,
                 data: Array(data)
             ))
         }
         flags = msg.pointee.msg_flags
         self.control = control
         __init_storage()
     }
     */

    func __init_storage() {
        Swift.withUnsafeMutablePointer(to: &address) { pointer in
            // forces didSet to be called
            _ = pointer
        }
        buffer.withUnsafeMutableBytes { bytes in
            // forces didSet to be called
            _ = bytes
        }
        Swift.withUnsafeMutablePointer(to: &__iov_storage) { iov_storage in
            __storage.msg_iov = iov_storage
            __storage.msg_iovlen = 1
        }
    }
}
