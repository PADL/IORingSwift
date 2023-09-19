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

// MARK: - actor

public actor IORing {
    public typealias FileDescriptor = CInt

    private let manager: Manager

    private struct AcceptIoPrio: OptionSet {
        typealias RawValue = UInt16

        var rawValue: RawValue

        static let multishot = UInt16(1 << 0)
    }

    private struct RecvSendIoPrio: OptionSet {
        typealias RawValue = UInt16

        var rawValue: RawValue

        static let pollFirst = UInt16(1 << 0)
        static let multishot = UInt16(1 << 1)
        static let fixedBuf = UInt16(1 << 2)
        static let zcReportUsage = UInt16(1 << 3)
    }

    public init(depth: Int = 1, flags: UInt32 = 0) throws {
        manager = try Manager(depth: CUnsignedInt(depth), flags: flags)
    }

    private final class Manager {
        private typealias Continuation = CheckedContinuation<(), Error>

        private var ring: io_uring
        private var eventHandle: UnsafeMutableRawPointer?
        private var pendingSubmissions = [Continuation]()

        init(depth: CUnsignedInt = 64, flags: CUnsignedInt = 0) throws {
            var ring = io_uring()

            try Errno.throwingErrno {
                io_uring_queue_init(depth, &ring, flags)
            }
            self.ring = ring
            try Errno.throwingErrno {
                io_uring_init_event(&self.eventHandle, &self.ring)
            }
        }

        deinit {
            cancelPendingSubmissions()
            io_uring_deinit_event(eventHandle, &ring)
            // FIXME: where are unhandled completion blocks deallocated?
            io_uring_queue_exit(&ring)
        }

        private typealias BlockHandler = (UnsafePointer<io_uring_cqe>) -> ()

        // FIXME: update kernel headers
        private func setSocketAddress(
            _ sqe: UnsafeMutablePointer<io_uring_sqe>,
            socketAddress: sockaddr_storage
        ) throws {
            var socketAddress = socketAddress
            try withUnsafePointer(to: &socketAddress) { pointer in
                try pointer
                    .withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
                        sqe.pointee.addr2 = UInt64(UInt(bitPattern: pointer))
                        let size: Int
                        switch Int32(pointer.pointee.sa_family) {
                        case AF_INET:
                            size = MemoryLayout<sockaddr_in>.size
                        case AF_INET6:
                            size = MemoryLayout<sockaddr_in6>.size
                        case AF_LOCAL:
                            size = MemoryLayout<sockaddr_un>.size
                        default:
                            throw Errno(rawValue: EAFNOSUPPORT)
                        }

                        withUnsafeMutablePointer(to: &sqe.pointee.file_index) { pointer in
                            pointer.withMemoryRebound(to: UInt16.self, capacity: 2) { pointer in
                                pointer[0] = UInt16(size)
                            }
                        }
                    }
            }
        }

        private func setFlags(
            _ sqe: UnsafeMutablePointer<io_uring_sqe>,
            flags: UInt8,
            ioprio: UInt16,
            moreFlags: UInt32
        ) {
            io_uring_sqe_set_flags(sqe, UInt32(flags))
            sqe.pointee.ioprio = ioprio
            sqe.pointee.fsync_flags = moreFlags
        }

        private func submit() throws {
            try Errno.throwingErrno {
                io_uring_submit(&self.ring)
            }
        }

        private func submitRetryingIfInterrupted<T>(
            body: @escaping (UnsafeMutablePointer<io_uring_sqe>) async throws -> T
        ) async throws -> T {
            repeat {
                do {
                    let sqe = io_uring_get_sqe(&ring)

                    guard let sqe else {
                        // queue is full, suspend
                        try await suspendPendingSubmission()
                        continue
                    }

                    let result = try await body(sqe)
                    try submit()
                    return result
                } catch let error as Errno {
                    if error.rawValue != EAGAIN {
                        throw error
                    }
                }
            } while true
        }

        private func suspendPendingSubmission() async throws {
            try await withCheckedThrowingContinuation { continuation in
                pendingSubmissions.insert(continuation, at: 0)
            }
        }

        private func resumePendingSubmission() {
            Task {
                guard let continuation = pendingSubmissions.popLast() else {
                    return
                }
                continuation.resume()
            }
        }

        private func cancelPendingSubmissions() {
            for submission in pendingSubmissions {
                submission.resume(throwing: Errno(rawValue: -ECANCELED))
            }
        }

        private func prepare(
            _ opcode: UInt8,
            sqe: UnsafeMutablePointer<io_uring_sqe>,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            offset: UInt64,
            handler: @escaping BlockHandler
        ) {
            io_uring_prep_rw_block(
                CInt(opcode),
                sqe,
                fd,
                address,
                length,
                offset
            ) {
                // FIXME: this could race before io_uring_cqe_seen() is called
                defer { self.resumePendingSubmission() }
                handler($0)
            }
        }

        func prepareAndSubmit<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer? = nil,
            length: CUnsignedInt = 0,
            offset: Int = 0,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            socketAddress: sockaddr_storage? = nil,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> T {
            try await submitRetryingIfInterrupted { [self] sqe in
                try await withCheckedThrowingContinuation { (
                    continuation: CheckedContinuation<
                        T,
                        Error
                    >
                ) in
                    let offset = offset == -1 ? UInt64(bitPattern: -1) : UInt64(offset)

                    do {
                        prepare(
                            opcode,
                            sqe: sqe,
                            fd: fd,
                            address: address,
                            length: length,
                            offset: offset
                        ) { cqe in
                            guard cqe.pointee.res >= 0 else {
                                continuation.resume(throwing: Errno(rawValue: cqe.pointee.res))
                                return
                            }
                            do {
                                let result = try handler(cqe.pointee)
                                continuation.resume(returning: result)
                            } catch {
                                continuation.resume(throwing: error)
                            }
                        }
                        setFlags(sqe, flags: flags, ioprio: ioprio, moreFlags: moreFlags)
                        if let socketAddress {
                            try setSocketAddress(sqe, socketAddress: socketAddress)
                        }
                        try submit()
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }

        func prepareAndSubmitMultishot<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer? = nil,
            length: CUnsignedInt = 0,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> AsyncThrowingChannel<T, Error> {
            try await submitRetryingIfInterrupted { [self] sqe in
                let channel = AsyncThrowingChannel<T, Error>()

                prepare(
                    opcode,
                    sqe: sqe,
                    fd: fd,
                    address: address,
                    length: length,
                    offset: 0
                ) { cqe in
                    guard cqe.pointee.res >= 0 else {
                        if cqe.pointee.res != -ECANCELED {
                            channel.fail(Errno(rawValue: cqe.pointee.res))
                        }
                        return
                    }
                    Task {
                        do {
                            try await channel.send(handler(cqe.pointee))
                        } catch {
                            channel.fail(error)
                        }
                    }
                }

                setFlags(sqe, flags: flags, ioprio: ioprio, moreFlags: moreFlags)
                try submit()
                return channel
            }
        }

        func prepareAndSubmitIovec<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            iovecs: [iovec]? = nil,
            offset: Int = 0,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> T {
            // FIXME: surely there's a better way, but can't pass async function to withUnsafeBufferPointer
            let iovecs = iovecs ?? []
            return try await withCheckedThrowingContinuation { (
                continuation: CheckedContinuation<
                    T,
                    Error
                >
            ) in
                _ = iovecs.withUnsafeBufferPointer { pointer in
                    Task {
                        try await prepareAndSubmit(
                            opcode,
                            fd: fd,
                            address: pointer.baseAddress,
                            length: CUnsignedInt(pointer.count),
                            offset: offset,
                            flags: flags,
                            ioprio: ioprio,
                            moreFlags: moreFlags
                        ) { cqe in
                            do {
                                try continuation.resume(returning: handler(cqe))
                            } catch {
                                continuation.resume(throwing: error)
                            }
                        }
                    }
                }
                return ()
            }
        }
    }

    public struct Message {
        private var __storage = msghdr()
        private var __iov_storage = iovec()

        public struct Control {
            public var level: Int32
            public var type: Int32
            public var data: [UInt8]
        }

        public var name: sockaddr_storage
        public var buffer: [UInt8]
        public var control: [Control]
        public var flags: Int32 {
            get {
                __storage.msg_flags
            }
            set {
                __storage.msg_flags = newValue
            }
        }

        private mutating func __storage_init() {
            Swift.withUnsafeMutablePointer(to: &name) { pointer in
                __storage.msg_name = UnsafeMutableRawPointer(pointer)
                __storage.msg_namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            }
            buffer.withUnsafeMutableBytes { bytes in
                __iov_storage.iov_base = bytes.baseAddress!
                __iov_storage.iov_len = bytes.count
            }
            Swift.withUnsafeMutablePointer(to: &__iov_storage) { pointer in
                __storage.msg_iov = pointer
                __storage.msg_iovlen = 1
            }
            // FIXME: support control
        }

        mutating func withUnsafeMutablePointer<T>(
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

        init(_ message: Message) {
            name = message.name
            buffer = message.buffer
            control = message.control
            __storage_init()
            flags = message.flags
        }

        init(messageBufferSize: Int = 1024) {
            name = sockaddr_storage()
            buffer = [UInt8](repeating: 0, count: messageBufferSize)
            control = [Control]()
            __storage_init()
        }

        init(_ msg: UnsafePointer<msghdr>) {
            name = sockaddr_storage()
            Swift.withUnsafeMutablePointer(to: &name) { pointer in
                _ = memcpy(pointer, msg.pointee.msg_name, Int(msg.pointee.msg_namelen))
            }
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
            self.control = control
            __storage_init()
            flags = msg.pointee.msg_flags
        }
    }
}

// MARK: - operation wrappers

private extension IORing {
    func io_uring_op_cancel(
        fd: FileDescriptor,
        flags: UInt32 = 0
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_ASYNC_CANCEL),
            fd: fd,
            moreFlags: flags
        ) { _ in }
    }

    func io_uring_op_close(
        fd: FileDescriptor
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_CLOSE),
            fd: fd
        ) { _ in }
    }

    func io_uring_op_readv(
        fd: FileDescriptor,
        iovecs: [iovec],
        offset: Int
    ) async throws -> Int {
        try await manager.prepareAndSubmitIovec(
            UInt8(IORING_OP_READV),
            fd: fd,
            iovecs: iovecs,
            offset: offset
        ) { cqe in
            Int(cqe.res)
        }
    }

    func io_uring_op_writev(
        fd: FileDescriptor,
        iovecs: [iovec],
        count: Int,
        offset: Int
    ) async throws -> Int {
        try await manager.prepareAndSubmitIovec(
            UInt8(IORING_OP_WRITEV),
            fd: fd,
            iovecs: iovecs,
            offset: offset
        ) { cqe in
            Int(cqe.res)
        }
    }

    func io_uring_op_read(
        fd: FileDescriptor,
        buffer: inout [UInt8],
        count: Int,
        offset: Int
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_READ),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(count),
            offset: offset
        ) { [buffer] cqe in
            _ = buffer
            return Int(cqe.res)
        }
    }

    func io_uring_op_write(
        fd: FileDescriptor,
        buffer: [UInt8],
        count: Int,
        offset: Int
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_WRITE),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(count),
            offset: offset
        ) { [buffer] cqe in
            _ = buffer
            return Int(cqe.res)
        }
    }

    func io_uring_op_send(
        fd: FileDescriptor,
        buffer: [UInt8],
        to socketAddress: sockaddr_storage? = nil,
        flags: UInt32 = 0
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_SEND),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(buffer.count),
            offset: 0,
            moreFlags: flags,
            socketAddress: socketAddress
        ) { [buffer] _ in
            _ = buffer
            return ()
        }
    }

    func io_uring_op_recv(
        fd: FileDescriptor,
        buffer: inout [UInt8],
        flags: UInt32 = 0
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_RECV),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(buffer.count),
            offset: 0,
            moreFlags: flags
        ) { [buffer] _ in
            _ = buffer
            return ()
        }
    }

    func io_uring_op_recv_multishot(
        fd: FileDescriptor,
        count: Int
    ) async throws -> AsyncThrowingChannel<[UInt8], Error> {
        // FIXME: check this will be captured or do we need to
        var buffer = [UInt8](repeating: 0, count: count)
        return try await manager.prepareAndSubmitMultishot(
            UInt8(IORING_OP_RECV),
            fd: fd,
            address: &buffer[0],
            length: CUnsignedInt(count),
            ioprio: RecvSendIoPrio.multishot
        ) { [buffer] _ in
            buffer
        }
    }

    func io_uring_op_recvmsg(
        fd: FileDescriptor,
        message: inout Message,
        flags: UInt32 = 0
    ) async throws {
        try await message.withUnsafeMutablePointer { pointer in
            try await manager.prepareAndSubmit(
                UInt8(IORING_OP_RECVMSG),
                fd: fd,
                address: pointer,
                length: 1,
                offset: 0,
                moreFlags: flags
            ) { _ in }
        }
    }

    func io_uring_op_recvmsg_multishot(
        fd: FileDescriptor,
        flags: UInt32 = 0
    ) async throws -> AsyncThrowingChannel<Message, Error> {
        var message = Message()
        return try await message.withUnsafeMutablePointer { pointer in
            try await manager.prepareAndSubmitMultishot(
                UInt8(IORING_OP_RECVMSG),
                fd: fd,
                address: pointer,
                ioprio: AcceptIoPrio.multishot,
                moreFlags: flags
            ) { [pointer] _ in
                _ = pointer
                return message
            }
        }
    }

    func io_uring_op_sendmsg(
        fd: FileDescriptor,
        message: Message,
        flags: UInt32 = 0
    ) async throws {
        try await message.withUnsafePointer { pointer in
            try await manager.prepareAndSubmit(
                UInt8(IORING_OP_SENDMSG),
                fd: fd,
                address: pointer,
                length: 1,
                offset: 0,
                moreFlags: flags
            ) { _ in }
        }
    }

    func io_uring_op_accept(
        fd: FileDescriptor,
        flags: UInt32 = 0
    ) async throws -> (FileDescriptor, sockaddr_storage) {
        var ss = sockaddr_storage()
        return try await manager.prepareAndSubmit(
            UInt8(IORING_OP_ACCEPT),
            fd: fd,
            address: &ss,
            length: CUnsignedInt(MemoryLayout<sockaddr_storage>.size),
            offset: 0,
            moreFlags: flags
        ) { [ss] cqe in
            _ = ss
            return (cqe.res, ss)
        }
    }

    func io_uring_op_multishot_accept(
        fd: FileDescriptor,
        flags: UInt32 = 0
    ) async throws -> AsyncThrowingChannel<FileDescriptor, Error> {
        try await manager.prepareAndSubmitMultishot(
            UInt8(IORING_OP_ACCEPT),
            fd: fd,
            ioprio: AcceptIoPrio.multishot,
            moreFlags: flags
        ) { cqe in
            cqe.res
        }
    }
}

// MARK: - public API

public extension IORing {
    func close(_ fd: FileDescriptor) async throws {
        try await io_uring_op_close(fd: fd)
    }

    @discardableResult
    func read(
        into buffer: inout [UInt8],
        count: Int? = nil,
        offset: Int = -1,
        from fd: FileDescriptor
    ) async throws -> Bool {
        var nread = 0
        let count = count ?? buffer.count

        // handle short reads; breaking reads into blocks should be done by caller
        repeat {
            let nbytes = try await io_uring_op_read(
                fd: fd,
                buffer: &buffer,
                count: count - nread,
                offset: offset == -1 ? -1 : offset + nread
            )
            if nbytes == 0 {
                // done reading
                return false
            }
            nread += nbytes
        } while nread < count

        return true
    }

    func read(count: Int, from fd: FileDescriptor) async throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        try await read(into: &buffer, count: count, from: fd)
        return buffer
    }

    func write(
        _ data: [UInt8],
        count: Int? = nil,
        offset: Int = -1,
        to fd: FileDescriptor
    ) async throws {
        var nwritten = 0
        let count = count ?? data.count

        // handle short writes; breaking writes into blocks should be done by caller
        repeat {
            nwritten += try await io_uring_op_write(
                fd: fd,
                buffer: data,
                count: count - nwritten,
                offset: offset == -1 ? -1 : offset + nwritten
            )
        } while nwritten < count
    }

    func recv(count: Int, from fd: FileDescriptor) async throws -> AnyAsyncSequence<[UInt8]> {
        try await io_uring_op_recv_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
    }

    func recv(count: Int, from fd: FileDescriptor) async throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        try await io_uring_op_recv(fd: fd, buffer: &buffer)
        return buffer
    }

    func send(_ data: [UInt8], to fd: FileDescriptor) async throws {
        try await io_uring_op_send(fd: fd, buffer: data)
    }

    func recvmsg(count: Int, from fd: FileDescriptor) async throws -> AnyAsyncSequence<Message> {
        try await io_uring_op_recvmsg_multishot(fd: fd).eraseToAnyAsyncSequence()
    }

    func recvmsg(count: Int, from fd: FileDescriptor) async throws -> Message {
        var message = Message(messageBufferSize: count)
        try await io_uring_op_recvmsg(fd: fd, message: &message)
        return message
    }

    func sendmsg(_ message: Message, to fd: FileDescriptor) async throws {
        var message = message
        try await io_uring_op_recvmsg(fd: fd, message: &message)
    }

    func accept(from fd: FileDescriptor) async throws
        -> AnyAsyncSequence<FileDescriptor>
    {
        try await io_uring_op_multishot_accept(fd: fd).eraseToAnyAsyncSequence()
    }
}
