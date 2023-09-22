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
import ErrNo
import Glibc

// MARK: - actor

public actor IORing {
    public static let shared = try? IORing()

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
        private var pendingSubmissions = Queue<Continuation>()

        init(depth: CUnsignedInt = 64, flags: CUnsignedInt = 0) throws {
            var ring = io_uring()

            try ErrNo.throwingErrNo {
                io_uring_queue_init(depth, &ring, flags)
            }
            self.ring = ring
            try ErrNo.throwingErrNo {
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

        private func setSocketAddress(
            _ sqe: UnsafeMutablePointer<io_uring_sqe>,
            socketAddress: UnsafePointer<sockaddr>
        ) throws {
            sqe.pointee.addr2 = UInt64(UInt(bitPattern: socketAddress))
            // FIXME: update kernel headers to get size, pad structure definition
            try withUnsafeMutablePointer(to: &sqe.pointee.file_index) { pointer in
                try pointer.withMemoryRebound(to: UInt16.self, capacity: 2) { pointer in
                    pointer[0] = try UInt16(socketAddress.pointee.size)
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
            try ErrNo.throwingErrNo {
                io_uring_submit(&self.ring)
            }
        }

        private func submitRetrying<T>(
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
                } catch let error as ErrNo {
                    switch error {
                    case .EAGAIN:
                        fallthrough
                    // FIXME: should we always retry on cancel?
                    case .ECANCELED:
                        break
                    default:
                        throw error
                    }
                }
            } while true
        }

        private func suspendPendingSubmission() async throws {
            try await withCheckedThrowingContinuation { continuation in
                pendingSubmissions.enqueue(continuation)
            }
        }

        private func resumePendingSubmission() {
            Task {
                guard let continuation = pendingSubmissions.dequeue() else {
                    return
                }
                continuation.resume()
            }
        }

        private func cancelPendingSubmissions() {
            while let continuation = pendingSubmissions.dequeue() {
                continuation.resume(throwing: ErrNo(rawValue: ECANCELED))
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
                // FIXME: this could race before io_uring_cqe_seen() is called, although shouldn't happen if on same actor
                handler($0)
                self.resumePendingSubmission()
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
            try await submitRetrying { [self] sqe in
                try await withCheckedThrowingContinuation { (
                    continuation: CheckedContinuation<
                        T,
                        Error
                    >
                ) in
                    do {
                        prepare(
                            opcode,
                            sqe: sqe,
                            fd: fd,
                            address: address,
                            length: length,
                            offset: offset == -1 ? UInt64(bitPattern: -1) : UInt64(offset)
                        ) { cqe in
                            guard cqe.pointee.res >= 0 else {
                                continuation.resume(throwing: ErrNo(rawValue: cqe.pointee.res))
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
                            try socketAddress.withSockAddr { socketAddress in
                                try setSocketAddress(sqe, socketAddress: socketAddress)
                            }
                        }
                        try submit()
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }

        private func prepareAndSubmitMultishot<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            flags: UInt8,
            ioprio: UInt16,
            moreFlags: UInt32,
            retryOnCancel: Bool,
            handler: @escaping (io_uring_cqe) throws -> T,
            channel: AsyncThrowingChannel<T, Error>
        ) async throws {
            try await submitRetrying { [self] sqe in
                prepare(
                    opcode,
                    sqe: sqe,
                    fd: fd,
                    address: address,
                    length: length,
                    offset: 0
                ) { cqe in
                    guard cqe.pointee.res >= 0 else {
                        if cqe.pointee.res == -ECANCELED, retryOnCancel {
                            // looks like we need to resubmit the entire request
                            Task {
                                do {
                                    try await self.prepareAndSubmitMultishot(
                                        opcode,
                                        fd: fd,
                                        address: address,
                                        length: length,
                                        flags: flags,
                                        ioprio: ioprio,
                                        moreFlags: moreFlags,
                                        retryOnCancel: retryOnCancel,
                                        handler: handler,
                                        channel: channel
                                    )
                                } catch {
                                    channel.fail(error)
                                }
                            }
                        } else {
                            channel.fail(ErrNo(rawValue: cqe.pointee.res))
                        }
                        return
                    }
                    do {
                        let result = try handler(cqe.pointee)
                        Task {
                            await channel.send(result)
                        }
                    } catch {
                        channel.fail(error)
                    }
                }

                setFlags(sqe, flags: flags, ioprio: ioprio, moreFlags: moreFlags)
                try submit()
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
            retryOnCancel: Bool = false,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> AsyncThrowingChannel<T, Error> {
            let channel = AsyncThrowingChannel<T, Error>()
            try await prepareAndSubmitMultishot(
                opcode,
                fd: fd,
                address: address,
                length: length,
                flags: flags,
                ioprio: ioprio,
                moreFlags: moreFlags,
                retryOnCancel: retryOnCancel,
                handler: handler,
                channel: channel
            )
            return channel
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
        count: Int,
        flags: UInt32 = 0
    ) async throws -> AsyncThrowingChannel<Message, Error> {
        let message = Message(capacity: count)
        return try await message.withUnsafeMutablePointer { pointer in
            try await manager.prepareAndSubmitMultishot(
                UInt8(IORING_OP_RECVMSG),
                fd: fd,
                address: pointer,
                ioprio: AcceptIoPrio.multishot,
                moreFlags: flags
            ) { [message] _ in
                message.copy()
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
            moreFlags: flags,
            retryOnCancel: true
        ) { cqe in
            cqe.res
        }
    }

    func io_uring_op_connect(
        fd: FileDescriptor,
        address: sockaddr_storage
    ) async throws {
        var address = address // FIXME: check lifetime
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_CONNECT),
            fd: fd,
            address: &address,
            offset: Int(address.size)
        ) { [address] _ in
            _ = address
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
        guard try await read(into: &buffer, count: count, from: fd) else {
            return []
        }
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
        try await io_uring_op_recvmsg_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
    }

    func recvmsg(count: Int, from fd: FileDescriptor) async throws -> Message {
        var message = Message(capacity: count)
        try await io_uring_op_recvmsg(fd: fd, message: &message)
        return message
    }

    func sendmsg(_ message: Message, to fd: FileDescriptor) async throws {
        try await io_uring_op_sendmsg(fd: fd, message: message)
    }

    func accept(from fd: FileDescriptor) async throws
        -> AnyAsyncSequence<FileDescriptor>
    {
        try await io_uring_op_multishot_accept(fd: fd).eraseToAnyAsyncSequence()
    }

    func connect(_ fd: FileDescriptor, to address: sockaddr_storage) async throws {
        try await io_uring_op_connect(fd: fd, address: address)
    }

    // FIXME: _XOPEN_SOURCE=500 is implictly defined by liburing.h and is also defined
    // when building IORing (so we can import CIORingShims). However we can't expect
    // depending packages to also define this, and in not doing so we lose the ability
    // to define APIs with `sockaddr_storage` and friends as the clang importer does
    // not know the types defined with and without _XOPEN_SOURCE=500 are equivalent.
    //
    // Provide an escape hatch by encoding sockaddr_storage into [UInt8]. We can provide
    // wrapper APIs in IORingUtils that take the non-X/Open sockaddr layout.

    func connect(_ fd: FileDescriptor, to address: [UInt8]) async throws {
        let ss = try sockaddr_storage(bytes: address)
        try await io_uring_op_connect(fd: fd, address: ss)
    }
}

extension IORing: Equatable {
    public static func == (lhs: IORing, rhs: IORing) -> Bool {
        ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
    }
}

extension IORing: Hashable {
    public nonisolated func hash(into hasher: inout Hasher) {
        ObjectIdentifier(self).hash(into: &hasher)
    }
}
