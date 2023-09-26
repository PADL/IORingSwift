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

public actor IORing: CustomStringConvertible {
    public static let shared = try? IORing()

    public static let IOSqeFixedFile: UInt8 = (1 << IOSQE_FIXED_FILE_BIT)
    public static let IOSqeIODrain: UInt8 = (1 << IOSQE_IO_DRAIN_BIT)
    public static let IOSqeIOLink: UInt8 = (1 << IOSQE_IO_LINK_BIT)
    public static let IOSqeIOHardLink: UInt8 = (1 << IOSQE_IO_HARDLINK_BIT)
    public static let IOSqeAsync: UInt8 = (1 << IOSQE_ASYNC_BIT)
    public static let IOSqeBufferSelect: UInt8 = (1 << IOSQE_BUFFER_SELECT_BIT)

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

    // FIXME: should we make default depth >1?
    public init(depth: Int = 1, flags: UInt32 = 0) throws {
        manager = try Manager(depth: CUnsignedInt(depth), flags: flags)
    }

    func submit() throws {
        try manager.submit()
    }

    public nonisolated var description: String {
        withUnsafePointer(to: self) { pointer in
            "\(type(of: self))(\(pointer))"
        }
    }

    fileprivate final class Manager {
        private typealias Continuation = CheckedContinuation<(), Error>

        private var ring: io_uring
        private var eventHandle: UnsafeMutableRawPointer?
        private var pendingSubmissions = Queue<Continuation>()

        let depth: CUnsignedInt

        static func logDebug(message: String, functionName: String = #function) {
            debugPrint("IORing.Manager.\(functionName): \(message)")
        }

        init(depth: CUnsignedInt = 64, flags: CUnsignedInt = 0) throws {
            var ring = io_uring()

            self.depth = depth
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
            if hasRegisteredBuffers {
                try? unregisterBuffers()
            }
            // FIXME: where are unhandled completion blocks deallocated?
            io_uring_queue_exit(&ring)
        }

        private typealias BlockHandler = (UnsafePointer<io_uring_cqe>) -> ()

        private var sqe: UnsafeMutablePointer<io_uring_sqe> {
            get throws {
                guard let sqe = io_uring_get_sqe(&ring) else {
                    throw Errno.resourceTemporarilyUnavailable
                }
                return sqe
            }
        }

        private var asyncSqe: UnsafeMutablePointer<io_uring_sqe> {
            get async throws {
                repeat {
                    do {
                        guard let sqe = try? sqe else {
                            // queue is full, suspend
                            try await suspendPendingSubmission()
                            continue
                        }

                        return sqe
                    } catch let error as Errno {
                        switch error {
                        case .resourceTemporarilyUnavailable:
                            fallthrough
                        // FIXME: should we always retry on cancel?
                        case .canceled:
                            break
                        default:
                            throw error
                        }
                    }
                } while true
            }
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
                continuation.resume(throwing: Errno.canceled)
            }
        }

        private func prepare(
            _ opcode: UInt8,
            sqe: UnsafeMutablePointer<io_uring_sqe>,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            offset: UInt64
        ) {
            io_uring_prep_rw(
                CInt(opcode),
                sqe,
                fd,
                address,
                length,
                offset
            )
        }

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
            moreFlags: UInt32,
            bufferIndex: UInt16,
            bufferGroup: UInt16
        ) {
            io_uring_sqe_set_flags(sqe, UInt32(flags))
            sqe.pointee.ioprio = ioprio
            sqe.pointee.fsync_flags = moreFlags
            sqe.pointee.buf_index = bufferIndex
            sqe.pointee.buf_group = bufferGroup
        }

        private func prepareAndSetFlags(
            _ opcode: UInt8,
            sqe: UnsafeMutablePointer<io_uring_sqe>,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            offset: Int = 0,
            flags: UInt8,
            ioprio: UInt16,
            moreFlags: UInt32,
            bufferIndex: UInt16,
            bufferGroup: UInt16,
            socketAddress: sockaddr_storage? = nil
        ) throws {
            prepare(
                opcode,
                sqe: sqe,
                fd: fd,
                address: address,
                length: length,
                offset: offset == -1 ? UInt64(bitPattern: -1) : UInt64(offset)
            )
            setFlags(
                sqe,
                flags: flags,
                ioprio: ioprio,
                moreFlags: moreFlags,
                bufferIndex: bufferIndex,
                bufferGroup: bufferGroup
            )
            if let socketAddress {
                try socketAddress.withSockAddr { socketAddress in
                    try setSocketAddress(sqe, socketAddress: socketAddress)
                }
            }
        }

        private func setBlock(
            _ sqe: UnsafeMutablePointer<io_uring_sqe>,
            handler: @escaping BlockHandler
        ) {
            io_uring_sqe_set_block(sqe) {
                // FIXME: this could race before io_uring_cqe_seen() is called, although shouldn't happen if on same actor
                handler($0)
                self.resumePendingSubmission()
            }
        }

        func submit() throws {
            try Errno.throwingErrno {
                io_uring_submit(&self.ring)
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
            bufferIndex: UInt16 = 0,
            bufferGroup: UInt16 = 0,
            socketAddress: sockaddr_storage? = nil,
            operation: SubmissionGroup<T>.Operation? = nil,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> T {
            let sqe = try await asyncSqe

            try prepareAndSetFlags(
                opcode,
                sqe: sqe,
                fd: fd,
                address: address,
                length: length,
                offset: offset,
                flags: flags,
                ioprio: ioprio,
                moreFlags: moreFlags,
                bufferIndex: bufferIndex,
                bufferGroup: bufferGroup,
                socketAddress: socketAddress
            )

            return try await withCheckedThrowingContinuation { (
                continuation: CheckedContinuation<
                    T,
                    Error
                >
            ) in
                setBlock(sqe) { cqe in
                    guard cqe.pointee.res >= 0 else {
                        Self
                            .logDebug(
                                message: "completion failed: \(Errno(rawValue: cqe.pointee.res))"
                            )
                        continuation.resume(throwing: Errno(rawValue: cqe.pointee.res))
                        return
                    }
                    do {
                        try continuation.resume(returning: handler(cqe.pointee))
                    } catch {
                        Self.logDebug(message: "handler failed: \(error)")
                        continuation.resume(throwing: error)
                    }
                }
                if let operation {
                    operation.notifyBlockRegistration()
                } else {
                    do { try submit() }
                    catch { continuation.resume(throwing: error) }
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
            bufferIndex: UInt16,
            bufferGroup: UInt16,
            retryOnCancel: Bool,
            handler: @escaping (io_uring_cqe) throws -> T,
            channel: AsyncThrowingChannel<T, Error>
        ) async throws {
            let sqe = try await asyncSqe

            try prepareAndSetFlags(
                opcode,
                sqe: sqe,
                fd: fd,
                address: address,
                length: length,
                flags: flags,
                ioprio: ioprio,
                moreFlags: moreFlags,
                bufferIndex: bufferIndex,
                bufferGroup: bufferGroup,
                socketAddress: nil
            )

            setBlock(sqe) { cqe in
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
                                    bufferIndex: bufferIndex,
                                    bufferGroup: bufferGroup,
                                    retryOnCancel: retryOnCancel,
                                    handler: handler,
                                    channel: channel
                                )
                            } catch {
                                channel.fail(error)
                            }
                        }
                    } else {
                        Self
                            .logDebug(
                                message: "completion failed: \(Errno(rawValue: cqe.pointee.res))"
                            )
                        if cqe.pointee.res == -EINVAL {
                            print("IORingSwift: multishot io_uring submission failed, are you running a recent enough kernel?")
                        }
                        channel.fail(Errno(rawValue: cqe.pointee.res))
                    }
                    return
                }
                do {
                    let result = try handler(cqe.pointee)
                    Task {
                        await channel.send(result)
                    }
                } catch {
                    Self.logDebug(message: "handler failed: \(error)")
                    channel.fail(error)
                }
            }
            try submit()
        }

        func prepareAndSubmitMultishot<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer? = nil,
            length: CUnsignedInt = 0,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            bufferIndex: UInt16 = 0,
            bufferGroup: UInt16 = 0,
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
                bufferIndex: bufferIndex,
                bufferGroup: bufferGroup,
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
                            moreFlags: moreFlags,
                            operation: nil as SubmissionGroup<()>.Operation?
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

        // MARK: - fixed buffer support

        private typealias FixedBuffer = [UInt8]
        private var buffers: [FixedBuffer]?
        private var iov: [iovec]?

        var hasRegisteredBuffers: Bool {
            iov != nil
        }

        var registeredBuffersCount: Int {
            get throws {
                guard let iov else {
                    throw Errno.invalidArgument
                }

                return iov.count
            }
        }

        var registeredBuffersSize: Int {
            get throws {
                guard let buffers else {
                    throw Errno.invalidArgument
                }

                return buffers[0].count
            }
        }

        // FIXME: currently only supporting a single buffer size
        func registerBuffers(count: Int, size: Int) throws {
            guard buffers == nil else {
                throw Errno.fileExists
            }

            guard count > 0, size > 0 else {
                throw Errno.invalidArgument
            }

            var buffers = [FixedBuffer](repeating: [UInt8](repeating: 0, count: size), count: count)
            var iov = [iovec](repeating: iovec(), count: count)

            for i in 0..<count {
                buffers[i].withUnsafeMutableBufferPointer { pointer in
                    iov[i].iov_base = UnsafeMutableRawPointer(pointer.baseAddress)
                    iov[i].iov_len = size
                }
            }

            try Errno.throwingErrno {
                io_uring_register_buffers(&self.ring, iov, UInt32(iov.count))
            }

            self.buffers = buffers
            self.iov = iov
        }

        func unregisterBuffers() throws {
            if !hasRegisteredBuffers {
                throw Errno.invalidArgument
            }

            try Errno.throwingErrno {
                io_uring_unregister_buffers(&self.ring)
            }

            buffers = nil
            iov = nil
        }

        func validateFixedBuffer(at index: UInt16, length: Int, offset: Int) throws {
            guard let iov, index < iov.count else {
                throw Errno.invalidArgument
            }

            guard offset + length <= iov[Int(index)].iov_len else {
                throw Errno.outOfRange
            }
        }

        func unsafePointerForFixedBuffer(at index: UInt16, offset: Int) -> UnsafeMutableRawPointer {
            precondition(hasRegisteredBuffers)
            precondition(try! index < registeredBuffersCount)

            return iov![Int(index)].iov_base! + offset
        }

        func buffer(at index: UInt16, range: Range<Int>) -> ArraySlice<UInt8> {
            precondition(hasRegisteredBuffers)
            precondition(try! index < registeredBuffersCount)
            precondition(try! range.upperBound <= registeredBuffersSize)

            return buffers![Int(index)][range]
        }

        func withFixedBufferSlice<T>(
            at index: UInt16,
            range: Range<Int>,
            _ body: (inout ArraySlice<UInt8>) throws -> T
        ) rethrows -> T {
            precondition(hasRegisteredBuffers)
            precondition(try! index < registeredBuffersCount)
            precondition(try! range.upperBound <= registeredBuffersSize)

            return try body(&buffers![Int(index)][range])
        }

        func withUnsafeMutableBytesOfFixedBuffer<T>(
            at index: UInt16,
            length: Int,
            offset: Int = 0,
            _ body: (UnsafeMutableRawBufferPointer) throws -> T
        ) rethrows -> T {
            precondition(hasRegisteredBuffers)
            precondition(try! index < registeredBuffersCount)
            precondition(try! offset + length <= registeredBuffersSize)

            return try buffers![Int(index)][offset..<offset + length]
                .withUnsafeMutableBytes { bytes in
                    try body(bytes)
                }
        }
    }

    fileprivate func withSubmissionGroup<T>(@_inheritActorContext _ body: (
        SubmissionGroup<T>
    ) async throws -> ()) async throws -> [T] {
        let submissionGroup = try await SubmissionGroup<T>(ring: self)
        try await body(submissionGroup)
        return try await submissionGroup.finish()
    }
}

// MARK: - operation wrappers

private extension IORing {
    func io_uring_op_cancel(
        fd: FileDescriptor,
        link: Bool = false,
        flags: UInt32 = 0
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_ASYNC_CANCEL),
            fd: fd,
            flags: link ? IORing.IOSqeIOLink : 0,
            moreFlags: flags
        ) { _ in }
    }

    func io_uring_op_close(
        fd: FileDescriptor,
        link: Bool = false
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_CLOSE),
            fd: fd,
            flags: link ? IORing.IOSqeIOLink : 0
        ) { _ in }
    }

    func io_uring_op_readv(
        fd: FileDescriptor,
        iovecs: [iovec],
        offset: Int,
        link: Bool = false
    ) async throws -> Int {
        try await manager.prepareAndSubmitIovec(
            UInt8(IORING_OP_READV),
            fd: fd,
            iovecs: iovecs,
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0
        ) { cqe in
            Int(cqe.res)
        }
    }

    func io_uring_op_writev(
        fd: FileDescriptor,
        iovecs: [iovec],
        count: Int,
        offset: Int,
        link: Bool = false
    ) async throws -> Int {
        try await manager.prepareAndSubmitIovec(
            UInt8(IORING_OP_WRITEV),
            fd: fd,
            iovecs: iovecs,
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0
        ) { cqe in
            Int(cqe.res)
        }
    }

    func io_uring_op_read(
        fd: FileDescriptor,
        buffer: inout [UInt8],
        count: Int,
        offset: Int,
        link: Bool = false
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_READ),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(count),
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0
        ) { [buffer] cqe in
            _ = buffer
            return Int(cqe.res)
        }
    }

    func io_uring_op_write(
        fd: FileDescriptor,
        buffer: [UInt8],
        count: Int,
        offset: Int,
        link: Bool = false
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_WRITE),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(count),
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0
        ) { [buffer] cqe in
            _ = buffer
            return Int(cqe.res)
        }
    }

    // FIXME: support partial reads
    func io_uring_op_read_fixed(
        fd: FileDescriptor,
        count: Int,
        offset: Int, // offset into the file we are reading
        bufferIndex: UInt16,
        bufferOffset: Int, // offset into the fixed buffer
        link: Bool = false,
        operation: SubmissionGroup<Int>.Operation? = nil
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_READ_FIXED),
            fd: fd,
            address: manager.unsafePointerForFixedBuffer(at: bufferIndex, offset: bufferOffset),
            length: CUnsignedInt(count),
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0,
            bufferIndex: bufferIndex,
            operation: operation
        ) { cqe in
            Int(cqe.res)
        }
    }

    // FIXME: support partial writes
    func io_uring_op_write_fixed(
        fd: FileDescriptor,
        count: Int,
        offset: Int, // offset into the file we are writing
        bufferIndex: UInt16,
        bufferOffset: Int, // offset into the fixed buffer
        link: Bool = false,
        operation: SubmissionGroup<Int>.Operation? = nil
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_WRITE_FIXED),
            fd: fd,
            address: manager.unsafePointerForFixedBuffer(at: bufferIndex, offset: bufferOffset),
            length: CUnsignedInt(count),
            offset: offset,
            flags: link ? IORing.IOSqeIOLink : 0,
            bufferIndex: bufferIndex,
            operation: operation
        ) { cqe in
            Int(cqe.res)
        }
    }

    func io_uring_op_send(
        fd: FileDescriptor,
        buffer: [UInt8],
        to socketAddress: sockaddr_storage? = nil,
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_SEND),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(buffer.count),
            offset: 0,
            flags: link ? IORing.IOSqeIOLink : 0,
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
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws {
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_RECV),
            fd: fd,
            address: buffer,
            length: CUnsignedInt(buffer.count),
            offset: 0,
            flags: link ? IORing.IOSqeIOLink : 0,
            moreFlags: flags
        ) { [buffer] _ in
            _ = buffer
            return ()
        }
    }

    func io_uring_op_recv_multishot(
        fd: FileDescriptor,
        count: Int,
        link: Bool = false
    ) async throws -> AsyncThrowingChannel<[UInt8], Error> {
        // FIXME: check this will be captured or do we need to
        var buffer = [UInt8](repeating: 0, count: count)
        return try await manager.prepareAndSubmitMultishot(
            UInt8(IORING_OP_RECV),
            fd: fd,
            address: &buffer[0],
            length: CUnsignedInt(count),
            flags: link ? IORing.IOSqeIOLink : 0,
            ioprio: RecvSendIoPrio.multishot
        ) { [buffer] _ in
            buffer
        }
    }

    func io_uring_op_recvmsg(
        fd: FileDescriptor,
        message: inout Message,
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws {
        try await message.withUnsafeMutablePointer { pointer in
            try await manager.prepareAndSubmit(
                UInt8(IORING_OP_RECVMSG),
                fd: fd,
                address: pointer,
                length: 1,
                offset: 0,
                flags: link ? IORing.IOSqeIOLink : 0,
                moreFlags: flags
            ) { _ in }
        }
    }

    func io_uring_op_recvmsg_multishot(
        fd: FileDescriptor,
        count: Int,
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws -> AsyncThrowingChannel<Message, Error> {
        let message = Message(capacity: count)
        return try await message.withUnsafeMutablePointer { pointer in
            try await manager.prepareAndSubmitMultishot(
                UInt8(IORING_OP_RECVMSG),
                fd: fd,
                address: pointer,
                flags: link ? IORing.IOSqeIOLink : 0,
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
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws {
        try await message.withUnsafePointer { pointer in
            try await manager.prepareAndSubmit(
                UInt8(IORING_OP_SENDMSG),
                fd: fd,
                address: pointer,
                length: 1,
                offset: 0,
                flags: link ? IORing.IOSqeIOLink : 0,
                moreFlags: flags
            ) { _ in }
        }
    }

    func io_uring_op_accept(
        fd: FileDescriptor,
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws -> (FileDescriptor, sockaddr_storage) {
        var ss = sockaddr_storage()
        return try await manager.prepareAndSubmit(
            UInt8(IORING_OP_ACCEPT),
            fd: fd,
            address: &ss,
            length: CUnsignedInt(MemoryLayout<sockaddr_storage>.size),
            offset: 0,
            flags: link ? IORing.IOSqeIOLink : 0,
            moreFlags: flags
        ) { [ss] cqe in
            _ = ss
            return (cqe.res, ss)
        }
    }

    func io_uring_op_multishot_accept(
        fd: FileDescriptor,
        flags: UInt32 = 0,
        link: Bool = false
    ) async throws -> AsyncThrowingChannel<FileDescriptor, Error> {
        try await manager.prepareAndSubmitMultishot(
            UInt8(IORING_OP_ACCEPT),
            fd: fd,
            flags: link ? IORing.IOSqeIOLink : 0,
            ioprio: AcceptIoPrio.multishot,
            moreFlags: flags,
            retryOnCancel: true
        ) { cqe in
            cqe.res
        }
    }

    func io_uring_op_connect(
        fd: FileDescriptor,
        address: sockaddr_storage,
        link: Bool = false
    ) async throws {
        var address = address // FIXME: check lifetime
        try await manager.prepareAndSubmit(
            UInt8(IORING_OP_CONNECT),
            fd: fd,
            address: &address,
            offset: Int(address.size),
            flags: link ? IORing.IOSqeIOLink : 0
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

    func receive(count: Int, from fd: FileDescriptor) async throws -> AnyAsyncSequence<[UInt8]> {
        try await io_uring_op_recv_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
    }

    func receive(count: Int, from fd: FileDescriptor) async throws -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        try await io_uring_op_recv(fd: fd, buffer: &buffer)
        return buffer
    }

    func send(_ data: [UInt8], to fd: FileDescriptor) async throws {
        try await io_uring_op_send(fd: fd, buffer: data)
    }

    func receiveMessages(
        count: Int,
        from fd: FileDescriptor
    ) async throws -> AnyAsyncSequence<Message> {
        try await io_uring_op_recvmsg_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
    }

    func receiveMessage(count: Int, from fd: FileDescriptor) async throws -> Message {
        var message = Message(capacity: count)
        try await io_uring_op_recvmsg(fd: fd, message: &message)
        return message
    }

    func send(message: Message, to fd: FileDescriptor) async throws {
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

    func registerFixedBuffers(count: Int, size: Int) throws {
        try manager.registerBuffers(count: count, size: size)
    }

    func unregisterFixedBuffers() async throws {
        try manager.unregisterBuffers()
    }

    var hasRegisteredFixedBuffers: Bool {
        manager.hasRegisteredBuffers
    }

    func readFixed(
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        bufferOffset: Int = 0,
        from fd: FileDescriptor
    ) async throws -> ArraySlice<UInt8> {
        let count = try count ?? manager.registeredBuffersSize

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

        let nwritten = try await io_uring_op_read_fixed(
            fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
            bufferOffset: bufferOffset
        )

        return manager.buffer(at: bufferIndex, range: bufferOffset..<(bufferOffset + nwritten))
    }

    func readFixed(
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        bufferOffset: Int = 0,
        from fd: FileDescriptor,
        _ body: (inout ArraySlice<UInt8>) throws -> ()
    ) async throws {
        let count = try count ?? manager.registeredBuffersSize

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

        let nwritten = try await io_uring_op_read_fixed(
            fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
            bufferOffset: bufferOffset
        )

        try manager.withFixedBufferSlice(
            at: bufferIndex,
            range: bufferOffset..<(bufferOffset + nwritten),
            body
        )
    }

    func writeFixed(
        _ data: ArraySlice<UInt8>,
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        bufferOffset: Int = 0,
        to fd: FileDescriptor
    ) async throws -> Int {
        let count = count ?? data.endIndex - data.startIndex

        guard count < data.endIndex - data.startIndex else {
            throw Errno.invalidArgument
        }

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

        let address = manager.unsafePointerForFixedBuffer(at: bufferIndex, offset: bufferOffset)

        data[data.startIndex..<data.endIndex].withUnsafeBytes { bytes in
            _ = memcpy(address, UnsafeRawPointer(bytes.baseAddress!), count)
        }

        return try await io_uring_op_write_fixed(
            fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
            bufferOffset: bufferOffset
        )
    }

    func writeFixed(
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        bufferOffset: Int = 0,
        to fd: FileDescriptor,
        _ body: (ArraySlice<UInt8>) throws -> ()
    ) async throws -> Int {
        let count = try count ?? manager.registeredBuffersSize

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

        try manager.withFixedBufferSlice(
            at: bufferIndex,
            range: bufferOffset..<(bufferOffset + count)
        ) {
            try body($0)
        }

        return try await io_uring_op_write_fixed(
            fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
            bufferOffset: bufferOffset
        )
    }

    func writeReadFixed(
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        bufferOffset: Int = 0,
        fd: FileDescriptor,
        _ body: (inout ArraySlice<UInt8>) throws -> ()
    ) async throws {
        let count = try count ?? manager.registeredBuffersSize

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

        try manager.withFixedBufferSlice(
            at: bufferIndex,
            range: bufferOffset..<(bufferOffset + count),
            body
        )

        let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
            await group.enqueue { [self] operation in
                try await io_uring_op_write_fixed(
                    fd: fd,
                    count: count,
                    offset: offset,
                    bufferIndex: bufferIndex,
                    bufferOffset: 0,
                    operation: operation
                )
            }
            await group.enqueue { [self] operation in
                try await io_uring_op_read_fixed(
                    fd: fd,
                    count: count,
                    offset: offset,
                    bufferIndex: bufferIndex,
                    bufferOffset: 0,
                    link: true,
                    operation: operation
                )
            }
        }

        guard result.count == 2, result[0] == result[1] else {
            throw Errno.resourceTemporarilyUnavailable
        }
    }

    func copy(
        count: Int? = nil,
        offset: Int = -1,
        bufferIndex: UInt16,
        from fd1: FileDescriptor,
        to fd2: FileDescriptor
    ) async throws {
        let count = try count ?? manager.registeredBuffersSize

        try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: 0)

        let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
            await group.enqueue { [self] operation in
                try await io_uring_op_read_fixed(
                    fd: fd1,
                    count: count,
                    offset: offset,
                    bufferIndex: bufferIndex,
                    bufferOffset: 0,
                    link: true,
                    operation: operation
                )
            }
            await group.enqueue { [self] operation in
                try await io_uring_op_write_fixed(
                    fd: fd2,
                    count: count,
                    offset: offset,
                    bufferIndex: bufferIndex,
                    bufferOffset: 0,
                    operation: operation
                )
            }
        }

        guard result.count == 2, result[0] == result[1] else {
            throw Errno.resourceTemporarilyUnavailable
        }
    }
}

// MARK: - conformances

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
