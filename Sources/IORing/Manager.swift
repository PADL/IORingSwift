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
@_implementationOnly
import CIORingShims
@_implementationOnly
import CIOURing
import Glibc

final class Manager {
    private typealias Continuation = CheckedContinuation<(), Error>

    private var ring: io_uring
    private var eventHandle: UnsafeMutableRawPointer?
    private var pendingSubmissions = Queue<Continuation>()

    fileprivate typealias FixedBuffer = [UInt8]
    private var buffers: [FixedBuffer]?
    private var iov: [iovec]?

    static func logDebug(message: String, functionName: String = #function) {
        debugPrint("IORing.Manager.\(functionName): \(message)")
    }

    init(depth: CUnsignedInt, flags: CUnsignedInt) throws {
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
        fd: IORing.FileDescriptor,
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
        sqe: UnsafeMutablePointer<io_uring_sqe>,
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
        sqe: UnsafeMutablePointer<io_uring_sqe>,
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
        fd: IORing.FileDescriptor,
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
            sqe: sqe,
            flags: flags,
            ioprio: ioprio,
            moreFlags: moreFlags,
            bufferIndex: bufferIndex,
            bufferGroup: bufferGroup
        )
        if let socketAddress {
            try socketAddress.withSockAddr { socketAddress in
                try setSocketAddress(sqe: sqe, socketAddress: socketAddress)
            }
        }
    }

    private func setBlock(
        sqe: UnsafeMutablePointer<io_uring_sqe>,
        operation: SubmissionGroup<some Any>.Operation?,
        handler: @escaping BlockHandler
    ) throws {
        io_uring_sqe_set_block(sqe) {
            // FIXME: this could race before io_uring_cqe_seen() is called, although shouldn't happen if on same actor
            handler($0)
            self.resumePendingSubmission()
        }
        if let operation {
            operation.notifyBlockRegistration()
        } else {
            try submit()
        }
    }

    func submit() throws {
        try Errno.throwingErrno {
            io_uring_submit(&self.ring)
        }
    }

    func notifyBlockRegistration() throws {
        try submit()
    }

    func prepareAndSubmit<T>(
        _ opcode: UInt8,
        fd: IORing.FileDescriptor,
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
            do {
                try setBlock(sqe: sqe, operation: operation) { cqe in
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
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func prepareAndSubmitMultishot<T>(
        _ opcode: UInt8,
        fd: IORing.FileDescriptor,
        address: UnsafeRawPointer?,
        length: CUnsignedInt,
        flags: UInt8,
        ioprio: UInt16,
        moreFlags: UInt32,
        bufferIndex: UInt16,
        bufferGroup: UInt16,
        retryOnCancel: Bool,
        handler: @escaping (io_uring_cqe) throws -> T,
        operation: SubmissionGroup<T>.Operation? = nil,
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

        try setBlock(sqe: sqe, operation: operation) { cqe in
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
                        print(
                            "IORingSwift: multishot io_uring submission failed, are you running a recent enough kernel?"
                        )
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
    }

    func prepareAndSubmitMultishot<T>(
        _ opcode: UInt8,
        fd: IORing.FileDescriptor,
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
        fd: IORing.FileDescriptor,
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
                        operation: nil
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

// MARK: - fixed buffer support

extension Manager {
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
}
