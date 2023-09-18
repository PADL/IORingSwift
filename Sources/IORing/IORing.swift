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

    private class Manager {
        private typealias Continuation = CheckedContinuation<(), Error>

        private var ring: io_uring
        private var notifyThread = pthread_t()
        private var pendingSubmissions = [Continuation]()

        init(depth: CUnsignedInt = 64, flags: CUnsignedInt = 0) throws {
            var ring = io_uring()

            try Errno.throwingErrno {
                io_uring_queue_init(depth, &ring, flags)
            }
            self.ring = ring
            try Errno.throwingErrno {
                io_uring_init_notify(&self.notifyThread, &self.ring)
            }
        }

        deinit {
            cancelPendingSubmissions()
            io_uring_deinit_notify(notifyThread, &ring) // calls pthread_join()
            // FIXME: where are unhandled completion blocks deallocated?
            io_uring_queue_exit(&ring)
        }

        private typealias BlockHandler = (UnsafePointer<io_uring_cqe>) -> ()

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
                submission.resume(throwing: Errno(rawValue: ECANCELED))
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

        private func prepareAndSubmitOnce<T>(
            _ opcode: UInt8,
            sqe: UnsafeMutablePointer<io_uring_sqe>,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            offset: UInt64,
            flags: UInt8,
            ioprio: UInt16,
            moreFlags: UInt32,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> T {
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
                        offset: offset
                    ) { cqe in
                        guard cqe.pointee.res >= 0 else {
                            continuation.resume(throwing: Errno(rawValue: cqe.pointee.res))
                            return
                        }
                        do {
                            try continuation.resume(returning: handler(cqe.pointee))
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                    setFlags(sqe, flags: flags, ioprio: ioprio, moreFlags: moreFlags)
                    try submit()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }

        func prepareAndSubmitMultishot<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer? = nil,
            length: CUnsignedInt = 0,
            offset: UInt64 = 0,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> AsyncThrowingChannel<T, Error> {
            repeat {
                let sqe = io_uring_get_sqe(&ring)

                guard let sqe else {
                    // queue is full, suspend
                    try await suspendPendingSubmission()
                    continue
                }

                let channel = AsyncThrowingChannel<T, Error>()

                prepare(
                    opcode,
                    sqe: sqe,
                    fd: fd,
                    address: address,
                    length: length,
                    offset: offset
                ) { cqe in
                    guard cqe.pointee.res >= 0 else {
                        channel.fail(Errno(rawValue: cqe.pointee.res))
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
            } while true
        }

        func prepareAndSubmit<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            address: UnsafeRawPointer?,
            length: CUnsignedInt,
            offset: Int,
            flags: UInt8 = 0,
            ioprio: UInt16 = 0,
            moreFlags: UInt32 = 0,
            handler: @escaping (io_uring_cqe) throws -> T
        ) async throws -> T {
            repeat {
                do {
                    let sqe = io_uring_get_sqe(&ring)

                    guard let sqe else {
                        // queue is full, suspend
                        try await suspendPendingSubmission()
                        continue
                    }

                    return try await prepareAndSubmitOnce(
                        opcode,
                        sqe: sqe,
                        fd: fd,
                        address: address,
                        length: length,
                        offset: offset == -1 ? UInt64(bitPattern: -1) : UInt64(offset),
                        flags: flags,
                        ioprio: ioprio,
                        moreFlags: moreFlags,
                        handler: handler
                    )
                } catch let error as Errno {
                    if error.rawValue != EAGAIN {
                        throw error
                    }
                }
            } while true
        }

        func prepareAndSubmit<T>(
            _ opcode: UInt8,
            fd: FileDescriptor,
            iovecs: [iovec]? = nil,
            offset: Int,
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
    func io_uring_op_readv(
        fd: FileDescriptor,
        iovecs: [iovec],
        offset: Int
    ) async throws -> Int {
        try await manager.prepareAndSubmit(
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
        try await manager.prepareAndSubmit(
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
    func read(
        into buffer: inout [UInt8],
        count: Int? = nil,
        offset: Int = -1,
        from fd: FileDescriptor
    ) async throws {
        var nread = 0
        let count = count ?? buffer.count

        // handle short reads; breaking reads into blocks should be done by caller
        repeat {
            nread += try await io_uring_op_read(
                fd: fd,
                buffer: &buffer,
                count: count - nread,
                offset: offset == -1 ? -1 : offset + nread
            )
        } while nread < count
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

    func accept(from fd: FileDescriptor) async throws
        -> AsyncThrowingChannel<FileDescriptor, Error>
    {
        try await io_uring_op_multishot_accept(fd: fd)
    }
}
