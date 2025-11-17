//
// Copyright (c) 2023-2025 PADL Software Pty Ltd
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
internal import CIORingShims
internal import CIOURing
import Glibc
import SystemPackage

// MARK: - Submission Protocol

protocol Submission: CustomStringConvertible, Sendable, Hashable {
  associatedtype Result: Sendable

  var core: SubmissionCore<Result> { get }

  func onCompletion(cqe: io_uring_cqe)
  func onCancel(cqe: io_uring_cqe)
}

extension Submission {
  var ring: IORing { core.ring }
  var fd: FileDescriptorRepresentable { core.fd }
  var opcode: IORingOperation { core.opcode }

  nonisolated var description: String {
    "(\(type(of: self)))(fd: \(fd.fileDescriptor), opcode: \(opcode), handler: \(String(describing: core.handler)))"
  }

  func cancel(ring: isolated IORing) throws {
    try core.cancel(ring: ring, onCancel: onCancel)
  }

  func throwingErrno(
    cqe: io_uring_cqe,
    _ body: @escaping @Sendable (_: io_uring_cqe) throws -> Result
  ) throws -> Result {
    try core.throwingErrno(cqe: cqe, body)
  }
}

// MARK: - Submission Core

final class SubmissionCore<T: Sendable>: @unchecked Sendable {
  // reference to owner which owns ring
  let ring: IORing
  /// user-supplied callback to transform a completion queue entry to a result
  let handler: @Sendable (io_uring_cqe) throws -> T
  /// file descriptor, stored so that it is not closed before the completion handler is run
  let fd: FileDescriptorRepresentable
  /// opcode, useful for debugging
  let opcode: IORingOperation
  /// assigned submission queue entry for this object
  private let sqe: UnsafeMutablePointer<io_uring_sqe>
  private var cancellationToken: UnsafeMutableRawPointer?

  private func prepare(
    _ opcode: IORingOperation,
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer?,
    length: CUnsignedInt,
    offset: IORing.Offset
  ) {
    io_uring_prep_rw(
      Int32(opcode.rawValue),
      sqe,
      fd.fileDescriptor,
      address,
      length,
      offset == -1 ? UInt64(bitPattern: -1) : UInt64(offset)
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
    bufferIndexOrGroup: UInt16
  ) {
    io_uring_sqe_set_flags(sqe, UInt32(flags))
    sqe.pointee.ioprio = ioprio
    sqe.pointee.fsync_flags = moreFlags
    sqe.pointee.buf_index = bufferIndexOrGroup // this is an anonymous union
  }

  /// because actors are reentrant, `setBlock()` must be called immediately after
  /// the io_uring assigned a SQE (or, at least before any suspension point)
  /// FIXME: `swift_allocObject()` here appears to be a potential performance issue
  private func setBlock(onCompletion: @escaping (io_uring_cqe) -> ()) {
    cancellationToken = io_uring_sqe_set_block(sqe) { cqe in
      let cqe = cqe.pointee
      onCompletion(cqe)
    }
  }

  func cancel(ring: isolated IORing, onCancel: @escaping (io_uring_cqe) -> ()) throws {
    do {
      precondition(cancellationToken != nil)
      let sqe = try ring.getSqe()
      io_uring_prep_cancel(sqe, cancellationToken, AsyncCancelFlags.userData.rawValue)
      _ = io_uring_sqe_set_block(sqe) { cqe in
        onCancel(cqe.pointee)
      }
      try ring.submit()
    } catch {
      IORing.shared.logger.debug("failed to cancel submission")
      throw error
    }
  }

  init(
    ring: isolated IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: IORing.Offset = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T,
    onCompletion: @escaping (io_uring_cqe) -> ()
  ) throws {
    sqe = try ring.getSqe()
    self.ring = ring
    self.opcode = opcode
    self.fd = fd
    self.handler = handler
    prepare(opcode, sqe: sqe, fd: fd, address: address, length: length, offset: offset)
    setFlags(
      sqe: sqe,
      flags: flags.rawValue,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndexOrGroup
    )
    if let socketAddress {
      try socketAddress.withSockAddr { socketAddress in
        try setSocketAddress(sqe: sqe, socketAddress: socketAddress)
      }
    }
    setBlock(onCompletion: onCompletion)
  }

  func throwingErrno(
    cqe: io_uring_cqe,
    _ body: @escaping @Sendable (_: io_uring_cqe) throws -> T
  ) throws -> T {
    guard cqe.res >= 0 else {
      let error = Errno(rawValue: -cqe.res)
      if error != .brokenPipe {
        IORing.shared.logger
          .debug(
            "completion fileDescriptor: \(fd) opcode: \(opcode) error: \(Errno(rawValue: -cqe.res))"
          )
      }
      throw error
    }
    return try body(cqe)
  }
}

// MARK: - SingleshotSubmission

struct SingleshotSubmission<T: Sendable>: Submission, @unchecked Sendable {
  typealias Result = T

  let core: SubmissionCore<T>
  weak var group: SubmissionGroup<T>?

  private final class ContinuationHolder: @unchecked Sendable {
    var continuation: UnsafeContinuation<T, Error>?
  }

  private let holder: ContinuationHolder

  init(
    ring: isolated IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: IORing.Offset = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    group: SubmissionGroup<T>? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws {
    self.group = group
    holder = ContinuationHolder()

    core = try SubmissionCore(
      ring: ring,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: offset,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndex,
      socketAddress: socketAddress,
      handler: handler,
      onCompletion: { [holder] cqe in
        guard let continuation = holder.continuation else { return }
        do {
          try continuation.resume(returning: handler(cqe))
        } catch {
          continuation.resume(throwing: error)
        }
      }
    )

    if let group {
      await group.enqueue(submission: self)
    }
  }

  private func _submit(ring: isolated IORing) async throws -> T {
    try await withTaskCancellationHandler(operation: {
      try await withUnsafeThrowingContinuation { continuation in
        // guaranteed to run immediately
        holder.continuation = continuation
        if group != nil {
          Task { await ready() }
        } else {
          _ = try? ring.submit()
        }
      }
    }, onCancel: {
      // if the operation supports it, will cause the operation to fail early
      Task { try? await cancel(ring: ring) }
    })
  }

  func submit() async throws -> T {
    try await _submit(ring: ring)
  }

  func onCompletion(cqe: io_uring_cqe) {
    guard let continuation = holder.continuation else { return }
    do {
      try continuation.resume(returning: throwingErrno(cqe: cqe, core.handler))
    } catch {
      continuation.resume(throwing: error)
    }
  }

  func onCancel(cqe: io_uring_cqe) {}
}

struct BufferCount: FileDescriptorRepresentable {
  let count: Int

  var fileDescriptor: Int32 {
    Int32(count)
  }
}

// MARK: - BufferSubmission

final class BufferSubmission<U>: Submission, @unchecked Sendable {
  typealias Result = ()

  let core: SubmissionCore<()>

  nonisolated var count: Int {
    Int(fd.fileDescriptor)
  }

  let size: Int
  let bufferGroup: UInt16
  let buffer: UnsafeMutablePointer<U>
  let deallocate: Bool

  func onCompletion(cqe: io_uring_cqe) {}
  func onCancel(cqe: io_uring_cqe) {}

  private func _submit(ring: isolated IORing) throws {
    try ring.submit()
  }

  func submit() throws {
    try ring.assumeIsolated { ring in
      try _submit(ring: ring)
    }
  }

  nonisolated func bufferPointer(id bufferID: Int) -> UnsafeMutablePointer<U> {
    precondition(bufferID < count)
    return buffer + (bufferID * size)
  }

  init(
    ring: isolated IORing,
    count: Int,
    buffer: UnsafeMutablePointer<U>?,
    size: Int,
    offset: IORing.Offset,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    bufferGroup: UInt16,
    deallocate: Bool
  ) throws {
    guard let buffer else { throw Errno.invalidArgument }

    self.size = size
    self.bufferGroup = bufferGroup
    self.deallocate = deallocate
    self.buffer = buffer

    core = try SubmissionCore(
      ring: ring,
      .provide_buffers,
      fd: BufferCount(count: count),
      address: buffer,
      length: UInt32(size),
      offset: offset,
      flags: flags,
      bufferIndexOrGroup: bufferGroup,
      handler: { _ in },
      onCompletion: { _ in }
    )
  }

  convenience init(
    ring: isolated IORing,
    size: Int,
    count: Int,
    flags: IORing.SqeFlags = IORing.SqeFlags()
  ) throws {
    let bufferGroup = ring.getNextBufferGroup()
    let buffer = UnsafeMutablePointer<U>.allocate(capacity: MemoryLayout<U>.stride * size * count)
    try self.init(
      ring: ring,
      count: count,
      buffer: buffer,
      size: size,
      offset: 0,
      bufferGroup: bufferGroup,
      deallocate: true
    )
  }

  convenience init(
    ring: isolated IORing,
    reproviding bufferID: Int,
    from submission: BufferSubmission<U>
  ) throws {
    guard submission.deallocate == true && bufferID < submission.count
    else { throw Errno.invalidArgument }
    let buffer = submission.bufferPointer(id: bufferID)

    try self.init(
      ring: ring,
      count: 1,
      buffer: buffer,
      size: submission.size,
      offset: IORing.Offset(bufferID),
      bufferGroup: submission.bufferGroup,
      deallocate: false
    )
  }

  convenience init(
    ring: isolated IORing,
    removing count: Int,
    from bufferGroup: UInt16
  ) async throws {
    try self.init(
      ring: ring,
      count: count,
      buffer: nil,
      size: 0,
      offset: 0,
      bufferGroup: bufferGroup,
      deallocate: false
    )
  }

  nonisolated func withUnsafeRawBufferPointer<V>(
    id bufferID: Int,
    _ body: (UnsafeMutableRawBufferPointer) throws -> V
  ) throws -> V {
    guard bufferID < count else { throw Errno.invalidArgument }
    let bufferPointer = UnsafeMutableRawBufferPointer(
      start: bufferPointer(id: bufferID),
      count: size
    )
    return try body(bufferPointer)
  }

  private func _reprovideAndSubmit(ring: isolated IORing, bufferID: Int) throws {
    let submission = try BufferSubmission(ring: ring, reproviding: bufferID, from: self)
    try submission.submit()
  }

  func reprovideAndSubmit(id bufferID: Int) async throws {
    try await _reprovideAndSubmit(ring: ring, bufferID: bufferID)
  }

  deinit {
    if deallocate {
      buffer.deallocate()
    }
  }
}

// MARK: - MultishotSubmission

final class MultishotSubmission<T: Sendable>: Submission, @unchecked Sendable {
  typealias Result = T

  let core: SubmissionCore<T>

  // Shared holder ensures continuation is accessible across resubmissions
  private final class _StreamHolder: Sendable {
    let stream: AsyncThrowingStream<T, Error>
    let continuation: AsyncThrowingStream<T, Error>.Continuation

    init() {
      var continuation: AsyncThrowingStream<T, Error>.Continuation!
      let stream = AsyncThrowingStream<T, Error> {
        continuation = $0
      }
      self.stream = stream
      self.continuation = continuation
    }
  }

  // state for resubmission
  private let address: UnsafeRawPointer?
  private let length: CUnsignedInt
  private let offset: IORing.Offset
  private let flags: IORing.SqeFlags
  private let ioprio: UInt16
  private let moreFlags: UInt32
  private let bufferIndexOrGroup: UInt16
  private let socketAddress: sockaddr_storage?
  private let holder: _StreamHolder

  private init(
    ring: isolated IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: IORing.Offset = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    holder: _StreamHolder,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) throws {
    self.address = address
    self.length = length
    self.offset = offset
    self.flags = flags
    self.ioprio = ioprio
    self.moreFlags = moreFlags
    self.bufferIndexOrGroup = bufferIndexOrGroup
    self.socketAddress = socketAddress
    self.holder = holder

    core = try SubmissionCore(
      ring: ring,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: offset,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndexOrGroup,
      socketAddress: socketAddress,
      handler: handler,
      onCompletion: { [holder] cqe in
        do {
          let result = try handler(cqe)
          holder.continuation.yield(result)
        } catch {
          holder.continuation.finish(throwing: error)
        }
      }
    )
  }

  private convenience init(ring: isolated IORing, _ submission: MultishotSubmission) throws {
    try self.init(
      ring: ring,
      submission.opcode,
      fd: submission.fd,
      address: submission.address,
      length: submission.length,
      offset: submission.offset,
      flags: submission.flags,
      ioprio: submission.ioprio,
      moreFlags: submission.moreFlags,
      bufferIndexOrGroup: submission.bufferIndexOrGroup,
      socketAddress: submission.socketAddress,
      holder: submission.holder,
      handler: submission.core.handler
    )
  }

  convenience init(
    ring: isolated IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: IORing.Offset = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) throws {
    try self.init(
      ring: ring,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: offset,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndexOrGroup,
      socketAddress: socketAddress,
      holder: _StreamHolder(),
      handler: handler
    )
  }

  private func _submit(ring: isolated IORing) throws -> AsyncThrowingStream<T, Error> {
    try ring.submit()
    return holder.stream
  }

  func submit() throws -> AsyncThrowingStream<T, Error> {
    try ring.assumeIsolated { ring in
      try _submit(ring: ring)
    }
  }

  private func resubmit(ring: isolated IORing) {
    do {
      // Create new SQE with same holder (shared stream/continuation)
      let resubmission = try MultishotSubmission(ring: ring, self)
      IORing.shared.logger.debug("resubmitting multishot submission \(resubmission)")
      _ = try resubmission._submit(ring: ring)
    } catch {
      IORing.shared.logger.debug("resubmitting multishot submission failed: \(error)")
      holder.continuation.finish(throwing: error)
    }
  }

  func onCompletion(cqe: io_uring_cqe) {
    do {
      let result = try throwingErrno(cqe: cqe, core.handler)
      holder.continuation.yield(result) // No suspension point!
      if cqe.flags & IORING_CQE_F_MORE == 0 {
        // if IORING_CQE_F_MORE is not set, we need to issue a new request
        // try to do this implictily
        Task { await resubmit(ring: ring) }
      }
      if Task.isCancelled {
        Task { try? await cancel(ring: ring) }
      }
    } catch {
      holder.continuation.finish(throwing: error)
    }
  }

  func onCancel(cqe: io_uring_cqe) {}
}

enum IORingOperation: UInt32 {
  case nop = 0
  case readv
  case writev
  case fsync
  case read_fixed
  case write_fixed
  case poll_add
  case poll_remove
  case sync_file_range
  case sendmsg
  case recvmsg
  case timeout
  case timeout_remove
  case accept
  case async_cancel
  case link_timeout
  case connect
  case fallocate
  case openat
  case close
  case files_update
  case statx
  case read
  case write
  case fadvise
  case madvise
  case send
  case recv
  case openat2
  case epoll_ctl
  case splice
  case provide_buffers
  case remove_buffers
  case tee
  case shutdown
  case renameat
  case unlinkat
  case mkdirat
  case symlinkat
  case linkat
  case msg_ring
  case fsetxattr
  case setxattr
  case fgetxattr
  case getxattr
  case socket
  case uring_cmd
  case send_zc
  case sendmsg_zc
}

struct AsyncCancelFlags: OptionSet {
  typealias RawValue = CInt

  let rawValue: RawValue

  init(rawValue: RawValue) {
    self.rawValue = rawValue
  }

  static let all = AsyncCancelFlags(rawValue: 1 << 0)
  static let fd = AsyncCancelFlags(rawValue: 1 << 1)
  static let any = AsyncCancelFlags(rawValue: 1 << 2)
  static let fdFixed = AsyncCancelFlags(rawValue: 1 << 3)
  static let userData = AsyncCancelFlags(rawValue: 1 << 4)
  static let op = AsyncCancelFlags(rawValue: 1 << 5)
}

// MARK: - Equatable and Hashable conformances

extension SingleshotSubmission: Equatable {
  nonisolated static func == (lhs: SingleshotSubmission, rhs: SingleshotSubmission) -> Bool {
    lhs.core === rhs.core
  }

  nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(core).hash(into: &hasher)
  }
}

extension BufferSubmission: Equatable {
  nonisolated static func == (lhs: BufferSubmission, rhs: BufferSubmission) -> Bool {
    lhs === rhs
  }

  nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}

extension MultishotSubmission: Equatable {
  nonisolated static func == (lhs: MultishotSubmission, rhs: MultishotSubmission) -> Bool {
    lhs === rhs
  }

  nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}
