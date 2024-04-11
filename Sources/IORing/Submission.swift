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
import Glibc
import SystemPackage

@IORingActor
class Submission<T: Sendable>: CustomStringConvertible {
  // reference to owner which owns ring
  let ring: IORing
  /// user-supplied callback to transform a completion queue entry to a result
  fileprivate let handler: @Sendable (io_uring_cqe) throws -> T
  /// file descriptor, stored so that it is not closed before the completion handler is run
  fileprivate let fd: FileDescriptorRepresentable

  /// opcode, useful for debugging
  fileprivate let opcode: IORingOperation
  /// assigned submission queue entry for this object
  private let sqe: UnsafeMutablePointer<io_uring_sqe>
  private var cancellationToken: UnsafeMutableRawPointer?

  public nonisolated var description: String {
    "(\(type(of: self)))(fd: \(fd.fileDescriptor), opcode: \(opcode), handler: \(String(describing: handler)))"
  }

  private func prepare(
    _ opcode: IORingOperation,
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer?,
    length: CUnsignedInt,
    offset: Int
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
  private func setBlock() {
    cancellationToken = io_uring_sqe_set_block(sqe) { cqe in
      let cqe = cqe.pointee
      Task { @IORingActor in
        await self.onCompletion(cqe: cqe)
      }
    }
  }

  func cancel() async throws {
    do {
      precondition(cancellationToken != nil)
      let sqe = try ring.getSqe()
      io_uring_prep_cancel(sqe, cancellationToken, 0)
      _ = io_uring_sqe_set_block(sqe) { cqe in
        self.onCancel(cqe: cqe.pointee)
      }
      try ring.submit()
    } catch {
      IORing.shared.logger.debug("failed to cancel submission \(self)")
      throw error
    }
  }

  init(
    ring: IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: Int = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
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
    setBlock()
  }

  func onCompletion(cqe: io_uring_cqe) async { fatalError("must be implemented by concrete class") }
  func onCancel(cqe: io_uring_cqe) {}

  func throwingErrno(
    cqe: io_uring_cqe,
    _ body: @escaping @Sendable (_: io_uring_cqe) throws -> T
  ) throws -> T {
    guard cqe.res >= 0 else {
      let error = Errno(rawValue: -cqe.res)
      if error != .brokenPipe {
        IORing.shared.logger
          .debug(
            "\(type(of: self)) completion fileDescriptor: \(fd) opcode: \(opcode) error: \(Errno(rawValue: -cqe.res))"
          )
      }
      throw error
    }
    return try body(cqe)
  }
}

final class SingleshotSubmission<T: Sendable>: Submission<T> {
  weak var group: SubmissionGroup<T>?

  private typealias Continuation = CheckedContinuation<T, Error>
  private var continuation: Continuation!

  init(
    ring: IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: Int = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    group: SubmissionGroup<T>? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws {
    self.group = group
    try super.init(
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
      handler: handler
    )
    if let group {
      await group.enqueue(submission: self)
    }
  }

  func submit() async throws -> T {
    try await withTaskCancellationHandler(operation: {
      try await withCheckedThrowingContinuation { continuation in
        // guaranteed to run immediately
        self.continuation = continuation
        Task {
          if group != nil {
            await ready()
          } else {
            try ring.submit()
          }
        }
      }
    }, onCancel: {
      // if the operation supports it, will cause the operation to fail early
      Task { @IORingActor in try await cancel() }
    })
  }

  override func onCompletion(cqe: io_uring_cqe) async {
    do {
      try continuation.resume(returning: throwingErrno(cqe: cqe, handler))
    } catch {
      continuation.resume(throwing: error)
    }
  }
}

struct BufferCount: FileDescriptorRepresentable {
  let count: Int

  var fileDescriptor: Int32 {
    Int32(count)
  }
}

final class BufferSubmission<U>: Submission<()> {
  nonisolated var count: Int {
    Int(fd.fileDescriptor)
  }

  let size: Int
  let bufferGroup: UInt16
  let buffer: UnsafeMutablePointer<U>
  let deallocate: Bool

  override func onCompletion(cqe: io_uring_cqe) async {}

  func submit() throws {
    try ring.submit()
  }

  nonisolated func bufferPointer(id bufferID: Int) -> UnsafeMutablePointer<U> {
    precondition(bufferID < count)
    return buffer + (bufferID * size)
  }

  init(
    ring: IORing,
    count: Int,
    buffer: UnsafeMutablePointer<U>?,
    size: Int,
    offset: Int,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    bufferGroup: UInt16,
    deallocate: Bool
  ) throws {
    guard let buffer else { throw Errno.invalidArgument }

    self.size = size
    self.bufferGroup = bufferGroup
    self.deallocate = deallocate
    self.buffer = buffer

    try super.init(
      ring: ring,
      .provide_buffers,
      fd: BufferCount(count: count),
      address: buffer,
      length: UInt32(size),
      offset: offset,
      flags: flags,
      bufferIndexOrGroup: bufferGroup
    ) { _ in }
  }

  convenience init(
    ring: IORing,
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

  convenience init(reproviding bufferID: Int, from submission: BufferSubmission<U>) async throws {
    guard submission.deallocate == true && bufferID < submission.count
    else { throw Errno.invalidArgument }
    let buffer = submission.bufferPointer(id: bufferID)

    try self.init(
      ring: submission.ring,
      count: 1,
      buffer: buffer,
      size: submission.size,
      offset: bufferID,
      bufferGroup: submission.bufferGroup,
      deallocate: false
    )
  }

  convenience init(ring: IORing, removing count: Int, from bufferGroup: UInt16) async throws {
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

  func reprovideAndSubmit(id bufferID: Int) async throws {
    let submission = try await BufferSubmission(reproviding: bufferID, from: self)
    try submission.submit()
  }

  deinit {
    if deallocate {
      buffer.deallocate()
    }
  }
}

final class MultishotSubmission<T: Sendable>: Submission<T> {
  private let channel = AsyncThrowingChannel<T, Error>()

  // state for resubmission
  private let address: UnsafeRawPointer?
  private let length: CUnsignedInt
  private let offset: Int
  private let flags: IORing.SqeFlags
  private let ioprio: UInt16
  private let moreFlags: UInt32
  private let bufferIndexOrGroup: UInt16
  private let socketAddress: sockaddr_storage?

  override init(
    ring: IORing,
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: Int = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
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

    try super.init(
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
      handler: handler
    )
  }

  private convenience init(_ submission: MultishotSubmission) throws {
    try self.init(
      ring: submission.ring,
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
      handler: submission.handler
    )
  }

  func submit() throws -> AsyncThrowingChannel<T, Error> {
    try ring.submit()
    return channel
  }

  private func resubmit() {
    do {
      // this will allocate a new SQE with the same channel, fd, opcode and handler
      let resubmission = try MultishotSubmission(self)
      IORing.shared.logger.debug("resubmitting multishot submission \(resubmission)")
      _ = try resubmission.submit()
    } catch {
      IORing.shared.logger.debug("resubmitting multishot submission failed: \(error)")
      channel.fail(error)
    }
  }

  override func onCompletion(cqe: io_uring_cqe) async {
    do {
      let result = try throwingErrno(cqe: cqe, handler)
      await channel.send(result)
      if cqe.flags & IORING_CQE_F_MORE == 0 {
        // if IORING_CQE_F_MORE is not set, we need to issue a new request
        // try to do this implictily
        resubmit()
      }
      if Task.isCancelled {
        try await cancel()
      }
    } catch {
      channel.fail(error)
    }
  }
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
}

extension Submission: Equatable {
  public nonisolated static func == (lhs: Submission, rhs: Submission) -> Bool {
    ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
  }
}

extension Submission: Hashable {
  public nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}
