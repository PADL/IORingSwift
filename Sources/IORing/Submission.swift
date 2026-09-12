//
// Copyright (c) 2023-2026 PADL Software Pty Ltd
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
@_implementationOnly import CIORingShims
@_implementationOnly import CIOURing
import Glibc
import Synchronization
import SystemPackage

/// A submission is allocated per request, and `SingleshotSubmission` is 120 bytes: the largest
/// object glibc serves from a fastbin. A byte more and, once the seven-entry tcache is full,
/// every free consolidates and every malloc searches the unsorted bin, which costs a few percent
/// of a round trip under load. Fields are laid out in declaration order, so keep the small ones
/// together in the padding the `Int32`s leave, and check the size when adding one.
class Submission<T: Sendable>: CustomStringConvertible, @unchecked Sendable {
  /// reference to owner which owns ring
  let ring: IORing
  /// user-supplied callback to transform a completion queue entry to a result
  fileprivate let handler: @Sendable (io_uring_cqe) throws -> T
  /// the file descriptor the request is on
  fileprivate let fileDescriptor: CInt
  /// opcode, useful for debugging
  fileprivate let opcode: IORingOperation
  /// `SingleshotSubmission`'s handoff state (see there)
  fileprivate let handoff = Atomic<UInt8>(0)
  /// whether `retained` is the `SocketAddressStorage` of a send to an address
  private let hasSocketAddress: Bool
  /// what must outlive the request: the descriptor's owner, if it has one, so that it is not
  /// closed before the completion handler runs; for a send to an address, the copy of that
  /// address the kernel reads from the SQE at submission, which holds the owner in turn
  fileprivate let retained: AnyObject?
  private(set) var cancellationToken: UnsafeMutableRawPointer?

  nonisolated var description: String {
    "(\(type(of: self)))(fd: \(fileDescriptor), opcode: \(opcode), handler: \(String(describing: handler)))"
  }

  /// The address a send goes to, if any.
  fileprivate var socketAddress: sockaddr_storage? {
    hasSocketAddress ? unsafeDowncast(retained!, to: SocketAddressStorage.self).pointer
      .pointee : nil
  }

  private func prepare(
    _ opcode: IORingOperation,
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    address: UnsafeRawPointer?,
    length: CUnsignedInt,
    offset: IORing.Offset
  ) {
    io_uring_prep_rw(
      Int32(opcode.rawValue),
      sqe,
      fileDescriptor,
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
  private func setBlock(sqe: UnsafeMutablePointer<io_uring_sqe>) {
    cancellationToken = io_uring_sqe_set_block(sqe) { cqe in
      let cqe = cqe.pointee
      self.onCompletion(cqe: cqe)
    }
  }

  func cancel(ring: isolated IORing) throws {
    do {
      precondition(cancellationToken != nil)
      let sqe = try ring.getSqe()
      io_uring_prep_cancel(sqe, cancellationToken, AsyncCancelFlags.userData.rawValue)
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
    let sqe = try ring.getSqe()
    self.ring = ring
    self.opcode = opcode
    fileDescriptor = fd.fileDescriptor
    self.handler = handler
    if let socketAddress {
      hasSocketAddress = true
      retained = SocketAddressStorage(socketAddress, owner: fd.fileDescriptorOwner)
    } else {
      hasSocketAddress = false
      retained = fd.fileDescriptorOwner
    }
    prepare(opcode, sqe: sqe, address: address, length: length, offset: offset)
    setFlags(
      sqe: sqe,
      flags: flags.rawValue,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndexOrGroup
    )
    if hasSocketAddress {
      // a copy that outlives this call: the kernel reads it at submission, not preparation
      let storage = unsafeDowncast(retained!, to: SocketAddressStorage.self)
      try UnsafeRawPointer(storage.pointer).withMemoryRebound(to: sockaddr.self, capacity: 1) {
        try setSocketAddress(sqe: sqe, socketAddress: $0)
      }
    }
    setBlock(sqe: sqe)
  }

  func onCompletion(cqe: io_uring_cqe) {
    fatalError("must be implemented by concrete class")
  }

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
            "\(type(of: self)) completion fileDescriptor: \(fileDescriptor) opcode: \(opcode) error: \(Errno(rawValue: -cqe.res))"
          )
      }
      throw error
    }
    return try body(cqe)
  }
}

final class SingleshotSubmission<T: Sendable>: Submission<T>, @unchecked Sendable {
  weak var group: SubmissionGroup<T>?

  private typealias Continuation = UnsafeContinuation<T, Error>

  /// How the continuation and the completion meet. A request submitted by `submit()` itself is
  /// `direct`: its continuation is registered and its SQE submitted in one go, so the completion
  /// finds the continuation waiting, and needs nothing more than a load to see that. A linked
  /// request's SQE is prepared when its group is built but its continuation is registered in a
  /// later actor job, and any submit in between flushes the SQE, so the completion can come
  /// first: each side stores its half, then swaps its state into `handoff`, and the side that
  /// finds the other's state already there resumes the continuation. The swap is an atomic
  /// read-modify-write on a line the other thread just wrote, a cross-core stall, which is why
  /// only linked requests pay for it.
  private enum Handoff: UInt8 {
    case direct, idle, waiting, completed
  }

  private var continuation: Continuation?
  /// the completion, when it came first; all a single-shot completion is judged by
  private var completionResult: Int32 = 0
  private var completionFlags: UInt32 = 0

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
      handoff.store(Handoff.idle.rawValue, ordering: .relaxed)
      group.enqueue(submission: self, ring: ring)
    }
  }

  private func _submit(ring: isolated IORing) async throws -> T {
    try await withTaskCancellationHandler(operation: {
      try await withUnsafeThrowingContinuation { continuation in
        // guaranteed to run immediately
        self.continuation = continuation
        if group != nil {
          if handoff.exchange(Handoff.waiting.rawValue, ordering: .acquiringAndReleasing)
            == Handoff.completed.rawValue
          {
            var cqe = io_uring_cqe()
            cqe.res = completionResult
            cqe.flags = completionFlags
            resume(continuation, with: cqe)
          }
          // a group counts every member ready before it submits, this one included
          ready()
        } else {
          // a failed enter leaves the flushed SQE for the next submit to carry, so its
          // completion is still coming; failing the continuation now would resume it twice
          _ = try? ring.submit()
        }
      }
    }, onCancel: {
      // if the operation supports it, will cause the operation to fail early
      Task(executorPreference: ring.executor) { try? await self.cancel(ring: ring) }
    })
  }

  func submit() async throws -> T {
    try await _submit(ring: ring)
  }

  override func onCompletion(cqe: io_uring_cqe) {
    if handoff.load(ordering: .acquiring) == Handoff.direct.rawValue {
      resume(continuation!, with: cqe)
      return
    }
    completionResult = cqe.res
    completionFlags = cqe.flags
    if handoff.exchange(Handoff.completed.rawValue, ordering: .acquiringAndReleasing)
      == Handoff.waiting.rawValue
    {
      resume(continuation!, with: cqe)
    }
  }

  private func resume(_ continuation: Continuation, with cqe: io_uring_cqe) {
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

final class BufferSubmission<U>: Submission<()>, @unchecked Sendable {
  nonisolated var count: Int {
    Int(fileDescriptor)
  }

  let size: Int
  let bufferGroup: UInt16
  let buffer: UnsafeMutablePointer<U>

  override func onCompletion(cqe: io_uring_cqe) {}

  /// a failed submit leaves the SQE flushed and a retry pending, so the buffers are provided
  /// either way, before whatever follows them in the queue
  private func _submit(ring: isolated IORing) {
    _ = try? ring.submit()
  }

  func submit() {
    ring.assumeIsolated { ring in
      _submit(ring: ring)
    }
  }

  nonisolated func bufferPointer(id bufferID: Int) -> UnsafeMutablePointer<U> {
    precondition(bufferID < count)
    return buffer + (bufferID * size)
  }

  private init(
    ring: isolated IORing,
    count: Int,
    buffer: UnsafeMutablePointer<U>?,
    size: Int,
    offset: IORing.Offset,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    bufferGroup: UInt16
  ) throws {
    guard let buffer else { throw Errno.invalidArgument }

    self.size = size
    self.bufferGroup = bufferGroup
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
    ring: isolated IORing,
    size: Int,
    count: Int,
    flags: IORing.SqeFlags = IORing.SqeFlags()
  ) throws {
    let bufferGroup = ring.getNextBufferGroup()
    let buffer = UnsafeMutablePointer<U>.allocate(capacity: size * count)
    try self.init(
      ring: ring,
      count: count,
      buffer: buffer,
      size: size,
      offset: 0,
      bufferGroup: bufferGroup
    )
  }

  convenience init(
    ring: isolated IORing,
    reproviding bufferID: Int,
    from submission: BufferSubmission<U>
  ) throws {
    guard bufferID < submission.count else { throw Errno.invalidArgument }
    let buffer = submission.bufferPointer(id: bufferID)

    try self.init(
      ring: ring,
      count: 1,
      buffer: buffer,
      size: submission.size,
      offset: IORing.Offset(bufferID),
      bufferGroup: submission.bufferGroup
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
      bufferGroup: bufferGroup
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

  /// Take single ownership of one kernel-provided slot from this pool as a
  /// noncopyable `ProvidedBuffer`. See `ProvidedBuffer` for the ownership contract.
  nonisolated func borrowSlot(id bufferID: Int) throws -> ProvidedBuffer<U> {
    guard bufferID < count else { throw Errno.invalidArgument }
    return ProvidedBuffer(submission: self, id: bufferID)
  }

  private func _reprovideAndSubmit(ring: isolated IORing, bufferID: Int) throws {
    let submission = try BufferSubmission(ring: ring, reproviding: bufferID, from: self)
    submission.submit()
  }

  func reprovideAndSubmit(id bufferID: Int) async throws {
    try await _reprovideAndSubmit(ring: ring, bufferID: bufferID)
  }

  func deallocate() {
    buffer.deallocate()
  }
}

/// A single kernel-provided buffer slot, borrowed from a `BufferSubmission` pool.
///
/// The provided-buffer lifecycle is fragile: after a multishot completion hands you a
/// buffer ID, you must copy the payload out and then hand the slot back to the ring
/// (`reprovide`) exactly once — never touching it again, never returning it twice.
/// Previously this was enforced only by a `defer { Task { ... } }` convention.
///
/// `ProvidedBuffer` makes the contract compiler-checked:
///   - `~Copyable`: the slot has exactly one owner, so it cannot be reprovided twice.
///   - `borrowing withUnsafeRawBufferPointer`: payload access is scoped; the compiler
///     stops you using the slot after ownership ends.
///   - `deinit`: the slot is reprovided automatically when the handle goes out of
///     scope (RAII), so a slot can never leak by a forgotten reprovide.
struct ProvidedBuffer<U>: ~Copyable {
  private let submission: BufferSubmission<U>
  let id: Int

  fileprivate init(submission: BufferSubmission<U>, id: Int) {
    self.submission = submission
    self.id = id
  }

  /// Scoped access to the slot's bytes. Only valid for the duration of `body`.
  borrowing func withUnsafeRawBufferPointer<V>(
    _ body: (UnsafeMutableRawBufferPointer) throws -> V
  ) throws -> V {
    try submission.withUnsafeRawBufferPointer(id: id, body)
  }

  deinit {
    // Return the slot to the ring exactly once, when the borrow ends. Copy the
    // fields out of `self` (being destroyed) into the detached task; reprovision
    // still has to hop onto the ring actor, matching the previous behaviour.
    let submission = submission
    let id = id
    Task(executorPreference: submission.ring.executor) {
      try? await submission.reprovideAndSubmit(id: id)
    }
  }
}

final class MultishotSubmission<T: Sendable>: Submission<T>, @unchecked Sendable {
  /// Shared holder ensures continuation is accessible across resubmissions. When the stream
  /// ends, by the consumer leaving it or by the ring finishing it, the request still armed
  /// is cancelled before `onTermination` runs, which is where its buffers are released.
  /// The stream is handed out once and not kept: a consumer letting go of its last copy is
  /// what ends it, which nothing would notice if the holder kept one.
  private final class _StreamHolder: @unchecked Sendable {
    private var stream: AsyncThrowingStream<T, Error>?
    let continuation: AsyncThrowingStream<T, Error>.Continuation
    // ring-isolated: the request currently armed, and whether the stream has ended
    nonisolated(unsafe) weak var current: MultishotSubmission?
    nonisolated(unsafe) var terminated = false

    init(ring: IORing, onTermination: (@Sendable () -> ())?) {
      var continuation: AsyncThrowingStream<T, Error>.Continuation!
      let stream = AsyncThrowingStream<T, Error> { continuation = $0 }
      self.stream = stream
      self.continuation = continuation
      self.continuation.onTermination = { @Sendable _ in
        Task(executorPreference: ring.executor) {
          await self.end(ring: ring)
          onTermination?()
        }
      }
    }

    func takeStream() -> AsyncThrowingStream<T, Error> {
      defer { stream = nil }
      return stream!
    }

    func end(ring: isolated IORing) async {
      terminated = true
      guard let current, let token = current.cancellationToken else { return }
      try? await ring.cancel(userData: token) // gone already, if it says so
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
  /// as given, for the request made again after each completion
  private let fd: FileDescriptorRepresentable
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
    self.fd = fd
    self.holder = holder

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
      handler: submission.handler
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
    handler: @escaping @Sendable (io_uring_cqe) throws -> T,
    onTermination: (@Sendable () -> ())? = nil
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
      holder: _StreamHolder(ring: ring, onTermination: onTermination),
      handler: handler
    )
  }

  /// A failed submit leaves the SQE flushed and a retry pending, so the request is armed
  /// either way; `current` first, so that ending the stream meanwhile cancels this request.
  private func _submit(ring: isolated IORing) {
    holder.current = self
    _ = try? ring.submit()
  }

  func submit() -> AsyncThrowingStream<T, Error> {
    ring.assumeIsolated { ring in
      _submit(ring: ring)
    }
    return holder.takeStream()
  }

  private func resubmit(ring: isolated IORing) {
    guard !holder.terminated else { return }
    let resubmission: MultishotSubmission
    do {
      // Create new SQE with same holder (shared stream/continuation)
      resubmission = try MultishotSubmission(ring: ring, self)
    } catch {
      IORing.shared.logger.debug("resubmitting multishot submission failed: \(error)")
      holder.continuation.finish(throwing: error)
      return
    }
    IORing.shared.logger.debug("resubmitting multishot submission \(resubmission)")
    resubmission._submit(ring: ring)
  }

  override func onCompletion(cqe: io_uring_cqe) {
    // end of stream: nothing was received, and no provided buffer was selected for the handler
    if cqe.flags & IORING_CQE_F_MORE == 0, opcode != .accept, cqe.res == 0 {
      holder.continuation.finish()
      return
    }
    do {
      let result = try throwingErrno(cqe: cqe, handler)
      holder.continuation.yield(result) // No suspension point!
      if cqe.flags & IORING_CQE_F_MORE == 0 {
        Task(executorPreference: ring.executor) { await self.resubmit(ring: self.ring) }
      }
    } catch let error as Errno where error == .noBufferSpace {
      // provided-buffer pool momentarily exhausted: re-arm after in-flight
      // buffers are reprovided rather than ending the stream (drops overflow)
      Task(executorPreference: ring.executor) {
        try? await Task.sleep(nanoseconds: 10_000_000)
        await self.resubmit(ring: self.ring)
      }
    } catch {
      holder.continuation.finish(throwing: error)
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

/// A socket address for a send's SQE, alive as long as the submission: the kernel reads it at
/// submission, after the address given to the send has gone. Holds the file descriptor's owner
/// too, since a submission keeps one object.
final class SocketAddressStorage: @unchecked Sendable {
  let pointer: UnsafeMutablePointer<sockaddr_storage>
  let owner: AnyObject?

  init(_ address: sockaddr_storage, owner: AnyObject?) {
    pointer = .allocate(capacity: 1)
    pointer.initialize(to: address)
    self.owner = owner
  }

  deinit {
    pointer.deallocate()
  }
}

struct AsyncCancelFlags: OptionSet {
  typealias RawValue = CInt

  let rawValue: RawValue

  static let all = AsyncCancelFlags(rawValue: 1 << 0)
  static let fd = AsyncCancelFlags(rawValue: 1 << 1)
  static let any = AsyncCancelFlags(rawValue: 1 << 2)
  static let fdFixed = AsyncCancelFlags(rawValue: 1 << 3)
  static let userData = AsyncCancelFlags(rawValue: 1 << 4)
  static let op = AsyncCancelFlags(rawValue: 1 << 5)
}

extension Submission: Equatable {
  nonisolated static func == (lhs: Submission, rhs: Submission) -> Bool {
    lhs === rhs
  }
}

extension Submission: Hashable {
  nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}
