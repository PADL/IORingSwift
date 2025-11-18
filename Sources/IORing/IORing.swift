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
@_implementationOnly import CIORingShims
@_implementationOnly import CIOURing
import Glibc
import Logging
import SystemPackage

extension io_uring: @retroactive @unchecked Sendable {}

// MARK: - actor

public actor IORing: CustomStringConvertible {
  public typealias Offset = Int64 // for 64-bit offsetes on 32-bit platforms

  public nonisolated static let shared = try! IORing(entries: nil, flags: [], shared: true)

  private nonisolated static let DefaultIORingQueueEntries = 128

  private var ring: io_uring
  private var cqHandle: UInt = 0

  private var fixedBuffers: FixedBuffer?
  private var nextBufferGroup: UInt16 = 1
  private let entries: Int
  private let ringFd: Int32

  let logger = Logger(label: "com.padl.IORing")

  private final class FixedBuffer {
    fileprivate let count: Int
    fileprivate let size: Int
    private var storage: UnsafeMutablePointer<UInt8>
    private var iovecs: UnsafeMutableBufferPointer<iovec>

    var iov: UnsafeMutablePointer<iovec> {
      iovecs.baseAddress!
    }

    init(count: Int, size: Int) {
      self.count = count // number of buffers
      self.size = size // size of each buffer

      // use allocate() so we have a stable address, but allocate in a contiguous block
      storage = .allocate(capacity: size * count)
      storage.initialize(to: 0)

      iovecs = .allocate(capacity: count)
      iovecs.initialize(repeating: iovec())

      for i in 0..<count {
        iovecs[i].iov_base = UnsafeMutableRawPointer(storage + i * size)
        iovecs[i].iov_len = size
      }
    }

    func validate(
      count: Int,
      bufferIndex: UInt16,
      bufferOffset: Int
    ) throws {
      guard Int(bufferIndex) < self.count, count + bufferOffset <= size else {
        throw Errno.outOfRange
      }
    }

    func unsafeMutablePointer(
      at bufferIndex: UInt16,
      range: Range<Int>
    ) throws -> UnsafeMutableBufferPointer<UInt8> {
      try unsafeMutablePointer(
        at: bufferIndex,
        count: range.upperBound - range.lowerBound,
        bufferOffset: range.lowerBound
      )
    }

    func unsafeMutablePointer(
      at bufferIndex: UInt16,
      count: Int,
      bufferOffset: Int
    ) throws -> UnsafeMutableBufferPointer<UInt8> {
      try validate(count: count, bufferIndex: bufferIndex, bufferOffset: bufferOffset)

      return UnsafeMutableBufferPointer(
        start: iovecs[Int(bufferIndex)].iov_base
          .bindMemory(to: UInt8.self, capacity: size) + bufferOffset,
        count: count
      )
    }

    func unsafeMutableRawPointer(
      at bufferIndex: UInt16,
      count: Int,
      bufferOffset: Int
    ) throws -> UnsafeMutableRawPointer {
      try UnsafeMutableRawPointer(
        unsafeMutablePointer(at: bufferIndex, count: count, bufferOffset: bufferOffset)
          .baseAddress!
      )
    }

    deinit {
      storage.deallocate()
      iovecs.deallocate()
    }
  }

  struct SqeFlags: OptionSet, Sendable {
    typealias RawValue = UInt8

    let rawValue: RawValue

    init(rawValue: RawValue) {
      self.rawValue = rawValue
    }

    init(link: Bool) {
      if link {
        self = SqeFlags.ioLink
      } else {
        self = SqeFlags()
      }
    }

    static let fixedFile = SqeFlags(rawValue: 1 << 0) // IOSQE_FIXED_FILE_BIT
    static let ioDrain = SqeFlags(rawValue: 1 << 1) // IOSQE_IO_DRAIN_BIT
    static let ioLink = SqeFlags(rawValue: 1 << 2) // IOSQE_IO_LINK_BIT
    static let ioHardLink = SqeFlags(rawValue: 1 << 3) // IOSQE_IO_HARDLINK_BIT
    static let async = SqeFlags(rawValue: 1 << 4) // IOSQE_ASYNC_BIT
    static let bufferSelect = SqeFlags(rawValue: 1 << 5) // IOSQE_BUFFER_SELECT_BIT
    static let cqeSkipSuccess = SqeFlags(rawValue: 1 << 6) // IOSQE_CQE_SKIP_SUCCESS_BIT
  }

  public struct SetupFlags: OptionSet, Sendable {
    public typealias RawValue = UInt32

    public let rawValue: RawValue

    public init(rawValue: RawValue) {
      self.rawValue = rawValue
    }

    public static let ioPoll = SetupFlags(rawValue: 1 << 0) // IORING_SETUP_IOPOLL
    public static let sqPoll = SetupFlags(rawValue: 1 << 1) // IORING_SETUP_SQPOLL
    public static let sqAff = SetupFlags(rawValue: 1 << 2) // IORING_SETUP_SQ_AFF
    public static let cqSize = SetupFlags(rawValue: 1 << 3) // IORING_SETUP_CQSIZE
    public static let clamp = SetupFlags(rawValue: 1 << 4) // IORING_SETUP_CLAMP
    public static let attachWq = SetupFlags(rawValue: 1 << 5) // IORING_SETUP_ATTACH_WQ
    public static let rDisabled = SetupFlags(rawValue: 1 << 6) // IORING_SETUP_R_DISABLED
    public static let submitAll = SetupFlags(rawValue: 1 << 7) // IORING_SETUP_SUBMIT_ALL
    public static let coopTaskRun = SetupFlags(rawValue: 1 << 8) // IORING_SETUP_COOP_TASKRUN
    public static let taskRunFlag = SetupFlags(rawValue: 1 << 9) // IORING_SETUP_TASKRUN_FLAG
    public static let sqe128 = SetupFlags(rawValue: 1 << 10) // IORING_SETUP_SQE128
    public static let cqe32 = SetupFlags(rawValue: 1 << 11) // IORING_SETUP_CQE32
    public static let singleIssuer = SetupFlags(rawValue: 1 << 12) // IORING_SETUP_SINGLE_ISSUER
    public static let deferTaskRun = SetupFlags(rawValue: 1 << 13) // IORING_SETUP_DEFER_TASKRUN
    public static let noMmap = SetupFlags(rawValue: 1 << 14) // IORING_SETUP_NO_MMAP
    public static let registeredFdOnly =
      SetupFlags(rawValue: 1 << 15) // IORING_SETUP_REGISTERED_FD_ONLY
    public static let noSqArray = SetupFlags(rawValue: 1 << 16) // IORING_SETUP_NO_SQARRAY
  }

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

  public nonisolated var description: String {
    withUnsafePointer(to: self) { pointer in
      "\(type(of: self))(\(pointer))"
    }
  }

  private nonisolated static func getIORingQueueEntries() -> Int {
    if let ioRingQueueEntriesEnvVar = getenv("SWIFT_IORING_QUEUE_ENTRIES"),
       let entries = Int(String(cString: ioRingQueueEntriesEnvVar))
    {
      entries
    } else {
      DefaultIORingQueueEntries
    }
  }

  public init(
    entries: Int? = nil,
    flags: SetupFlags = [],
    sqThreadCpu: UInt32 = 0,
    sqThreadIdle: Duration = .zero
  ) throws {
    try self.init(
      entries: entries,
      flags: flags,
      shared: false,
      sqThreadCpu: sqThreadCpu,
      sqThreadIdle: sqThreadIdle
    )
  }

  public init(
    entries: Int? = nil,
    flags: UInt32,
    sqThreadCpu: UInt32 = 0,
    sqThreadIdle: Duration = .zero
  ) throws {
    try self.init(entries: entries, flags: SetupFlags(rawValue: flags), shared: false)
  }

  private init(
    entries: Int?,
    flags: SetupFlags,
    shared: Bool,
    sqThreadCpu: UInt32 = 0,
    sqThreadIdle: Duration = .zero
  ) throws {
    let entries = entries ?? IORing.getIORingQueueEntries()
    var ring = io_uring()
    var params = io_uring_params()
    var flags = flags

    flags.remove(.attachWq)

    if !shared {
      flags.insert(.attachWq)
      params.wq_fd = UInt32(IORing.shared.ringFd)
    }

    params.flags = flags.rawValue
    if flags.contains(.sqAff) { params.sq_thread_cpu = sqThreadCpu }
    if flags.contains(.sqPoll) {
      let sqThreadIdle = sqThreadIdle.milliseconds
      guard sqThreadIdle >= 0, sqThreadIdle <= UInt32.max else {
        throw Errno.invalidArgument
      }
      params.sq_thread_idle = UInt32(sqThreadIdle)
    }
    try Errno.throwingErrno {
      io_uring_queue_init_params(CUnsignedInt(entries), &ring, &params)
    }
    self.entries = entries
    self.ring = ring
    ringFd = ring.ring_fd

    let error = io_uring_init_cq_handler(&cqHandle, &self.ring)
    guard error == 0 else {
      io_uring_queue_exit(&ring)
      throw Errno(rawValue: -error)
    }
  }

  // FIXME: currently only supporting a single buffer size
  public func registerFixedBuffers(count: Int, size: Int) throws {
    guard fixedBuffers == nil else {
      throw Errno.fileExists
    }

    guard count > 0, size > 0 else {
      throw Errno.invalidArgument
    }

    fixedBuffers = FixedBuffer(count: count, size: size)

    try Errno.throwingErrno {
      io_uring_register_buffers(&self.ring, self.fixedBuffers!.iov, UInt32(count))
    }
  }

  public func unregisterFixedBuffers() throws {
    guard fixedBuffers != nil else { throw Errno.invalidArgument }
    try Errno.throwingErrno { io_uring_unregister_buffers(&self.ring) }
  }

  deinit {
    io_uring_deinit_cq_handler(cqHandle, &ring)
    // FIXME: checking if we have registered buffers is an error in Swift 6.0
    // because IORing.FixedBuffer is non-sendable, is this safe to do anyway?
    io_uring_unregister_buffers(&ring)
    // FIXME: where are unhandled completion blocks deallocated?
    io_uring_queue_exit(&ring)
  }

  // important note: caller MUST NOT suspend after calling getSqe() until preparation,
  // ideally not until submission particularly if linked requests are involved (this
  // may be impossible)
  func getSqe() throws -> UnsafeMutablePointer<io_uring_sqe> {
    let sqe = io_uring_get_sqe(&ring)
    guard let sqe else {
      throw Errno.resourceTemporarilyUnavailable
    }

    return sqe
  }

  func getNextBufferGroup() -> UInt16 {
    defer { nextBufferGroup += 1 }
    return nextBufferGroup
  }

  @discardableResult
  func submit() throws -> Int {
    try Int(Errno.throwingErrno {
      io_uring_submit(&self.ring)
    })
  }

  func withSubmissionGroup<T: Sendable>(_ body: (
    SubmissionGroup<T>
  ) async throws -> ()) async throws -> [T] {
    let submissionGroup = try SubmissionGroup<T>(ring: self)
    try await body(submissionGroup)
    return try await submissionGroup.finish(ring: self)
  }

  fileprivate func prepareAndSubmit<T: Sendable>(
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: Offset = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    socketAddress: sockaddr_storage? = nil,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws -> T {
    try await SingleshotSubmission(
      ring: self,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: offset,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndex: bufferIndex,
      socketAddress: socketAddress,
      handler: handler
    ).submit()
  }

  fileprivate func prepareAndSubmitMultishot<T: Sendable>(
    _ opcode: IORingOperation,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndexOrGroup: UInt16 = 0,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) throws -> AsyncThrowingStream<T, Error> {
    try MultishotSubmission(
      ring: self,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: 0,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndexOrGroup: bufferIndexOrGroup,
      socketAddress: nil,
      handler: handler
    ).submit()
  }
}

private extension IORing {
  func io_uring_op_cancel(
    fd: FileDescriptorRepresentable,
    link: Bool = false,
    flags: UInt32 = 0
  ) async throws {
    try await prepareAndSubmit(
      .async_cancel,
      fd: fd,
      flags: IORing.SqeFlags(link: link),
      moreFlags: flags
    ) { _ in }
  }

  func io_uring_op_close(
    fd: FileDescriptorRepresentable,
    link: Bool = false
  ) async throws {
    try await prepareAndSubmit(
      .close,
      fd: fd,
      flags: IORing.SqeFlags(link: link)
    ) { _ in }
  }

  func io_uring_op_read(
    fd: FileDescriptorRepresentable,
    buffer: inout [UInt8],
    count: Int,
    offset: Offset,
    link: Bool = false
  ) async throws -> Int {
    try await prepareAndSubmit(
      .read,
      fd: fd,
      address: buffer,
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link)
    ) { [buffer] cqe in
      _ = buffer
      return Int(cqe.res)
    }
  }

  func io_uring_op_write(
    fd: FileDescriptorRepresentable,
    buffer: [UInt8],
    count: Int,
    offset: Offset,
    link: Bool = false
  ) async throws -> Int {
    try await prepareAndSubmit(
      .write,
      fd: fd,
      address: buffer,
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link)
    ) { [buffer] cqe in
      _ = buffer
      return Int(cqe.res)
    }
  }

  func io_uring_op_read_fixed(
    fd: FileDescriptorRepresentable,
    count: Int, // number of bytes to read
    offset: Offset, // offset into the file we are reading
    bufferIndex: UInt16, // buffer selector
    bufferOffset: Int, // offset into the fixed buffers
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> SingleshotSubmission<Int> {
    try await SingleshotSubmission(
      ring: self,
      .read_fixed,
      fd: fd,
      address: fixedBuffers!.unsafeMutableRawPointer(
        at: bufferIndex,
        count: count,
        bufferOffset: bufferOffset
      ),
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link),
      bufferIndex: bufferIndex,
      group: group
    ) { cqe in
      Int(cqe.res)
    }
  }

  func io_uring_op_read_fixed(
    fd: FileDescriptorRepresentable,
    count: Int, // number of bytes to write
    offset: Offset, // offset into the file we are writing
    bufferIndex: UInt16, // buffer selector
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> Int {
    try await io_uring_op_read_fixed(
      fd: fd,
      count: count,
      offset: offset,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset,
      link: link,
      group: group
    ).submit()
  }

  func io_uring_op_write_fixed(
    fd: FileDescriptorRepresentable,
    count: Int,
    offset: Offset, // offset into the file we are writing
    bufferIndex: UInt16,
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> SingleshotSubmission<Int> {
    try await SingleshotSubmission(
      ring: self,
      .write_fixed,
      fd: fd,
      address: fixedBuffers!.unsafeMutableRawPointer(
        at: bufferIndex,
        count: count,
        bufferOffset: bufferOffset
      ),
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link),
      bufferIndex: bufferIndex,
      group: group
    ) { cqe in
      Int(cqe.res)
    }
  }

  func io_uring_op_write_fixed(
    fd: FileDescriptorRepresentable,
    count: Int,
    offset: Offset, // offset into the file we are writing
    bufferIndex: UInt16,
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> Int {
    try await io_uring_op_write_fixed(
      fd: fd,
      count: count,
      offset: offset,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset,
      link: link,
      group: group
    ).submit()
  }

  func io_uring_op_send(
    fd: FileDescriptorRepresentable,
    buffer: [UInt8],
    to socketAddress: sockaddr_storage? = nil,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await prepareAndSubmit(
      .send,
      fd: fd,
      address: buffer,
      length: CUnsignedInt(buffer.count),
      offset: 0,
      flags: IORing.SqeFlags(link: link),
      moreFlags: flags,
      socketAddress: socketAddress
    ) { [buffer] _ in
      _ = buffer
      return ()
    }
  }

  func io_uring_op_recv(
    fd: FileDescriptorRepresentable,
    buffer: inout [UInt8],
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await prepareAndSubmit(
      .recv,
      fd: fd,
      address: buffer,
      length: CUnsignedInt(buffer.count),
      offset: 0,
      flags: IORing.SqeFlags(link: link),
      moreFlags: flags
    ) { [buffer] _ in
      _ = buffer
      return ()
    }
  }

  func io_uring_op_recv_multishot(
    fd: FileDescriptorRepresentable,
    count: Int,
    link: Bool = false
  ) throws -> AsyncThrowingStream<[UInt8], Error> {
    var buffer = [UInt8]._unsafelyInitialized(count: count)
    return try prepareAndSubmitMultishot(
      .recv,
      fd: fd,
      address: &buffer[0],
      length: CUnsignedInt(count),
      flags: IORing.SqeFlags(link: link),
      ioprio: RecvSendIoPrio.multishot
    ) { [buffer] _ in
      buffer
    }
  }

  func io_uring_op_recvmsg(
    fd: FileDescriptorRepresentable,
    message: inout Message,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await message.withUnsafeMutablePointer(ring: self) { pointer in
      try await prepareAndSubmit(
        .recvmsg,
        fd: fd,
        address: pointer,
        length: 1,
        offset: 0,
        flags: IORing.SqeFlags(link: link),
        moreFlags: flags
      ) { _ in }
    }
  }

  func io_uring_op_recvmsg_multishot(
    fd: FileDescriptorRepresentable,
    count: Int,
    capacity: Int,
    flags: UInt32 = 0
  ) async throws -> AsyncThrowingStream<Message, Error> {
    // FIXME: combine message holder buffer registration with multishot registration to avoid extra system call
    let holder = try await MessageHolder(ring: self, size: count, count: capacity)
    return try await holder.withUnsafeMutablePointer(ring: self) { pointer in
      try MultishotSubmission(
        ring: self,
        .recvmsg,
        fd: fd,
        address: pointer,
        flags: SqeFlags.bufferSelect,
        ioprio: RecvSendIoPrio.multishot,
        moreFlags: flags,
        bufferIndexOrGroup: holder.bufferGroup
      ) { [holder] cqe in
        // because the default for multishots is to resubmit when IORING_CQE_F_MORE is unset,
        // we don't need to deallocate the buffer here. FIXME: do this when stream finishes.
        // we know that handlers are always executed in an @IORingActor actor's execution context
        // so it's safe to access the holder's buffer. But we should make this more explicit
        // by making the callback take an async function.
        try holder.receive(id: Int(cqe.flags >> 16), count: Int(cqe.res))
      }
    }.submit()
  }

  func io_uring_op_sendmsg(
    fd: FileDescriptorRepresentable,
    message: Message,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await message.withUnsafeMutablePointer(ring: self) { pointer in
      try await prepareAndSubmit(
        .sendmsg,
        fd: fd,
        address: pointer,
        length: 1,
        offset: 0,
        flags: IORing.SqeFlags(link: link),
        moreFlags: flags
      ) { _ in }
    }
  }

  func io_uring_op_accept(
    fd: FileDescriptorRepresentable,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws -> FileDescriptorRepresentable {
    try await prepareAndSubmit(
      .accept,
      fd: fd,
      flags: IORing.SqeFlags(link: link),
      moreFlags: flags
    ) { cqe in
      try FileHandle(fileDescriptor: cqe.res, closeOnDealloc: true)
    }
  }

  func io_uring_op_multishot_accept(
    fd: FileDescriptorRepresentable,
    flags: UInt32 = 0
  ) throws -> AsyncThrowingStream<FileDescriptorRepresentable, Error> {
    try prepareAndSubmitMultishot(
      .accept,
      fd: fd,
      ioprio: AcceptIoPrio.multishot,
      moreFlags: flags
    ) { cqe in
      try FileHandle(fileDescriptor: cqe.res, closeOnDealloc: true)
    }
  }

  func io_uring_op_connect(
    fd: FileDescriptorRepresentable,
    address: sockaddr_storage,
    link: Bool = false
  ) async throws {
    var address = address
    try await prepareAndSubmit(
      .connect,
      fd: fd,
      address: &address,
      offset: Offset(address.size),
      flags: IORing.SqeFlags(link: link)
    ) { [address] _ in
      _ = address
    }
  }
}

// MARK: - public API

public extension IORing {
  func close(_ fd: FileDescriptorRepresentable) async throws {
    try await io_uring_op_close(fd: fd)
  }

  @discardableResult
  func read(
    into buffer: inout [UInt8],
    count: Int? = nil,
    offset: Offset = -1,
    from fd: FileDescriptorRepresentable
  ) async throws -> Int {
    try await io_uring_op_read(
      fd: fd,
      buffer: &buffer,
      count: count ?? buffer.count,
      offset: offset
    )
  }

  func read(count: Int, from fd: FileDescriptorRepresentable) async throws -> [UInt8] {
    var buffer = [UInt8]._unsafelyInitialized(count: count)
    let nread = try await read(into: &buffer, count: count, from: fd)
    return Array(buffer.prefix(nread))
  }

  func write(
    _ data: [UInt8],
    count: Int? = nil,
    offset: Offset = -1,
    to fd: FileDescriptorRepresentable
  ) async throws -> Int {
    try await io_uring_op_write(
      fd: fd,
      buffer: data,
      count: count ?? data.count,
      offset: offset
    )
  }

  func receive(
    count: Int,
    from fd: FileDescriptorRepresentable
  ) throws -> AnyAsyncSequence<[UInt8]> {
    try io_uring_op_recv_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
  }

  func receive(count: Int, from fd: FileDescriptorRepresentable) async throws -> [UInt8] {
    var buffer = [UInt8]._unsafelyInitialized(count: count)
    try await io_uring_op_recv(fd: fd, buffer: &buffer)
    return buffer
  }

  func send(_ data: [UInt8], to fd: FileDescriptorRepresentable) async throws {
    try await io_uring_op_send(fd: fd, buffer: data)
  }

  func receiveMessages(
    count: Int,
    capacity: Int? = nil,
    from fd: FileDescriptorRepresentable
  ) async throws -> AnyAsyncSequence<Message> {
    try await io_uring_op_recvmsg_multishot(
      fd: fd,
      count: count,
      capacity: capacity ?? entries
    ).eraseToAnyAsyncSequence()
  }

  func receiveMessage(count: Int, from fd: FileDescriptorRepresentable) async throws -> Message {
    var message = Message(capacity: count)
    try await io_uring_op_recvmsg(fd: fd, message: &message)
    return message
  }

  func send(message: Message, to fd: FileDescriptorRepresentable) async throws {
    try await io_uring_op_sendmsg(fd: fd, message: message)
  }

  func accept(from fd: FileDescriptorRepresentable) async throws
    -> any FileDescriptorRepresentable
  {
    try await io_uring_op_accept(fd: fd)
  }

  func accept(from fd: FileDescriptorRepresentable) throws
    -> AnyAsyncSequence<FileDescriptorRepresentable>
  {
    try io_uring_op_multishot_accept(fd: fd).eraseToAnyAsyncSequence()
  }

  package func connect(
    _ fd: FileDescriptorRepresentable,
    to address: sockaddr_storage
  ) async throws {
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

  func connect(_ fd: FileDescriptorRepresentable, to address: [UInt8]) async throws {
    let ss = try sockaddr_storage(bytes: address)
    try await io_uring_op_connect(fd: fd, address: ss)
  }

  func readFixed<U>(
    count: Int? = nil,
    offset: Offset = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    from fd: FileDescriptorRepresentable,
    _ body: (UnsafeMutableBufferPointer<UInt8>) throws -> U
  ) async throws -> U {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.size
    try fixedBuffers.validate(
      count: count,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    let nread: Int = try await io_uring_op_read_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    let address = try fixedBuffers.unsafeMutablePointer(
      at: bufferIndex,
      count: nread,
      bufferOffset: bufferOffset
    )
    return try body(address)
  }

  func writeFixed(
    _ data: [UInt8],
    count: Int? = nil,
    offset: Offset = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    to fd: FileDescriptorRepresentable
  ) async throws -> Int {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? data.count
    guard count <= data.count else { throw Errno.outOfRange }
    try fixedBuffers.validate(
      count: count,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    let address = try fixedBuffers.unsafeMutableRawPointer(
      at: bufferIndex,
      count: count,
      bufferOffset: bufferOffset
    )
    data.withUnsafeBytes { bytes in
      _ = memcpy(address, UnsafeRawPointer(bytes.baseAddress!), count)
    }

    return try await io_uring_op_write_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )
  }

  // FIXME: if we suspend between the linked submissions and another task calls submit,
  // then the ordering of SQEs will be broken! we need to figure out if this can practically
  // happen
  func writeReadFixed(
    _ data: inout [UInt8],
    writeCount: Int? = nil,
    readCount: Int? = nil,
    offset: Offset = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    fd: FileDescriptorRepresentable
  ) async throws {
    guard let fixedBuffers else { throw Errno.invalidArgument }

    let writeCount = writeCount ?? fixedBuffers.size
    let readCount = readCount ?? fixedBuffers.size

    guard writeCount <= data.count, readCount <= data.count else { throw Errno.outOfRange }

    try fixedBuffers.validate(
      count: max(readCount, writeCount),
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    let address = try fixedBuffers.unsafeMutableRawPointer(
      at: bufferIndex,
      count: writeCount,
      bufferOffset: bufferOffset
    )
    data.withUnsafeBytes { bytes in
      _ = memcpy(address, UnsafeRawPointer(bytes.baseAddress!), writeCount)
    }

    let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
      let _: SingleshotSubmission<Int> = try await io_uring_op_write_fixed(
        fd: fd,
        count: writeCount,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        link: true,
        group: group
      )

      let _: SingleshotSubmission<Int> = try await io_uring_op_read_fixed(
        fd: fd,
        count: readCount,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        group: group
      )
    }

    guard result.count == 2, result[0] == result[1] else {
      throw Errno.resourceTemporarilyUnavailable
    }

    data.withUnsafeMutableBytes { bytes in
      _ = memcpy(UnsafeMutableRawPointer(bytes.baseAddress!), address, readCount)
    }
  }

  func copy(
    count: Int? = nil,
    offset: Offset = -1,
    bufferIndex: UInt16,
    from fd1: FileDescriptorRepresentable,
    to fd2: FileDescriptorRepresentable
  ) async throws {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.size
    try fixedBuffers.validate(
      count: count,
      bufferIndex: bufferIndex,
      bufferOffset: 0
    )

    let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
      let _: SingleshotSubmission<Int> = try await io_uring_op_read_fixed(
        fd: fd1,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        link: true,
        group: group
      )

      let _: SingleshotSubmission<Int> = try await io_uring_op_write_fixed(
        fd: fd2,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        group: group
      )
    }

    guard result.count == 2, result[0] == result[1] else {
      throw Errno.resourceTemporarilyUnavailable
    }
  }
}

// MARK: - conformances

extension IORing: Equatable {
  public nonisolated static func == (lhs: IORing, rhs: IORing) -> Bool {
    lhs === rhs
  }
}

extension IORing: Hashable {
  public nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}

package extension [UInt8] {
  static func _unsafelyInitialized(count: Int) -> Self {
    Self(unsafeUninitializedCapacity: count) { _, initializedCount in
      initializedCount = count
    }
  }
}

package extension Duration {
  var seconds: Int64 {
    components.seconds
  }

  var milliseconds: Int64 {
    components.seconds * 1000 + Int64(Double(components.attoseconds) * 1e-15)
  }
}
