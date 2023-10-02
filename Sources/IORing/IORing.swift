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

@globalActor
public actor IORing: CustomStringConvertible {
  public static let shared = try! IORing()

  private static let DefaultIORingQueueEntries = 128

  private var ring: io_uring
  private var cqHandle: UnsafeMutableRawPointer?

  private var fixedBuffers: FixedBuffer?
  private var nextBufferGroup: UInt16 = 1
  private let entries: Int

  final class FixedBuffer {
    let count: Int
    let size: Int
    var storage: UnsafeMutablePointer<UInt8>
    var indices: UnsafeMutableBufferPointer<iovec>

    var iov: UnsafeMutablePointer<iovec> {
      indices.baseAddress!
    }

    init(count: Int, size: Int) {
      self.count = count
      self.size = size
      storage = .allocate(capacity: size * count)
      indices = .allocate(capacity: count)

      for i in 0..<count {
        indices[i].iov_base = UnsafeMutableRawPointer(storage + i * size)
        indices[i].iov_len = size
      }
    }

    func validate(index: UInt16, count: Int, offset: Int) throws {
      guard index < count, count + offset <= size else {
        throw Errno.outOfRange
      }
    }

    func unsafeMutablePointer(
      at index: UInt16,
      range: Range<Int>
    ) throws -> UnsafeMutableBufferPointer<UInt8> {
      try unsafeMutablePointer(
        at: index,
        count: range.upperBound - range.lowerBound,
        offset: range.lowerBound
      )
    }

    func unsafeMutablePointer(
      at index: UInt16,
      count: Int,
      offset: Int
    ) throws -> UnsafeMutableBufferPointer<UInt8> {
      guard index < count, count + offset <= size else {
        throw Errno.outOfRange
      }

      return UnsafeMutableBufferPointer(start: storage + Int(index) * size + offset, count: count)
    }

    func unsafeMutableRawPointer(
      at index: UInt16,
      count: Int,
      offset: Int
    ) throws -> UnsafeMutableRawPointer {
      try UnsafeMutableRawPointer(
        unsafeMutablePointer(at: index, count: count, offset: offset)
          .baseAddress!
      )
    }

    deinit {
      storage.deallocate()
      indices.deallocate()
    }
  }

  struct SqeFlags: OptionSet {
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

    static let fixedFile = SqeFlags(rawValue: 1 << IOSQE_FIXED_FILE_BIT)
    static let ioDrain = SqeFlags(rawValue: 1 << IOSQE_IO_DRAIN_BIT)
    static let ioLink = SqeFlags(rawValue: 1 << IOSQE_IO_LINK_BIT)
    static let ioHardLink = SqeFlags(rawValue: 1 << IOSQE_IO_HARDLINK_BIT)
    static let async = SqeFlags(rawValue: 1 << IOSQE_ASYNC_BIT)
    static let bufferSelect = SqeFlags(rawValue: 1 << IOSQE_BUFFER_SELECT_BIT)
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

  static func logDebug(message: String, functionName: String = #function) {
    debugPrint("IORing.\(functionName): \(message)")
  }

  private static func getIORingQueueEntries() -> Int {
    if let ioRingQueueEntriesEnvVar = getenv("SWIFT_IORING_QUEUE_ENTRIES"),
       let entries = Int(String(cString: ioRingQueueEntriesEnvVar))
    {
      return entries
    } else {
      return DefaultIORingQueueEntries
    }
  }

  public init(entries: Int? = nil, flags: UInt32 = 0) throws {
    let entries = entries ?? IORing.getIORingQueueEntries()
    var ring = io_uring()

    try Errno.throwingErrno {
      io_uring_queue_init(CUnsignedInt(entries), &ring, flags)
    }
    self.entries = entries
    self.ring = ring

    let error = io_uring_init_cq_handler(&cqHandle, &self.ring)
    guard error == 0 else {
      io_uring_queue_exit(&ring)
      throw Errno(rawValue: error)
    }
  }

  // FIXME: currently only supporting a single buffer size
  public func registerFixedBuffers(count: Int, size: Int) async throws {
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
    if fixedBuffers != nil {
      io_uring_unregister_buffers(&ring)
    }
    // FIXME: where are unhandled completion blocks deallocated?
    io_uring_queue_exit(&ring)
  }

  // important note: caller MUST NOT suspend after calling getSqe() until submission
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

  func withSubmissionGroup<T>(_ body: (
    SubmissionGroup<T>
  ) async throws -> ()) async throws -> [T] {
    let submissionGroup = try await SubmissionGroup<T>(ring: self)
    try await body(submissionGroup)
    return try await submissionGroup.finish()
  }

  fileprivate func prepareAndSubmit<T>(
    _ opcode: io_uring_op,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    offset: Int = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    bufferGroup: UInt16 = 0,
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
      bufferGroup: bufferGroup,
      socketAddress: socketAddress,
      handler: handler
    ).submit()
  }

  fileprivate func prepareAndSubmitMultishot<T>(
    _ opcode: io_uring_op,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    bufferGroup: UInt16 = 0,
    handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws -> AsyncThrowingChannel<T, Error> {
    try await MultishotSubmission(
      ring: self,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: 0,
      flags: flags,
      ioprio: ioprio,
      moreFlags: moreFlags,
      bufferIndex: bufferIndex,
      bufferGroup: bufferGroup,
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
      IORING_OP_ASYNC_CANCEL,
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
      IORING_OP_CLOSE,
      fd: fd,
      flags: IORing.SqeFlags(link: link)
    ) { _ in }
  }

  func io_uring_op_read(
    fd: FileDescriptorRepresentable,
    buffer: inout [UInt8],
    count: Int,
    offset: Int,
    link: Bool = false
  ) async throws -> Int {
    try await prepareAndSubmit(
      IORING_OP_READ,
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
    offset: Int,
    link: Bool = false
  ) async throws -> Int {
    try await prepareAndSubmit(
      IORING_OP_WRITE,
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
    count: Int,
    offset: Int, // offset into the file we are reading
    bufferIndex: UInt16,
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> SingleshotSubmission<Int> {
    try await SingleshotSubmission(
      ring: self,
      IORING_OP_READ_FIXED,
      fd: fd,
      address: fixedBuffers!.unsafeMutableRawPointer(
        at: bufferIndex,
        count: count,
        offset: bufferOffset
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

  // FIXME: support partial reads
  func io_uring_op_read_fixed(
    fd: FileDescriptorRepresentable,
    count: Int,
    offset: Int, // offset into the file we are writing
    bufferIndex: UInt16,
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
    offset: Int, // offset into the file we are writing
    bufferIndex: UInt16,
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false,
    group: SubmissionGroup<Int>? = nil
  ) async throws -> SingleshotSubmission<Int> {
    try await SingleshotSubmission(
      ring: self,
      IORING_OP_WRITE_FIXED,
      fd: fd,
      address: fixedBuffers!.unsafeMutableRawPointer(
        at: bufferIndex,
        count: count,
        offset: bufferOffset
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

  // FIXME: support partial writes
  func io_uring_op_write_fixed(
    fd: FileDescriptorRepresentable,
    count: Int,
    offset: Int, // offset into the file we are writing
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
      IORING_OP_SEND,
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
      IORING_OP_RECV,
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
  ) async throws -> AsyncThrowingChannel<[UInt8], Error> {
    var buffer = [UInt8](repeating: 0, count: count)
    return try await prepareAndSubmitMultishot(
      IORING_OP_RECV,
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
    try await message.withUnsafeMutablePointer { pointer in
      try await prepareAndSubmit(
        IORING_OP_RECVMSG,
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
  ) async throws -> AsyncThrowingChannel<Message, Error> {
    // FIXME: combine message holder buffer registration with multishot registration to avoid extra system call
    let holder = try await MessageHolder(ring: self, size: count, count: capacity)
    return try await holder.withUnsafeMutablePointer { pointer in
      try await MultishotSubmission(
        ring: self,
        IORING_OP_RECVMSG,
        fd: fd,
        address: pointer,
        flags: SqeFlags.bufferSelect,
        ioprio: RecvSendIoPrio.multishot,
        moreFlags: flags,
        bufferGroup: holder.bufferGroup
      ) { [holder] cqe in
        // because the default for multishots is to resubmit when IORING_CQE_F_MORE is unset,
        // we don't need to deallocate the buffer here. FIXME: do this when channel closes.
        // we know that handlers are always executed in an @IORing actor's execution context
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
    try await message.withUnsafeMutablePointer { pointer in
      try await prepareAndSubmit(
        IORING_OP_SENDMSG,
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
      IORING_OP_ACCEPT,
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
  ) async throws -> AsyncThrowingChannel<FileDescriptorRepresentable, Error> {
    try await prepareAndSubmitMultishot(
      IORING_OP_ACCEPT,
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
      IORING_OP_CONNECT,
      fd: fd,
      address: &address,
      offset: Int(address.size),
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
    offset: Int = -1,
    from fd: FileDescriptorRepresentable
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

  func read(count: Int, from fd: FileDescriptorRepresentable) async throws -> [UInt8] {
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
    to fd: FileDescriptorRepresentable
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

  func receive(
    count: Int,
    from fd: FileDescriptorRepresentable
  ) async throws -> AnyAsyncSequence<[UInt8]> {
    try await io_uring_op_recv_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
  }

  func receive(count: Int, from fd: FileDescriptorRepresentable) async throws -> [UInt8] {
    var buffer = [UInt8](repeating: 0, count: count)
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

  func accept(from fd: FileDescriptorRepresentable) async throws
    -> AnyAsyncSequence<FileDescriptorRepresentable>
  {
    try await io_uring_op_multishot_accept(fd: fd).eraseToAnyAsyncSequence()
  }

  func connect(_ fd: FileDescriptorRepresentable, to address: sockaddr_storage) async throws {
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
    offset: Int = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    from fd: FileDescriptorRepresentable,
    _ body: (UnsafeMutableBufferPointer<UInt8>) throws -> U
  ) async throws -> U {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.count
    try fixedBuffers.validate(index: bufferIndex, count: count, offset: bufferOffset)

    let nread: Int = try await io_uring_op_read_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    let address = try fixedBuffers.unsafeMutablePointer(
      at: bufferIndex,
      count: nread,
      offset: bufferOffset
    )
    return try body(address)
  }

  func writeFixed(
    _ data: [UInt8],
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    to fd: FileDescriptorRepresentable
  ) async throws -> Int {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.count
    guard count <= data.count else { throw Errno.outOfRange }
    try fixedBuffers.validate(index: bufferIndex, count: count, offset: bufferOffset)

    let address = try fixedBuffers.unsafeMutableRawPointer(
      at: bufferIndex,
      count: count,
      offset: bufferOffset
    )
    data.withUnsafeBytes { bytes in
      _ = memcpy(address, UnsafeRawPointer(bytes.baseAddress!), count)
    }

    return try await io_uring_op_write_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )
  }

  func writeReadFixed(
    _ data: inout [UInt8],
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    fd: FileDescriptorRepresentable
  ) async throws {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.count
    guard count <= data.count else { throw Errno.outOfRange }
    try fixedBuffers.validate(index: bufferIndex, count: count, offset: bufferOffset)

    let address = try fixedBuffers.unsafeMutableRawPointer(
      at: bufferIndex,
      count: count,
      offset: bufferOffset
    )
    data.withUnsafeBytes { bytes in
      _ = memcpy(address, UnsafeRawPointer(bytes.baseAddress!), count)
    }

    let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
      let _: SingleshotSubmission<Int> = try await io_uring_op_write_fixed(
        fd: fd,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        link: true,
        group: group
      )

      let _: SingleshotSubmission<Int> = try await io_uring_op_read_fixed(
        fd: fd,
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

    data.withUnsafeMutableBytes { bytes in
      _ = memcpy(UnsafeMutableRawPointer(bytes.baseAddress!), address, count)
    }
  }

  func copy(
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    from fd1: FileDescriptorRepresentable,
    to fd2: FileDescriptorRepresentable
  ) async throws {
    guard let fixedBuffers else { throw Errno.invalidArgument }
    let count = count ?? fixedBuffers.count
    try fixedBuffers.validate(index: bufferIndex, count: count, offset: 0)

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
  public static func == (lhs: IORing, rhs: IORing) -> Bool {
    ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
  }
}

extension IORing: Hashable {
  public nonisolated func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}
