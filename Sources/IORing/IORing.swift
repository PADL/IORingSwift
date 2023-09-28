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

  public struct SqeFlags: OptionSet {
    public typealias RawValue = UInt8
    public let rawValue: RawValue

    public init(rawValue: RawValue) {
      self.rawValue = rawValue
    }

    public init(link: Bool) {
      if link {
        self = SqeFlags.ioLink
      } else {
        self = SqeFlags()
      }
    }

    public static let fixedFile = SqeFlags(rawValue: 1 << IOSQE_FIXED_FILE_BIT)
    public static let ioDrain = SqeFlags(rawValue: 1 << IOSQE_IO_DRAIN_BIT)
    public static let ioLink = SqeFlags(rawValue: 1 << IOSQE_IO_LINK_BIT)
    public static let ioHardLink = SqeFlags(rawValue: 1 << IOSQE_IO_HARDLINK_BIT)
    public static let async = SqeFlags(rawValue: 1 << IOSQE_ASYNC_BIT)
    public static let bufferSelect = SqeFlags(rawValue: 1 << IOSQE_BUFFER_SELECT_BIT)
  }

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
  public init(
    depth: Int = 1,
    flags: UInt32 = 0,
    suspendIfSubmissionQueueFull: Bool = false
  ) throws {
    manager = try Manager(
      depth: CUnsignedInt(depth),
      flags: flags,
      suspendIfSubmissionQueueFull: suspendIfSubmissionQueueFull
    )
  }

  public nonisolated var description: String {
    withUnsafePointer(to: self) { pointer in
      "\(type(of: self))(\(pointer))"
    }
  }

  @discardableResult
  func submit() throws -> Int {
    try manager.submit()
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
    fd: FileDescriptorRepresentable,
    link: Bool = false,
    flags: UInt32 = 0
  ) async throws {
    try await manager.prepareAndSubmit(
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
    try await manager.prepareAndSubmit(
      IORING_OP_CLOSE,
      fd: fd,
      flags: IORing.SqeFlags(link: link)
    ) { _ in }
  }

  func io_uring_op_readv(
    fd: FileDescriptorRepresentable,
    iovecs: [iovec],
    offset: Int,
    link: Bool = false
  ) async throws -> Int {
    try await manager.prepareAndSubmitIovec(
      IORING_OP_READV,
      fd: fd,
      iovecs: iovecs,
      offset: offset,
      flags: IORing.SqeFlags(link: link)
    ) { cqe in
      Int(cqe.res)
    }
  }

  func io_uring_op_writev(
    fd: FileDescriptorRepresentable,
    iovecs: [iovec],
    count: Int,
    offset: Int,
    link: Bool = false
  ) async throws -> Int {
    try await manager.prepareAndSubmitIovec(
      IORING_OP_WRITEV,
      fd: fd,
      iovecs: iovecs,
      offset: offset,
      flags: IORing.SqeFlags(link: link)
    ) { cqe in
      Int(cqe.res)
    }
  }

  func io_uring_op_read(
    fd: FileDescriptorRepresentable,
    buffer: inout [UInt8],
    count: Int,
    offset: Int,
    link: Bool = false
  ) async throws -> Int {
    try await manager.prepareAndSubmit(
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
    try await manager.prepareAndSubmit(
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
    link: Bool = false
  ) async throws -> Submission<Int> {
    try await Submission(
      manager: manager,
      IORING_OP_READ_FIXED,
      fd: fd,
      address: manager.unsafePointerForFixedBuffer(at: bufferIndex, offset: bufferOffset),
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link),
      bufferIndex: bufferIndex
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
    link: Bool = false
  ) async throws -> Int {
    try await io_uring_op_read_fixed(
      fd: fd,
      count: count,
      offset: offset,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset,
      link: link
    ).submitSingleshot()
  }

  func io_uring_op_write_fixed(
    fd: FileDescriptorRepresentable,
    count: Int,
    offset: Int, // offset into the file we are writing
    bufferIndex: UInt16,
    bufferOffset: Int, // offset into the fixed buffer
    link: Bool = false
  ) async throws -> Submission<Int> {
    try await Submission(
      manager: manager,
      IORING_OP_WRITE_FIXED,
      fd: fd,
      address: manager.unsafePointerForFixedBuffer(at: bufferIndex, offset: bufferOffset),
      length: CUnsignedInt(count),
      offset: offset,
      flags: IORing.SqeFlags(link: link),
      bufferIndex: bufferIndex
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
    link: Bool = false
  ) async throws -> Int {
    try await io_uring_op_write_fixed(
      fd: fd,
      count: count,
      offset: offset,
      bufferIndex: bufferIndex,
      bufferOffset: bufferOffset,
      link: link
    ).submitSingleshot()
  }

  func io_uring_op_send(
    fd: FileDescriptorRepresentable,
    buffer: [UInt8],
    to socketAddress: sockaddr_storage? = nil,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await manager.prepareAndSubmit(
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
    try await manager.prepareAndSubmit(
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
    // FIXME: check this will be captured or do we need to
    var buffer = [UInt8](repeating: 0, count: count)
    return try await manager.prepareAndSubmitMultishot(
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
      try await manager.prepareAndSubmit(
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
    flags: UInt32 = 0
  ) async throws -> AsyncThrowingChannel<Message, Error> {
    let message = Message(capacity: count)
    return try await message.withUnsafeMutablePointer { pointer in
      try await manager.prepareAndSubmitMultishot(
        IORING_OP_RECVMSG,
        fd: fd,
        address: pointer,
        ioprio: RecvSendIoPrio.multishot,
        moreFlags: flags
      ) { [message] _ in
        message.copy()
      }
    }
  }

  func io_uring_op_sendmsg(
    fd: FileDescriptorRepresentable,
    message: Message,
    flags: UInt32 = 0,
    link: Bool = false
  ) async throws {
    try await message.withUnsafePointer { pointer in
      try await manager.prepareAndSubmit(
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
    try await manager.prepareAndSubmit(
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
    try await manager.prepareAndSubmitMultishot(
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
    var address = address // FIXME: check lifetime
    try await manager.prepareAndSubmit(
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
    from fd: FileDescriptorRepresentable
  ) async throws -> AnyAsyncSequence<Message> {
    try await io_uring_op_recvmsg_multishot(fd: fd, count: count).eraseToAnyAsyncSequence()
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
    from fd: FileDescriptorRepresentable
  ) async throws -> ArraySlice<UInt8> {
    let count = try count ?? manager.registeredBuffersSize

    try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

    let nread: Int = try await io_uring_op_read_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    return manager.buffer(at: bufferIndex, range: bufferOffset..<(bufferOffset + nread))
  }

  func readFixed(
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    from fd: FileDescriptorRepresentable,
    _ body: (inout ArraySlice<UInt8>) throws -> ()
  ) async throws {
    let count = try count ?? manager.registeredBuffersSize

    try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: bufferOffset)

    let nread: Int = try await io_uring_op_read_fixed(
      fd: fd, count: count, offset: offset, bufferIndex: bufferIndex,
      bufferOffset: bufferOffset
    )

    try manager.withFixedBufferSlice(
      at: bufferIndex,
      range: bufferOffset..<(bufferOffset + nread),
      body
    )
  }

  func writeFixed(
    _ data: ArraySlice<UInt8>,
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    bufferOffset: Int = 0,
    to fd: FileDescriptorRepresentable
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
    to fd: FileDescriptorRepresentable,
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
    fd: FileDescriptorRepresentable,
    _ body: (inout ArraySlice<UInt8>) throws -> ()
  ) async throws {
    let count = try count ?? manager.registeredBuffersSize

    try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: 0)

    let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
      let writeSubmission: Submission<Int> = try await io_uring_op_write_fixed(
        fd: fd,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        link: true
      )
      await group.enqueue(submission: writeSubmission)

      let readSubmission: Submission<Int> = try await io_uring_op_read_fixed(
        fd: fd,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0
      )
      await group.enqueue(submission: readSubmission)
    }

    guard result.count == 2, result[0] == result[1] else {
      throw Errno.resourceTemporarilyUnavailable
    }
  }

  func copy(
    count: Int? = nil,
    offset: Int = -1,
    bufferIndex: UInt16,
    from fd1: FileDescriptorRepresentable,
    to fd2: FileDescriptorRepresentable
  ) async throws {
    let count = try count ?? manager.registeredBuffersSize

    try manager.validateFixedBuffer(at: bufferIndex, length: count, offset: 0)

    let result = try await withSubmissionGroup { (group: SubmissionGroup<Int>) in
      let readSubmission: Submission<Int> = try await io_uring_op_read_fixed(
        fd: fd1,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0,
        link: true
      )
      await group.enqueue(submission: readSubmission)

      let writeSubmission: Submission<Int> = try await io_uring_op_write_fixed(
        fd: fd2,
        count: count,
        offset: offset,
        bufferIndex: bufferIndex,
        bufferOffset: 0
      )
      await group.enqueue(submission: writeSubmission)
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
