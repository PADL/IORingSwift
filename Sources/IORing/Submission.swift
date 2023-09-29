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
import Glibc

class Submission<T>: CustomStringConvertible {
  // reference to owner which owns ring
  fileprivate let manager: Manager
  /// user-supplied callback to transform a completion queue entry to a result
  fileprivate let handler: @Sendable (io_uring_cqe) throws -> T

  /// file descriptor, stored so that it is not closed before the completion handler is run
  private let fd: FileDescriptorRepresentable
  /// opcode, useful for debugging
  private let opcode: io_uring_op
  /// assigned submission queue entry for this object
  private let sqe: UnsafeMutablePointer<io_uring_sqe>

  fileprivate var id: ObjectIdentifier {
    ObjectIdentifier(self)
  }

  public var description: String {
    "(\(type(of: self)): \(id))(fd: \(fd.fileDescriptor), opcode: \(opcodeDescription(opcode)), handler: \(String(describing: handler)))"
  }

  // MARK: - initializer helpers

  private func prepare(
    _ opcode: io_uring_op,
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer?,
    length: CUnsignedInt,
    offset: Int
  ) {
    io_uring_prep_rw(
      io_uring_op_to_int(opcode),
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
    bufferIndex: UInt16,
    bufferGroup: UInt16
  ) {
    io_uring_sqe_set_flags(sqe, UInt32(flags))
    sqe.pointee.ioprio = ioprio
    sqe.pointee.fsync_flags = moreFlags
    sqe.pointee.buf_index = bufferIndex
    sqe.pointee.buf_group = bufferGroup
  }

  /// because actors are reentrant, `setBlock()` must be called immediately after
  /// the manager assigned a SQE (or, at least before any suspension point)
  private func setBlock() {
    io_uring_sqe_set_block(sqe) { [self] in
      onCompletion(cqe: $0)
      // FIXME: this could race before io_uring_cqe_seen() is called
      manager.resumeSubmission()
    }
  }

  init(
    manager: Manager,
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
  ) async throws {
    sqe = try await manager.getSqe()
    self.fd = fd
    self.manager = manager
    self.opcode = opcode
    self.handler = handler

    prepare(opcode, sqe: sqe, fd: fd, address: address, length: length, offset: offset)
    setFlags(
      sqe: sqe,
      flags: flags.rawValue,
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
    setBlock()
  }

  fileprivate init(_ submission: Submission) async throws {
    manager = submission.manager
    handler = submission.handler
    fd = submission.fd
    opcode = submission.opcode
    sqe = try await manager.getSqe()
    setBlock()
  }

  fileprivate func onCompletion(cqe: UnsafePointer<io_uring_cqe>) {
    fatalError("handle(cqe:) must be implemented by subclass")
  }

  fileprivate func throwingErrno(
    cqe: UnsafePointer<io_uring_cqe>,
    _ body: @escaping @Sendable (_: io_uring_cqe) throws -> T
  ) throws -> T {
    guard cqe.pointee.res >= 0 else {
      Manager
        .logDebug(
          message: "\(type(of: self)) completion fileDescriptor: \(fd) opcode: \(opcodeDescription(opcode)) error: \(Errno(rawValue: cqe.pointee.res))"
        )
      throw (Errno(rawValue: cqe.pointee.res))
    }
    return try body(cqe.pointee)
  }
}

extension Submission: Equatable {
  public static func == (lhs: Submission, rhs: Submission) -> Bool {
    lhs.id == rhs.id
  }
}

extension Submission: Hashable {
  public func hash(into hasher: inout Hasher) {
    id.hash(into: &hasher)
  }
}

final class SingleshotSubmission<T>: Submission<T> {
  typealias Continuation = CheckedContinuation<T, Error>

  weak var group: SubmissionGroup<T>?
  private var continuation: Continuation!

  func submit() async throws -> T {
    try await withCheckedThrowingContinuation { (continuation: Continuation) in
      self.continuation = continuation
      do {
        if group != nil {
          ready()
        } else {
          try manager.submit()
        }
      } catch {
        continuation.resume(throwing: error)
        self.continuation = nil
      }
    }
  }

  override fileprivate func onCompletion(cqe: UnsafePointer<io_uring_cqe>) {
    do {
      try continuation.resume(returning: throwingErrno(cqe: cqe, handler))
    } catch {
      continuation.resume(throwing: error)
    }
  }
}

final class MultishotSubmission<T>: Submission<T> {
  private var channel = AsyncThrowingChannel<T, Error>()

  override init(
    manager: Manager,
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
  ) async throws {
    try await super.init(
      manager: manager,
      opcode,
      fd: fd,
      address: address,
      length: length,
      offset: offset,
      flags: flags,
      ioprio: ioprio,
      bufferIndex: bufferIndex,
      bufferGroup: bufferGroup,
      socketAddress: socketAddress,
      handler: handler
    )
  }

  fileprivate init(_ submission: MultishotSubmission) async throws {
    try await super.init(submission)
    channel = submission.channel
  }

  func submit() throws -> AsyncThrowingChannel<T, Error> {
    try manager.submit()
    return channel
  }

  private func resubmit() async {
    do {
      // this will allocate a new SQE with the same channel, fd, opcode and handler
      let resubmission = try await MultishotSubmission(self)
      Manager
        .logDebug(
          message: "resubmitting multishot submission \(resubmission) after cancel received"
        )
      _ = try resubmission.submit()
    } catch {
      Manager
        .logDebug(
          message: "resubmitting multishot submission failed: \(error)"
        )
      channel.fail(error)
    }
  }

  override fileprivate func onCompletion(cqe: UnsafePointer<io_uring_cqe>) {
    do {
      let result = try throwingErrno(cqe: cqe, handler)
      Task {
        await channel.send(result)
        if cqe.pointee.flags & IORING_CQE_F_MORE == 0 {
          // if IORING_CQE_F_MORE is not set, we need to issue a new request
          // try to do this implictily
          await resubmit()
        }
      }
      /*
       } catch Errno.canceled {
         // for some reason accept() likes to cancel, try to resubmit
         Task { await resubmit() }
       */
    } catch {
      channel.fail(error)
    }
  }
}

private func opcodeDescription(_ opcode: io_uring_op) -> String {
  switch opcode {
  case IORING_OP_NOP:
    "nop"
  case IORING_OP_READV:
    "readv"
  case IORING_OP_WRITEV:
    "writev"
  case IORING_OP_FSYNC:
    "fsync"
  case IORING_OP_READ_FIXED:
    "read_fixed"
  case IORING_OP_WRITE_FIXED:
    "write_fixed"
  case IORING_OP_POLL_ADD:
    "add"
  case IORING_OP_POLL_REMOVE:
    "remove"
  case IORING_OP_SYNC_FILE_RANGE:
    "sync_file_range"
  case IORING_OP_SENDMSG:
    "sendmsg"
  case IORING_OP_RECVMSG:
    "recvmsg"
  case IORING_OP_TIMEOUT:
    "timeout"
  case IORING_OP_TIMEOUT_REMOVE:
    "timeout_remove"
  case IORING_OP_ACCEPT:
    "accept"
  case IORING_OP_ASYNC_CANCEL:
    "async_cancel"
  case IORING_OP_LINK_TIMEOUT:
    "link_timeout"
  case IORING_OP_CONNECT:
    "connect"
  case IORING_OP_FALLOCATE:
    "fallocate"
  case IORING_OP_OPENAT:
    "openat"
  case IORING_OP_CLOSE:
    "close"
  case IORING_OP_FILES_UPDATE:
    "files_update"
  case IORING_OP_STATX:
    "statx"
  case IORING_OP_READ:
    "read"
  case IORING_OP_WRITE:
    "write"
  case IORING_OP_FADVISE:
    "fadvise"
  case IORING_OP_MADVISE:
    "madvise"
  case IORING_OP_SEND:
    "send"
  case IORING_OP_RECV:
    "recv"
  case IORING_OP_OPENAT2:
    "openat2"
  case IORING_OP_EPOLL_CTL:
    "epoll_ctl"
  case IORING_OP_SPLICE:
    "splice"
  case IORING_OP_PROVIDE_BUFFERS:
    "provide_buffers"
  case IORING_OP_REMOVE_BUFFERS:
    "remove_buffers"
  case IORING_OP_TEE:
    "tee"
  case IORING_OP_SHUTDOWN:
    "shutdown"
  case IORING_OP_RENAMEAT:
    "renameat"
  case IORING_OP_UNLINKAT:
    "unlinkat"
  case IORING_OP_MKDIRAT:
    "mkdirat"
  case IORING_OP_SYMLINKAT:
    "symlinkat"
  case IORING_OP_LINKAT:
    "linkat"
  /*
   case IORING_OP_MSG_RING:
   return "msg_ring"
   case IORING_OP_FSETXATTR:
   return "fsetxattr"
   case IORING_OP_SETXATTR:
   return "setxattr"
   case IORING_OP_FGETXATTR:
   return "fgetxattr"
   case IORING_OP_GETXATTR:
   return "getxattr"
   case IORING_OP_SOCKET:
   return "socket"
   case IORING_OP_URING_CMD:
   return "uring_cmd"
   case IORING_OP_SEND_ZC:
   return "send_zc"
   case IORING_OP_SENDMSG_ZC:
   return "sendmsg_zc"
   */
  default:
    "unknown"
  }
}
