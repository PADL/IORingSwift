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

  fileprivate typealias FixedBuffer = [UInt8]
  private var buffers: [FixedBuffer]?
  private var iov: [iovec]?
  private var nextBufferGroup: UInt16 = 1

  weak var ioRing: IORing?
  let depth: Int

  static func logDebug(message: String, functionName: String = #function) {
    debugPrint("IORing.Manager.\(functionName): \(message)")
  }

  init(depth: CUnsignedInt, flags: CUnsignedInt) throws {
    var ring = io_uring()

    self.depth = Int(depth)
    try Errno.throwingErrno {
      io_uring_queue_init(depth, &ring, flags)
    }
    self.ring = ring
    try Errno.throwingErrno {
      io_uring_init_cq_handler(&self.eventHandle, &self.ring)
    }
  }

  func perform(_ body: @escaping (isolated IORing) async throws -> ()) {
    Task { try await ioRing?.perform(body) }
  }

  deinit {
    io_uring_deinit_cq_handler(eventHandle, &ring)
    if hasRegisteredBuffers {
      try? unregisterBuffers()
    }
    // FIXME: where are unhandled completion blocks deallocated?
    io_uring_queue_exit(&ring)
  }

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

  func prepareAndSubmit<T>(
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
    @_inheritActorContext handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws -> T {
    try await SingleshotSubmission(
      manager: self,
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

  func prepareAndSubmitMultishot<T>(
    _ opcode: io_uring_op,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer? = nil,
    length: CUnsignedInt = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    bufferIndex: UInt16 = 0,
    bufferGroup: UInt16 = 0,
    @_inheritActorContext handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) throws -> AsyncThrowingChannel<T, Error> {
    try MultishotSubmission(
      manager: self,
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

  func prepareAndSubmitIovec<T>(
    _ opcode: io_uring_op,
    fd: FileDescriptorRepresentable,
    iovecs: [iovec]? = nil,
    offset: Int = 0,
    flags: IORing.SqeFlags = IORing.SqeFlags(),
    ioprio: UInt16 = 0,
    moreFlags: UInt32 = 0,
    @_inheritActorContext handler: @escaping @Sendable (io_uring_cqe) throws -> T
  ) async throws -> T {
    let iovecs = iovecs ?? []
    var submission: SingleshotSubmission<T>!

    try iovecs.withUnsafeBufferPointer { pointer in
      submission = try SingleshotSubmission(
        manager: self,
        opcode,
        fd: fd,
        address: pointer.baseAddress,
        length: CUnsignedInt(pointer.count),
        offset: offset,
        flags: flags,
        ioprio: ioprio,
        moreFlags: moreFlags,
        handler: handler
      )
    }
    return try await submission.submit()
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
