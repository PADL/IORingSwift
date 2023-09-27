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

  var ring: io_uring
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

  private func getSqe() throws -> UnsafeMutablePointer<io_uring_sqe> {
    guard let sqe = io_uring_get_sqe(&ring) else {
      throw Errno.resourceTemporarilyUnavailable
    }
    return sqe
  }

  func getAsyncSqe() async throws -> UnsafeMutablePointer<io_uring_sqe> {
    repeat {
      do {
        guard let sqe = try? getSqe() else {
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

  func submit() throws {
    try Errno.throwingErrno {
      io_uring_submit(&self.ring)
    }
  }

  private func suspendPendingSubmission() async throws {
    try await withCheckedThrowingContinuation { continuation in
      pendingSubmissions.enqueue(continuation)
    }
  }

  func resumePendingSubmission() {
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
    handler: @escaping (io_uring_cqe) throws -> T
  ) async throws -> T {
    let submission = try await Submission(
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
    )
    return try await submission.submitSingleshot()
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
    handler: @escaping (io_uring_cqe) throws -> T
  ) async throws -> AsyncThrowingChannel<T, Error> {
    let channel = AsyncThrowingChannel<T, Error>()
    let submission = try await Submission(
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
    )
    try submission.submitMultishot(channel)
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
