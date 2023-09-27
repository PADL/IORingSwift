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

final class Submission<T>: CustomStringConvertible {
  weak var manager: Manager?
  weak var group: SubmissionGroup<T>?

  private let fd: FileDescriptorRepresentable
  private let opcode: UInt8 // store this for debugging
  private let ioprio: UInt16 // store this for distinguishing multishot
  private let handler: (io_uring_cqe) throws -> T

  private let sqe: UnsafeMutablePointer<io_uring_sqe>

  public var description: String {
    "\(type(of: self))(opcode: \(opcode), handler: \(String(describing: handler)), inGroup: \(inGroup))"
  }

  var inGroup: Bool {
    group != nil
  }

  private func setBlock(
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    handler: @escaping (UnsafePointer<io_uring_cqe>) -> ()
  ) throws {
    guard let manager else {
      return
    }
    io_uring_sqe_set_block(sqe) {
      // FIXME: this could race before io_uring_cqe_seen() is called, although shouldn't happen if on same actor
      handler($0)
      manager.resumePendingSubmission()
    }
    if inGroup {
      ready() // don't submit yet, but indicate to submission group that this submission has
      // registered continuation
    } else {
      try manager.submit()
    }
  }

  private func prepare(
    _ opcode: UInt8,
    sqe: UnsafeMutablePointer<io_uring_sqe>,
    fd: FileDescriptorRepresentable,
    address: UnsafeRawPointer?,
    length: CUnsignedInt,
    offset: Int
  ) {
    io_uring_prep_rw(
      CInt(opcode),
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

  init(
    manager: Manager,
    _ opcode: UInt8,
    fd: FileDescriptorRepresentable,
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
  ) async throws {
    sqe = try await manager.getAsyncSqe()
    self.fd = fd
    self.manager = manager
    self.opcode = opcode
    self.ioprio = ioprio
    self.handler = handler

    prepare(opcode, sqe: sqe, fd: fd, address: address, length: length, offset: offset)
    setFlags(
      sqe: sqe,
      flags: flags,
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
  }

  func submitSingleshot() async throws -> T {
    try await withCheckedThrowingContinuation { (
      continuation: CheckedContinuation<
        T,
        Error
      >
    ) in
      do {
        try setBlock(sqe: sqe) { [self] cqe in
          guard cqe.pointee.res >= 0 else {
            Manager
              .logDebug(
                message: "completion failed: \(Errno(rawValue: cqe.pointee.res))"
              )
            continuation.resume(throwing: Errno(rawValue: cqe.pointee.res))
            return
          }
          do {
            try continuation.resume(returning: handler(cqe.pointee))
          } catch {
            Manager.logDebug(message: "handler failed: \(error)")
            continuation.resume(throwing: error)
          }
        }
      } catch {
        continuation.resume(throwing: error)
      }
    }
  }

  func submitMultishot(_ channel: AsyncThrowingChannel<T, Error>) throws {
    try setBlock(sqe: sqe) { [self] cqe in
      guard cqe.pointee.res >= 0 else {
        if cqe.pointee.res == -ECANCELED {
          Task {
            do {
              try submitMultishot(channel)
            } catch {
              channel.fail(error)
            }
          }
        } else {
          Manager
            .logDebug(
              message: "completion failed: \(Errno(rawValue: cqe.pointee.res))"
            )
          if cqe.pointee.res == -EINVAL {
            print(
              "IORingSwift: multishot io_uring submission failed, are you running a recent enough kernel?"
            )
          }
          channel.fail(Errno(rawValue: cqe.pointee.res))
        }
        return
      }
      do {
        let result = try handler(cqe.pointee)
        Task { await channel.send(result) }
      } catch {
        Manager.logDebug(message: "handler failed: \(error)")
        channel.fail(error)
      }
    }
  }
}

extension Submission: Equatable {
  public static func == (lhs: Submission, rhs: Submission) -> Bool {
    ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
  }
}

extension Submission: Hashable {
  public func hash(into hasher: inout Hasher) {
    ObjectIdentifier(self).hash(into: &hasher)
  }
}
