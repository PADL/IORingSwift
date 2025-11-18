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

import AsyncAlgorithms
import AsyncExtensions
@_implementationOnly import CIORingShims
@_implementationOnly import CIOURing
import Glibc
import SystemPackage

extension msghdr: @retroactive @unchecked Sendable {}

// TODO: support for CMSG
public final class Message: @unchecked Sendable {
  // FIXME: again, this is a workaround for _XOPEN_SOURCE=500 clang importer issues
  public private(set) var name: [UInt8] {
    didSet {
      storage.msg_namelen = socklen_t(name.count)
    }
  }

  public private(set) var buffer: [UInt8]

  public var flags: UInt32 {
    UInt32(storage.msg_flags)
  }

  private var storage = msghdr()
  private var iov_storage = iovec()

  func withUnsafeMutablePointer<T>(
    ring: isolated IORing,
    _ body: (UnsafeMutablePointer<msghdr>) async throws -> T
  ) async rethrows -> T {
    try await body(&storage)
  }

  public init(
    name: [UInt8] = [],
    buffer: [UInt8] = [],
    flags: UInt32 = 0
  ) {
    self.name = name
    self.buffer = buffer

    storage.msg_flags = CInt(flags)
    self.buffer.withUnsafeMutableBytes {
      iov_storage.iov_base = UnsafeMutableRawPointer(mutating: $0.baseAddress)
    }
    iov_storage.iov_len = self.buffer.count
    self.name.withUnsafeMutableBytes {
      storage.msg_name = UnsafeMutableRawPointer(mutating: $0.baseAddress)
      storage.msg_namelen = socklen_t($0.count)
    }
    Swift.withUnsafeMutablePointer(to: &iov_storage) { iov_storage in
      storage.msg_iov = iov_storage
      storage.msg_iovlen = 1
    }
  }

  public convenience init(capacity: Int, flags: UInt32 = 0) {
    self.init(
      name: Array(repeating: 0, count: MemoryLayout<sockaddr_storage>.size),
      buffer: [UInt8](repeating: 0, count: capacity),
      flags: flags
    )
  }

  func copy() -> Self {
    Self(name: name, buffer: buffer, flags: flags)
  }
}

// TODO: support for CMSG
final class MessageHolder: @unchecked Sendable {
  private let size: Int
  private var storage = msghdr()
  private var address = sockaddr_storage()
  private var bufferSubmission: BufferSubmission<UInt8>
  let bufferGroup: UInt16

  init(ring: IORing, size: Int, count: Int, flags: UInt32 = 0) async throws {
    if size % MemoryLayout<io_uring_recvmsg_out>.alignment != 0 {
      throw Errno.invalidArgument
    }
    self.size = size + MemoryLayout<io_uring_recvmsg_out>.size + MemoryLayout<sockaddr_storage>.size
    bufferSubmission = try await BufferSubmission(ring: ring, size: size, count: count)
    bufferGroup = bufferSubmission.bufferGroup
    Swift.withUnsafeMutablePointer(to: &address) {
      self.storage.msg_name = UnsafeMutableRawPointer($0)
    }
    storage.msg_namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
    try bufferSubmission.submit()
    storage.msg_flags = Int32(flags)
  }

  deinit {
    let ring = bufferSubmission.ring
    let count = bufferSubmission.count
    let bufferGroup = bufferGroup
    Task {
      try await BufferSubmission<UInt8>(
        ring: ring,
        removing: count,
        from: bufferGroup
      ).submit()
    }
  }

  func receive(id bufferID: Int, count: Int? = nil) throws -> Message {
    try bufferSubmission.withUnsafeRawBufferPointer(id: bufferID) { pointer in
      guard let out = io_uring_recvmsg_validate(
        pointer.baseAddress!,
        Int32(count ?? size),
        &storage
      ) else {
        throw Errno.invalidArgument
      }

      // make the buffer available for reuse once we've copied the contents
      defer {
        Task {
          try await bufferSubmission.reprovideAndSubmit(id: bufferID)
        }
      }

      let name: [UInt8]

      if out.pointee.namelen != 0 {
        guard let peerName = io_uring_recvmsg_name(out) else {
          throw Errno.noMemory
        }
        name = Array(UnsafeRawBufferPointer(start: peerName, count: Int(out.pointee.namelen)))
      } else {
        name = []
      }

      var buffer = [UInt8]()
      if out.pointee.payloadlen != 0 {
        guard let payload = io_uring_recvmsg_payload(out, &storage) else {
          throw Errno.noMemory
        }
        buffer = Array(UnsafeRawBufferPointer(start: payload, count: Int(out.pointee.payloadlen)))
      }
      return Message(name: name, buffer: buffer, flags: out.pointee.flags)
    }
  }

  func withUnsafeMutablePointer<T: Sendable>(
    ring: isolated IORing,
    _ body: (UnsafeMutablePointer<msghdr>) async throws -> T
  ) async rethrows -> T {
    try await body(&storage)
  }
}
