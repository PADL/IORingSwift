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

public struct Control {
  public var level: Int32
  public var type: Int32
  public var data: [UInt8]
}

public final class Message {
  // FIXME: again, this is a workaround for _XOPEN_SOURCE=500 clang importer issues
  public var name: [UInt8] {
    get {
      withUnsafeBytes(of: address) {
        Array($0)
      }
    }
    set {
      address = try! sockaddr_storage(bytes: newValue)
    }
  }

  public var address: sockaddr_storage {
    didSet {
      Swift.withUnsafeMutablePointer(to: &address) { pointer in
        storage.msg_name = UnsafeMutableRawPointer(pointer)
        storage.msg_namelen = (try? pointer.pointee.size) ?? 0
      }
    }
  }

  public var buffer: [UInt8] {
    didSet {
      buffer.withUnsafeMutableBytes { bytes in
        iov_storage.iov_base = bytes.baseAddress
        iov_storage.iov_len = bytes.count
      }
    }
  }

  public var control = [Control]()

  public var flags: UInt32 {
    get {
      UInt32(storage.msg_flags)
    }
    set {
      storage.msg_flags = Int32(newValue)
    }
  }

  private var storage = msghdr()
  private var iov_storage = iovec()

  func withUnsafeMutablePointer<T>(
    _ body: (UnsafeMutablePointer<msghdr>) async throws
      -> T
  ) async rethrows
    -> T
  {
    try await body(&storage)
  }

  init(address: sockaddr_storage, buffer: [UInt8] = [], flags: UInt32 = 0) {
    self.address = address
    self.buffer = buffer
    self.flags = flags
    init_storage()
  }

  func copy() -> Self {
    Self(address: address, buffer: buffer, flags: flags)
  }

  // FIXME: see note below about _XOPEN_SOURCE=500 sockaddr clang importer issues
  public convenience init(
    name: [UInt8]? = nil,
    buffer: [UInt8] = [],
    flags: UInt32 = 0
  ) throws {
    let ss: sockaddr_storage = if let name {
      try sockaddr_storage(bytes: name)
    } else {
      sockaddr_storage()
    }
    self.init(address: ss, buffer: buffer, flags: 0)
  }

  public convenience init(capacity: Int, flags: UInt32 = 0) {
    self.init(
      address: sockaddr_storage(),
      buffer: [UInt8](repeating: 0, count: capacity),
      flags: flags
    )
    // special case for receiving messages
    storage.msg_namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
  }

  func init_storage() {
    Swift.withUnsafeMutablePointer(to: &address) { pointer in
      // forces didSet to be called
      _ = pointer
    }
    buffer.withUnsafeMutableBytes { bytes in
      // forces didSet to be called
      _ = bytes
    }
    Swift.withUnsafeMutablePointer(to: &iov_storage) { iov_storage in
      storage.msg_iov = iov_storage
      storage.msg_iovlen = 1
    }
  }
}

final class MessageHolder {
  private let size: Int
  private var storage = msghdr()
  private var bufferSubmission: BufferSubmission<UInt8>
  let bufferGroup: UInt16

  init(manager: Manager, size: Int, count: Int) throws {
    if size % MemoryLayout<io_uring_recvmsg_out>.alignment != 0 {
      throw Errno.invalidArgument
    }
    self.size = size + MemoryLayout<io_uring_recvmsg_out>.size + MemoryLayout<sockaddr_storage>.size
    bufferSubmission = try BufferSubmission(manager: manager, size: size, count: count)
    bufferGroup = bufferSubmission.bufferGroup
    try bufferSubmission.submit()
  }

  private func removeBuffer() {
    let manager = bufferSubmission.manager
    let count = bufferSubmission.count
    let bufferGroup = bufferGroup
    manager.perform { ring in
      let submission = try BufferSubmission<UInt8>(
        manager: ring.manager,
        removing: count,
        from: bufferGroup
      )
      try submission.submit()
    }
  }

  deinit {
    removeBuffer()
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
        bufferSubmission.manager.perform { [self] _ in
          try bufferSubmission.reprovideAndSubmit(id: bufferID)
        }
      }

      var address = sockaddr_storage()
      if out.pointee.namelen != 0 {
        guard let name = io_uring_recvmsg_name(out) else {
          throw Errno.noMemory
        }
        name.withMemoryRebound(to: sockaddr_storage.self, capacity: 1) { name in
          address = name.pointee
        }
      }

      var buffer = [UInt8]()
      if out.pointee.payloadlen != 0 {
        guard let payload = io_uring_recvmsg_payload(out, &storage) else {
          throw Errno.noMemory
        }
        buffer = Array(UnsafeRawBufferPointer(start: payload, count: Int(out.pointee.payloadlen)))
      }
      return Message(address: address, buffer: buffer, flags: out.pointee.flags)
    }
  }

  func withUnsafeMutablePointer<T>(
    _ body: (UnsafeMutablePointer<msghdr>) throws
      -> T
  ) rethrows
    -> T
  {
    try body(&storage)
  }
}
