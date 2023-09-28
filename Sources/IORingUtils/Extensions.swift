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

import AsyncExtensions
import Glibc
import IORing

private func hexDescription(_ bytes: [UInt8]) -> String {
  bytes.reduce("") { $0 + String(format: "%02x", $1) }
}

extension Message: CustomStringConvertible {
  public convenience init(
    address: any SocketAddress,
    buffer: [UInt8],
    flags: Int32 = 0
  ) throws {
    var addressBuffer = [UInt8](repeating: 0, count: Int(address.size))
    addressBuffer.withUnsafeMutableBytes { bytes in
      var storage = address.asStorage()
      _ = memcpy(bytes.baseAddress!, &storage, bytes.count)
    }
    try self.init(name: addressBuffer, buffer: buffer, flags: flags)
  }

  public var description: String {
    let address = (try? sockaddr(bytes: name).presentationAddress) ?? "<unknown>"
    return "\(type(of: self))(address: \(address), buffer: \(hexDescription(buffer)), flags: \(flags))"
  }
}

public extension IORing {
  struct AsyncByteSequence: AsyncSequence {
    public typealias Element = UInt8

    let ring: IORing
    let fd: FileDescriptorRepresentable

    public struct AsyncIterator: AsyncIteratorProtocol {
      let ring: IORing
      let fd: FileDescriptorRepresentable

      public mutating func next() async throws -> Element? {
        guard !Task.isCancelled else {
          return nil
        }

        var buffer = [UInt8](repeating: 0, count: 1)
        if try await ring.read(into: &buffer, count: 1, from: fd) == false {
          return nil
        }
        return buffer.first
      }
    }

    public func makeAsyncIterator() -> AsyncIterator {
      AsyncIterator(ring: ring, fd: fd)
    }
  }

  func asyncBytes(
    from fd: FileDescriptorRepresentable
  ) -> AnyAsyncSequence<UInt8> {
    AsyncByteSequence(ring: self, fd: fd).eraseToAnyAsyncSequence()
  }
}

extension UnsafeMutablePointer {
  func propertyBasePointer<Property>(to property: KeyPath<Pointee, Property>)
    -> UnsafePointer<Property>?
  {
    guard let offset = MemoryLayout<Pointee>.offset(of: property) else { return nil }
    return (UnsafeRawPointer(self) + offset).assumingMemoryBound(to: Property.self)
  }
}

extension IORing {
  func connect(_ fd: FileDescriptorRepresentable, to address: any SocketAddress) async throws {
    var addressBuffer = [UInt8]()
    withUnsafeBytes(of: address.asStorage()) {
      addressBuffer = [UInt8]($0)
    }
    try await connect(fd, to: addressBuffer)
  }
}

public extension FileDescriptorRepresentable {
  func set(flags: Int32, mask: Int32) throws {
    var flags = try Errno.throwingErrno { fcntl(self.fileDescriptor, F_GETFL, 0) }
    flags &= ~(mask)
    flags |= mask
    try Errno.throwingErrno { fcntl(self.fileDescriptor, F_SETFL, flags) }
  }

  func get(flag: Int32) throws -> Bool {
    let flags = try Errno.throwingErrno { fcntl(self.fileDescriptor, F_GETFL, 0) }
    return flags & flag != 0
  }

  func set(flag: Int32, to enabled: Bool) throws {
    try set(flags: enabled ? flag : 0, mask: flag)
  }

  func setBlocking(_ enabled: Bool) throws {
    try set(flag: O_NONBLOCK, to: enabled)
  }

  var isBlocking: Bool {
    get throws {
      try get(flag: O_NONBLOCK)
    }
  }

  func getSize() throws -> Int {
    var st = stat()

    if fstat(fileDescriptor, &st) < 0 {
      throw Errno.lastError
    }

    if st.st_mode & S_IFMT == S_IFREG {
      return st.st_size
    } else {
      throw Errno.invalidArgument
    }
  }
}
