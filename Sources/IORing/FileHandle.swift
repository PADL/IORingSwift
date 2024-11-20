//
// Copyright (c) 2023-2024 PADL Software Pty Ltd
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

import Glibc
import SystemPackage

/// FileDescriptorRepresentable is required for lifecycle management so file
/// descriptors are not closed whilst there are outstanding completions
public protocol FileDescriptorRepresentable: Sendable {
  var fileDescriptor: CInt { get }
}

/// Include our own FileHandle for accept() so we do not need to import Foundation
public final class FileHandle: FileDescriptorRepresentable, CustomStringConvertible, Sendable {
  public var fileDescriptor: CInt { _fileDescriptor.rawValue }
  private let _fileDescriptor: FileDescriptor
  private let closeOnDealloc: Bool

  public convenience init(fileDescriptor: CInt, closeOnDealloc: Bool = false) throws {
    if fileDescriptor < 0 {
      let lastError = errno
      if lastError == 0 {
        throw Errno.badFileDescriptor
      } else {
        throw Errno(rawValue: lastError)
      }
    }
    try self.init(
      fileDescriptor: FileDescriptor(rawValue: fileDescriptor),
      closeOnDealloc: closeOnDealloc
    )
  }

  public init(fileDescriptor: FileDescriptor, closeOnDealloc: Bool = false) throws {
    self.closeOnDealloc = closeOnDealloc
    _fileDescriptor = fileDescriptor
  }

  public var description: String {
    "\(type(of: self))(fileDescriptor: \(fileDescriptor))"
  }

  deinit {
    if closeOnDealloc, _fileDescriptor.rawValue != -1 {
      try? self._fileDescriptor.close()
    }
  }
}

extension FileHandle: Equatable {
  public static func == (lhs: FileHandle, rhs: FileHandle) -> Bool {
    lhs._fileDescriptor == rhs._fileDescriptor
  }
}

extension FileHandle: Hashable {
  public func hash(into hasher: inout Hasher) {
    _fileDescriptor.hash(into: &hasher)
  }
}

extension FileDescriptor: FileDescriptorRepresentable {
  public var fileDescriptor: CInt { rawValue }
}
