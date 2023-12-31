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

import Glibc

/// FileDescriptorRepresentable is required for lifecycle management so file
/// descriptors are not closed whilst there are outstanding completions
public protocol FileDescriptorRepresentable: Sendable {
  var fileDescriptor: Int32 { get }
}

/// Include our own FileHandle for accept() so we do not need to import Foundation
public final class FileHandle: FileDescriptorRepresentable, CustomStringConvertible, Sendable {
  public let fileDescriptor: Int32
  private let closeOnDealloc: Bool

  public init(fileDescriptor: Int32, closeOnDealloc: Bool = false) throws {
    if fileDescriptor < 0 {
      let lastError = Errno.lastError
      if lastError.rawValue == 0 {
        throw Errno.badFileDescriptor
      } else {
        throw lastError
      }
    }
    self.closeOnDealloc = closeOnDealloc
    self.fileDescriptor = fileDescriptor
  }

  public var description: String {
    "\(type(of: self))(fileDescriptor: \(fileDescriptor))"
  }

  deinit {
    if closeOnDealloc, fileDescriptor != -1 {
      close(self.fileDescriptor)
    }
  }
}

extension FileHandle: Equatable {
  public static func == (lhs: FileHandle, rhs: FileHandle) -> Bool {
    lhs.fileDescriptor == rhs.fileDescriptor
  }
}

extension FileHandle: Hashable {
  public func hash(into hasher: inout Hasher) {
    fileDescriptor.hash(into: &hasher)
  }
}
