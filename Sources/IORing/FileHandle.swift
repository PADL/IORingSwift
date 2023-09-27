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
public protocol FileDescriptorRepresentable {
  var fileDescriptor: Int32 { get }
}

/// Include our own FileHandle for accept() so we do not need to import Foundation
public final class FileHandle: FileDescriptorRepresentable, CustomStringConvertible {
  public private(set) var fileDescriptor: Int32

  public init(fileDescriptor: Int32) throws {
    if fileDescriptor < 0 {
      let lastError = Errno.lastError
      if lastError.rawValue == 0 {
        throw Errno.badFileDescriptor
      } else {
        throw lastError
      }
    }
    self.fileDescriptor = fileDescriptor
  }

  public var description: String {
    "\(type(of: self))(fileDescriptor: \(fileDescriptor))"
  }

  deinit {
    if fileDescriptor != -1 {
      try? _close()
    }
  }

  private func _close() throws {
    try Errno.throwingErrno {
      SwiftGlibc.close(self.fileDescriptor)
    }
    fileDescriptor = -1
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
