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

import Foundation
import IORing
import IORingUtils
import SocketAddress
import SystemPackage

public extension Data {
  var socketAddress: any SocketAddress {
    get throws {
      try AnySocketAddress(bytes: Array(self))
    }
  }
}

public extension sockaddr_un {
  static var ephemeralDatagramDomainSocketName: Self {
    get throws {
      let temporaryDirectoryURL = FileManager.default.temporaryDirectory
      let uniqueFilename = UUID().uuidString
      let temporaryFileURL = temporaryDirectoryURL.appendingPathComponent(uniqueFilename)
      return try sockaddr_un(
        family: sa_family_t(AF_UNIX),
        presentationAddress: temporaryFileURL.path
      )
    }
  }
}

extension Foundation.FileHandle: FileDescriptorRepresentable, @unchecked Sendable {}
