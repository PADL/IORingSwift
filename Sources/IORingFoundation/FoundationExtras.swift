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
      try withUnsafeBytes { data -> (any SocketAddress) in
        var family = sa_family_t(AF_UNSPEC)

        try data.withMemoryRebound(to: sockaddr.self) {
          let sa = $0.baseAddress!.pointee
          family = sa.sa_family
          guard sa.size <= self.count else { // ignores trailing bytes
            throw Errno.addressFamilyNotSupported
          }
        }

        switch Int32(family) {
        case AF_INET:
          var sin = sockaddr_in()
          memcpy(&sin, data.baseAddress!, Int(sin.size))
          return sin
        case AF_INET6:
          var sin6 = sockaddr_in6()
          memcpy(&sin6, data.baseAddress!, Int(sin6.size))
          return sin6
        case AF_LOCAL:
          var sun = sockaddr_un()
          memcpy(&sun, data.baseAddress!, Int(sun.size))
          return sun
        default:
          throw Errno.addressFamilyNotSupported
        }
      }
    }
  }
}

extension Foundation.FileHandle: FileDescriptorRepresentable, @unchecked Sendable {}
