//
// Copyright (c) 2023-2025 PADL Software Pty Ltd
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
import IORingUtils
import struct SystemPackage.Errno

private func usage() -> Never {
  print("Usage: \(CommandLine.arguments[0]) [port|dg-path]")
  exit(1)
}

@main
public struct IORingDatagramServer {
  private let socket: Socket
  private let ring: IORing

  public static func main() async throws {
    guard CommandLine.arguments.count == 2 else { usage() }

    var path: String?
    var port: UInt16?

    if CommandLine.arguments[1].hasPrefix("/") {
      path = CommandLine.arguments[1]
    } else if let p = UInt16(CommandLine.arguments[1]) {
      port = p
    } else {
      usage()
    }

    let server = try Self(domain: sa_family_t(path != nil ? AF_LOCAL : AF_INET))
    if let path {
      try await server.bind(path: path)
    } else if let port {
      try await server.bind(port: port)
    }
    try await server.run()
  }

  init(domain: sa_family_t) throws {
    ring = IORing.shared
    socket = try Socket(ring: ring, domain: domain, type: SOCK_DGRAM, protocol: 0)
  }

  func bind(port: UInt16) async throws {
    try socket.bind(port: port)
  }

  func bind(path: String) async throws {
    try socket.bind(path: path)
  }

  func run() async throws {
    repeat {
      do {
        let channel = try await socket.receiveMessages(count: 1500)
        for try await message in channel {
          print(message)
        }
      } catch let errno as SystemPackage.Errno {
        guard errno == .canceled else { throw errno }
      }
    } while true
  }
}
