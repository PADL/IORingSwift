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
import Foundation
import Glibc
import IORing
import IORingUtils

@main
public struct IORingUDPServer {
  private let socket: Socket
  private let ring: IORing

  public static func main() async throws {
    guard CommandLine.arguments.count == 2,
          let port = UInt16(CommandLine.arguments[1])
    else {
      print("Usage: \(CommandLine.arguments[0]) [port]")
      exit(1)
    }

    let server = try IORingUDPServer()
    try await server.bind(port: port)
    try await server.run()
  }

  init() throws {
    ring = try IORing()
    socket = try Socket(ring: ring, domain: sa_family_t(AF_INET), type: SOCK_DGRAM, protocol: 0)
  }

  func bind(port: UInt16) async throws {
    try socket.bind(port: port)
  }

  func run() async throws {
    let channel = try await socket.receiveMessages(count: 1500)
    for try await message in channel {
      print(message)
    }
  }
}
