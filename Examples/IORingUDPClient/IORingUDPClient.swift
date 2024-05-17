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
import IORingUtils
import SocketAddress
import SystemPackage

@main
public struct IORingUDPClient {
  private let socket: Socket
  private let ring: IORing

  public static func main() async throws {
    guard CommandLine.arguments.count == 3,
          let address = try? sockaddr_storage(
            family: sa_family_t(AF_INET),
            presentationAddress: CommandLine.arguments[1]
          )
    else {
      print("Usage: \(CommandLine.arguments[0]) [address:port] [message]")
      exit(1)
    }

    let message = CommandLine.arguments[2]
    let client = try IORingUDPClient()
    try await client.connect(to: address)
    try await client.send(message: message)
  }

  init() throws {
    ring = IORing.shared
    socket = try Socket(ring: ring, domain: sa_family_t(AF_INET), type: SOCK_DGRAM, protocol: 0)
  }

  func connect(to address: any SocketAddress) async throws {
    debugPrint("connecting to address \(String(describing: try? address.presentationAddress))")
    try await socket.connect(to: address)
  }

  func send(message: String) async throws {
    guard let messageData = message.data(using: .utf8) else {
      throw Errno.invalidArgument
    }
    let message = try Message(buffer: [UInt8](messageData + [0]))
    try await socket.sendMessage(message)
  }
}
