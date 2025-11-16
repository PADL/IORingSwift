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
import IORingFoundation
import IORingUtils
import SocketAddress
import struct SystemPackage.Errno

private func usage() -> Never {
  print("Usage: \(CommandLine.arguments[0]) [address:port|dg-path] [message]")
  exit(1)
}

@main
public struct IORingDatagramClient {
  private let socket: Socket
  private let ring: IORing

  public static func main() async throws {
    guard CommandLine.arguments.count == 3 else { usage() }

    let family = sa_family_t(CommandLine.arguments[1].hasPrefix("/") ? AF_LOCAL : AF_INET)
    guard let address = try? AnySocketAddress(
      family: family,
      presentationAddress: CommandLine.arguments[1]
    ) else {
      usage()
    }
    let client = try Self(domain: family)
    let message = CommandLine.arguments[2]

    do {
      if family == sa_family_t(AF_LOCAL) {
        try await client.bind(to: sockaddr_un.ephemeralDatagramDomainSocketName)
      }
      try await client.connect(to: address)
      try await client.send(message: message)
    } catch {
      print("error: \(error)")
    }
  }

  init(domain: sa_family_t) throws {
    ring = IORing.shared
    socket = try Socket(ring: ring, domain: domain, type: SOCK_DGRAM, protocol: 0)
  }

  func bind(to address: any SocketAddress) async throws {
    debugPrint("binding to local address \(String(describing: try? address.presentationAddress))")
    try socket.bind(to: address)
  }

  func connect(to address: any SocketAddress) async throws {
    debugPrint(
      "connecting to remote address \(String(describing: try? address.presentationAddress))"
    )
    try await socket.connect(to: address)
  }

  func send(message: String) async throws {
    guard let messageData = message.data(using: .utf8) else {
      throw Errno.invalidArgument
    }
    let message = Message(buffer: [UInt8](messageData + [0]))
    try await socket.sendMessage(message)
  }
}
