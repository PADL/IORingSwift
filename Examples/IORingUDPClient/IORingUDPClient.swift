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
public struct IORingUDPClient {
    private let socket: Socket
    private let ring: IORing

    public static func main() async throws {
        guard CommandLine.arguments.count == 3,
              let address = try? sockaddr_storage(
                  family: AF_INET,
                  presentationAddress: CommandLine.arguments[1]
              )
        else {
            print("Usage: \(CommandLine.arguments[0]) [address:port] [message]")
            exit(1)
        }

        let message = CommandLine.arguments[2]
        let client = try IORingUDPClient()
        try await client.send(message: message, to: address)
    }

    init() throws {
        ring = try IORing()
        socket = try Socket(domain: AF_INET, type: SOCK_DGRAM.rawValue, protocol: 0)
    }

    func send(message: String, to address: sockaddr_storage) async throws {
        guard let messageData = message.data(using: .utf8) else {
            throw Errno(rawValue: EINVAL)
        }
        let message = IORing.Message(buffer: [UInt8](messageData))
        try await socket.sendmsg(message, ring: ring)
    }
}
