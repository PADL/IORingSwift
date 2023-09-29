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

@main
public struct IORingTCPEcho {
  private let socket: Socket
  private let ring: IORing
  private let bufferSize: Int

  public static func main() async throws {
    guard CommandLine.arguments.count == 2,
          let port = UInt16(CommandLine.arguments[1])
    else {
      print("Usage: \(CommandLine.arguments[0]) [port]")
      exit(1)
    }

    let echo = try IORingTCPEcho(port: port)
    try await echo.runMultishot()
  }

  init(port: UInt16, bufferSize: Int = 32, backlog: Int = 5) throws {
    self.bufferSize = bufferSize
    ring = try IORing(depth: 10)
    socket = try Socket(
      ring: ring,
      domain: sa_family_t(AF_INET),
      type: SOCK_STREAM,
      protocol: 0
    )
    try socket.setReuseAddr()
    try socket.setTcpNoDelay()
    try socket.bind(port: port)
    try socket.listen(backlog: backlog)
  }

  func readWriteEcho(client: Socket) async {
    do {
      var more = false
      repeat {
        var buffer = [UInt8](repeating: 0, count: 1)
        more = try await client.read(into: &buffer, count: 1)
        if more {
          try await client.write(buffer, count: 1)
        }
      } while more
    } catch {
      debugPrint("closed client \(client): error \(error)")
    }
    debugPrint("closed client \(client)")
  }

  func receiveSendEcho(client: Socket) async {
    do {
      repeat {
        let data = try await client.receive(count: bufferSize)
        try await client.send(data)
      } while true
    } catch {
      debugPrint("closed client \(client)")
    }
  }

  func runSingleshot() async throws {
    repeat {
      let client: Socket = try await socket.accept()
      debugPrint("accepted client \(client)")
      Task { await readWriteEcho(client: client) }
    } while true
  }

  func runMultishot() async throws {
    let clients: AnyAsyncSequence<Socket> = try await socket.accept()
    for try await client in clients {
      debugPrint("accepted client \(client)")
      Task { await readWriteEcho(client: client) }
    }
  }
}
