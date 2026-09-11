//
// Copyright (c) 2026 PADL Software Pty Ltd
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

// Round trips between pairs of sockets on the shared ring, both ends in this process: each
// pair's client writes a message, its server reads it and writes it back. Uses only the
// public API, so it builds against any revision.
//
//   IORingSocketBench [seconds per pair count]
//
// Environment: BENCH_TRANSPORT (unix or tcp, default unix), BENCH_PAIRS (default
// "1 4 16 64"), BENCH_SIZE (message bytes, default 64), BENCH_PORT (tcp, default 58800).
//
// For each pair count prints
//   RESULT <transport> <pairs> <round trips/s> <ns per round trip> <CPU ns per round trip>
// where ns per round trip is as one pair sees it, and CPU is user and system time for the
// whole process.

import Glibc
import IORing
import IORingUtils
import struct SystemPackage.Errno

private func environment(_ name: String) -> String? {
  getenv(name).map { String(cString: $0) }
}

private func cpuNanoseconds() -> Double {
  var usage = rusage()
  getrusage(Int32(RUSAGE_SELF.rawValue), &usage)
  func ns(_ tv: timeval) -> Double { Double(tv.tv_sec) * 1e9 + Double(tv.tv_usec) * 1e3 }
  return ns(usage.ru_utime) + ns(usage.ru_stime)
}

private func unixPair() throws -> (Socket, Socket) {
  var fds = [Int32](repeating: -1, count: 2)
  guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
    throw Errno(rawValue: errno)
  }
  return try (
    Socket(ring: IORing.shared, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
    Socket(ring: IORing.shared, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
  )
}

private func tcpPairs(_ count: Int, port: UInt16) async throws -> [(Socket, Socket)] {
  let listener = try Socket(ring: IORing.shared, domain: sa_family_t(AF_INET), type: SOCK_STREAM)
  try listener.setReuseAddr()
  try listener.bind(port: port)
  try listener.listen(backlog: count)
  var address = sockaddr_in()
  address.sin_family = sa_family_t(AF_INET)
  address.sin_port = port.bigEndian
  address.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian
  var pairs = [(Socket, Socket)]()
  for _ in 0..<count {
    let client = try Socket(ring: IORing.shared, domain: sa_family_t(AF_INET), type: SOCK_STREAM)
    try await client.connect(to: address)
    let server = try await listener.accept() as Socket
    try client.setTcpNoDelay()
    try server.setTcpNoDelay()
    pairs.append((client, server))
  }
  return pairs
}

private func echo(_ server: Socket, size: Int) async {
  while let message = try? await server.read(count: size, awaitingAllRead: true),
        message.count == size
  {
    guard (try? await server.write(message, count: size, awaitingAllWritten: true)) != nil else {
      return
    }
  }
}

private func roundTrips(_ client: Socket, size: Int, until deadline: ContinuousClock.Instant) async throws -> Int {
  let message = [UInt8](repeating: 0x5A, count: size)
  var count = 0
  while ContinuousClock.now < deadline {
    _ = try await client.write(message, count: size, awaitingAllWritten: true)
    let reply = try await client.read(count: size, awaitingAllRead: true)
    guard reply.count == size else { throw Errno.connectionReset }
    count += 1
  }
  return count
}

@main
enum IORingSocketBench {
  static func main() async throws {
    let seconds = CommandLine.arguments.count > 1 ? Double(CommandLine.arguments[1]) ?? 5 : 5
    let transport = environment("BENCH_TRANSPORT") ?? "unix"
    let pairCounts = (environment("BENCH_PAIRS") ?? "1 4 16 64").split(separator: " ").compactMap { Int($0) }
    let size = environment("BENCH_SIZE").flatMap(Int.init) ?? 64
    var port = environment("BENCH_PORT").flatMap(UInt16.init) ?? 58800

    for pairCount in pairCounts {
      let pairs = if transport == "tcp" {
        try await tcpPairs(pairCount, port: port)
      } else {
        try (0..<pairCount).map { _ in try unixPair() }
      }
      port += 1

      for (_, server) in pairs {
        Task { await echo(server, size: size) }
      }
      // warm up, then measure
      _ = try await roundTrips(pairs[0].0, size: size, until: .now + .milliseconds(200))

      let cpuStart = cpuNanoseconds()
      let start = ContinuousClock.now
      let deadline = start + .milliseconds(Int(seconds * 1000))
      let total = try await withThrowingTaskGroup(of: Int.self) { group in
        for (client, _) in pairs {
          group.addTask { try await roundTrips(client, size: size, until: deadline) }
        }
        var total = 0
        for try await count in group {
          total += count
        }
        return total
      }
      let elapsed = ContinuousClock.now - start
      let elapsedNs = Double(elapsed.components.seconds) * 1e9 + Double(elapsed.components.attoseconds) / 1e9
      let cpu = cpuNanoseconds() - cpuStart
      print(
        "RESULT \(transport) \(pairCount) \(Int(Double(total) / elapsedNs * 1e9)) " +
          "\(Int(elapsedNs * Double(pairCount) / Double(total))) \(Int(cpu / Double(total)))"
      )
    }
  }
}
