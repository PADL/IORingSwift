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

// Small awaited writes on unix stream socket pairs, one way: each writer task sends a message,
// awaits its completion, and sends the next; a reader per pair drains it. Models a daemon that
// notifies a local peer one PDU at a time. Uses only the public API, so it builds against any
// revision.
//
// Environment:
//   BENCH_WRITERS   writer counts to run, default "1 8"; each writer has its own socket pair
//   BENCH_OPS       writes per writer, default 200000
//   BENCH_SIZE      message bytes, default 40 (at least 8: a message starts with its send time)
//   BENCH_READER    "ring" (default): a task reading through the ring; "thread": a thread in
//                   read(2), as a peer process would be, whose CPU time is reported apart
//   BENCH_PACE_US   if set, a writer sleeps this long between bursts, so each burst starts from
//                   an idle pool; BENCH_BURST (default 1) writes per burst
//
// For each writer count prints
//   RESULT <reader> <writers> <ops> <wall ns/op> <cpu ns/op> <user ns/op> <sys ns/op>
//          <voluntary switches/op> <write p50> <write p99> <write max>
//          <delivery p50> <delivery p99> <delivery max>
// CPU and voluntary context switches are the process's less the reader threads'; user and
// system time are the whole process's. A write's time is from the call to its
// return; delivery is from the call to the reader having the message, both in ns. Wall time
// per op is the elapsed time over one writer's count.

import Foundation
import IORing
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno

private func environment(_ name: String) -> String? {
  getenv(name).map { String(cString: $0) }
}

private func now() -> UInt64 {
  var ts = timespec()
  clock_gettime(CLOCK_MONOTONIC, &ts)
  return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
}

private struct Usage {
  var user: Double
  var system: Double
  var switches: Double

  static func current() -> Usage {
    var usage = rusage()
    getrusage(Int32(RUSAGE_SELF.rawValue), &usage)
    func ns(_ tv: timeval) -> Double {
      Double(tv.tv_sec) * 1e9 + Double(tv.tv_usec) * 1e3
    }
    return Usage(
      user: ns(usage.ru_utime),
      system: ns(usage.ru_stime),
      switches: Double(usage.ru_nvcsw)
    )
  }
}

private final class Samples: @unchecked Sendable {
  var values: [UInt32]

  init(capacity: Int) {
    values = []
    values.reserveCapacity(capacity)
  }

  func add(_ ns: UInt64) {
    values.append(UInt32(clamping: ns))
  }
}

private func percentiles(_ samples: [Samples]) -> (UInt32, UInt32, UInt32) {
  var all = samples.flatMap(\.values)
  guard !all.isEmpty else { return (0, 0, 0) }
  all.sort()
  return (all[all.count / 2], all[min(all.count - 1, all.count * 99 / 100)], all[all.count - 1])
}

/// what a reader thread is given, and what it leaves behind
private final class ThreadReader: @unchecked Sendable {
  let fd: Int32
  let size: Int
  let expected: Int
  let delivery: Samples
  var cpu: Double = 0
  var switches: Double = 0
  var thread = pthread_t()

  init(fd: Int32, size: Int, expected: Int) {
    self.fd = fd
    self.size = size
    self.expected = expected
    delivery = Samples(capacity: expected)
  }

  func run() {
    var buffer = [UInt8](repeating: 0, count: size * 256)
    var received = 0, held = 0
    while received < expected {
      let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress! + held, $0.count - held) }
      guard n > 0 else { break }
      let time = now()
      held += n
      var offset = 0
      buffer.withUnsafeBytes { bytes in
        while held - offset >= size {
          let sent = bytes.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
          delivery.add(time &- sent)
          offset += size
          received += 1
        }
      }
      buffer.withUnsafeMutableBytes { bytes in
        _ = memmove(bytes.baseAddress!, bytes.baseAddress! + offset, held - offset)
      }
      held -= offset
    }
    var usage = rusage()
    getrusage(__rusage_who_t(1), &usage) // RUSAGE_THREAD
    cpu = Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1e9 +
      Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) * 1e3
    switches = Double(usage.ru_nvcsw)
  }
}

private func ringReader(_ socket: Socket, size: Int, expected: Int, delivery: Samples) async {
  var buffer = [UInt8](repeating: 0, count: size * 256)
  var received = 0
  var pending = [UInt8]()
  while received < expected {
    guard let n = try? await socket.read(into: &buffer, count: buffer.count), n > 0 else { break }
    let time = now()
    pending.append(contentsOf: buffer[0..<n])
    var offset = 0
    pending.withUnsafeBytes { bytes in
      while bytes.count - offset >= size {
        let sent = bytes.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
        delivery.add(time &- sent)
        offset += size
        received += 1
      }
    }
    pending.removeFirst(offset)
  }
}

private func writer(
  _ socket: Socket,
  size: Int,
  ops: Int,
  pace: Duration?,
  burst: Int,
  latency: Samples
) async throws {
  var message = [UInt8](repeating: 0x5A, count: size)
  var sent = 0
  while sent < ops {
    for _ in 0..<min(burst, ops - sent) {
      let start = now()
      message.withUnsafeMutableBytes { $0.storeBytes(of: start, as: UInt64.self) }
      _ = try await socket.write(message, count: size, awaitingAllWritten: true)
      latency.add(now() &- start)
      sent += 1
    }
    if let pace { try await Task.sleep(for: pace) }
  }
}

@main
enum IORingWriteBench {
  static func main() async throws {
    try IORing.installExecutor(policy: .global)
    let writerCounts = (environment("BENCH_WRITERS") ?? "1 8").split(separator: " ")
      .compactMap { Int($0) }
    let ops = environment("BENCH_OPS").flatMap(Int.init) ?? 200_000
    let size = max(environment("BENCH_SIZE").flatMap(Int.init) ?? 40, 8)
    let threadReader = environment("BENCH_READER") == "thread"
    let pace = environment("BENCH_PACE_US").flatMap(Int.init).map { Duration.microseconds($0) }
    let burst = pace == nil ? ops : max(environment("BENCH_BURST").flatMap(Int.init) ?? 1, 1)

    for writers in writerCounts {
      var sockets = [(Socket, Socket)]()
      var readerFds = [Int32]()
      for _ in 0..<writers {
        var fds = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
          throw Errno(rawValue: errno)
        }
        try sockets.append((
          Socket(
            ring: IORing.shared,
            fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
          ),
          Socket(
            ring: IORing.shared,
            fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
          )
        ))
        readerFds.append(fds[1])
      }

      let latencies = (0..<writers).map { _ in Samples(capacity: ops) }
      let deliveries = (0..<writers).map { _ in Samples(capacity: ops) }
      var threadReaders = [ThreadReader]()
      var readerTasks = [Task<(), Never>]()

      if threadReader {
        for fd in readerFds {
          let reader = ThreadReader(fd: fd, size: size, expected: ops)
          let context = Unmanaged.passRetained(reader).toOpaque()
          pthread_create(&reader.thread, nil, { context in
            Unmanaged<ThreadReader>.fromOpaque(context!).takeRetainedValue().run()
            return nil
          }, context)
          threadReaders.append(reader)
        }
      } else {
        for (index, pair) in sockets.enumerated() {
          let delivery = deliveries[index]
          readerTasks.append(Task.detached {
            await ringReader(pair.1, size: size, expected: ops, delivery: delivery)
          })
        }
      }

      let usageStart = Usage.current()
      let start = now()
      try await withThrowingTaskGroup(of: Void.self) { group in
        for (index, pair) in sockets.enumerated() {
          let latency = latencies[index]
          group.addTask {
            try await writer(
              pair.0,
              size: size,
              ops: ops,
              pace: pace,
              burst: burst,
              latency: latency
            )
          }
        }
        try await group.waitForAll()
      }
      var readerCpu = 0.0, readerSwitches = 0.0
      for reader in threadReaders {
        pthread_join(reader.thread, nil)
        readerCpu += reader.cpu
        readerSwitches += reader.switches
      }
      for task in readerTasks {
        await task.value
      }
      let elapsed = Double(now() - start)
      let usage = Usage.current()

      let total = Double(ops * writers)
      let cpu = usage.user + usage.system - usageStart.user - usageStart.system - readerCpu
      let write = percentiles(latencies)
      let delivery = percentiles(threadReader ? threadReaders.map(\.delivery) : deliveries)
      let fields: [String] = [
        "RESULT", threadReader ? "thread" : "ring", String(writers), String(ops),
        String(Int(elapsed / Double(ops))), String(Int(cpu / total)),
        String(Int((usage.user - usageStart.user) / total)),
        String(Int((usage.system - usageStart.system) / total)),
        String(format: "%.3f", (usage.switches - usageStart.switches - readerSwitches) / total),
        String(write.0), String(write.1), String(write.2),
        String(delivery.0), String(delivery.1), String(delivery.2),
      ]
      print(fields.joined(separator: " "))
    }
  }
}
