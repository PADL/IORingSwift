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

@preconcurrency import Foundation
@preconcurrency import Glibc
@testable import IORing
import class IORing.FileHandle
import IORingUtils
import struct SystemPackage.Errno
import Synchronization
import XCTest

/// The executor is installed when the first ring is created: with SWIFT_IORING_EXECUTOR=global
/// every test in the package runs on it, and by default (`.preference`) beside it, where every
/// request from an unannotated task takes the submit handoff to the pool; these check what it
/// does beyond running jobs.
final class ExecutorTests: XCTestCase {
  private static let threadName = "IORingExecutor"

  private static func currentThreadName() -> String {
    let comm = (try? String(contentsOfFile: "/proc/thread-self/comm", encoding: .utf8)) ?? ""
    return comm.trimmingCharacters(in: .whitespacesAndNewlines)
  }

  private final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) {
      self.value = value
    }
  }

  private final class Counter: Sendable {
    let value = Atomic<Int>(0)
  }

  private var threads: Int {
    get throws { try IORingExecutor.install().threads }
  }

  /// a round trip and a sleep on the pool, which must be served while `busy` tasks keep every
  /// thread occupied
  private func assertCompletionsAndTimersServed<Failure>(
    while busy: [Task<(), Failure>],
    started: Counter
  ) async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    while started.value.load(ordering: .relaxed) < busy.count {
      await Task.yield()
    }
    let start = ContinuousClock.now
    try await a.send([1])
    _ = try await b.receive(count: 1) as [UInt8]
    let sleeper = try Task(executorPreference: IORing.taskExecutor) {
      try await Task.sleep(for: .milliseconds(10))
    }
    try await sleeper.value
    XCTAssertLessThan(ContinuousClock.now - start, .seconds(1))
    for task in busy {
      task.cancel()
      _ = await task.result
    }
  }

  private var policy: IORing.ExecutorPolicy {
    get throws { try IORingExecutor.install().policy }
  }

  private static func makePair(ring: IORing) throws -> (Socket, Socket) {
    var fds = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0, &fds) == 0 else {
      throw Errno(rawValue: errno)
    }
    return try (
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)),
      Socket(ring: ring, fileHandle: FileHandle(fileDescriptor: fds[1], closeOnDealloc: true))
    )
  }

  /// Under `.preference` only the opposite is checked: a task with no preference is not kept
  /// off the pool, since a default actor it shares with a task that prefers the pool drains
  /// its jobs on whichever thread holds the actor.
  func testTasksRunOnItsThreads() async throws {
    let global = try policy == .global
    let detached = Task.detached { ExecutorTests.currentThreadName() }
    let name = await detached.value
    if global {
      XCTAssertEqual(name, ExecutorTests.threadName)
    }
    let preferred = try Task(executorPreference: IORing.taskExecutor) {
      ExecutorTests.currentThreadName()
    }
    let preferredName = await preferred.value
    XCTAssertEqual(preferredName, ExecutorTests.threadName)
    // a completion resumes its task on the thread that reaped it
    let (a, b) = try Self.makePair(ring: IORing.shared)
    try await a.send([1])
    _ = try await b.receive(count: 1) as [UInt8]
    if global {
      XCTAssertEqual(ExecutorTests.currentThreadName(), ExecutorTests.threadName)
    }
  }

  /// a task that prefers the executor does its I/O without leaving it
  func testPreferredTaskStaysOnItsThreads() async throws {
    let (a, b) = try Self.makePair(ring: IORing.shared)
    let task = try Task(executorPreference: IORing.taskExecutor) {
      let before = ExecutorTests.currentThreadName()
      try await a.send([1])
      _ = try await b.receive(count: 1) as [UInt8]
      return (before, ExecutorTests.currentThreadName())
    }
    let (before, after) = try await task.value
    XCTAssertEqual(before, ExecutorTests.threadName)
    XCTAssertEqual(after, ExecutorTests.threadName)
  }

  func testSleepOnEachClock() async throws {
    _ = try threads
    let delay = Duration.milliseconds(50)
    let continuousStart = ContinuousClock.now
    try await Task.sleep(for: delay, clock: .continuous)
    let continuousElapsed = ContinuousClock.now - continuousStart
    XCTAssertGreaterThanOrEqual(continuousElapsed, delay)
    XCTAssertLessThan(continuousElapsed, .seconds(1))

    let suspendingStart = SuspendingClock.now
    try await Task.sleep(until: .now + delay, clock: .suspending)
    let suspendingElapsed = SuspendingClock.now - suspendingStart
    XCTAssertGreaterThanOrEqual(suspendingElapsed, delay)
    XCTAssertLessThan(suspendingElapsed, .seconds(1))
  }

  /// timers added out of order fire in deadline order
  func testSleepsFireInOrder() async throws {
    _ = try threads
    let delays = (1...20).map { Duration.milliseconds(20 * (($0 * 7) % 20 + 1)) }
    let order = await withTaskGroup(of: (Duration, ContinuousClock.Instant).self) { group in
      for delay in delays {
        group.addTask {
          try? await Task.sleep(for: delay)
          return (delay, .now)
        }
      }
      return await group.reduce(into: [(Duration, ContinuousClock.Instant)]()) { $0.append($1) }
    }
    let byCompletion = order.sorted { $0.1 < $1.1 }.map(\.0)
    XCTAssertEqual(byCompletion, delays.sorted())
  }

  func testCancelledSleepEndsAtOnce() async throws {
    _ = try threads
    let sleeper = Task { try await Task.sleep(for: .seconds(10)) }
    try await Task.sleep(for: .milliseconds(20))
    let start = ContinuousClock.now
    sleeper.cancel()
    do {
      try await sleeper.value
      XCTFail("the sleep was not cancelled")
    } catch is CancellationError {}
    XCTAssertLessThan(ContinuousClock.now - start, .seconds(1))
  }

  /// a task started from a thread the pool knows nothing about
  func testTaskFromForeignThread() throws {
    let global = try policy == .global
    let done = DispatchSemaphore(value: 0)
    let result = Box("")
    let thread = Thread {
      Task {
        result.value = ExecutorTests.currentThreadName()
        done.signal()
      }
    }
    thread.start()
    XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
    if global {
      XCTAssertEqual(result.value, ExecutorTests.threadName)
    }
  }

  /// requests are submitted from whichever pool thread is current, which is never one issuer
  func testSingleIssuerIsRejected() throws {
    XCTAssertThrowsError(try IORing(flags: .singleIssuer)) {
      XCTAssertEqual($0 as? Errno, .invalidArgument)
    }
    // the kernel requires the one for the other; the combination is rejected here, not there
    XCTAssertThrowsError(try IORing(flags: [.singleIssuer, .deferTaskRun])) {
      XCTAssertEqual($0 as? Errno, .invalidArgument)
    }
  }

  /// with every thread running jobs that yield and come straight back, so that the queue never
  /// empties, completions and timers are still served between them
  func testBacklogDoesNotStarveCompletions() async throws {
    let deadline = ContinuousClock.now + .seconds(3)
    let started = Counter()
    let yielders = try (0..<(threads * 4)).map { _ in
      try Task(executorPreference: IORing.taskExecutor) {
        started.value.add(1, ordering: .relaxed)
        while !Task.isCancelled, ContinuousClock.now < deadline {
          await Task.yield()
        }
      }
    }
    try await assertCompletionsAndTimersServed(while: yielders, started: started)
  }

  /// a job that blocks its thread, as jobs must not, neither stalls a task it started nor,
  /// for long, the completions of tasks doing I/O
  func testBlockedJobDoesNotStallTheRest() async throws {
    guard try threads > 1 else { throw XCTSkip("one thread") }
    let ring = IORing.shared
    let (a, b) = try Self.makePair(ring: ring)
    let released = DispatchSemaphore(value: 0)
    let blocker = try Task(executorPreference: IORing.taskExecutor) {
      let child = Task { released.signal() }
      // the child runs on another thread while this one is stuck
      XCTAssertEqual(released.wait(timeout: .now() + 5), .success)
      _ = child
      sleep(1)
    }
    let start = ContinuousClock.now
    for _ in 0..<100 {
      try await a.send([1])
      _ = try await b.receive(count: 1) as [UInt8]
    }
    XCTAssertLessThan(ContinuousClock.now - start, .seconds(1))
    await blocker.value
  }
}
