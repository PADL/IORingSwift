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

@_spi(ExperimentalCustomExecutors) @_spi(ExperimentalScheduling) import _Concurrency
@_implementationOnly import CIORingShims
import Glibc
import Synchronization
import SystemPackage

/// The executor `IORing` installs: as many threads as the process has CPUs, none of which
/// ever exits, that run tasks and reap the completions of every ring.
///
/// The kernel cancels an io_uring request when the thread that submitted it exits, and the
/// default executor's threads exit after five idle seconds. On these threads a request waits
/// as long as it needs to; and the thread that reaps a completion runs the task waiting on
/// it, without another thread in between.
///
/// Installed when the first ring is created, or earlier by `IORing.installExecutor()`, as
/// one tasks opt into (`IORing.ExecutorPolicy.preference`, the default) or, with `.global`,
/// as the global executor; `SWIFT_IORING_EXECUTOR` in the environment chooses (`global` or
/// `preference`) and `SWIFT_IORING_EXECUTOR_THREADS` sets the thread count. Job priorities
/// are not observed.
final class IORingExecutor: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
  /// The installed executor, if installing it succeeded
  static var installed: IORingExecutor? {
    _install.state.withLock { $0.executor }
  }

  /// Installs the executor, once; a failure to create it is thrown and can be retried,
  /// and `Errno.invalidArgument` is thrown for a policy other than the one it was
  /// installed with.
  @discardableResult
  static func install(
    policy: IORing.ExecutorPolicy? = nil,
    threads: Int? = nil
  ) throws -> IORingExecutor {
    let executor = try _install.state.withLock { state in
      if let executor = state.executor {
        return executor
      }
      let executor = try _install.create(
        policy: policy ?? state.policy,
        threads: threads ?? state.threads
      )
      state.executor = executor
      return executor
    }
    if let policy, policy != executor.policy {
      throw Errno.invalidArgument
    }
    return executor
  }

  let pool: ioring_pool_t
  let threads: Int
  let policy: IORing.ExecutorPolicy
  private var unownedExecutor: UnownedTaskExecutor!
  /// the executor replaced, which jobs already on it may still refer to
  private let previous: any TaskExecutor

  private init(
    pool: ioring_pool_t,
    threads: Int,
    policy: IORing.ExecutorPolicy,
    previous: any TaskExecutor
  ) {
    self.pool = pool
    self.threads = threads
    self.policy = policy
    self.previous = previous
    unownedExecutor = UnownedTaskExecutor(ordinary: self)
  }

  private struct Factory: ExecutorFactory {
    nonisolated(unsafe) static var executor: IORingExecutor!
    static let mainExecutor: any MainExecutor = MainActor.executor
    static let defaultExecutor: any TaskExecutor = executor
  }

  private enum _install {
    struct State {
      var executor: IORingExecutor?
      /// the environment's choices, which an argument to install overrides
      var policy: IORing.ExecutorPolicy = getenv("SWIFT_IORING_EXECUTOR").map {
        String(cString: $0) == "preference" ? .preference : .global
      } ?? .global
      var threads: Int = getenv("SWIFT_IORING_EXECUTOR_THREADS")
        .map { Int(String(cString: $0)) ?? 0 } ?? 0
    }

    static let state = Mutex(State())

    static func create(policy: IORing.ExecutorPolicy, threads: Int) throws -> IORingExecutor {
      let count = threads > 0 ? threads : Int(ioring_pool_default_threads())
      // reading it creates the platform executors, so that they are replaced, not preempted
      let previous = Task.defaultExecutor
      guard let pool = ioring_pool_create(UInt32(count), runJob, nil) else {
        throw Errno(rawValue: errno)
      }
      let executor = IORingExecutor(pool: pool, threads: count, policy: policy, previous: previous)
      // handed to the pool unretained; the executor lives for the process
      ioring_pool_set_context(pool, Unmanaged.passUnretained(executor).toOpaque())
      if policy == .global {
        Factory.executor = executor
        _createExecutors(factory: Factory.self)
      }
      return executor
    }
  }

  /// Whether the calling thread is one of the pool's: a request submitted from it outlives it.
  var isCurrentThread: Bool {
    ioring_pool_is_worker(pool)
  }

  func enqueue(_ job: consuming ExecutorJob) {
    ioring_pool_enqueue(pool, unsafeBitCast(UnownedJob(job), to: UnsafeMutableRawPointer.self))
  }

  func enqueue<C: Clock>(
    _ job: consuming ExecutorJob,
    after delay: C.Duration,
    tolerance: C.Duration?,
    clock: C
  ) {
    guard let delay = delay as? Swift.Duration else {
      fatalError("IORingExecutor cannot schedule on \(C.self)")
    }
    // the clocks the standard library reads on Linux
    let clockID = clock is ContinuousClock ? CLOCK_BOOTTIME : CLOCK_MONOTONIC
    let (seconds, attoseconds) = delay.components
    let (scaled, overflow) = UInt64(clamping: seconds)
      .multipliedReportingOverflow(by: 1_000_000_000)
    let nanoseconds = seconds <= 0 && attoseconds <= 0
      ? 0
      : overflow ? UInt64.max : scaled + UInt64(attoseconds / 1_000_000_000)
    ioring_pool_enqueue_after(
      pool,
      clockID,
      nanoseconds,
      unsafeBitCast(UnownedJob(job), to: UnsafeMutableRawPointer.self)
    )
  }

  func asUnownedTaskExecutor() -> UnownedTaskExecutor {
    unownedExecutor
  }
}

private let runJob: ioring_job_runner = { context, job in
  let executor = Unmanaged<IORingExecutor>.fromOpaque(context!).takeUnretainedValue()
  unsafeBitCast(job, to: UnownedJob.self).runSynchronously(on: executor.asUnownedTaskExecutor())
}

public extension IORing {
  /// How the executor whose threads never exit, on which requests are submitted and
  /// completions reaped, relates to the rest of the process.
  enum ExecutorPolicy: Sendable {
    /// It is the global executor: every task not on the main actor or an executor of its own
    /// runs there, and nothing needs to change to do so. This is what a program whose work
    /// is I/O wants, and what the benchmarks measure; a long-running daemon should select it
    /// at the top of `main`, before its first ring.
    case global
    /// It is an executor tasks opt into, with `Task(executorPreference: IORing.taskExecutor)`
    /// or `withTaskExecutorPreference`, which their child tasks and default actors inherit;
    /// other tasks stay on the default executor. A request from a task that has not opted in
    /// is submitted from the pool all the same, at the cost of a thread switch each way, so
    /// nothing breaks in a program that has not chosen — it is only slower. The default.
    case preference
  }

  /// Installs the executor, which creating the first ring does with `.preference` unless
  /// `SWIFT_IORING_EXECUTOR=global` is set; call it earlier to choose, or to have tasks run
  /// there from the start. A policy given here wins over the environment. Throws
  /// `Errno.invalidArgument` once installed with another policy.
  nonisolated static func installExecutor(
    policy: ExecutorPolicy? = nil,
    threads: Int? = nil
  ) throws {
    try IORingExecutor.install(policy: policy, threads: threads)
  }

  /// The executor, for tasks to prefer under `ExecutorPolicy.preference`.
  nonisolated static var taskExecutor: any TaskExecutor {
    get throws { try IORingExecutor.install() }
  }
}
