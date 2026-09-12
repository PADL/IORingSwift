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
/// the global executor or, with `IORing.ExecutorPolicy.preference`, as one tasks opt into;
/// `SWIFT_IORING_EXECUTOR` in the environment chooses (`global` or `preference`) and
/// `SWIFT_IORING_EXECUTOR_THREADS` sets the thread count. Job priorities are not observed.
final class IORingExecutor: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
  /// The installed executor, if installing it succeeded
  static var installed: IORingExecutor? { try? _install.result.get() }

  /// Installs the executor, once; throws what stopped it, every time, and
  /// `Errno.invalidArgument` for a policy other than the one it was installed with.
  @discardableResult
  static func install(policy: IORing.ExecutorPolicy? = nil, threads: Int? = nil) throws -> IORingExecutor {
    if let threads {
      _install.threads = threads
    }
    if let policy {
      _install.policy = policy
    }
    let executor = try _install.result.get()
    if let policy, policy != executor.policy {
      throw Errno.invalidArgument
    }
    return executor
  }

  let pool: ioring_pool_t
  let threads: Int
  let policy: IORing.ExecutorPolicy
  private var unownedExecutor: UnownedTaskExecutor!
  // the executor replaced, which jobs already on it may still refer to
  private let previous: any TaskExecutor

  private init(pool: ioring_pool_t, threads: Int, policy: IORing.ExecutorPolicy, previous: any TaskExecutor) {
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
    nonisolated(unsafe) static var threads: Int?
    nonisolated(unsafe) static var policy: IORing.ExecutorPolicy?

    static let result: Result<IORingExecutor, Errno> = {
      var policy = _install.policy ?? .global
      if let value = getenv("SWIFT_IORING_EXECUTOR").map({ String(cString: $0) }) {
        policy = value == "preference" ? .preference : .global
      }
      var count = _install.threads ?? 0
      if count <= 0, let value = getenv("SWIFT_IORING_EXECUTOR_THREADS") {
        count = Int(String(cString: value)) ?? 0
      }
      if count <= 0 {
        count = Int(ioring_pool_default_threads())
      }
      // reading it creates the platform executors, so that they are replaced, not preempted
      let previous = Task.defaultExecutor
      guard let pool = ioring_pool_create(UInt32(count), runJob, nil) else {
        return .failure(Errno(rawValue: errno))
      }
      let executor = IORingExecutor(pool: pool, threads: count, policy: policy, previous: previous)
      // handed to the pool unretained; the executor lives for the process
      ioring_pool_set_context(pool, Unmanaged.passUnretained(executor).toOpaque())
      if policy == .global {
        Factory.executor = executor
        _createExecutors(factory: Factory.self)
      }
      return .success(executor)
    }()
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
    let nanoseconds = seconds <= 0 && attoseconds <= 0
      ? 0
      : UInt64(clamping: seconds).multipliedReportingOverflow(by: 1_000_000_000).partialValue
      + UInt64(attoseconds / 1_000_000_000)
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
    /// runs there, and nothing needs to change to do so.
    case global
    /// It is an executor tasks opt into, with `Task(executorPreference: IORing.taskExecutor)`
    /// or `withTaskExecutorPreference`, which their child tasks and default actors inherit;
    /// other tasks stay on the default executor. A request from a task that has not opted in
    /// is submitted from the pool all the same, at the cost of a thread switch each way.
    case preference
  }

  /// Installs the executor, which creating the first ring does with `.global` unless
  /// `SWIFT_IORING_EXECUTOR=preference` is set; call it earlier to choose, or to have
  /// tasks run there from the start. Throws `Errno.invalidArgument` once installed with
  /// another policy.
  nonisolated static func installExecutor(
    policy: ExecutorPolicy = .global,
    threads: Int? = nil
  ) throws {
    try IORingExecutor.install(policy: policy, threads: threads)
  }

  /// The executor, for tasks to prefer under `ExecutorPolicy.preference`.
  nonisolated static var taskExecutor: any TaskExecutor {
    get throws { try IORingExecutor.install() }
  }
}
