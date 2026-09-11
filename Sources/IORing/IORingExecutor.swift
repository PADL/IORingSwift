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

#if os(Linux) && compiler(>=6.3)

@_spi(ExperimentalCustomExecutors) @_spi(ExperimentalScheduling) import _Concurrency
@_implementationOnly import CIORingShims
import Glibc
import Logging
import SystemPackage

/// The global executor `IORing` installs: as many threads as the process has CPUs, none of
/// which ever exits, that run tasks and reap the completions of every ring created after it.
///
/// The kernel cancels an io_uring request when the thread that submitted it exits, and the
/// default executor's threads exit after five idle seconds. On these threads a request waits
/// as long as it needs to; and the thread that reaps a completion runs the task waiting on
/// it, without another thread in between.
///
/// Installed when the first ring is created, or earlier by `IORing.installExecutor()`; the
/// environment variable `SWIFT_IORING_EXECUTOR=dispatch` keeps the default executor instead,
/// and `SWIFT_IORING_EXECUTOR_THREADS` sets the thread count. Job priorities are not observed.
final class IORingExecutor: TaskExecutor, SchedulingExecutor, @unchecked Sendable {
  /// The installed executor, if any; set once
  nonisolated(unsafe) private(set) static var installed: IORingExecutor?

  /// Installs the executor, unless one is installed or the environment declines it.
  @discardableResult
  static func install(threads: Int? = nil) -> Bool {
    _install.threads = threads
    return _install.installed
  }

  let pool: ioring_pool_t
  let threads: Int
  private var unownedExecutor: UnownedTaskExecutor!
  // the executor replaced, which jobs already on it may still refer to
  private let previous: any TaskExecutor

  private init(pool: ioring_pool_t, threads: Int, previous: any TaskExecutor) {
    self.pool = pool
    self.threads = threads
    self.previous = previous
    unownedExecutor = UnownedTaskExecutor(ordinary: self)
  }

  private struct Factory: ExecutorFactory {
    static let mainExecutor: any MainExecutor = MainActor.executor
    static let defaultExecutor: any TaskExecutor = IORingExecutor.installed!
  }

  private enum _install {
    nonisolated(unsafe) static var threads: Int?

    static let installed: Bool = {
      if let choice = getenv("SWIFT_IORING_EXECUTOR").map({ String(cString: $0) }),
         choice == "dispatch"
      {
        return false
      }
      var count = threads ?? 0
      if count <= 0, let value = getenv("SWIFT_IORING_EXECUTOR_THREADS") {
        count = Int(String(cString: value)) ?? 0
      }
      if count <= 0 {
        count = Int(ioring_pool_default_threads())
      }
      // reading it creates the platform executors, so that they are replaced, not preempted
      let previous = Task.defaultExecutor
      guard let pool = ioring_pool_create(UInt32(count), runJob, nil) else {
        Logger(label: "com.padl.IORing").error("could not start the executor: \(Errno(rawValue: errno))")
        return false
      }
      let executor = IORingExecutor(pool: pool, threads: count, previous: previous)
      // handed to the pool unretained; the executor lives for the process
      ioring_pool_set_context(pool, Unmanaged.passUnretained(executor).toOpaque())
      IORingExecutor.installed = executor
      _createExecutors(factory: Factory.self)
      return true
    }()
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
  /// Installs the global executor whose threads never exit, on which every ring's requests
  /// are submitted and completions reaped. Called when the first ring is created; call it
  /// earlier, before tasks start, to have everything run there. Returns whether it is
  /// installed: `SWIFT_IORING_EXECUTOR=dispatch` in the environment declines it.
  @discardableResult
  nonisolated static func installExecutor(threads: Int? = nil) -> Bool {
    IORingExecutor.install(threads: threads)
  }
}

#endif
