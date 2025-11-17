//
// Copyright (c) 2023-2025 PADL Software Pty Ltd
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

import AsyncAlgorithms
import AsyncQueue
import Glibc

extension SingleshotSubmission {
  func enqueue(ring: isolated IORing) async {
    let result: Result<T, Error>
    do {
      result = try await .success(submit())
    } catch {
      result = .failure(error)
    }
    group!.resultContinuation?.yield(result)
  }

  func ready() {
    group!.readinessContinuation!.yield(())
  }
}

final class SubmissionGroup<T: Sendable>: Sendable {
  private let ring: IORing
  private let queue = ActorQueue<IORing>()
  private nonisolated(unsafe) var submissions = [SingleshotSubmission<T>]()
  private let readinessStream: AsyncStream<()>
  private let resultStream: AsyncStream<Result<T, Error>>

  fileprivate nonisolated(unsafe) var readinessContinuation: AsyncStream<()>.Continuation?
  fileprivate nonisolated(unsafe) var resultContinuation: AsyncStream<Result<T, Error>>
    .Continuation?

  init(ring: isolated IORing) throws {
    self.ring = ring

    var readinessContinuation: AsyncStream<()>.Continuation!
    readinessStream = AsyncStream<()> {
      readinessContinuation = $0
    }
    self.readinessContinuation = readinessContinuation

    var resultContinuation: AsyncStream<Result<T, Error>>.Continuation!
    resultStream = AsyncStream<Result<T, Error>> {
      resultContinuation = $0
    }
    self.resultContinuation = resultContinuation
    queue.adoptExecutionContext(of: ring)
  }

  ///
  /// Asynchronously enqueues an submission. Submission must call `ready()` when
  /// its continuation is registered in the SQE `user_data` otherwise the group
  /// will never be submitted.
  ///
  func enqueue(submission: SingleshotSubmission<T>, ring: isolated IORing) {
    submissions.append(submission)
    Task(on: queue) { (ring: isolated IORing) in
      await submission.enqueue(ring: ring)
    }
  }

  private func allReady() async {
    _ = await readinessStream.collect(max: submissions.count)
  }

  private func allComplete() async throws -> [T] {
    defer { resultContinuation?.finish() }
    let results = await resultStream.collect(max: submissions.count)
    return try results.map { try $0.get() }
  }

  ///
  /// Call `finish()` once all submissions have been submitted to the submission group.
  ///
  /// Completing the submission group involves the following:
  ///
  /// - Wait for all submissions to have continuations registered
  /// - Submit SQEs to I/O ring
  /// - Collect results from results channel
  ///
  func finish(ring: isolated IORing) async throws -> [T] {
    await allReady()
    try ring.submit()
    readinessContinuation?.finish()
    return try await allComplete()
  }
}

private extension AsyncSequence {
  func collect(max: Int) async rethrows -> [Element] {
    var collected = 0
    var elements = [Element]()
    for try await element in self {
      elements.append(element)
      collected += 1
      if collected == max {
        break
      }
    }
    return elements
  }
}
