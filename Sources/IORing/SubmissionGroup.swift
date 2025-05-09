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

import AsyncAlgorithms
import AsyncQueue
import Glibc

extension SingleshotSubmission {
  func enqueue() {
    guard let group else { return }
    Task {
      do {
        let result = try await submit()
        await group.resultChannel.send(result)
      } catch {
        group.resultChannel.fail(error)
      }
    }
  }

  func ready() async {
    await group?.readinessChannel.send(())
  }
}

actor SubmissionGroup<T: Sendable> {
  private let ring: IORing
  private let queue = ActorQueue<SubmissionGroup>()
  private var submissions = [SingleshotSubmission<T>]()

  fileprivate let readinessChannel = AsyncChannel<()>()
  fileprivate let resultChannel = AsyncThrowingChannel<T, Error>()

  init(ring: IORing) async throws {
    self.ring = ring
    queue.adoptExecutionContext(of: self)
  }

  ///
  /// Asynchronously enqueues an submission. Submission must call `ready()` when
  /// its continuation is registered in the SQE `user_data` otherwise the group
  /// will never be submitted.
  ///
  func enqueue(submission: SingleshotSubmission<T>) {
    submissions.append(submission)
    Task(on: queue) { _ in
      await submission.enqueue()
    }
  }

  private func allReady() async {
    _ = await readinessChannel.collect(max: submissions.count)
  }

  private func allComplete() async throws -> [T] {
    defer { resultChannel.finish() }
    return try await resultChannel.collect(max: submissions.count)
  }

  ///
  /// Call `finish()` once all submissions have been submitted to the submission group.
  ///
  /// Completing the submission group involves the following:
  ///
  /// - Await all submissions to be scheduled on queue
  /// - Wait for all submissions to have continuations registered
  /// - Submit SQEs to I/O ring
  /// - Collect results from results channel
  ///
  func finish() async throws -> [T] {
    await Task(on: queue) { _ in }.value
    await allReady()
    try await ring.submit()
    readinessChannel.finish()
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
