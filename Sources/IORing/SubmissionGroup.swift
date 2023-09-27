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

@_implementationOnly
import AsyncQueue
@_implementationOnly
import AsyncAlgorithms
import Glibc

actor SubmissionGroup<T> {
    private let ring: IORing
    private let queue = ActorQueue<SubmissionGroup>()
    private var operations = [Operation]()

    private let readinessChannel = AsyncChannel<Operation>()
    private let resultChannel = AsyncThrowingChannel<T, Error>()

    final class Operation {
        private let body: @Sendable (_: Operation) async throws -> T
        fileprivate var result: Result<T, Error> = .failure(Errno.resourceTemporarilyUnavailable)
        fileprivate weak var group: SubmissionGroup?

        fileprivate init(
            group: SubmissionGroup,
            @_inheritActorContext _ body: @escaping @Sendable (_: Operation) async throws
                -> T
        ) {
            self.group = group
            self.body = body
        }

        fileprivate func perform() async {
            do {
                let result = try await body(self)
                await group?.resultChannel.send(result)
            } catch {
                group?.resultChannel.fail(error)
            }
        }

        func ready() {
            Task { await group?.readinessChannel.send(self) }
        }
    }

    init(@_inheritActorContext ring: IORing) async throws {
        self.ring = ring
        queue.adoptExecutionContext(of: self)
    }

    ///
    /// Asynchronously enqueues an operation. Operation must call `ready()` when
    /// its continuation is registered in the SQE `user_data` otherwise the group
    /// will never be submitted.
    ///
    func enqueue(_ body: @escaping @Sendable (_: Operation) async throws -> T) {
        let operation = Operation(group: self, body)
        operations.append(operation)
        queue.enqueue { _ in
            await operation.perform()
        }
    }

    ///
    /// Call `finish()` once all operations have been submitted to the submission group.
    ///
    /// Completing the submission group involves the following:
    ///
    /// - Await all operations to be scheduled on queue
    /// - Wait for all operations to have continuations registered
    /// - Submit SQEs to I/O ring
    /// - Collect results from results channel
    ///
    func finish() async throws -> [T] {
        await queue.enqueueAndWait { _ in }
        _ = await readinessChannel.collect(max: operations.count)
        try await ring.submit()
        readinessChannel.finish()
        defer { resultChannel.finish() }
        return try await resultChannel.collect(max: operations.count)
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
