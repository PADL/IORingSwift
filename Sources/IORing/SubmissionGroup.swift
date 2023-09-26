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
    private var channel = AsyncThrowingChannel<T, Error>()

    final class Operation {
        private let body: @Sendable (_: Operation) async throws -> T
        fileprivate var isReady = false
        fileprivate var result: Result<T, Error> = .failure(Errno.resourceTemporarilyUnavailable)
        fileprivate let channel: AsyncThrowingChannel<T, Error>

        fileprivate init(
            channel: AsyncThrowingChannel<T, Error>,
            @_inheritActorContext _ body: @escaping @Sendable (_: Operation) async throws
                -> T
        ) {
            self.channel = channel
            self.body = body
        }

        fileprivate func perform() async {
            do {
                let result = try await body(self)
                await channel.send(result)
            } catch {
                channel.fail(error)
            }
        }

        func ready() {
            isReady = true
        }
    }

    init(@_inheritActorContext ring: IORing) async throws {
        self.ring = ring
        queue.adoptExecutionContext(of: self)
    }

    func enqueue(_ body: @escaping @Sendable (_: Operation) async throws -> T) {
        let operation = Operation(channel: channel, body)
        operations.append(operation)
        queue.enqueue { _ in
            await operation.perform()
        }
    }

    // FIXME: there has to be a better way to do this than "busy" wait
    private func operationsReady() async {
        for operation in operations {
            while !operation.isReady {
                await Task.yield()
            }
        }
    }

    func finish() async throws -> [T] {
        await queue.enqueueAndWait { _ in }
        await operationsReady()
        try await ring.submit()
        defer { channel.finish() }
        return try await channel.collect(max: operations.count)
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
