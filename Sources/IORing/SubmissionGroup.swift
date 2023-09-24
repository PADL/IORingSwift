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
import Glibc

actor SubmissionGroup<T> {
    private let ring: IORing
    private let queue = ActorQueue<SubmissionGroup>()
    private var operations = [Operation]()

    final class Operation {
        fileprivate enum State: UInt8 {
            case enqueued
            case registered
            case complete
        }

        private let body: @Sendable (_: Operation) async throws -> T
        fileprivate var result: Result<T, Error> = .failure(Errno.resourceTemporarilyUnavailable)
        fileprivate var state: State = .enqueued

        fileprivate init(
            @_inheritActorContext _ body: @escaping @Sendable (_: Operation) async throws
                -> T
        ) {
            self.body = body
        }

        fileprivate func perform() async {
            do {
                result = try await .success(body(self))
            } catch {
                result = .failure(error)
            }
            state = .complete
        }

        func notifyBlockRegistration() {
            state = .registered
        }
    }

    init(@_inheritActorContext ring: IORing) async throws {
        self.ring = ring
        queue.adoptExecutionContext(of: self)
    }

    func enqueue(_ body: @escaping @Sendable (_: Operation) async throws -> T) {
        queue.enqueue { group in
            let operation = Operation(body)
            group.operations.append(operation)
            await operation.perform()
        }
    }

    // FIXME: there has to be a better way to do this than "busy" wait
    private func yieldUntilOperationState(is state: Operation.State) async {
        for operation in operations {
            while operation.state.rawValue < state.rawValue {
                await Task.yield()
            }
        }
    }

    func finish() async throws -> [T] {
        await queue.enqueueAndWait { _ in }
        await yieldUntilOperationState(is: .registered)
        try await ring.submit()
        await yieldUntilOperationState(is: .complete)
        return try operations.map { try $0.result.get() }
    }
}
