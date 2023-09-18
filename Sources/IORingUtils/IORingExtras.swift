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
import AsyncExtensions
import Foundation
import Glibc
import IORing

public extension IORing {
    func readChannel(
        _ chunkSize: Int,
        from fd: FileDescriptor
    ) -> AsyncThrowingChannel<[UInt8], Error> {
        let channel = AsyncThrowingChannel<[UInt8], Error>()

        Task {
            repeat {
                do {
                    let bytes = try await read(count: chunkSize, from: fd)
                    await channel.send(bytes)
                } catch {
                    channel.fail(error)
                }
            } while true
        }

        return channel
    }
}
