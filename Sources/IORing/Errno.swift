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
import CIORingShims
@_implementationOnly
import CIOURing
import Glibc

public struct Errno: Error, CustomStringConvertible, Equatable {
    public typealias RawValue = CInt

    public let rawValue: RawValue

    public init(rawValue: RawValue) {
        precondition(rawValue != 0)
        self.rawValue = rawValue < 0 ? -rawValue : rawValue
    }

    private var stringError: String {
        String(cString: strerror(rawValue))
    }

    public var description: String {
        stringError
    }

    static func throwingErrno(_ body: @escaping () -> RawValue) throws {
        let error = body()
        if error < 0 {
            throw Errno(rawValue: error)
        }
    }

    public static var lastError: Errno {
        Errno(rawValue: errno)
    }
}
