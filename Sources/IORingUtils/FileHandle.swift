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

import Foundation
import Glibc
import IORing

public final class FileHandle: CustomStringConvertible {
    private var fd: IORing.FileDescriptor

    public init(fd: IORing.FileDescriptor) throws {
        if fd < 0 {
            let lastError = Errno.lastError
            if lastError.rawValue == 0 {
                throw Errno.badFileDescriptor
            } else {
                throw lastError
            }
        }
        self.fd = fd
    }

    public var description: String {
        "\(type(of: self))(fd: \(fd))"
    }

    public func setNonBlocking() throws {
        try withDescriptor { fd in
            let flags = try Errno.throwingErrno { fcntl(fd, F_GETFL, 0) }
            try Errno.throwingErrno { fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
        }
    }

    deinit {
        if isValid {
            try? close()
        }
    }

    @discardableResult
    public func withDescriptor<T>(_ body: (_: IORing.FileDescriptor) throws -> T) rethrows
        -> T
    {
        try body(fd)
    }

    @discardableResult
    public func withDescriptor<T>(
        _ body: (_: IORing.FileDescriptor) async throws
            -> T
    ) async rethrows
        -> T
    {
        try await body(fd)
    }

    public func getSize() throws -> Int {
        var st = stat()

        if fstat(fd, &st) < 0 {
            throw Errno.lastError
        }

        if st.st_mode & S_IFMT == S_IFREG {
            return st.st_size
        } else {
            throw Errno.invalidArgument
        }
    }

    public func close() throws {
        try Errno.throwingErrno {
            SwiftGlibc.close(self.fd)
        }
        invalidate()
    }

    func invalidate() {
        fd = -1
    }

    var isValid: Bool {
        fd != -1
    }
}

extension FileHandle: Equatable {
    public static func == (lhs: FileHandle, rhs: FileHandle) -> Bool {
        lhs.fd == rhs.fd
    }
}

extension FileHandle: Hashable {
    public func hash(into hasher: inout Hasher) {
        fd.hash(into: &hasher)
    }
}
