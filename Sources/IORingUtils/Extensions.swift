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

import AsyncExtensions
import Foundation
import Glibc
import IORing

private func hexDescription(_ bytes: [UInt8]) -> String {
    bytes.reduce("") { $0 + String(format: "%02x", $1) }
}

extension IORing.Message: CustomStringConvertible {
    public var description: String {
        let address = try! sockaddr(bytes: name).presentationAddress
        return "\(type(of: self))(address: \(address), buffer: \(hexDescription(buffer)), flags: \(flags))"
    }
}

public extension IORing {
    struct AsyncByteSequence: AsyncSequence {
        public typealias Element = UInt8

        let ring: IORing
        let fd: IORing.FileDescriptor

        public struct AsyncIterator: AsyncIteratorProtocol {
            let ring: IORing
            let fd: IORing.FileDescriptor

            public mutating func next() async throws -> Element? {
                guard !Task.isCancelled else {
                    return nil
                }

                var buffer = [UInt8](repeating: 0, count: 1)
                if try await ring.read(into: &buffer, count: 1, from: fd) == false {
                    return nil
                }
                return buffer.first
            }
        }

        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator(ring: ring, fd: fd)
        }
    }

    func asyncBytes(
        from fd: FileDescriptor
    ) -> AnyAsyncSequence<UInt8> {
        AsyncByteSequence(ring: self, fd: fd).eraseToAnyAsyncSequence()
    }
}

extension UnsafeMutablePointer {
    func propertyBasePointer<Property>(to property: KeyPath<Pointee, Property>)
        -> UnsafePointer<Property>?
    {
        guard let offset = MemoryLayout<Pointee>.offset(of: property) else { return nil }
        return (UnsafeRawPointer(self) + offset).assumingMemoryBound(to: Property.self)
    }
}

extension IORing {
    func connect(_ fd: FileDescriptor, to address: any SocketAddress) async throws {
        var addressBuffer = [UInt8]()
        withUnsafeBytes(of: address.asStorage()) {
            addressBuffer = [UInt8]($0)
        }
        try await connect(fd, to: addressBuffer)
    }
}
