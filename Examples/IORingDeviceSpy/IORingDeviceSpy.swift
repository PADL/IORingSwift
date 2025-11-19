//
// Copyright (c) 2024 PADL Software Pty Ltd
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

import Glibc
import IORing
import IORingUtils

@main
public struct IORingDeviceSpy: Sendable {
  private let blockSize: Int
  private let ring: IORing
  private let fixed = true // compile time constant for using fixed buffers

  public static func main() async throws {
    if CommandLine.arguments.count < 2 {
      Swift.print("Usage: \(CommandLine.arguments[0]) [device] <[block_size]>")
      exit(1)
    }

    let blockSize = if CommandLine.arguments.count > 2 {
      Int(CommandLine.arguments[2])!
    } else {
      1
    }

    let spy = try await IORingDeviceSpy(blockSize: blockSize)
    let device = CommandLine.arguments[1]

    try await spy.spy(device: device)
  }

  init(blockSize: Int = 1) async throws {
    ring = IORing.shared
    self.blockSize = blockSize

    if fixed {
      // allocate more than one buffer to test we can access non-zero indexed buffers
      try await ring.registerFixedBuffers(count: 2, size: blockSize)
    }
  }

  func spy(device: String) async throws {
    let fd = try FileHandle(fileDescriptor: open(device, O_RDONLY), closeOnDealloc: true)

    try fd.setBlocking(false)
    if fd.isATty {
      var tty = try fd.getTty()
      try tty.setN81(speed: 115_200)
      try fd.set(tty: tty)
    }

    if fixed {
      try await readFixed(from: fd)
    } else {
      try await read(from: fd)
    }
  }

  func print(_ data: [UInt8]) {
    Swift.print(data.map { String($0, radix: 16) }.joined())
  }

  func readFixed(from fd: FileDescriptorRepresentable) async throws {
    repeat {
      try await ring.readFixed(count: blockSize, bufferIndex: 1, from: fd) { @Sendable in
        self.print([UInt8]($0))
      }
    } while !Task.isCancelled
  }

  func read(from fd: FileDescriptorRepresentable) async throws {
    repeat {
      let bytes = try await ring.read(count: blockSize, from: fd)
      self.print(bytes)
    } while !Task.isCancelled
  }
}
