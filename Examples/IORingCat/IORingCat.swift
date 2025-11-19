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

@preconcurrency import Glibc
import IORing
import IORingUtils

@main
public struct IORingCat: Sendable {
  private let blockSize: Int
  private let ring: IORing

  public static func main() async throws {
    if CommandLine.arguments.count < 2 {
      print("Usage: \(CommandLine.arguments[0]) [file name] <(file name) ...>")
      exit(1)
    }

    let cat = try await IORingCat()

    for file in CommandLine.arguments[1...] {
      try await cat.cat(file)
    }
  }

  init(blockSize: Int = 64) async throws {
    ring = IORing.shared
    self.blockSize = blockSize

    try await ring.registerFixedBuffers(count: 1, size: blockSize)
  }

  func cat(_ file: String) async throws {
    let fd = try FileHandle(fileDescriptor: open(file, O_RDONLY), closeOnDealloc: true)

    let size = try fd.getSize()
    var blocks = size % IORing.Offset(blockSize)
    if size % blocks != 0 { blocks += 1 }
    var nremain = size

    while nremain != 0 {
      let blockSize = IORing.Offset(blockSize)
      let count = nremain > blockSize ? blockSize : nremain
      let data = try await ring.readFixed(
        count: Int(count),
        offset: size - nremain,
        bufferIndex: 0,
        from: fd
      ) { @Sendable in Array($0) }
      outputToConsole(data)
      nremain -= IORing.Offset(data.count)
    }
  }

  func outputToConsole(_ data: [UInt8]) {
    data.forEach { fputc(Int32($0), stdout) }
  }
}
