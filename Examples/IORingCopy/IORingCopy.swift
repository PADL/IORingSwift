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

import Glibc
import IORing
import IORingUtils

@main
public struct IORingCopy {
  static let BlockSize = 64
  private let ring: IORing

  public static func main() async throws {
    if CommandLine.arguments.count < 3 {
      print("Usage: \(CommandLine.arguments[0]) [infile] [outfile]")
      exit(1)
    }

    let copier = try await IORingCopy()
    try await copier.copy(from: CommandLine.arguments[1], to: CommandLine.arguments[2])
  }

  init() async throws {
    ring = IORing.shared
    try await ring.registerFixedBuffers(count: 1, size: Self.BlockSize)
  }

  func copy(from: String, to: String) async throws {
    let infd = try FileHandle(fileDescriptor: open(from, O_RDONLY), closeOnDealloc: true)
    let outfd = try FileHandle(
      fileDescriptor: open(to, O_WRONLY | O_CREAT | O_TRUNC, 0o644),
      closeOnDealloc: true
    )

    let size = try infd.getSize()
    var blocks = size % Self.BlockSize
    if size % blocks != 0 { blocks += 1 }
    var nremain = size

    while nremain != 0 {
      let count = nremain > Self.BlockSize ? Self.BlockSize : nremain
      let offset = size - nremain

      try await ring.copy(
        count: count,
        offset: offset,
        bufferIndex: 0,
        from: infd,
        to: outfd
      )

      nremain -= count
    }
  }
}
