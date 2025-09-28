//
// Copyright (c) 2025 PADL Software Pty Ltd
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

import Foundation // for String(format:)
@testable import IORing
import struct SystemPackage.Errno
import struct SystemPackage.FileDescriptor

let operationCount = 100

@main
struct BatchingDemo {
  static func main() async {
    print("IORing Batching Performance Demo")
    print("================================")

    await testBatchingPerformance()
  }

  static func testBatchingPerformance() async {
    do {
      // Test 1: No batching (batch size 1)
      print("\nTest 1: No Batching (batch size 1)")
      let noBatchRing = try IORing(batchSize: 1, batchTimeout: .microseconds(1))
      let noBatchTime = await measureOperations(ring: noBatchRing, count: operationCount)
      print("Time: \(String(format: "%.3f", noBatchTime)) seconds")

      // Test 2: Small batches (batch size 4)
      print("\nTest 2: Small Batching (batch size 4)")
      let smallBatchRing = try IORing(batchSize: 4, batchTimeout: .microseconds(100))
      let smallBatchTime = await measureOperations(ring: smallBatchRing, count: operationCount)
      print("Time: \(String(format: "%.3f", smallBatchTime)) seconds")

      // Test 3: Large batches (batch size 16)
      print("\nTest 3: Large Batching (batch size 16)")
      let largeBatchRing = try IORing(batchSize: 16, batchTimeout: .microseconds(200))
      let largeBatchTime = await measureOperations(ring: largeBatchRing, count: operationCount)
      print("Time: \(String(format: "%.3f", largeBatchTime)) seconds")

      // Analysis
      print("\nPerformance Analysis:")
      print("--------------------")
      let smallBatchImprovement = ((noBatchTime - smallBatchTime) / noBatchTime) * 100
      let largeBatchImprovement = ((noBatchTime - largeBatchTime) / noBatchTime) * 100

      if smallBatchImprovement > 0 {
        print(
          "Small batching improved performance by \(String(format: "%.1f", smallBatchImprovement))%"
        )
      }
      if largeBatchImprovement > 0 {
        print(
          "Large batching improved performance by \(String(format: "%.1f", largeBatchImprovement))%"
        )
      }

    } catch {
      print("Error: \(error)")
    }
  }

  static func measureOperations(ring: IORing, count: Int) async -> Double {
    let startTime = ContinuousClock.now

    await withTaskGroup(of: Void.self) { group in
      for i in 0..<count {
        group.addTask {
          do {
            let data = "Test operation \(i)\n".data(using: .utf8) ?? Data()
            // Write to /dev/null to avoid actual I/O overhead
            let devNull = try FileDescriptor.open("/dev/null", .writeOnly)
            defer { try? devNull.close() }
            _ = try await ring.write([UInt8](data), to: devNull)
          } catch {
            // Ignore errors for performance testing
          }
        }
      }
    }

    let endTime = ContinuousClock.now
    let duration = endTime - startTime
    return Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
  }
}
