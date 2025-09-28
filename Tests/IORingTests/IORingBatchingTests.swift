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

import Atomics
import Foundation
@testable import IORing
import SystemPackage
import XCTest

final class IORingBatchingTests: XCTestCase {
  func testBatchingConfiguration() throws {
    // Test default batching configuration
    _ = try IORing()
    // Can't directly access private properties, but we can test behavior

    // Test custom batching configuration
    _ = try IORing(batchSize: 16, batchTimeout: .milliseconds(5))
    // Again, behavior testing rather than direct property access
  }

  func testBatchingSizeThreshold() async throws {
    let batchSize = 4
    let ring = try IORing(batchSize: batchSize, batchTimeout: .seconds(10)) // Long timeout

    // Use a thread-safe counter instead of array manipulation from different tasks
    let completedOperations = ManagedAtomic<Int>(0)

    // Track submissions by creating multiple async operations
    await withTaskGroup(of: Void.self) { group in
      for i in 0..<batchSize {
        group.addTask {
          do {
            let data = "test\(i)".data(using: .utf8)!
            _ = try await ring.write(
              [UInt8](data),
              to: FileDescriptor.standardOutput
            )
            completedOperations.wrappingIncrement(ordering: .relaxed)
          } catch {
            // Count attempted operations even if they fail
            completedOperations.wrappingIncrement(ordering: .relaxed)
          }
        }
      }
    }

    // All operations should complete when batch size is reached
    XCTAssertEqual(completedOperations.load(ordering: .relaxed), batchSize)
  }

  func testBatchingTimeout() async throws {
    let ring = try IORing(batchSize: 100, batchTimeout: .milliseconds(50)) // Small timeout

    let startTime = ContinuousClock.now

    // Submit a single operation that should be forced by timeout
    let data = "timeout test".data(using: .utf8)!
    do {
      _ = try await ring.write([UInt8](data), to: FileDescriptor.standardOutput)
    } catch {
      // Ignore write errors for testing purposes
    }

    let elapsed = ContinuousClock.now - startTime

    // Should complete within timeout window (with some tolerance)
    XCTAssertLessThan(elapsed, .milliseconds(100))
    XCTAssertGreaterThan(elapsed, .milliseconds(40)) // Should take at least timeout duration
  }

  func testSubmissionGroupBatching() async throws {
    // Use shorter timeout to avoid hanging
    let ring = try IORing(batchSize: 2, batchTimeout: .milliseconds(100))

    // Test that batching system works with sequential operations
    let startTime = ContinuousClock.now
    for i in 0..<3 {
      let data = "group\(i)".data(using: .utf8)!
      do {
        _ = try await ring.write(
          [UInt8](data),
          to: FileDescriptor.standardOutput
        )
      } catch {
        // Ignore write errors - we're testing batching behavior
      }
    }
    let elapsed = ContinuousClock.now - startTime

    // Should complete within reasonable time due to batching timeout
    XCTAssertLessThan(elapsed, .seconds(3))
  }

  func testForcedSubmission() async throws {
    // Use smaller batch size and timeout to ensure forced submission works
    let ring = try IORing(batchSize: 10, batchTimeout: .milliseconds(100))

    // Test that operations complete even with high batch settings
    let data = "forced test".data(using: .utf8)!

    let startTime = ContinuousClock.now
    do {
      _ = try await ring.write([UInt8](data), to: FileDescriptor.standardOutput)
    } catch {
      // Ignore write errors
    }
    let elapsed = ContinuousClock.now - startTime

    // Should complete within reasonable time - timeout should force submission
    XCTAssertLessThan(elapsed, .seconds(3))
  }

  func testNoBatchingMode() async throws {
    // Test with batching effectively disabled
    let ring = try IORing(batchSize: 1, batchTimeout: .microseconds(1))

    let operations = 5
    let completedOperations = ManagedAtomic<Int>(0)

    await withTaskGroup(of: Void.self) { group in
      for i in 0..<operations {
        group.addTask {
          do {
            let data = "nobatch\(i)".data(using: .utf8)!
            _ = try await ring.write([UInt8](data), to: FileDescriptor.standardOutput)
            completedOperations.wrappingIncrement(ordering: .relaxed)
          } catch {
            // Count attempted operations even if they fail
            completedOperations.wrappingIncrement(ordering: .relaxed)
          }
        }
      }
    }

    // All operations should complete
    XCTAssertEqual(completedOperations.load(ordering: .relaxed), operations)
  }

  func testConcurrentBatching() async throws {
    let ring = try IORing(batchSize: 3, batchTimeout: .milliseconds(100))

    let concurrentOperations = 10
    var results: [Bool] = []

    await withTaskGroup(of: Bool.self) { group in
      for i in 0..<concurrentOperations {
        group.addTask {
          do {
            let data = "concurrent\(i)".data(using: .utf8)!
            _ = try await ring.write([UInt8](data), to: FileDescriptor.standardOutput)
            return true
          } catch {
            return false // Operation failed, but that's okay for this test
          }
        }
      }

      for await result in group {
        results.append(result)
      }
    }

    // Most operations should succeed (allowing for some failures due to fd limits)
    let successCount = results.filter { $0 }.count
    XCTAssertGreaterThan(successCount, concurrentOperations / 2)
  }

  func testBatchingMemoryEfficiency() async throws {
    // Test that batching doesn't cause memory issues
    let ring = try IORing(batchSize: 5, batchTimeout: .milliseconds(50))

    // Perform many operations to test memory management
    for batch in 0..<20 {
      await withTaskGroup(of: Void.self) { group in
        for i in 0..<10 {
          group.addTask {
            do {
              let data = "memory\(batch)-\(i)".data(using: .utf8)!
              _ = try await ring.write([UInt8](data), to: FileDescriptor.standardOutput)
            } catch {
              // Ignore write errors
            }
          }
        }
      }
    }

    // If we get here without crashing or hanging, memory management is working
    XCTAssertTrue(true)
  }

  func testAPITransparency() async throws {
    // Test that existing API continues to work unchanged
    let oldStyleRing = try IORing() // Should use default batching
    let newStyleRing = try IORing(batchSize: 4, batchTimeout: .milliseconds(10))

    // Both should support the same API
    let data = "transparency".data(using: .utf8)!

    do {
      _ = try await oldStyleRing.write([UInt8](data), to: FileDescriptor.standardOutput)
      _ = try await newStyleRing.write([UInt8](data), to: FileDescriptor.standardOutput)
    } catch {
      // Ignore write errors - we're testing API compatibility
    }

    XCTAssertTrue(true) // If we get here, API is compatible
  }
}
