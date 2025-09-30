import Foundation
import Glibc
@testable import IORing
import IORingUtils
import struct SystemPackage.Errno
import struct SystemPackage.FileDescriptor
import XCTest

final class IORingTests: XCTestCase {
  var tmpDir: String {
    ProcessInfo.processInfo.environment["RUNNER_TEMP"] ?? "/var/tmp"
  }

  func testIORingInitialization() async throws {
    let ring = try IORing()
    XCTAssertNotNil(ring)
    XCTAssertEqual(ring.description.contains("IORing"), true)
  }

  func testFixedBufferRegistration() async throws {
    let ring = try IORing()

    try await ring.registerFixedBuffers(count: 4, size: 4096)

    try await ring.unregisterFixedBuffers()
  }

  func testFixedBufferRegistrationErrors() async throws {
    let ring = try IORing()

    do {
      try await ring.registerFixedBuffers(count: 0, size: 4096)
      XCTFail("Should have thrown an error for count=0")
    } catch {
      XCTAssertEqual(error as? Errno, .invalidArgument)
    }

    do {
      try await ring.registerFixedBuffers(count: 4, size: 0)
      XCTFail("Should have thrown an error for size=0")
    } catch {
      XCTAssertEqual(error as? Errno, .invalidArgument)
    }
  }

  func testBasicFileOperations() async throws {
    let ring = try IORing()
    let tempFile = "\(tmpDir)/ioring_test_\(getpid()).txt"
    let testData = "Hello, IORing World!"
    let testBytes = Array(testData.utf8)

    defer {
      unlink(tempFile)
    }

    let writeFd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))
    defer { try? writeFd.close() }

    let bytesWritten = try await ring.write(testBytes, to: writeFd)
    XCTAssertEqual(bytesWritten, testBytes.count)

    let readFd = FileDescriptor(rawValue: open(tempFile, O_RDONLY))
    defer { try? readFd.close() }

    let readData = try await ring.read(count: testBytes.count, from: readFd)
    XCTAssertEqual(readData, testBytes)

    let readFd2 = FileDescriptor(rawValue: open(tempFile, O_RDONLY))
    defer { try? readFd2.close() }
    let readIntoBuffer = try await ring.read(count: testBytes.count, from: readFd2)
    XCTAssertEqual(readIntoBuffer, testBytes)
  }

  func testFixedBufferOperations() async throws {
    let ring = try IORing()
    let tempFile = "\(tmpDir)/ioring_fixed_test_\(getpid()).txt"
    let testData = "Fixed buffer test data!"
    let testBytes = Array(testData.utf8)

    defer {
      unlink(tempFile)
    }

    do {
      try await ring.registerFixedBuffers(count: 2, size: 1024)
    } catch {
      // Skip test if io_uring is not supported
      throw XCTSkip("io_uring not supported in this environment: \(error)")
    }

    defer {
      Task { try? await ring.unregisterFixedBuffers() }
    }

    let writeFd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))
    defer { try? writeFd.close() }

    let bytesWritten = try await ring.writeFixed(
      testBytes,
      offset: 0,
      bufferIndex: 0,
      to: writeFd
    )
    XCTAssertEqual(bytesWritten, testBytes.count)

    let readFd = FileDescriptor(rawValue: open(tempFile, O_RDONLY))
    defer { try? readFd.close() }

    try await ring.readFixed(
      count: testBytes.count,
      offset: 0,
      bufferIndex: 1,
      from: readFd
    ) { buffer in
      let readBytes = Array(buffer)
      XCTAssertEqual(readBytes, testBytes)
    }
  }

  func testSubmissionGroupBasic() async throws {
    let ring = try IORing()

    let tempFile = "\(tmpDir)/ioring_group_\(getpid()).txt"
    let testData = Array("Test data for submission group".utf8)

    defer {
      unlink(tempFile)
    }

    do {
      try await ring.registerFixedBuffers(count: 1, size: 1024)
    } catch {
      // Skip test if io_uring is not supported
      throw XCTSkip("io_uring not supported in this environment: \(error)")
    }

    defer {
      Task { try? await ring.unregisterFixedBuffers() }
    }

    let fd = FileDescriptor(rawValue: open(tempFile, O_CREAT | O_RDWR | O_TRUNC, 0o644))
    defer { try? fd.close() }

    _ = try await ring.writeFixed(
      testData,
      offset: 0,
      bufferIndex: 0,
      to: fd
    )

    try await ring.readFixed(
      count: testData.count,
      offset: 0,
      bufferIndex: 0,
      from: fd
    ) { buffer in
      let readBytes = Array(buffer)
      XCTAssertEqual(readBytes, testData)
    }
  }

  func testSqeFlags() {
    let defaultFlags = IORing.SqeFlags()
    XCTAssertEqual(defaultFlags.rawValue, 0)

    let linkFlags = IORing.SqeFlags(link: true)
    XCTAssertEqual(linkFlags, IORing.SqeFlags.ioLink)

    let combinedFlags: IORing.SqeFlags = [IORing.SqeFlags.fixedFile, IORing.SqeFlags.ioDrain]
    XCTAssertTrue(combinedFlags.contains(IORing.SqeFlags.fixedFile))
    XCTAssertTrue(combinedFlags.contains(IORing.SqeFlags.ioDrain))
    XCTAssertFalse(combinedFlags.contains(IORing.SqeFlags.ioLink))
  }

  func testMessageCreation() throws {
    let testData = "Hello, message world!"
    let testBytes = Array(testData.utf8)

    let message1 = Message(capacity: 100)
    XCTAssertEqual(message1.buffer.count, 100)
    XCTAssertEqual(message1.flags, 0)

    let message2 = Message(buffer: testBytes, flags: 42)
    XCTAssertEqual(message2.buffer, testBytes)
    XCTAssertEqual(message2.flags, 42)
  }

  func testErrnoThrowingHelper() throws {
    let successResult = try Errno.throwingErrno { 42 }
    XCTAssertEqual(successResult, 42)

    do {
      try Errno.throwingErrno { -22 }
      XCTFail("Should have thrown an error")
    } catch {
      XCTAssertEqual(error as? Errno, .invalidArgument)
    }
  }

  func testIORingEquality() async throws {
    let ring1 = try IORing()
    let ring2 = try IORing()

    XCTAssertEqual(ring1, ring1)
    XCTAssertNotEqual(ring1, ring2)
  }

  func testIORingHashing() async throws {
    let ring = try IORing()
    let hasher1 = ring.hashValue
    let hasher2 = ring.hashValue

    XCTAssertEqual(hasher1, hasher2)
  }

  func testIOVecExtensions() throws {
    var iov = iovec()
    XCTAssertEqual(iov.iov_len, 0)

    iov.iov_len = 42
    XCTAssertEqual(iov.iov_len, 42)
  }

  func testCopyOperation() async throws {
    let ring = try IORing()
    let sourceFile = "\(tmpDir)/ioring_source_\(getpid()).txt"
    let destFile = "\(tmpDir)/ioring_dest_\(getpid()).txt"
    let testData = "Data to copy between files"
    let testBytes = Array(testData.utf8)

    defer {
      unlink(sourceFile)
      unlink(destFile)
    }

    try await ring.registerFixedBuffers(count: 1, size: 1024)
    defer {
      Task { try? await ring.unregisterFixedBuffers() }
    }

    let writeFd = FileDescriptor(rawValue: open(sourceFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))
    _ = try await ring.write(testBytes, to: writeFd)
    try? writeFd.close()

    let sourceFd = FileDescriptor(rawValue: open(sourceFile, O_RDONLY))
    let destFd = FileDescriptor(rawValue: open(destFile, O_CREAT | O_WRONLY | O_TRUNC, 0o644))

    try await ring.copy(
      count: testBytes.count,
      bufferIndex: 0,
      from: sourceFd,
      to: destFd
    )

    try? sourceFd.close()
    try? destFd.close()

    let readFd = FileDescriptor(rawValue: open(destFile, O_RDONLY))
    defer { try? readFd.close() }
    let copiedData = try await ring.read(count: testBytes.count, from: readFd)
    XCTAssertEqual(copiedData, testBytes)
  }

  func testUnsafeBufferInitialization() {
    let buffer = [UInt8]._unsafelyInitialized(count: 10)
    XCTAssertEqual(buffer.count, 10)
  }
}
