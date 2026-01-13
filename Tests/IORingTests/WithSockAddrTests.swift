//
// Copyright (c) 2023-2026 PADL Software Pty Ltd
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

@preconcurrency import Foundation
@preconcurrency import Glibc
@testable import IORing
import IORingUtils
import SocketAddress
import struct SystemPackage.Errno
import XCTest

final class WithSockAddrTests: XCTestCase {
  // MARK: - IPv4 Tests

  func testWithSockAddrIPv4() throws {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(8080).bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")

    let (family, port, size) = try addr.withSockAddr { sa, size in
      (sa.pointee.sa_family, try sa.pointee.port, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_INET))
    XCTAssertEqual(port, 8080) // port property returns host byte order
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in>.size))
  }

  func testWithSockAddrIPv4AnyAddress() throws {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(9000).bigEndian
    addr.sin_addr.s_addr = INADDR_ANY

    let (isAny, size) = addr.withSockAddr { sa, size in
      let sinPtr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in.self)
      return (sinPtr.pointee.sin_addr.s_addr == INADDR_ANY, size)
    }

    XCTAssertTrue(isAny)
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in>.size))
  }

  func testWithSockAddrIPv4MultipleAddresses() throws {
    let testCases: [(String, UInt16)] = [
      ("192.168.1.1", 80),
      ("10.0.0.1", 443),
      ("172.16.0.1", 8443),
    ]

    for (ip, portNum) in testCases {
      var addr = sockaddr_in()
      addr.sin_family = sa_family_t(AF_INET)
      addr.sin_port = portNum.bigEndian
      addr.sin_addr.s_addr = inet_addr(ip)

      let (family, port, size) = try addr.withSockAddr { sa, size in
        (sa.pointee.sa_family, try sa.pointee.port, size)
      }

      XCTAssertEqual(family, sa_family_t(AF_INET), "Family mismatch for \(ip)")
      XCTAssertEqual(port, portNum, "Port mismatch for \(ip):\(portNum)") // port property returns host byte order
      XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in>.size), "Size mismatch for \(ip)")
    }
  }

  // MARK: - IPv6 Tests

  func testWithSockAddrIPv6() throws {
    var addr = sockaddr_in6()
    addr.sin6_family = sa_family_t(AF_INET6)
    addr.sin6_port = UInt16(8080).bigEndian
    addr.sin6_addr = in6_addr() // :: (all zeros = IPv6 any address)

    let (family, port, size) = try addr.withSockAddr { sa, size in
      (sa.pointee.sa_family, try sa.pointee.port, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_INET6))
    XCTAssertEqual(port, 8080) // port property returns host byte order
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in6>.size))
  }

  func testWithSockAddrIPv6Loopback() throws {
    var addr = sockaddr_in6()
    addr.sin6_family = sa_family_t(AF_INET6)
    addr.sin6_port = UInt16(3000).bigEndian
    // Set to ::1 (loopback)
    withUnsafeMutablePointer(to: &addr.sin6_addr) { ptr in
      ptr.withMemoryRebound(to: UInt8.self, capacity: 16) { bytes in
        bytes[15] = 1
      }
    }

    let (family, isLoopback, size) = addr.withSockAddr { sa, size in
      let sin6Ptr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in6.self)
      var address = sin6Ptr.pointee.sin6_addr
      var isLoopback = false
      withUnsafePointer(to: &address) { addrPtr in
        addrPtr.withMemoryRebound(to: UInt8.self, capacity: 16) { bytes in
          // Check if it's ::1
          isLoopback = (0..<15).allSatisfy { bytes[$0] == 0 } && bytes[15] == 1
        }
      }
      return (sin6Ptr.pointee.sin6_family, isLoopback, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_INET6))
    XCTAssertTrue(isLoopback)
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in6>.size))
  }

  func testWithSockAddrIPv6WithScopeId() throws {
    var addr = sockaddr_in6()
    addr.sin6_family = sa_family_t(AF_INET6)
    addr.sin6_port = UInt16(5000).bigEndian
    addr.sin6_scope_id = 42

    let (scopeId, size) = addr.withSockAddr { sa, size in
      let sin6Ptr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in6.self)
      return (sin6Ptr.pointee.sin6_scope_id, size)
    }

    XCTAssertEqual(scopeId, 42)
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in6>.size))
  }

  // MARK: - Unix Domain Socket Tests

  func testWithSockAddrUnixDomain() throws {
    let path = "/tmp/test.sock"
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_LOCAL)

    let pathSize = MemoryLayout.size(ofValue: addr.sun_path)
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
      ptr.withMemoryRebound(to: CChar.self, capacity: pathSize) { pathPtr in
        _ = path.withCString { strncpy(pathPtr, $0, pathSize) }
      }
    }

    let (family, retrievedPath, size) = addr.withSockAddr { sa, size in
      let sunPtr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_un.self)
      let pathBuffer = sunPtr.pointee.sun_path
      let retrievedPath = withUnsafeBytes(of: pathBuffer) { bytes in
        String(cString: bytes.baseAddress!.assumingMemoryBound(to: CChar.self))
      }
      return (sunPtr.pointee.sun_family, retrievedPath, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_LOCAL))
    XCTAssertEqual(retrievedPath, path)
    XCTAssertGreaterThan(size, 0)
  }

  func testWithSockAddrUnixDomainAbstractNamespace() throws {
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_LOCAL)

    // Abstract namespace (starts with null byte)
    let pathSize = MemoryLayout.size(ofValue: addr.sun_path)
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
      ptr.withMemoryRebound(to: UInt8.self, capacity: pathSize) { pathPtr in
        pathPtr[0] = 0 // Null byte indicates abstract namespace
        let abstractName = "test-socket"
        abstractName.utf8.enumerated().forEach { index, byte in
          pathPtr[index + 1] = byte
        }
      }
    }

    let (family, isAbstract, size) = addr.withSockAddr { sa, size in
      let sunPtr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_un.self)
      let pathBuffer = sunPtr.pointee.sun_path
      let isAbstract = withUnsafeBytes(of: pathBuffer) { bytes in
        bytes[0] == 0
      }
      return (sunPtr.pointee.sun_family, isAbstract, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_LOCAL))
    XCTAssertTrue(isAbstract)
    XCTAssertGreaterThan(size, 0)
  }

  // MARK: - sockaddr_storage Tests

  func testWithSockAddrStorageIPv4() {
    var storage = sockaddr_storage()
    withUnsafeMutablePointer(to: &storage) { storagePtr in
      storagePtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
        sin.pointee.sin_family = sa_family_t(AF_INET)
        sin.pointee.sin_port = UInt16(4000).bigEndian
        sin.pointee.sin_addr.s_addr = inet_addr("192.168.0.1")
      }
    }

    let (family, size) = storage.withSockAddr { sa, size in
      (sa.pointee.sa_family, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_INET))
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in>.size))
  }

  func testWithSockAddrStorageIPv6() {
    var storage = sockaddr_storage()
    withUnsafeMutablePointer(to: &storage) { storagePtr in
      storagePtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
        sin6.pointee.sin6_family = sa_family_t(AF_INET6)
        sin6.pointee.sin6_port = UInt16(6000).bigEndian
      }
    }

    let (family, size) = storage.withSockAddr { sa, size in
      (sa.pointee.sa_family, size)
    }

    XCTAssertEqual(family, sa_family_t(AF_INET6))
    XCTAssertEqual(size, socklen_t(MemoryLayout<sockaddr_in6>.size))
  }

  // MARK: - Size Consistency Tests

  func testSizePropertyConsistency() {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)

    let sizeFromWithSockAddr = addr.withSockAddr { _, size in size }
    let sizeFromProperty = addr.size

    XCTAssertEqual(sizeFromWithSockAddr, sizeFromProperty)
  }

  func testSizePropertyIPv6Consistency() {
    var addr = sockaddr_in6()
    addr.sin6_family = sa_family_t(AF_INET6)

    let sizeFromWithSockAddr = addr.withSockAddr { _, size in size }
    let sizeFromProperty = addr.size

    XCTAssertEqual(sizeFromWithSockAddr, sizeFromProperty)
  }

  // MARK: - Error Handling Tests

  func testWithSockAddrThrowingClosure() {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)

    do {
      _ = try addr.withSockAddr { _, _ in
        throw Errno.invalidArgument
      }
      XCTFail("Should have thrown an error")
    } catch {
      XCTAssertEqual(error as? Errno, .invalidArgument)
    }
  }

  func testWithSockAddrStorageThrowingClosure() {
    let storage = sockaddr_storage()

    do {
      _ = try storage.withSockAddr { _, _ in
        throw Errno.addressNotAvailable
      }
      XCTFail("Should have thrown an error")
    } catch {
      XCTAssertEqual(error as? Errno, .addressNotAvailable)
    }
  }

  // MARK: - Integration Tests

  func testWithSockAddrInMessageCreation() throws {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(7000).bigEndian
    addr.sin_addr.s_addr = inet_addr("10.0.0.1")

    let testData = Array("Test message data".utf8)
    let message = try Message(address: addr, buffer: testData, flags: 0)

    XCTAssertEqual(message.buffer, testData)
    XCTAssertEqual(message.flags, 0)

    // Verify we can extract the address
    let extractedAddress = try message.address
    XCTAssertNotNil(extractedAddress)
  }

  func testWithSockAddrInSocketBind() async throws {
    let ring = try IORing()
    let socket = try Socket(ring: ring, domain: sa_family_t(AF_INET), type: SOCK_STREAM)

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0 // Let kernel assign port
    addr.sin_addr.s_addr = INADDR_ANY

    try socket.bind(to: addr)

    let localAddress = try socket.localAddress
    XCTAssertNotNil(localAddress)
  }

  func testWithSockAddrMultipleOperations() {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(8888).bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")

    // Call withSockAddr multiple times on the same address
    for i in 1...5 {
      let (family, size) = addr.withSockAddr { sa, size in
        (sa.pointee.sa_family, size)
      }

      XCTAssertEqual(family, sa_family_t(AF_INET), "Iteration \(i): family mismatch")
      XCTAssertEqual(
        size,
        socklen_t(MemoryLayout<sockaddr_in>.size),
        "Iteration \(i): size mismatch"
      )
    }
  }

  // MARK: - Port Byte Order Tests

  func testWithSockAddrPortByteOrder() throws {
    let hostPort: UInt16 = 12345

    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = hostPort.bigEndian

    let retrievedPort = try addr.withSockAddr { sa, _ in
      try sa.pointee.port
    }

    // The port property automatically converts from network byte order to host byte order
    XCTAssertEqual(retrievedPort, hostPort)
  }
}
