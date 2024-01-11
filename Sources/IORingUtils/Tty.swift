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

public enum Parity {
  case none
  case odd
  case even
}

public enum StopBits {
  case one
  case two
}

public enum DataBits {
  case seven
  case eight
}

public extension termios {
  mutating func setN81(speed: UInt32) throws {
    try makeRaw()
    try set(speed: speed)
    set(parity: .none)
    set(stopBits: .one)
    set(dataBits: .eight)
  }

  mutating func makeRaw() throws {
    cfmakeraw(&self)
  }

  mutating func set(speed: UInt32) throws {
    var tty = self
    try Errno.throwingErrno {
      cfsetspeed(&tty, speed)
    }
    self = tty
  }

  mutating func set(parity: Parity) {
    switch parity {
    case .none:
      c_cflag &= ~tcflag_t(PARENB | PARODD)
    case .odd:
      c_cflag |= tcflag_t(PARENB | PARODD)
    case .even:
      c_cflag |= tcflag_t(PARENB)
      c_cflag &= ~tcflag_t(PARODD)
    }
  }

  mutating func set(stopBits: StopBits) {
    switch stopBits {
    case .two:
      c_cflag |= tcflag_t(CSTOPB)
    case .one:
      c_cflag &= ~tcflag_t(CSTOPB)
    }
  }

  mutating func set(dataBits: DataBits) {
    switch dataBits {
    case .eight:
      c_cflag |= tcflag_t(CS8)
    case .seven:
      c_cflag |= tcflag_t(CS7)
    }
  }
}

public extension FileDescriptorRepresentable {
  func set(tty: termios) throws {
    var tty = tty
    try Errno.throwingErrno {
      tcsetattr(self.fileDescriptor, TCSANOW, &tty)
    }
  }

  func getTty() throws -> termios {
    var tty = termios()
    try Errno.throwingErrno {
      tcgetattr(self.fileDescriptor, &tty)
    }
    return tty
  }

  var isATty: Bool {
    isatty(fileDescriptor) != 0
  }
}
