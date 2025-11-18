IORingSwift
===========

IORingSwift is a lightweight Swift wrapper for [io\_uring](https://en.wikipedia.org/wiki/Io_uring) designed for use cases where performance is more important than portability. It is not intended to be a replacement for [libdispatch](https://github.com/apple/swift-corelibs-libdispatch) or [SwiftNIO](https://github.com/apple/swift-nio); indeed, it presently requires the former, and it is somewhat less abstracted than the latter.

It was originally designed to support [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface) in an embedded application, as the Linux SPI user space driver is synchronous, however it is equally adept at sockets. A discussion which led to its development can be found [here](https://forums.swift.org/t/blocking-i-o-and-concurrency/67276).

The package consists of two libraries:

* [IORing](Sources/IORing), which provides `async/await` Swift concurrency-aware wrappers for making `io_uring` requests
* [IORingUtils](Sources/IORingUtils), an optional library of helper functions
* [IORingFoundation](Sources/IORingFoundation), an optional library for using with Foundation

The intention is that this will also eventually support the real-time I/O subsystem in Zephyr, for use with [SwiftIO](https://github.com/madmachineio/SwiftIO) and its wrapper cousin [AsyncSwiftIO](https://github.com/PADL/LinuxHalSwiftIO/tree/main/Sources/AsyncSwiftIO).

Architecture
------------

IORing may be used as a singleton (`IORing.shared`), or they may be individually allocated; each `IORing` instance has a separate underlying ring.

Public API provides structured concurrency wrappers around common operations such as reading and writing. Multishot APIs, such as `accept(2)`, which can return multiple completions over time return an `AsyncThrowingStream`. Internally, wrappers allocate a concrete instance of `Submission<T>`, representing an initialized Submission Queue Entry (SQE), which is then submitted to the `io_uring`. Completion handlers are handled by having `libdispatch` monitor an `eventfd(2)` representing available completions. The `user_data` in each queue entry is a block, which executes the `onCompletion(cqe:)` method of the `Submission<T>` instance in the ring's isolated context. Care must be taken to manager pointer lifetimes across the event lifecycle.

Examples
--------

Here's an example of a TCP echo server, adapted from [IORingTCPEcho](Examples/IORingTCPEcho/IORingTCPEcho.swift).

```swift
import AsyncExtensions
import IORing
import IORingUtils

let socket = try Socket(ring: IORing.shared, domain: sa_family_t(AF_INET), type: SOCK_STREAM, protocol: 0)
try socket.setReuseAddr()
try socket.setTcpNoDelay()
try socket.bind(port: 10000)
try socket.listen(backlog: 10)

let clients: AnyAsyncSequence<Socket> = try await socket.accept()
for try await client in clients {
    Task {
        repeat {
            let data = try await client.receive(count: bufferSize)
            try await client.send(data)
        } while true
    }
}
```

Further examples can be found in [Examples](Examples).

Notes
-----

* You'll need a recent (6.x) kernel to use some of the functionality, such as multi-shot `accept(2)`
* Tests are yet to be written, so caveat emptor

Pull requests are welcome, of course!

