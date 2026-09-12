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

Public API provides structured concurrency wrappers around common operations such as reading and writing. Multishot APIs, such as `accept(2)`, which can return multiple completions over time return an `AsyncThrowingStream`.

Internally, wrappers allocate a concrete instance of `Submission<T>`, representing an initialized Submission Queue Entry (SQE), which is then submitted to the `io_uring`. Completions are reaped by `IORingExecutor`, which the first ring installs as the global executor: a pool of threads, one per CPU, that never exit (the kernel cancels a request when the thread that submitted it exits, which the default executor's threads do after five idle seconds), with an `epoll(7)` of every ring's `eventfd(2)` that the idle thread waits in, so that the thread which reaps a completion runs the task waiting on it. `IORing.installExecutor(policy: .preference)` installs it instead as an executor tasks opt into with `Task(executorPreference: IORing.taskExecutor)`, leaving the global executor alone; a request from a task that has not opted in is still submitted by a pool thread, at the cost of a thread switch each way. `SWIFT_IORING_EXECUTOR` (`global` or `preference`) chooses from the environment and `SWIFT_IORING_EXECUTOR_THREADS` sets the thread count. The `user_data` in each queue entry is a block, which executes the `onCompletion(cqe:)` method of the `Submission<T>` instance in the ring's isolated context. Care must be taken to manager pointer lifetimes across the event lifecycle.

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

