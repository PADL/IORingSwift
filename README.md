IORingSwift
===========

IORingSwift is a lightweight Swift wrapper for [io\_uring](https://en.wikipedia.org/wiki/Io_uring) designed for use cases where performance is more important than portability. It is not intended to be a replacement for [libdispatch](https://github.com/apple/swift-corelibs-libdispatch) or [SwiftNIO](https://github.com/apple/swift-nio); indeed, it presently requires the former, and it is somewhat less abstracted than the latter.

It was originally designed to support [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface) in an embedded application, as the Linux SPI user space driver is synchronous, however it is equally adept at sockets. A discussion which led to its development can be found [here](https://forums.swift.org/t/blocking-i-o-and-concurrency/67276).

The package consists of two libraries:

* [IORing](Sources/IORing), which provides `async/await` Swift concurrency-aware wrappers for making `io_uring` requests
* [IORingUtils](Sources/IORingUtils), an optional library providing for managing file descriptor lifetimes and handling socket addresses

The intention is that this will also eventually support the real-time I/O subsystem in Zephyr, for use with SwiftIO.

Notes
-----

* You'll need a recent (6.x) kernel to use some of the functionality, such as multi-shot `accept(2)`
* There's a race condition with submission groups (e.g. `IORing.copy()`) that is still under investigation
* Not all system calls are yet supported
* Tests are yet to be written, so caveat emptor

Pull requests are welcome, of course!

