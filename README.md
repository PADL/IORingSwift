IORingSwift
===========

`IORingSwift` is a lightweight Swift wrapper for `io_uring` designed for use cases where performance is more important than portability. It is not intended to be a replacement for `libdispatch` or `SwiftNIO`; indeed, it presently requires the former, and it is somewhat less abstracted than the latter.

It was originally designed to support [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface) in an embedded application, as the Linux SPI user space driver is synchronous, however it is equally adept at sockets. A discussion which led to its development can be found [here](https://forums.swift.org/t/blocking-i-o-and-concurrency/67276).

The package consists of two libraries:

* `IORing`, which provides `async/await` Swift concurrency-aware wrappers for making `io_uring` requests
* `IORingUtils`, an optional library providing for managing file descriptor lifetimes and handling socket addresses

Not all system calls are yet supported and tests are yet to be written, so caveat emptor. Pull requests welcome.

The intention is that this will also eventually support the real-time I/O subsystem in Zephyr, for use with SwiftIO.
