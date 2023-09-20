IORingSwift
===========

This is a lightweight Swift wrapper for `io_uring` designed for embedded use cases.

It is not a replacement for `libdispatch` or `SwiftNIO`; indeed, it uses the former to wake on completion.

The package consists of two libraries:

* `IORing`, which provides `async/await` Swift concurrency-aware wrappers for making `io_uring` requests
* `IORingUtils`, an optional library providing for managing file descriptor lifetimes and handling socket addresses

Not all system calls are yet supported and tests are yet to be written, so caveat emptor. Pull requests welcome.

The intention is that this will also eventually support the real-time I/O subsystem in Zephyr, for use with SwiftIO.

