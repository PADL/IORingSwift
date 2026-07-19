#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

file(GLOB IORING_UTILS_SOURCES CONFIGURE_DEPENDS *.swift)

add_library(IORingUtils ${IORING_UTILS_SOURCES})
target_link_libraries(IORingUtils
  PUBLIC
    IORing
    SocketAddress::SocketAddress
    AsyncExtensions::AsyncExtensions
    AsyncAlgorithms::AsyncAlgorithms)

target_compile_options(IORingUtils PRIVATE
  "$<$<COMPILE_LANGUAGE:Swift>:SHELL:-enable-experimental-feature StrictConcurrency>")

get_swift_host_os(_swift_os)
set_target_properties(IORingUtils PROPERTIES
  SOVERSION 0
  INTERFACE_INCLUDE_DIRECTORIES
    "$<BUILD_INTERFACE:${CMAKE_Swift_MODULE_DIRECTORY}>;$<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}/swift/${_swift_os}>")

_install_target(IORingUtils)
set_property(GLOBAL APPEND PROPERTY IORING_SWIFT_EXPORTS IORingUtils)
