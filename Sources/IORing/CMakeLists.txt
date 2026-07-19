#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

file(GLOB IORING_SOURCES CONFIGURE_DEPENDS *.swift)

add_library(IORing ${IORING_SOURCES})
target_link_libraries(IORing
  PUBLIC
    SwiftSystem::SystemPackage
    AsyncAlgorithms::AsyncAlgorithms
    AsyncExtensions::AsyncExtensions
    Logging::Logging
    AsyncQueue::AsyncQueue
  PRIVATE
    CIORingShims
    CIOURing)

target_compile_options(IORing PRIVATE
  "$<$<COMPILE_LANGUAGE:Swift>:SHELL:-package-name IORingSwift>"
  "$<$<COMPILE_LANGUAGE:Swift>:SHELL:-enable-experimental-feature StrictConcurrency>"
  "$<$<COMPILE_LANGUAGE:Swift>:SHELL:-enable-experimental-feature NonisolatedNonsendingByDefault>")

get_swift_host_os(_swift_os)
set_target_properties(IORing PROPERTIES
  SOVERSION 0
  INTERFACE_INCLUDE_DIRECTORIES
    "$<BUILD_INTERFACE:${CMAKE_Swift_MODULE_DIRECTORY}>;$<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}/swift/${_swift_os}>")

_install_target(IORing)
set_property(GLOBAL APPEND PROPERTY IORING_SWIFT_EXPORTS IORing)
