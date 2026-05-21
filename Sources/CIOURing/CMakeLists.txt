#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

# Interface-only wrapper for the system liburing module map; symbols come
# from liburing at link time.
add_library(CIOURing INTERFACE)
target_include_directories(CIOURing INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/CIOURing>)
target_link_libraries(CIOURing INTERFACE LibUring::LibUring)

install(FILES
  CIOURing.h
  module.modulemap
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CIOURing)

_install_target(CIOURing)
set_property(GLOBAL APPEND PROPERTY IORING_SWIFT_EXPORTS CIOURing)
