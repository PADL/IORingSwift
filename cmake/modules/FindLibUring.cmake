#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

# FindLibUring.cmake
#
# Locates the liburing system library via pkg-config and creates an
# IMPORTED target LibUring::LibUring suitable for target_link_libraries().

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
  pkg_check_modules(LIBURING IMPORTED_TARGET liburing)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibUring
  REQUIRED_VARS LIBURING_FOUND)

if(LibUring_FOUND AND NOT TARGET LibUring::LibUring)
  add_library(LibUring::LibUring INTERFACE IMPORTED)
  target_link_libraries(LibUring::LibUring INTERFACE PkgConfig::LIBURING)
endif()
