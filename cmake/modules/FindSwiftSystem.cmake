#[[
This source file is part of the SocketAddress open source project

Copyright (c) 2024 PADL Software Pty Ltd and the SocketAddress project authors
Licensed under Apache License v2.0

See https://github.com/PADL/SocketAddress/blob/main/LICENSE.md for license information
#]]

# FindSwiftSystem.cmake
#
# Locates an installed apple/swift-system package built with its upstream
# CMake. Upstream installs `libSystemPackage.so`, the swiftmodule under
# `lib/swift/<os>/SystemPackage.swiftmodule/`, and `include/CSystem/*` headers,
# but does not ship an install-tree-usable Config.cmake.

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
  set(_swift_os macosx)
else()
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" _swift_os)
endif()

find_library(SwiftSystem_LIBRARY
  NAMES SystemPackage
  PATH_SUFFIXES lib)

find_path(SwiftSystem_MODULE_DIR
  NAMES SystemPackage.swiftmodule
  PATH_SUFFIXES lib/swift/${_swift_os})

find_path(SwiftSystem_CSYSTEM_INCLUDE_DIR
  NAMES module.modulemap
  PATH_SUFFIXES include/CSystem)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SwiftSystem
  REQUIRED_VARS
    SwiftSystem_LIBRARY
    SwiftSystem_MODULE_DIR
    SwiftSystem_CSYSTEM_INCLUDE_DIR)

if(SwiftSystem_FOUND)
  if(NOT TARGET SwiftSystem::CSystem)
    add_library(SwiftSystem::CSystem INTERFACE IMPORTED)
    set_target_properties(SwiftSystem::CSystem PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${SwiftSystem_CSYSTEM_INCLUDE_DIR}")
  endif()

  if(NOT TARGET SwiftSystem::SystemPackage)
    add_library(SwiftSystem::SystemPackage SHARED IMPORTED)
    set_target_properties(SwiftSystem::SystemPackage PROPERTIES
      IMPORTED_LOCATION "${SwiftSystem_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${SwiftSystem_MODULE_DIR}"
      INTERFACE_LINK_LIBRARIES "SwiftSystem::CSystem")
  endif()
endif()

mark_as_advanced(
  SwiftSystem_LIBRARY
  SwiftSystem_MODULE_DIR
  SwiftSystem_CSYSTEM_INCLUDE_DIR)
