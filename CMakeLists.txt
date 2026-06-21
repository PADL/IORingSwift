#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

cmake_minimum_required(VERSION 3.16)
project(IORingSwift
  LANGUAGES Swift CXX C)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

if(CMAKE_SYSTEM_NAME STREQUAL Windows OR CMAKE_SYSTEM_NAME STREQUAL Darwin)
  option(BUILD_SHARED_LIBS "Build shared libraries by default" YES)
endif()

option(IORING_BUILD_EXAMPLES "Build the example executables" OFF)

include(GNUInstallDirs)
include(SwiftSupport)

find_package(LibUring REQUIRED)
find_package(SwiftSystem REQUIRED)
find_package(SocketAddress REQUIRED)
find_package(AsyncExtensions REQUIRED)
find_package(AsyncAlgorithms REQUIRED)
find_package(Logging REQUIRED)
find_package(AsyncQueue REQUIRED)

add_subdirectory(Sources)

if(IORING_BUILD_EXAMPLES)
  add_subdirectory(Examples)
endif()

add_subdirectory(cmake/modules)
