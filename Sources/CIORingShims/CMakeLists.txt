#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

set(CIORINGSHIMS_SOURCES
  BackDeploy.cpp
  CQHandler.cpp
  Message.cpp)

# Choose between libdispatch- and pthread-based completion-queue handlers.
# Default to pthread on Linux to avoid forcing a hard libdispatch dependency;
# default to dispatch on Darwin where it is always available.
if(NOT IORING_CQ_HANDLER)
  if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(IORING_CQ_HANDLER dispatch)
  else()
    set(IORING_CQ_HANDLER pthread)
  endif()
endif()
set(IORING_CQ_HANDLER "${IORING_CQ_HANDLER}" CACHE STRING
  "Completion-queue handler implementation (dispatch or pthread)")

if(IORING_CQ_HANDLER STREQUAL dispatch)
  list(APPEND CIORINGSHIMS_SOURCES DispatchCQHandler.cpp)
  set(_handler_define DISPATCH_IO_URING=1)
elseif(IORING_CQ_HANDLER STREQUAL pthread)
  list(APPEND CIORINGSHIMS_SOURCES PthreadCQHandler.cpp)
  set(_handler_define PTHREAD_IO_URING=1)
else()
  message(FATAL_ERROR "IORING_CQ_HANDLER must be \"dispatch\" or \"pthread\", got \"${IORING_CQ_HANDLER}\"")
endif()

add_library(CIORingShims ${CIORINGSHIMS_SOURCES})
target_compile_features(CIORingShims PRIVATE cxx_std_20)
target_compile_definitions(CIORingShims PRIVATE
  _XOPEN_SOURCE=700
  _DEFAULT_SOURCE
  ${_handler_define})
get_swift_host_os(_swift_os)

# The shim uses Apple-style block syntax (`^`) to pass Swift closures across
# the C boundary; clang requires -fblocks to parse it.
target_compile_options(CIORingShims PRIVATE -fblocks)
# Resolve BlocksRuntime from the Swift toolchain (shared in older versions,
# static in 6.3+); fall back to libdispatch which provides the same symbols.
find_library(BLOCKS_RUNTIME_LIBRARY
  NAMES BlocksRuntime
  PATHS
    /usr/lib/swift/${_swift_os}
    $ENV{HOME}/.local/share/swiftly/toolchains/*/usr/lib/swift/${_swift_os}
    $ENV{HOME}/.local/share/swiftly/toolchains/*/usr/lib/swift_static/${_swift_os}
  PATH_SUFFIXES lib)
if(BLOCKS_RUNTIME_LIBRARY)
  target_link_libraries(CIORingShims PUBLIC ${BLOCKS_RUNTIME_LIBRARY})
else()
  # libdispatch reexports the BlocksRuntime symbols.
  target_link_libraries(CIORingShims PUBLIC dispatch)
endif()
target_include_directories(CIORingShims
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/CIORingShims>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(CIORingShims PRIVATE LibUring::LibUring pthread)

set_target_properties(CIORingShims PROPERTIES
  SOVERSION 0)

install(FILES
  include/CIORingShims.h
  include/BackDeploy.h
  include/module.modulemap
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/CIORingShims)

_install_target(CIORingShims)
set_property(GLOBAL APPEND PROPERTY IORING_SWIFT_EXPORTS CIORingShims)
