#[[
This source file is part of the IORingSwift open source project

Copyright (c) 2024 PADL Software Pty Ltd and the IORingSwift project authors
Licensed under Apache License v2.0

See https://github.com/PADL/IORingSwift/blob/main/LICENSE for license information
#]]

include(CMakePackageConfigHelpers)

set(IORING_SWIFT_EXPORTS_FILE
  ${CMAKE_CURRENT_BINARY_DIR}/IORingSwiftExports.cmake)

configure_file(IORingSwiftConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/IORingSwiftConfig.cmake)

get_property(IORING_SWIFT_EXPORTS GLOBAL PROPERTY IORING_SWIFT_EXPORTS)
export(TARGETS ${IORING_SWIFT_EXPORTS}
  NAMESPACE IORingSwift::
  FILE ${IORING_SWIFT_EXPORTS_FILE}
  EXPORT_LINK_INTERFACE_LIBRARIES)

install(EXPORT IORingSwiftTargets
  FILE IORingSwiftTargets.cmake
  NAMESPACE IORingSwift::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/IORingSwift)

configure_package_config_file(
  IORingSwiftConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/install/IORingSwiftConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/IORingSwift)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/install/IORingSwiftConfig.cmake
  FindLibUring.cmake
  FindSwiftSystem.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/IORingSwift)
