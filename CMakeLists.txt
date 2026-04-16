cmake_minimum_required(VERSION 3.12)

project(dbgx_mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Version management ---
set(DBGX_VERSION "0.0.0-dev" CACHE STRING "Project version (injected by CI from git tag)")

# Parse MAJOR.MINOR.PATCH for version.rc
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" _version_match "${DBGX_VERSION}")
if(_version_match)
  set(DBGX_VERSION_MAJOR "${CMAKE_MATCH_1}")
  set(DBGX_VERSION_MINOR "${CMAKE_MATCH_2}")
  set(DBGX_VERSION_PATCH "${CMAKE_MATCH_3}")
else()
  set(DBGX_VERSION_MAJOR 0)
  set(DBGX_VERSION_MINOR 0)
  set(DBGX_VERSION_PATCH 0)
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/version.rc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
  @ONLY
)

set(WINDBG_EXTENSION_DEF_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/dbgx-mcp.def")
set(WINDBG_EXPORT_CHECK_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/cmake/verify_windbg_exports.cmake")
set(WINDBG_EXTENSION_OUTPUT_NAME "dbgx-mcp")
set(WINDBG_REQUIRED_EXPORTS
  DebugExtensionInitialize
  DebugExtensionCanUnload
  DebugExtensionUninitialize
  DebugExtensionUnload
)
string(REPLACE ";" "|" WINDBG_REQUIRED_EXPORTS_ARG "${WINDBG_REQUIRED_EXPORTS}")
set(WINDBG_REQUIRED_EXPORTS_WITH_SENTINEL
  ${WINDBG_REQUIRED_EXPORTS}
  DebugExtensionMissingForGuardrail
)
string(REPLACE ";" "|" WINDBG_REQUIRED_EXPORTS_WITH_SENTINEL_ARG "${WINDBG_REQUIRED_EXPORTS_WITH_SENTINEL}")

add_library(dbgx-mcp SHARED
  src/mcp/http_server.cpp
  src/mcp/io_echo.cpp
  src/mcp/json.cpp
  src/mcp/json_rpc.cpp
  src/windbg/dbgeng_command_executor.cpp
  src/dbgx-mcp.cpp
  src/dbgx-mcp.def
  "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
)

set_target_properties(dbgx-mcp PROPERTIES
  OUTPUT_NAME ${WINDBG_EXTENSION_OUTPUT_NAME}
  OUTPUT_NAME_DEBUG ${WINDBG_EXTENSION_OUTPUT_NAME}
  OUTPUT_NAME_RELEASE ${WINDBG_EXTENSION_OUTPUT_NAME}
  VERSION ${DBGX_VERSION}
)

if(MSVC)
  # CMake 3.12 doesn't have target_link_options (added in 3.13)
  set_target_properties(dbgx-mcp PROPERTIES
    LINK_FLAGS "/DEF:\"${WINDBG_EXTENSION_DEF_FILE}\""
  )
endif()

target_include_directories(dbgx-mcp PRIVATE include)

target_compile_definitions(dbgx-mcp PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
  DBGX_VERSION_STRING="${DBGX_VERSION}"
)

target_link_libraries(dbgx-mcp PRIVATE
  dbgeng
  ws2_32
)

add_custom_target(check_windbg_exports
  COMMAND "${CMAKE_COMMAND}"
    "-DDLL_PATH=$<TARGET_FILE:dbgx-mcp>"
    "-DLINKER_EXECUTABLE=${CMAKE_LINKER}"
    "-DREQUIRED_EXPORTS=${WINDBG_REQUIRED_EXPORTS_ARG}"
    -P "${WINDBG_EXPORT_CHECK_SCRIPT}"
  DEPENDS dbgx-mcp
  COMMENT "Verifying WinDbg extension exports"
  VERBATIM
)

enable_testing()

add_executable(unit_tests
  src/mcp/http_server.cpp
  src/mcp/io_echo.cpp
  src/mcp/json.cpp
  src/mcp/json_rpc.cpp
  tests/unit_tests.cpp
)

target_include_directories(unit_tests PRIVATE include)
target_link_libraries(unit_tests PRIVATE ws2_32)

target_compile_definitions(unit_tests PRIVATE
  DBGX_VERSION_STRING="${DBGX_VERSION}"
)

add_test(NAME unit_tests COMMAND unit_tests)

add_test(NAME verify_windbg_exports
  COMMAND "${CMAKE_COMMAND}"
    "-DDLL_PATH=$<TARGET_FILE:dbgx-mcp>"
    "-DLINKER_EXECUTABLE=${CMAKE_LINKER}"
    "-DREQUIRED_EXPORTS=${WINDBG_REQUIRED_EXPORTS_ARG}"
    -P "${WINDBG_EXPORT_CHECK_SCRIPT}"
)

add_test(NAME verify_windbg_exports_missing_symbol
  COMMAND "${CMAKE_COMMAND}"
    "-DDLL_PATH=$<TARGET_FILE:dbgx-mcp>"
    "-DLINKER_EXECUTABLE=${CMAKE_LINKER}"
    "-DREQUIRED_EXPORTS=${WINDBG_REQUIRED_EXPORTS_WITH_SENTINEL_ARG}"
    -P "${WINDBG_EXPORT_CHECK_SCRIPT}"
)

set_tests_properties(verify_windbg_exports_missing_symbol PROPERTIES
  WILL_FAIL TRUE
)
