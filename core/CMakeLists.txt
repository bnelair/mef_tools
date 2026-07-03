# mef3io core C++ library.
cmake_minimum_required(VERSION 3.26)
project(mef3io_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

file(GLOB MEF3IO_CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(mef3io_core STATIC ${MEF3IO_CORE_SOURCES})
target_include_directories(mef3io_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
set_target_properties(mef3io_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(MSVC)
  target_compile_options(mef3io_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(mef3io_core PRIVATE -Wall -Wextra)
endif()

# --- Tests (Catch2, fetched only when building tests standalone) ---
option(MEF3IO_BUILD_TESTS "Build mef3io C++ unit tests" OFF)
if(MEF3IO_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2)
  FetchContent_MakeAvailable(Catch2)
  file(GLOB MEF3IO_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
  add_executable(mef3io_tests ${MEF3IO_TEST_SOURCES})
  target_link_libraries(mef3io_tests PRIVATE mef3io_core Catch2::Catch2WithMain)
  enable_testing()
  add_test(NAME mef3io_tests COMMAND mef3io_tests)
endif()
