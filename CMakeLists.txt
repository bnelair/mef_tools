# Top-level build for the mef3io Python extension (driven by scikit-build-core).
cmake_minimum_required(VERSION 3.26)
project(mef3io LANGUAGES CXX)

add_subdirectory(core)

# --- nanobind extension ---
find_package(Python 3.10 REQUIRED COMPONENTS Interpreter Development.Module)

# Locate nanobind's CMake config via the installed package.
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE
  OUTPUT_VARIABLE NB_DIR)
list(APPEND CMAKE_PREFIX_PATH "${NB_DIR}")
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(_mef3io STABLE_ABI bindings/python/mef3io_ext.cpp)
target_link_libraries(_mef3io PRIVATE mef3io_core)
target_compile_features(_mef3io PRIVATE cxx_std_20)

install(TARGETS _mef3io LIBRARY DESTINATION mef3io)
