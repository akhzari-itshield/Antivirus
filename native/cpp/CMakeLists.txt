cmake_minimum_required(VERSION 3.18)
project(itshield_native_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build a shared library that exposes a pure C ABI so Python (via cffi or
# ctypes) and Rust (via extern "C") can both link against it without ABI
# surprises. See section 4.3 of the architecture document.
add_library(itshield_native_cpp SHARED
    src/native.cpp
)

target_include_directories(itshield_native_cpp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Warnings as errors in release builds for security-sensitive code.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(itshield_native_cpp PRIVATE -Wall -Wextra -Wpedantic -Werror)
else()
    target_compile_options(itshield_native_cpp PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(
    TARGETS itshield_native_cpp
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(
    FILES include/itshield_native.h
    DESTINATION include
)
