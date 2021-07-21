cmake_minimum_required(VERSION 3.10)

project(optimin
    LANGUAGES CXX
    DESCRIPTION "MaxSAT-based fuzzing corpus minimizer"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Add LLVM
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS} -DNDEBUG)

add_subdirectory(EvalMaxSAT)
add_subdirectory(src)
