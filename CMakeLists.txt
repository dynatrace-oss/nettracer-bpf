cmake_minimum_required(VERSION 3.10.2)

# Supported custom arguments that can be passed from command line:
#
# KERNEL_VERSION
# Specifies which kernel headers are to be used by the compiler.
#
# GCC_VERSION
# Specifies which GCC headers are to be used by the compiler.
#
# ARCHITECTURE
# Specifies the target architecture.
#
# DEBUG_BPF
# Specifies the build type of the BPF program. By default, BPF program always compiles in release mode, even if CMAKE_BUILD_TYPE == Debug.
#

if(NOT UNIX)
	message(FATAL_ERROR "OS not supported!")
endif(NOT UNIX)

project(nettracer LANGUAGES C CXX DESCRIPTION "")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_VERBOSE_MAKEFILE TRUE)

set(CMAKE_CXX_EXTENSIONS FALSE)

if(NOT TARGET fmt)
	find_package(fmt 7.0.3 REQUIRED)
endif(NOT TARGET fmt)
if(NOT TARGET spdlog)
	find_package(spdlog 1.8.0 REQUIRED)
endif(NOT TARGET spdlog)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS program_options)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

if(DEFINED BPF_DEBUG)
	set(BPF_DEBUG ${BPF_DEBUG})  # suppress CMake's warning about unused variable - it IS used in bpf_program
endif()

if(NOT DEFINED KERNEL_VERSION)
	execute_process(COMMAND uname -r OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE KERNEL_VERSION)
endif()
if(NOT DEFINED GCC_VERSION)
	execute_process(COMMAND gcc -dumpversion OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE GCC_VERSION)
endif()

if(NOT DEFINED ARCHITECTURE)
	execute_process(COMMAND uname -m OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE ARCHITECTURE)
endif()

if(ARCHITECTURE STREQUAL "x86_64")
	set(ARCH "x86")
elseif(ARCHITECTURE STREQUAL "aarch64")
	set(ARCH "arm64")
else()
	message(FATAL_ERROR "Architecture not supported!")
endif()

set(KERNEL_HEADERS "/lib/modules/${KERNEL_VERSION}/build")
set(GCC_HEADERS "/usr/lib/gcc/${ARCHITECTURE}-linux-gnu/${GCC_VERSION}/include")

# Must add include paths here because includes are applied before flags in CMake and -nostdinc messes things up
add_compile_options(-Wall -I/usr/include -I/usr/include/${ARCHITECTURE}-linux-gnu)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Function used later to get absolute paths
function(PREPEND var prefix)
	set(listVar "")
	foreach(f ${ARGN})
		list(APPEND listVar "${prefix}/${f}")
	endforeach(f)
	set(${var} "${listVar}" PARENT_SCOPE)
endfunction(PREPEND)

# Set up GTest, similarly to how it's proposed in https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
configure_file(GoogleTest.cmake.in googletest-download/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
	RESULT_VARIABLE result
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download
)
if(result)
	message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
	RESULT_VARIABLE result
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)
if(result)
	message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                 ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                 EXCLUDE_FROM_ALL)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

file(READ "version.properties" ver)
string(REGEX MATCH "version=([0-9]+)\.([0-9]+)\.([0-9]+)" _ ${ver})
if(NOT CMAKE_MATCH_COUNT EQUAL 3)
	message(FATAL_ERROR "Version parsing failed\n    Got: ${ver}")
endif()
set(NETTRACER_VERSION_MAJOR ${CMAKE_MATCH_1})
set(NETTRACER_VERSION_MINOR ${CMAKE_MATCH_2})
set(NETTRACER_VERSION_PATCH ${CMAKE_MATCH_3})
add_definitions(-DNETTRACER_VERSION_MAJOR=${NETTRACER_VERSION_MAJOR})
add_definitions(-DNETTRACER_VERSION_MINOR=${NETTRACER_VERSION_MINOR})
add_definitions(-DNETTRACER_VERSION_PATCH=${NETTRACER_VERSION_PATCH})

include(CTest)
enable_testing()

add_subdirectory(bpf_program)
add_subdirectory(bpf_generic)
add_subdirectory(libnettracer)
add_subdirectory(nettracer)
add_subdirectory(nettracersrv)
