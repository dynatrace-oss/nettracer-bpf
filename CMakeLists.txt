cmake_minimum_required(VERSION 3.10.2)

# Supported custom arguments that can be passed from command line:
#
# KERNEL_VERSION
# Specifies which kernel headers are to be used by the compiler.
#
# LLVM_VERSION
# Specifies which LLVM headers are to be used by the compiler.
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

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_CXX_EXTENSIONS TRUE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CONAN_EXPORTED)
	include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
	conan_basic_setup(TARGETS)
else ()
	include(conan.cmake)
	conan_cmake_run(CONANFILE conanfile.txt
			BASIC_SETUP CMAKE_TARGETS UPDATE NO_OUTPUT_DIRS
			BUILD missing
	)
endif ()

if(DEFINED BPF_DEBUG)
	set(BPF_DEBUG ${BPF_DEBUG})  # suppress CMake's warning about unused variable - it IS used in bpf_program
endif()

if(NOT DEFINED KERNEL_VERSION)
	execute_process(COMMAND uname -r OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE KERNEL_VERSION)
endif()


if(NOT DEFINED LLVM_BINDIR)
	execute_process(COMMAND llvm-config  --bindir OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE LLVM_BINDIR)
	message("llvm bindir: ${LLVM_BINDIR}")
endif()

if(NOT DEFINED LLVM_INCLUDE)
	execute_process(COMMAND llvm-config  --version OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE LLVM_VERSION)
	find_path( LLVM_INCLUDE NAMES stdarg.h PATHS  "/usr/lib64/clang/${LLVM_VERSION}/include" "/usr/lib/clang/${LLVM_VERSION}/include")
	message("llvm headers: ${LLVM_INCLUDE}")
endif()

if(NOT DEFINED ARCHITECTURE)
	execute_process(COMMAND uname -m OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE ARCHITECTURE)
endif()

if(ARCHITECTURE STREQUAL "x86_64")
	set(ARCH "x86")
	add_definitions(-D__TARGET_ARCH_x86)
elseif(ARCHITECTURE STREQUAL "aarch64")
	set(ARCH "arm64")
else()
	message(FATAL_ERROR "Architecture not supported!")
endif()

# we need to detect locations of kernel headers
# first, we define base directories:
# - the one related to the current version & arch
# - and possibly another one for generic headers
function(try_adding_kernel_headers_base_dir suffix mod_include)
	string(REGEX REPLACE "-[^-]+$" "-${suffix}" MOD_KERNEL_VERSION "${KERNEL_VERSION}")
	if(NOT MOD_KERNEL_VERSION STREQUAL KERNEL_VERSION)
		set(DIR "/usr/src/linux-headers-${MOD_KERNEL_VERSION}")
		if(EXISTS "${DIR}")
			set(${mod_include} "${DIR}/include/linux" PARENT_SCOPE)
		endif()
	endif()
endfunction()

set(KERNEL_HEADERS_BASE "/usr/src/linux-headers-${KERNEL_VERSION}")
set(MOD_INCLUDE "")
try_adding_kernel_headers_base_dir("common" MOD_INCLUDE)
find_path( KERNEL_INCLUDE NAMES kconfig.h PATHS   "${MOD_INCLUDE}"
						"/usr/src/linux-headers-${KERNEL_VERSION}/include/linux" 
                         "/usr/src/kernels/${KERNEL_VERSION}/include/linux" )
if(DEFINED KERNEL_INCLUDE)
    get_filename_component(PARENT_DIR ${KERNEL_INCLUDE} PATH)
    get_filename_component(PARENT_DIR ${PARENT_DIR} PATH)
    if(NOT ${KERNEL_HEADERS_BASE} STREQUAL ${PARENT_DIR})
	    set(KERNEL_HEADERS_BASE "${KERNEL_HEADERS_BASE};${PARENT_DIR}")
    endif()
endif()

message( "root of kernel headers:  ${KERNEL_HEADERS_BASE}")
# then we add various potential suffixes to the base directories and obtain actual directories to include
function(collect_kernel_headers_dirs base_dirs out_dirs)
	set(SUBDIRS "\
include;\
include/uapi;\
include/generated;\
include/generated/uapi;\
arch/${ARCH}/include;\
arch/${ARCH}/include/uapi;\
arch/${ARCH}/include/generated;\
arch/${ARCH}/include/generated/uapi")
	set(COMBINED "")
	foreach(base_dir ${base_dirs})
		foreach(subdir ${SUBDIRS})
			set(DIR "${base_dir}/${subdir}")
			if(EXISTS "${DIR}")
				list(APPEND COMBINED "${DIR}")
			endif()
		endforeach()
	endforeach()
	set(${out_dirs} "${COMBINED}" PARENT_SCOPE)
endfunction()
collect_kernel_headers_dirs("${KERNEL_HEADERS_BASE}" KERNEL_HEADERS)


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
add_custom_target(run-tests COMMAND ${CMAKE_CTEST_COMMAND} -T Test --no-compress-output --output-on-failure)

add_subdirectory(bpf_program)
add_subdirectory(bpf_generic)
add_subdirectory(libnettracer)
add_subdirectory(nettracersrv)
