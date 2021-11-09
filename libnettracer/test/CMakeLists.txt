
if(DEFINED GITHUB_GTEST)
#Set up GTest, similarly to how it's proposed in https://github.com/google/googletest/tree/master/googletest#incorporating-into-an-existing-cmake-project
    configure_file(GoogleTest.cmake.in googletest-download/CMakeLists.txt)
    message(" ${CMAKE_COMMAND} ${CMAKE_GENERATOR} ${CMAKE_CURRENT_BINARY_DIR}" )
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
endif()

set(SOURCES
	connection_test.cpp
	connections_printing_test.cpp
	mock_bpf_maps_test.cpp
	netstat_test.cpp
	proc_tcp_test.cpp
	tuple_utils_test.cpp
)

PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${SOURCES})

set(HEADERS
	bpf_maps_processing_testing.h
	log_redirection.h
	mock_bpf_maps.h
)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${HEADERS})

add_executable(libnettracer_test ${SOURCES_FULL} ${HEADERS_FULL})
target_include_directories(libnettracer_test
	PRIVATE
		"${PROJECT_SOURCE_DIR}/libnettracer/src"
)

target_link_libraries(libnettracer_test libnettracer)
target_link_libraries(libnettracer_test -lpthread)
target_link_libraries(libnettracer_test -lz)
if(DEFINED GITHUB_GTEST)
    target_link_libraries(libnettracer_test gmock_main)
    target_link_libraries(libnettracer_test gtest_main)
else()
    target_link_libraries(libnettracer_test CONAN_PKG::gtest)
endif()

include(GoogleTest)
gtest_discover_tests(libnettracer_test)
