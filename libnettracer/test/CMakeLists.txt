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
target_link_libraries(libnettracer_test -lstdc++fs)
target_link_libraries(libnettracer_test spdlog::spdlog)
target_link_libraries(libnettracer_test fmt::fmt)
target_link_libraries(libnettracer_test gmock_main)
target_link_libraries(libnettracer_test gtest_main)

include(GoogleTest)
gtest_discover_tests(libnettracer_test)
