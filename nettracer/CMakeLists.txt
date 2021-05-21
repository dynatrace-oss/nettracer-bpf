set(SOURCES
	main.cpp
)
PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}" ${SOURCES})

set(HEADERS

)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}" ${HEADERS})

add_executable(nettracer ${SOURCES_FULL} ${HEADERS_FULL})

target_include_directories(nettracer
	PRIVATE
		"${PROJECT_SOURCE_DIR}/libnettracer/src/cpp"
)

target_link_libraries(nettracer bpf_generic)
target_link_libraries(nettracer libnettracer)
target_link_libraries(nettracer /usr/lib/${ARCHITECTURE}-linux-gnu/libelf.a)
target_link_libraries(nettracer -lpthread)
target_link_libraries(nettracer -lz)
target_link_libraries(nettracer -lstdc++fs)
target_link_libraries(nettracer spdlog::spdlog)
target_link_libraries(nettracer fmt::fmt)
target_link_libraries(nettracer Boost::program_options)
