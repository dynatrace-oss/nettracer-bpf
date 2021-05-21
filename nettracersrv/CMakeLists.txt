set(SOURCES
	nettracer.cpp
	unified_log.cpp
)
PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}" ${SOURCES})

set(HEADERS
	unified_log.h
)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}" ${HEADERS})

add_executable(nettracersrv ${SOURCES_FULL} ${HEADERS_FULL})

target_include_directories(nettracersrv
	PRIVATE
		"${PROJECT_SOURCE_DIR}/libnettracer/src/cpp"
)

target_link_libraries(nettracersrv bpf_generic)
target_link_libraries(nettracersrv libnettracer)
target_link_libraries(nettracersrv /usr/lib/${ARCHITECTURE}-linux-gnu/libelf.a)
target_link_libraries(nettracersrv -lpthread)
target_link_libraries(nettracersrv -lz)
target_link_libraries(nettracersrv -lstdc++fs)
target_link_libraries(nettracersrv spdlog::spdlog)
target_link_libraries(nettracersrv fmt::fmt)
target_link_libraries(nettracersrv Boost::program_options)

install(TARGETS nettracersrv
	RUNTIME DESTINATION "bin"
)
