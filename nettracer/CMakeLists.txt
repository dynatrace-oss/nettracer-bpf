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
		"${PROJECT_SOURCE_DIR}/libnettracer/src"
)

target_link_libraries(nettracer bpf_generic)
target_link_libraries(nettracer libnettracer)
target_link_libraries(nettracer -lpthread)
target_link_libraries(nettracer -lz)
if(DEFINED CONAN_DEPS)
    target_link_libraries(nettracer CONAN_PKG::boost)
else()
    target_link_libraries(nettracer Boost::program_options)
endif()
