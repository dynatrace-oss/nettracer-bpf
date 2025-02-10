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

if(CMAKE_VERSION VERSION_GREATER "3.13")
	target_link_options(nettracersrv PRIVATE -static-libgcc -static-libstdc++)
else()
	target_link_libraries(nettracersrv -static-libgcc  -static-libstdc++)
endif()

target_include_directories(nettracersrv
	PRIVATE
		"${PROJECT_SOURCE_DIR}/libnettracer/src"
)

target_link_libraries(nettracersrv libnettracer)
target_link_libraries(nettracersrv CONAN_PKG::boost)

install(TARGETS nettracersrv
	RUNTIME DESTINATION "bin"
)
