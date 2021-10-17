set(SOURCES
	connections_printing.cpp
	localsock.cpp
	localsock6.cpp
	offsetguess.cpp
	proc_tcp.cpp
	tuple_utils.cpp
	netstat.cpp
)
PREPEND(SOURCES_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${SOURCES})

set(HEADERS
	connections_printing.h
	localsock.h
	localsock6.h
	offsetguess.h
	proc_tcp.h
	tuple_utils.h
	netstat.h
)
PREPEND(HEADERS_FULL "${CMAKE_CURRENT_LIST_DIR}/cpp" ${HEADERS})

add_library(libnettracer STATIC ${SOURCES_FULL} ${HEADERS_FULL})

target_include_directories(libnettracer
	PUBLIC
		"${PROJECT_SOURCE_DIR}"
)

add_dependencies(libnettracer bpf_program)
target_link_libraries(libnettracer bpf_generic)
target_link_libraries(libnettracer -lpthread)
target_link_libraries(libnettracer -lz)
target_link_libraries(libnettracer -lstdc++fs)
