set(SOURCES
    bpf_events.cpp
	bpf_debug_counters.cpp
	config_watcher.cpp
	connections_printing.cpp
	inotify_watcher.cpp
	localsock.cpp
	localsock6.cpp
	offsetguess.cpp
	proc_tcp.cpp
	system_calls.cpp
	system_utils.cpp
	tuple_utils.cpp
	netstat.cpp
)

set(HEADERS
    bpf_events.h
	bpf_debug_counters.h
	config_watcher.h
	connections_printing.h
	inotify_watcher.h
	localsock.h
	localsock6.h
	offsetguess.h
	proc_tcp.h
	system_calls.h
	system_utils.h
	tuple_utils.h
	netstat.h
)

add_library(libnettracer STATIC ${SOURCES} ${HEADERS})

target_include_directories(libnettracer
	PUBLIC
		"${PROJECT_SOURCE_DIR}"
)

add_dependencies(libnettracer bpf_program)
target_link_libraries(libnettracer bpf_generic)
target_link_libraries(libnettracer /usr/lib/${ARCHITECTURE}-linux-gnu/libtinfo.a)
