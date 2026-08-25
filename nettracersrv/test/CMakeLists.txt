
set(SOURCES
	cpp/file_access_checker_test.cpp
    ../posix_file_access.cpp
)

set(SOURCES_FULL ${SOURCES})
list(TRANSFORM SOURCES_FULL PREPEND "${CMAKE_CURRENT_LIST_DIR}/")

set(HEADERS
	../posix_file_access.h
	../file_access_interface.h
)
set(HEADERS_FULL ${HEADERS})
list(TRANSFORM HEADERS_FULL PREPEND "${CMAKE_CURRENT_LIST_DIR}/")


add_executable(nettracersrv_test ${SOURCES_FULL} ${HEADERS_FULL})


target_include_directories(nettracersrv_test PRIVATE 
    ${CMAKE_CURRENT_LIST_DIR}/../
    "${PROJECT_SOURCE_DIR}/libnettracer/src"
)

find_package(Threads REQUIRED)

target_link_libraries(nettracersrv_test PRIVATE
    libnettracer
    z
    Threads::Threads
    ${CMAKE_DL_LIBS}
    CONAN_PKG::gtest
    CONAN_PKG::boost
)

install(TARGETS nettracersrv_test RUNTIME DESTINATION "bin")