cmake_minimum_required(VERSION 2.6)
project(simple-http-server C)
SET(CMAKE_BUILD_TYPE "Release")

add_definitions(-DLISTEN_ON_IPV6)
IF(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions("-DCPUBIT64")
ELSE()
    add_definitions("-DCPUBIT32")
ENDIF()

#在编译选项中加入c99支持
add_compile_options(-std=c99)
message(STATUS "optional:-std=c99") 

# include_directories("/usr/local/include")
# link_directories("/usr/local/lib")

add_executable(simple-http-server server.c)
target_link_libraries(simple-http-server pthread)

INSTALL(TARGETS simple-http-server RUNTIME DESTINATION bin)
