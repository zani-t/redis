cmake_minimum_required(VERSION 3.20)
project(redis VERSION 0.1.0)

include(CTest)
enable_testing()
add_subdirectory(testing)

set(CMAKE_CXX_STANDARD 11)
set(CMAXE_CXX_FLAGS "-Wall -Wextra -O2")

add_executable(client src/client.cpp)
add_executable(server src/server.cpp
    src/hashtable.cpp
    src/zset.cpp
    src/avl.cpp
    src/heap.cpp
    src/thread_pool.cpp)