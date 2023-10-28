cmake_minimum_required(VERSION 3.20)
project(redis VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAXE_CXX_FLAGS "-Wall -Wextra -O2")

add_executable(client client.cpp)
add_executable(server server.cpp
    hashtable.cpp
    zset.cpp
    avl.cpp
    heap.cpp
    thread_pool.cpp)