cmake_minimum_required(VERSION 3.20)

add_executable(test_avl test_avl.cpp)
add_executable(test_heap test_heap.cpp)
add_executable(test_offset test_offset.cpp)

add_test(avl test_avl)
add_test(avl test_heap)
add_test(avl test_offset)