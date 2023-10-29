cmake_minimum_required(VERSION 3.20)

add_executable(test_avl test_avl.cpp ../src/avl.cpp)
add_executable(test_heap test_heap.cpp ../src/heap.cpp)
add_executable(test_offset test_offset.cpp ../src/avl.cpp)

add_test(avl test_avl)
add_test(heap test_heap)
add_test(offset test_offset)