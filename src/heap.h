#pragma once

#include <cstddef>
#include <cstdint>

struct HeapItem {
    uint64_t val = 0;
    size_t *ref = NULL; // Points to heap_idx of Entry
};

size_t heap_left(size_t i);
size_t heap_right(size_t i);
void heap_update(HeapItem *a, size_t pos, size_t len);