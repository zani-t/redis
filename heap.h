#pragma once

#include <cstddef>
#include <cstdint>

struct HeapItem {
    uint64_t val = 0;
    size_t *ref = NULL; // Points to heap_idx of Entry
};

void heap_update(HeapItem *a, size_t pos, size_t len);