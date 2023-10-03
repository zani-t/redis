# pragma once

#include <iostream>
#include <cerrno>
#include <cstdint>

// Get pointer to Entry struct of which HNode is a member
#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type, member) );})

const size_t k_max_msg = 4096;
const size_t k_max_args = 1024;

static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d], %s\n", err, msg);
    abort();
}

// Hash code generator
static uint64_t str_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x2A051586;
    for (size_t i = 0; i < len; i++)
        h = (h + data[i]) * 0x95CE45FE;
    return h;
}

// Serialization datatypes
enum {
    SER_NIL = 0,
    SER_ERR = 1,
    SER_STR = 2,
    SER_INT = 3,
    SER_DBL = 4,
    SER_ARR = 5,
};