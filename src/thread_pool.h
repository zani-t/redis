#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include <pthread.h>

struct Work {
    void (*f)(void *) = NULL;
    void *arg = NULL;
};

// Thread Pool - used for key deletion processes separate from other tasks
// Producer and consumer threads provide & complete tasks listed in queue
struct ThreadPool {
    std::vector<pthread_t> threads;
    std::deque<Work> queue;
    pthread_mutex_t mu;
    pthread_cond_t not_empty;
};

void thread_pool_init(ThreadPool *tp, size_t num_threads);
void thread_pool_queue(ThreadPool *tp, void (*f)(void *), void *arg);