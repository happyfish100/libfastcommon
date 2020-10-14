/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef FC_THREAD_POOL_H_
#define FC_THREAD_POOL_H_

#include <time.h>
#include <pthread.h>
#include "fast_mblock.h"
#include "pthread_func.h"

typedef void (*fc_thread_pool_callback)(void *arg, void *thread_data);
typedef void* (*fc_alloc_thread_extra_data_callback)();
typedef void  (*fc_free_thread_extra_data_callback)(void *ptr);

typedef struct fc_thread_extra_data_callbacks
{
    fc_alloc_thread_extra_data_callback alloc;
    fc_free_thread_extra_data_callback free;
} FCThreadExtraDataCallbacks;

struct fc_thread_pool;
typedef struct fc_thread_info
{
    volatile int inited;
    int index;
    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    void *tdata;  //thread data defined by the caller
    struct {
        fc_thread_pool_callback func;
        void *arg;
    } callback;
    struct fc_thread_pool *pool;
    struct fc_thread_info *next;
} FCThreadInfo;

typedef struct fc_thread_pool
{
    char name[64];
	FCThreadInfo *threads;  //all thread info
	FCThreadInfo *freelist;
	pthread_mutex_t lock;
	pthread_cond_t cond;

    int stack_size;
    int max_idle_time;   //in seconds
    int min_idle_count;
    struct {
        int limit;
        volatile int running;  //running thread count
        volatile int dealing;  //dealing task thread count
    } thread_counts;
    bool * volatile pcontinue_flag;
    FCThreadExtraDataCallbacks extra_data_callbacks;
} FCThreadPool;

#ifdef __cplusplus
extern "C" {
#endif

#define fc_thread_pool_init(pool, name, limit, stack_size, max_idle_time, \
        min_idle_count, pcontinue_flag) \
    fc_thread_pool_init_ex(pool, name, limit, stack_size, max_idle_time, \
        min_idle_count, pcontinue_flag, NULL)

int fc_thread_pool_init_ex(FCThreadPool *pool, const char *name,
        const int limit, const int stack_size, const int max_idle_time,
        const int min_idle_count, bool * volatile pcontinue_flag,
        FCThreadExtraDataCallbacks *extra_data_callbacks);

void fc_thread_pool_destroy(FCThreadPool *pool);

int fc_thread_pool_run(FCThreadPool *pool, fc_thread_pool_callback func,
        void *arg);

static inline int fc_thread_pool_dealing_count(FCThreadPool *pool)
{
    return __sync_add_and_fetch(&pool->thread_counts.dealing, 0);
}

static inline int fc_thread_pool_avail_count(FCThreadPool *pool)
{
    return pool->thread_counts.limit -
        __sync_add_and_fetch(&pool->thread_counts.dealing, 0);
}

static inline int fc_thread_pool_running_count(FCThreadPool *pool)
{
    int running_count;

    PTHREAD_MUTEX_LOCK(&pool->lock);
    running_count = pool->thread_counts.running;
    PTHREAD_MUTEX_UNLOCK(&pool->lock);

    return running_count;
}

#ifdef __cplusplus
}
#endif

#endif
