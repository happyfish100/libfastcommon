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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "sched_thread.h"
#include "fc_memory.h"
#include "thread_pool.h"

static void *thread_entrance(void *arg)
{
    FCThreadInfo *thread;
    FCThreadPool *pool;
    struct timespec ts;
    fc_thread_pool_callback callback;
    time_t last_run_time;
    bool running;
    bool notify;
    int idle_count;

    thread = (FCThreadInfo *)arg;
    pool = thread->pool;

#ifdef OS_LINUX
    {
        char thread_name[64];
        snprintf(thread_name, sizeof(thread_name), "%s[%d]",
                pool->name, thread->index);
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    if (pool->extra_data_callbacks.alloc != NULL) {
        thread->tdata = pool->extra_data_callbacks.alloc();
    }

    PTHREAD_MUTEX_LOCK(&thread->lock);
    thread->inited = true;
    PTHREAD_MUTEX_UNLOCK(&thread->lock);

    PTHREAD_MUTEX_LOCK(&pool->lock);
    pool->thread_counts.running++;
    logDebug("thread pool: %s, index: %d start, running count: %d",
            pool->name, thread->index, pool->thread_counts.running);
    PTHREAD_MUTEX_UNLOCK(&pool->lock);

    running = true;
    ts.tv_nsec = 0;
    last_run_time = get_current_time();
    while (running && *pool->pcontinue_flag) {

        PTHREAD_MUTEX_LOCK(&thread->lock);
        if (thread->callback.func == NULL) {
            ts.tv_sec = get_current_time() + 2;
            pthread_cond_timedwait(&thread->cond, &thread->lock, &ts);
        }

        callback = thread->callback.func;
        if (callback == NULL) {
            if (pool->max_idle_time > 0 && get_current_time() -
                    last_run_time > pool->max_idle_time)
            {
                PTHREAD_MUTEX_LOCK(&pool->lock);
                idle_count = pool->thread_counts.running -
                    __sync_add_and_fetch(&pool->thread_counts.dealing, 0);

                if (idle_count > pool->min_idle_count) {
                    thread->inited = false;
                    pool->thread_counts.running--;
                    running = false;
                }
                PTHREAD_MUTEX_UNLOCK(&pool->lock);
            }
        } else {
            thread->callback.func = NULL;
        }
        PTHREAD_MUTEX_UNLOCK(&thread->lock);

        if (callback != NULL) {
            __sync_add_and_fetch(&pool->thread_counts.dealing, 1);
            callback(thread->callback.arg, thread->tdata);
            last_run_time = get_current_time();
            __sync_sub_and_fetch(&pool->thread_counts.dealing, 1);

            PTHREAD_MUTEX_LOCK(&pool->lock);
            notify = (pool->freelist == NULL);
            thread->next = pool->freelist;
            pool->freelist = thread;
            if (notify) {
                pthread_cond_signal(&pool->cond);
            }
            PTHREAD_MUTEX_UNLOCK(&pool->lock);
        }
    }

    if (pool->extra_data_callbacks.free != NULL && thread->tdata != NULL) {
        pool->extra_data_callbacks.free(thread->tdata);
        thread->tdata = NULL;
    }

    if (running) {
        PTHREAD_MUTEX_LOCK(&thread->lock);
        thread->inited = false;
        PTHREAD_MUTEX_UNLOCK(&thread->lock);

        PTHREAD_MUTEX_LOCK(&pool->lock);
        pool->thread_counts.running--;
        PTHREAD_MUTEX_UNLOCK(&pool->lock);
    }

    PTHREAD_MUTEX_LOCK(&pool->lock);
    logDebug("thread pool: %s, index: %d exit, running count: %d",
            pool->name, thread->index, pool->thread_counts.running);
    PTHREAD_MUTEX_UNLOCK(&pool->lock);

    return NULL;
}

static int init_pthread_lock_cond(pthread_mutex_t *lock, pthread_cond_t *cond)
{
    int result;
    if ((result=init_pthread_lock(lock)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "init_pthread_lock fail, errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    if ((result=pthread_cond_init(cond, NULL)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "pthread_cond_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    return 0;
}

static int thread_pool_alloc_init(FCThreadPool *pool)
{
    int result;
    int bytes;
    FCThreadInfo *thread;
    FCThreadInfo *end;
    FCThreadInfo *last;

    bytes = sizeof(FCThreadInfo) * pool->thread_counts.limit;
    pool->threads = (FCThreadInfo *)fc_malloc(bytes);
    if (pool->threads == NULL) {
        return ENOMEM;
    }
    memset(pool->threads, 0, bytes);

    end = pool->threads + pool->thread_counts.limit;
    for (thread=pool->threads; thread<end; thread++) {
        thread->pool = pool;
        thread->index = thread - pool->threads;
        if ((result=init_pthread_lock_cond(&thread->lock,
                        &thread->cond)) != 0)
        {
            return result;
        }
    }

    last = end - 1;
    pool->freelist = pool->threads;
    for (thread=pool->threads; thread<last; thread++) {
        thread->next = thread + 1;
    }

    if (pool->min_idle_count > 0) {
        end = pool->threads + pool->min_idle_count;
        for (thread=pool->threads; thread<end; thread++) {
            thread->inited = true;
            if ((result=fc_create_thread(&thread->tid, thread_entrance,
                            thread, pool->stack_size)) != 0)
            {
                return result;
            }
        }
    }

    return 0;
}

int fc_thread_pool_init_ex(FCThreadPool *pool, const char *name,
        const int limit, const int stack_size, const int max_idle_time,
        const int min_idle_count, bool * volatile pcontinue_flag,
        FCThreadExtraDataCallbacks *extra_data_callbacks)
{
    int result;

    if ((result=init_pthread_lock_cond(&pool->lock, &pool->cond)) != 0) {
        return result;
    }

    snprintf(pool->name, sizeof(pool->name), "%s", name);
    pool->stack_size = stack_size;
    pool->max_idle_time = max_idle_time;
    if (min_idle_count > limit) {
        pool->min_idle_count = limit;
    } else {
        pool->min_idle_count = min_idle_count;
    }
    pool->thread_counts.limit = limit;
    pool->thread_counts.running = 0;
    pool->thread_counts.dealing = 0;
    pool->pcontinue_flag = pcontinue_flag;
    if (extra_data_callbacks != NULL) {
        pool->extra_data_callbacks = *extra_data_callbacks;
    } else {
        pool->extra_data_callbacks.alloc = NULL;
        pool->extra_data_callbacks.free = NULL;
    }

    return thread_pool_alloc_init(pool);
}

void fc_thread_pool_destroy(FCThreadPool *pool)
{

}

int fc_thread_pool_run(FCThreadPool *pool, fc_thread_pool_callback func,
        void *arg)
{
    FCThreadInfo *thread;
    struct timespec ts;
    int result;

    thread = NULL;
    ts.tv_nsec = 0;
    PTHREAD_MUTEX_LOCK(&pool->lock);
    while (*pool->pcontinue_flag) {
        if (pool->freelist != NULL) {
            thread = pool->freelist;
            pool->freelist = pool->freelist->next;
            break;
        }

        ts.tv_sec = get_current_time() + 2;
        pthread_cond_timedwait(&pool->cond, &pool->lock, &ts);
    }
    PTHREAD_MUTEX_UNLOCK(&pool->lock);

    if (thread == NULL) {
        return EINTR;
    }

    PTHREAD_MUTEX_LOCK(&thread->lock);
    thread->callback.func = func;
    thread->callback.arg = arg;
    if (!thread->inited) {
        result = fc_create_thread(&thread->tid, thread_entrance,
                thread, pool->stack_size);
    } else {
        pthread_cond_signal(&thread->cond);
        result = 0;
    }
    PTHREAD_MUTEX_UNLOCK(&thread->lock);

    return result;
}
