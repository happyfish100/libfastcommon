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
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/thread_pool.h"

#define LOOP_COUNT (10 * 1000 * 1000)

static volatile int counter = 0;
static volatile int64_t total = 0;

#define TASK_COUNT 10

void thread2_func(void *args, void *thread_data)
{
    int i;
    for (i=0; i<LOOP_COUNT; i++) {
        __sync_add_and_fetch(&counter, 1);
        __sync_add_and_fetch(&total, 1);
    }
}

void thread1_func(void *args, void *thread_data)
{
    int i;
    for (i=0; i<LOOP_COUNT; i++) {
        __sync_sub_and_fetch(&counter, 1);
        __sync_add_and_fetch(&total, 1);
    }
}

void wait_thread_func(void *args, void *thread_data)
{
    int i;
    for (i=0; i<LOOP_COUNT; i++) {
        __sync_add_and_fetch(&counter, 0);
    }
}

int test(FCThreadPool *pool)
{
    int result;
    int i;

    for (i=0; i<TASK_COUNT / 2; i++) {
        if ((result=fc_thread_pool_run(pool, thread1_func, NULL)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "thread_pool_run fail, "
                    "errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

    for (i=0; i<TASK_COUNT / 2; i++) {
        if ((result=fc_thread_pool_run(pool, thread2_func, NULL)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "thread_pool_run fail, "
                    "errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

    if ((result=fc_thread_pool_run(pool, wait_thread_func, NULL)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "thread_pool_run fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    return 0;
}

static void output(FCThreadPool *pool, const int64_t start_time)
{
    printf("thread pool dealing count: %d, avail count: %d, "
            "counter: %d, total: %"PRId64", time used: %"PRId64" ms\n",
            fc_thread_pool_dealing_count(pool),
            fc_thread_pool_avail_count(pool),
            __sync_add_and_fetch(&counter, 0),
            __sync_add_and_fetch(&total, 0),
            get_current_time_ms() - start_time);
}

int main(int argc, char *argv[])
{
    FCThreadPool pool;
    const int limit = 8;
    const int stack_size = 128 * 1024;
    const int max_idle_time = 5;
    const int min_idle_count = 2;
    volatile bool continue_flag = true;
	int result;
	int64_t start_time;

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;
	
	start_time = get_current_time_ms();
    if ((result=fc_thread_pool_init(&pool, "test", limit, stack_size,
                    max_idle_time, min_idle_count,
                    (bool * volatile)&continue_flag)) != 0)
    {
        return result;
    }

    result = test(&pool);
    output(&pool, start_time);

    sleep(10);
    output(&pool, start_time);

    result = test(&pool);
    sleep(5);

    continue_flag = false;

    sleep(2);
    output(&pool, start_time);

    fc_thread_pool_destroy(&pool);
    logInfo("exit");
	return result;
}
