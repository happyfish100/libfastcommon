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
#include "fastcommon/fast_allocator.h"

#define LOOP_COUNT (30 * 1000 * 1000)
#define THREAD_COUNT  2
#define barrier()  __asm__ __volatile__("" ::: "memory")

static volatile int64_t sum;
static pthread_mutex_t lock;

static void *atomic_thread_func(void *arg)
{
	int k;
	for (k=1; k<=LOOP_COUNT; k++) {
        //__sync_synchronize();
        //barrier();
        __sync_add_and_fetch(&sum, k);
	}

    return NULL;
}

static void *mutex_thread_func(void *arg)
{
	int k;
	for (k=1; k<=LOOP_COUNT; k++) {
        pthread_mutex_lock(&lock);
        sum += k;
        pthread_mutex_unlock(&lock);
	}

    return NULL;
}

typedef void *(*thread_func)(void *arg);

static int test(const char *caption, thread_func thread_run)
{
	int64_t start_time;
    char time_buff[32];
    pthread_t tids[THREAD_COUNT];
    int i;
	int result;

    start_time = get_current_time_ms();
    sum = 0;

    for (i=0; i<THREAD_COUNT; i++) {
        if ((result=pthread_create(tids + i, NULL, thread_run, NULL)) != 0) {
            return result;
        }
    }

    for (i=0; i<THREAD_COUNT; i++) {
        pthread_join(tids[i], NULL);
    }

	printf("%s add, LOOP_COUNT: %s, sum: %"PRId64", time used: "
            "%"PRId64" ms\n", caption, int_to_comma_str(LOOP_COUNT, time_buff),
            sum, get_current_time_ms() - start_time);
    return 0;
}

int main(int argc, char *argv[])
{
	int result;

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;
	
    if ((result=init_pthread_lock(&lock)) != 0)
    {
        logCrit("init_pthread_lock fail, result: %d", result);
        return result;
    }

    printf("lock 1: %d\n", pthread_mutex_lock(&lock));
    printf("lock 2: %d\n", pthread_mutex_lock(&lock));
    printf("unlock 1: %d\n", pthread_mutex_unlock(&lock));
    printf("unlock 2: %d\n", pthread_mutex_unlock(&lock));

    test("atom", atomic_thread_func);
    test("lock", mutex_thread_func);

	return 0;
}
