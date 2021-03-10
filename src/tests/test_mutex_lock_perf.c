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

#define THREAD_COUNT 8
#define LOOP_COUNT (100)

static volatile int thread_count = THREAD_COUNT;
static pthread_mutex_t lock;

void *thread_func(void *arg)
{
    int64_t sum;
    int k;

    sum = 0;
    for (k=1; k<=LOOP_COUNT; k++) {
        pthread_mutex_lock(&lock);
        usleep(100 * 1000);
        sum += k;
        pthread_mutex_unlock(&lock);
    }

    printf("sum: %"PRId64"\n", sum);

    __sync_sub_and_fetch(&thread_count, 1);
    return NULL;
}

int main(int argc, char *argv[])
{
	int result;
    int count;
	int64_t start_time;
    int64_t time_used;
    void *args[THREAD_COUNT];
    pthread_t tids[THREAD_COUNT];
    char time_buff[32];

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;
	
    if ((result=init_pthread_lock(&lock)) != 0) {
        logCrit("init_pthread_lock fail, result: %d", result);
        return result;
    }

	start_time = get_current_time_ms();
    memset(args, 0, sizeof(args));
    count = THREAD_COUNT;
    if ((result=create_work_threads(&count, thread_func,
                    args, tids, 64 * 1024)) != 0)
    {
        return result;
    }

    while (__sync_add_and_fetch(&thread_count, 0) > 0) {
        usleep(10 * 1000);
    }

    time_used = get_current_time_ms() - start_time;
    printf("LOOP_COUNT: %d, time used: %s ms\n", LOOP_COUNT,
            long_to_comma_str(time_used, time_buff));

	return 0;
}
