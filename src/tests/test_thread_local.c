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
#include <time.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"

#define THREAD_COUNT 16

static pthread_key_t key;
volatile int running_count;

static void destroy(void *ptr)
{
    printf("destroy ptr: %p\n", ptr);
}

static void test_fetch(void *ptr)
{
    int i;

    for (i=0; i<10000000; i++) {
        if (pthread_getspecific(key) != ptr) {
            logError("pthread_getspecific fail");
        }
    }
}

static void *thread_run(void *args)
{
    void *ptr;

    ptr = pthread_getspecific(key);
    if (ptr == NULL) {
        ptr = malloc(64);
        pthread_setspecific(key, ptr);
        printf("create ptr: %p\n", ptr);
    }

    fc_sleep_ms(1);
    test_fetch(ptr);

    __sync_fetch_and_sub(&running_count, 1);
    return NULL;
}

int main(int argc, char *argv[])
{
    pthread_t tid;
    int64_t start_time;
    int i;
    int result;

    log_init();

    start_time = get_current_time_ms();
    if ((result=pthread_key_create(&key, destroy)) != 0) {
        logError("pthread_key_create fail");
        return result;
    }

    running_count = THREAD_COUNT;
    for (i=0; i<THREAD_COUNT; i++) {
        if ((result=fc_create_thread(&tid, thread_run, NULL, 64 * 1024)) != 0) {
            return result;
        }
    }

    fc_sleep_ms(1);
    printf("\nwaiting  thread exit ...\n");
    while (__sync_fetch_and_add(&running_count, 0) != 0) {
        fc_sleep_ms(1);
    }
    printf("time used: %"PRId64" ms\n", get_current_time_ms() - start_time);

    return 0;
}
