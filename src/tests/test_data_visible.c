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
#include "fastcommon/fc_queue.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"

typedef struct fs_api_slice_entry {
    int data;
    volatile int v;
    struct fs_api_slice_entry *next;
} FSAPISliceEntry;

static bool continue_flag = true;
static struct fast_mblock_man allocator;
static struct fc_queue queue;

static void *thread_func(void *arg)
{
    FSAPISliceEntry *slice;
    int value;

    printf("file: "__FILE__", line: %d, "
            "thread enter ...\n", __LINE__);
    while (continue_flag) {
        slice = (FSAPISliceEntry *)fc_queue_pop(&queue);
        if (slice != NULL) {
            value = __sync_fetch_and_add(&slice->v, 0);
            if (slice->data != value) {
                printf("data: %d != value: %d\n", slice->data, value);
            }
            fast_mblock_free_object(&allocator, slice);
        }
    }

    printf("file: "__FILE__", line: %d, "
            "thread done! \n", __LINE__);
    return NULL;
}

static void sigQuitHandler(int sig)
{
    if (continue_flag) {
        continue_flag = false;
        printf("file: "__FILE__", line: %d, "
                "catch signal %d, program exiting...\n",
                __LINE__, sig);
    }
}

static void sigHupHandler(int sig)
{
    printf("file: "__FILE__", line: %d, "
            "catch signal %d\n", __LINE__, sig);
}

static int setup_signal_handler()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);

    signal(SIGHUP, sigHupHandler);

    /*
    act.sa_handler = sigHupHandler;
    if(sigaction(SIGHUP, &act, NULL) < 0) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "call sigaction fail, errno: %d, error info: %s\n",
                __LINE__, errno, strerror(errno));
        return errno;
    }
    */

    act.sa_handler = sigQuitHandler;
    if(sigaction(SIGINT, &act, NULL) < 0 ||
            sigaction(SIGTERM, &act, NULL) < 0 ||
            sigaction(SIGQUIT, &act, NULL) < 0)
    {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "call sigaction fail, errno: %d, error info: %s\n",
                __LINE__, errno, strerror(errno));
        return errno;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int result;
    int i;
    int total;
    pthread_t tid;
    FSAPISliceEntry *slice;
    pthread_mutex_t lock;

    log_init();

    if ((result=setup_signal_handler()) != 0) {
        return result;
    }

    if ((result=fast_mblock_init_ex1(&allocator, "slice_entry",
                    sizeof(FSAPISliceEntry), 1024, 1024,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }
    allocator.alloc_elements.exceed_log_level = LOG_NOTHING;

    if ((result=init_pthread_lock(&lock)) != 0) {
        return result;
    }

    if ((result=fc_queue_init(&queue, (long)
                    (&((FSAPISliceEntry *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=pthread_create(&tid, NULL, thread_func, NULL)) != 0) {
        return result;
    }

    total = 0;
    i = 0;
    while (continue_flag && i++ < 100 * 1000 * 1000) {
        slice = (FSAPISliceEntry *)fast_mblock_alloc_object(&allocator);
        if (slice != NULL) {
            slice->data = __sync_add_and_fetch(&slice->v, 1);
            fc_queue_push(&queue, slice);
            total++;
        }
    }

    continue_flag = false;
    fc_sleep_ms(1000);
    printf("file: "__FILE__", line: %d, "
            "total count: %d.\n", __LINE__, total);
    return 0;
}
