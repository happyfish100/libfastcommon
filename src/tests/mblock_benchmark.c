/*
 * Copyright (c) 2025 YuQing <384681@qq.com>
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/fast_mblock.h"

static int thread_count = 2;
static int64_t loop_count = 10000000;
static struct fast_mblock_man mblock;

static void *thread_run(void *args)
{
    int thread_index;
    int i;
    void *obj;

    thread_index = (long)args;
    printf("thread #%d start\n", thread_index);

    for (i=0; i<loop_count; i++) {
        obj = fast_mblock_alloc_object(&mblock);
        fast_mblock_free_object(&mblock, obj);
    }

    printf("thread #%d done\n", thread_index);

    return NULL;
}

int main(int argc, char *argv[])
{
    const int stack_size = 64 * 1024;
    int result;
    int limit;
    int i;
    bool continue_flag = true;
    int64_t qps;
    pthread_t *tids;
    pthread_attr_t thread_attr;
    int64_t start_time;
    int64_t end_time;
    int64_t time_used;

    log_init();
    g_log_context.log_level = LOG_DEBUG;

    limit = (thread_count + 1) / 2;
    fast_mblock_manager_init();
    if ((result=fast_mblock_init_ex1(&mblock, "mblock", 1024,
                    limit, limit, NULL, NULL, true)) != 0)
    {
        return result;
    }
    fast_mblock_set_need_wait(&mblock, true, &continue_flag);

    if ((result=pthread_attr_init(&thread_attr)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "call pthread_attr_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }
    if ((result=pthread_attr_setstacksize(&thread_attr,
                stack_size)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call pthread_attr_setstacksize to %d fail, "
                "errno: %d, error info: %s", __LINE__,
                stack_size, result, STRERROR(result));
        return result;
    }

    tids = fc_malloc(sizeof(pthread_t) * thread_count);

    start_time = get_current_time_us();
    for (i=0; i<thread_count; i++) {
        if ((result=pthread_create(tids + i, &thread_attr,
                        thread_run, (void *)((long)i))) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "create thread failed, "
                    "errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

    for (i=0; i<thread_count; i++) {
        pthread_join(tids[i], NULL);
    }

    end_time = get_current_time_us();
    time_used = end_time - start_time;
    qps = (thread_count * loop_count * 1000 * 1000) / time_used;
    printf("time used: %"PRId64" ms, QPS: %"PRId64"\n", time_used / 1000, qps);

    free(tids);
    fast_mblock_manager_stat_print(false);
    fast_mblock_destroy(&mblock);

    return 0;
}
