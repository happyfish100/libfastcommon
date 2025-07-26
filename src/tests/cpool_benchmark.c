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
#include "fastcommon/connection_pool.h"

static int thread_count = 2;
static int64_t loop_count = 1000000;
static ConnectionPool cpool;

static void *thread_run(void *args)
{
    int thread_index;
    int result;
    int64_t i;
    ConnectionInfo cinfo;
    ConnectionInfo *conn;

    thread_index = (long)args;
    printf("thread #%d start\n", thread_index);
    
    if ((result=conn_pool_parse_server_info("127.0.0.1:23000", &cinfo, 23000)) != 0) {
        return NULL;
    }
    for (i=0; i<loop_count; i++) {
        if ((conn=conn_pool_get_connection_ex(&cpool, &cinfo,
                        NULL, true, &result)) == NULL)
        {
            break;
        }
        conn_pool_close_connection(&cpool, conn);
    }

    if (i == loop_count) {
        printf("thread #%d done\n", thread_index);
    } else {
        printf("thread #%d loop count: %"PRId64"\n", thread_index, i);
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    const int stack_size = 64 * 1024;
    const int connect_timeout = 2;
    const int max_count_per_entry = 0;
    const int max_idle_time = 3600;
    const int htable_capacity = 163;
    const int extra_data_size = 0;
    int result;
    int i;
    int64_t qps;
    pthread_t *tids;
    pthread_attr_t thread_attr;
    int64_t start_time;
    int64_t end_time;
    int64_t time_used;
    ConnectionExtraParams params;

    log_init();
    g_log_context.log_level = LOG_INFO;
    g_schedule_flag = true;
    g_current_time = time(NULL);

    memset(&params, 0, sizeof(params));
    params.tls.enabled = false;
    params.tls.htable_capacity = 13;
    if ((result=conn_pool_init_ex1(&cpool, connect_timeout, max_count_per_entry,
                    max_idle_time, htable_capacity, NULL, NULL, NULL, NULL,
                    extra_data_size, &params)) != 0)
    {
        return result;
    }

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
    conn_pool_destroy(&cpool);

    return 0;
}
