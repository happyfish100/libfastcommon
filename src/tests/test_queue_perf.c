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
#include "fastcommon/fc_queue.h"

typedef struct my_record {
    char type;
    struct my_record *next;  //for queue
} MyRecord;

const int LOOP_COUNT = 20 * 1000 * 1000;
static volatile bool g_continue_flag = true;
static struct fast_mblock_man record_allocator;
static struct fc_queue queue;

void *producer_thread(void *arg)
{
    const int BATCH_SIZE = 16;
    int64_t count;
    struct fast_mblock_node *node;
    struct fc_queue_info qinfo;
    MyRecord *record;

    count = 0;
    while (g_continue_flag && count < LOOP_COUNT) {
        qinfo.head = qinfo.tail = NULL;

        node = fast_mblock_batch_alloc1(
                &record_allocator, BATCH_SIZE);
        if (node == NULL) {
            g_continue_flag = false;
            return NULL;
        }

        do {
            record = (MyRecord *)node->data;
            if (qinfo.head == NULL) {
                qinfo.head = record;
            } else {
                ((MyRecord *)qinfo.tail)->next = record;
            }
            qinfo.tail = record;

            node = node->next;
        } while (node != NULL);

        count += BATCH_SIZE;
        ((MyRecord *)qinfo.tail)->next = NULL;
        fc_queue_push_queue_to_tail(&queue, &qinfo);
    }

    return NULL;
}

static void sigQuitHandler(int sig)
{
    g_continue_flag = false;
    fc_queue_terminate(&queue);

    logCrit("file: "__FILE__", line: %d, " \
            "catch signal %d, program exiting...", \
            __LINE__, sig);
}

int main(int argc, char *argv[])
{
    const int alloc_elements_once = 8 * 1024;
    int elements_limit;
    pthread_t tid;
    struct sigaction act;
    int result;
    int qps;
    int64_t count;
    struct fast_mblock_node *node;
    MyRecord *record;
    struct fast_mblock_chain chain;
    int64_t start_time;
    int64_t end_time;
    int64_t time_used;
    char time_buff[32];

    start_time = get_current_time_ms();

    srand(time(NULL));
    log_init();
    g_log_context.log_level = LOG_DEBUG;

    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = sigQuitHandler;
    if(sigaction(SIGINT, &act, NULL) < 0 ||
            sigaction(SIGTERM, &act, NULL) < 0 ||
            sigaction(SIGQUIT, &act, NULL) < 0)
    {
        logCrit("file: "__FILE__", line: %d, " \
                "call sigaction fail, errno: %d, error info: %s", \
                __LINE__, errno, STRERROR(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }

    fast_mblock_manager_init();

    elements_limit = 2 * alloc_elements_once;
    //elements_limit = 0;
    if ((result=fast_mblock_init_ex1(&record_allocator,
                    "my_record", sizeof(MyRecord),
                    alloc_elements_once, elements_limit,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }
    if (elements_limit > 0) {
        fast_mblock_set_need_wait(&record_allocator,
                true, (bool *)&g_continue_flag);
    }

    if ((result=fc_queue_init(&queue, (long)(
                        &((MyRecord *)NULL)->next))) != 0)
    {
        return result;
    }

    pthread_create(&tid, NULL, producer_thread, NULL);

    count = 0;
    while (g_continue_flag && count < LOOP_COUNT) {
        /*
        record = (MyRecord *)fc_queue_pop(&queue);
        if (record != NULL) {
            ++count;
            fast_mblock_free_object(&record_allocator, record);
        }
        */

        if ((record=(MyRecord *)fc_queue_pop_all(&queue)) == NULL) {
            continue;
        }

        chain.head = chain.tail = NULL;
        while (record != NULL) {
            ++count;
            node = fast_mblock_to_node_ptr(record);
            if (chain.head == NULL) {
                chain.head = node;
            } else {
                chain.tail->next = node;
            }
            chain.tail = node;

            record = record->next;
        }
        chain.tail->next = NULL;
        fast_mblock_batch_free(&record_allocator, &chain);
    }

    end_time = get_current_time_ms();
    time_used = end_time - start_time;
    long_to_comma_str(time_used, time_buff);

    fast_mblock_manager_stat_print(false);

    qps = count * 1000LL / time_used;
    printf("time used: %s ms, QPS: %d\n", time_buff, qps);
    return 0;
}
