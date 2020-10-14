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
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/server_id_func.h"

static int mblock_stat_task_func1(void *args)
{
    logInfo("file: "__FILE__", line: %d, func: %s",
            __LINE__, __FUNCTION__);
    return 0;
}

static int mblock_stat_task_func2(void *args)
{
    sched_print_all_entries();
    logInfo("file: "__FILE__", line: %d, func: %s",
            __LINE__, __FUNCTION__);
    return 0;
}

volatile bool continue_flag = true;
static pthread_t tid;
static int setup_mblock_stat_task()
{
    ScheduleEntry schedule_entry[2];
    ScheduleArray schedule_array;

    INIT_SCHEDULE_ENTRY(schedule_entry[1], sched_generate_next_id(),
            TIME_NONE, TIME_NONE, TIME_NONE, 1,  mblock_stat_task_func1, NULL);
    INIT_SCHEDULE_ENTRY(schedule_entry[0], sched_generate_next_id(),
            0, 0, 0, 1,  mblock_stat_task_func2, NULL);

    schedule_array.count = 2;
    schedule_array.entries = schedule_entry;
    return sched_start(&schedule_array, &tid,
            64 * 1024, (bool *)&continue_flag);
}

static void sigQuitHandler(int sig)
{
    if (continue_flag) {
        continue_flag = false;
        logCrit("file: "__FILE__", line: %d, "
                "catch signal %d, program exiting...",
                __LINE__, sig);
    }
}

int main(int argc, char *argv[])
{
	int result;
    const char *config_filename = "servers.conf";
    FCServerConfig ctx;
    const int default_port = 1111;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = true;
    FastBuffer buffer;
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);


    if (argc > 1) {
        config_filename = argv[1];
    }
	
	log_init();
    if ((result=fc_server_load_from_file_ex(&ctx, config_filename,
                    default_port, min_hosts_each_group,
                    share_between_groups)) != 0)
    {
        return result;
    }


    act.sa_handler = sigQuitHandler;
    if(sigaction(SIGINT, &act, NULL) < 0 ||
        sigaction(SIGTERM, &act, NULL) < 0 ||
        sigaction(SIGQUIT, &act, NULL) < 0)
    {
        logCrit("file: "__FILE__", line: %d, "
            "call sigaction fail, errno: %d, error info: %s",
            __LINE__, errno, strerror(errno));
        logCrit("exit abnormally!\n");
        return errno;
    }

    setup_mblock_stat_task();

    if ((result=fast_buffer_init_ex(&buffer, 1024)) != 0) {
        return result;
    }
    fc_server_to_config_string(&ctx, &buffer);
    printf("%.*s", buffer.length, buffer.data);
    //printf("%.*s\n(%d)", buffer.length, buffer.data, buffer.length);

    sleep(10);

    fast_buffer_destroy(&buffer);

    //fc_server_to_log(&ctx);
    fc_server_destroy(&ctx);
	return 0;
}
