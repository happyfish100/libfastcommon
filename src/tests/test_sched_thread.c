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
#include "fastcommon/sched_thread.h"

static int schedule_func(void* arg)
{
    static int count = 0;
    logInfo("schedule count: %d", ++count);
    return 0;
}

int main(int argc, char *argv[])
{
#define SCHEDULE_ENTRIES_COUNT 2

    ScheduleEntry scheduleEntries[SCHEDULE_ENTRIES_COUNT];
    ScheduleArray scheduleArray;
    ScheduleEntry *pEntry;
    pthread_t schedule_tid;
    time_t current_time;
    struct tm tm_base;
    int second;
    bool continue_flag = true;

    log_init();
    g_log_context.log_level = LOG_DEBUG;


    pEntry = scheduleEntries;
    memset(scheduleEntries, 0, sizeof(scheduleEntries));

    logInfo("start...");

    current_time = time(NULL);
    localtime_r(&current_time, &tm_base);

    second = (60 + (tm_base.tm_sec - 10)) % 60;
    INIT_SCHEDULE_ENTRY((*pEntry), sched_generate_next_id(),
            tm_base.tm_hour, tm_base.tm_min, second, 60, schedule_func, NULL);
    pEntry++;

    scheduleArray.entries = scheduleEntries;
    scheduleArray.count = pEntry - scheduleEntries;
    sched_start(&scheduleArray, &schedule_tid,
            64 * 1024, (bool * volatile)&continue_flag);


    sleep(600);
    logInfo("done.");

    return 0;
}
