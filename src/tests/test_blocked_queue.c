#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include "logger.h"
#include "shared_func.h"
#include "sched_thread.h"
#include "ini_file_reader.h"
#include "fast_task_queue.h"
#include "fast_blocked_queue.h"

static bool g_continue_flag = true;
static int64_t produce_count = 0;
static int64_t consume_count = 0;
static struct fast_blocked_queue blocked_queue;

#define MAX_USLEEP 10000

void *producer_thread(void *arg)
{
    int usleep_time;
    int64_t count;
    struct fast_task_info *pTask;

    while (g_continue_flag) {
        usleep_time = (int64_t) MAX_USLEEP * (int64_t)rand() / RAND_MAX;
        if (usleep_time > 0) {
            usleep(usleep_time);
        }

        count = __sync_add_and_fetch(&produce_count, 1);
        if (count % 10000 == 0) {
            printf("produce count: %"PRId64"\n", count);
        }

        pTask = free_queue_pop();
        if (pTask != NULL) {
            blocked_queue_push(&blocked_queue, pTask);
        }
    }

    return NULL;
}

static void sigQuitHandler(int sig)
{
    g_continue_flag = false;
    blocked_queue_terminate(&blocked_queue);

    logCrit("file: "__FILE__", line: %d, " \
            "catch signal %d, program exiting...", \
            __LINE__, sig);
}

int main(int argc, char *argv[])
{
    pthread_t tid;
    struct sigaction act;
    const int min_buff_size = 1024;
    const int max_buff_size = 1024;
    const int arg_size = 0;
    int result;
    int64_t count;
    struct fast_task_info *pTask;

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

    result = free_queue_init(1024, min_buff_size, \
            max_buff_size, arg_size);
    if (result != 0) {
        return result;
    }

    if ((result=blocked_queue_init(&blocked_queue)) != 0) {
        return result;
    }

    pthread_create(&tid, NULL, producer_thread, NULL);
    pthread_create(&tid, NULL, producer_thread, NULL);
    pthread_create(&tid, NULL, producer_thread, NULL);
    pthread_create(&tid, NULL, producer_thread, NULL);

    while (g_continue_flag) {
        pTask = blocked_queue_pop(&blocked_queue);
        if (pTask != NULL) {
            count = __sync_add_and_fetch(&consume_count, 1);
            if (count % 10000 == 0) {
                printf("consume count: %"PRId64"\n", count);
            }
            free_queue_push(pTask);
            usleep(1000);
        }
    }

    return 0;
}

