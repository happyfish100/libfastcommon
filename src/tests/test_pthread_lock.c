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
#define barrier()  __asm__ __volatile__("" ::: "memory")

int main(int argc, char *argv[])
{
	int result;
	int k;
    int64_t sum;
	int64_t start_time;
    pthread_mutex_t lock;

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;
	
    if ((result=init_pthread_lock(&lock)) != 0)
    {
        logCrit("init_pthread_lock fail, result: %d", result);
        return result;
    }

	start_time = get_current_time_ms();
    sum = 0;
	for (k=1; k<=LOOP_COUNT; k++) {
        __sync_synchronize();
        //barrier();
        __sync_add_and_fetch(&sum, k);
	}

	printf("atom add, sum: %"PRId64", time used: %"PRId64" ms\n",
            sum, get_current_time_ms() - start_time);

	start_time = get_current_time_ms();
    sum = 0;
	for (k=1; k<=LOOP_COUNT; k++) {
        pthread_mutex_lock(&lock);
        sum += k;
        pthread_mutex_unlock(&lock);
	}

	printf("locked add, sum: %"PRId64", time used: %"PRId64" ms\n",
            sum, get_current_time_ms() - start_time);
	return 0;
}
