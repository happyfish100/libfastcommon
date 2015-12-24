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
#include "fast_allocator.h"

#define OUTER_LOOP_COUNT 128
#define INNER_LOOP_COUNT 1024 * 64

#define USE_ALLOCATOR 1

#if USE_ALLOCATOR == 1
#define MALLOC(bytes) fast_allocator_alloc(&acontext, bytes)
#define FREE(ptr) fast_allocator_free(&acontext, ptr)
#else
#define MALLOC(bytes) malloc(bytes)
#define FREE(ptr) free(ptr)
#endif


int main(int argc, char *argv[])
{
	int result;
	struct fast_allocator_context acontext;
	void *ptrs[INNER_LOOP_COUNT];
	int bytes;
	int i;
	int k;
	int64_t start_time;

	printf("use allocator: %d\n", USE_ALLOCATOR);
	start_time = get_current_time_ms();

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;
	
	fast_mblock_manager_init();
	if ((result=fast_allocator_init(&acontext, 0, 0.00, 0, true)) != 0)
	{
		return result;
	}
	fast_mblock_manager_stat_print(true);
	for (k=0; k<OUTER_LOOP_COUNT; k++) {
		for (i=0; i<INNER_LOOP_COUNT; i++) {
			bytes = 65536L * rand() / RAND_MAX;

			ptrs[i] = MALLOC(bytes);
		}

		printf("after alloc, bytes: %"PRId64"\n", acontext.alloc_bytes);
		//fast_mblock_manager_stat_print(true);

		for (i=0; i<INNER_LOOP_COUNT; i++) {
			FREE(ptrs[i]);
		}
	}

	fast_mblock_manager_stat_print(true);
	printf("after free, bytes: %"PRId64"\n", acontext.alloc_bytes);
	printf("time used: %"PRId64" ms\n", get_current_time_ms() - start_time);

	fast_allocator_destroy(&acontext);
	return 0;
}

