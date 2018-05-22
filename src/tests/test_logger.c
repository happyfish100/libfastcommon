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

int main(int argc, char *argv[])
{
    char buff[256];
    int len;

	log_init();
	//g_log_context.log_level = LOG_DEBUG;
	g_log_context.log_level = LOG_INFO;
    log_take_over_stderr();
    log_take_over_stdout();
    log_set_compress_log_flags(LOG_COMPRESS_FLAGS_ENABLED | LOG_COMPRESS_FLAGS_NEW_THREAD);
    
    printf("sizeof(LogContext): %d, time_precision: %d, compress_log_flags: %d, "
            "use_file_write_lock: %d\n", (int)sizeof(LogContext),
            g_log_context.time_precision,
            g_log_context.compress_log_flags,
            g_log_context.use_file_write_lock);

    log_it_ex(&g_log_context, LOG_DEBUG,
            "by log_it_ex, timestamp: %d", (int)time(NULL));

    len = sprintf(buff, "this is by log_it_ex1, "
            "timestamp: %d", (int)time(NULL));
    log_it_ex1(&g_log_context, LOG_INFO, buff, len);

	return 0;
}

