#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "logger.h"
#include "ini_file_reader.h"

int main(int argc, char *argv[])
{
	int result;
    IniContext context;
    const char *szFilename = "/home/yuqing/watchd-config/order.conf";

    if (argc > 1) {
        szFilename = argv[1];
    }
	
	log_init();
	g_log_context.log_level = LOG_DEBUG;
    log_take_over_stderr();
    log_take_over_stdout();
    log_set_compress_log_flags(LOG_COMPRESS_FLAGS_ENABLED | LOG_COMPRESS_FLAGS_NEW_THREAD);
    
    printf("sizeof(LogContext): %d, time_precision: %d, compress_log_flags: %d, "
            "use_file_write_lock: %d\n", (int)sizeof(LogContext),
            g_log_context.time_precision,
            g_log_context.compress_log_flags,
            g_log_context.use_file_write_lock);

    if ((result=iniLoadFromFile(szFilename, &context)) != 0)
    {
        return result;
    }

    iniPrintItems(&context);

    iniFreeContext(&context);
	return 0;
}

