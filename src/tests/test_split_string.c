#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/fast_allocator.h"

#define MAX_PATH_COUNT  100

int main(int argc, char *argv[])
{
    string_t path;
    string_t paths[MAX_PATH_COUNT];
    char new_path[PATH_MAX];
    int count;
    int i;
    int len;
    bool ignore_empty = false;

	log_init();
	srand(time(NULL));
	g_log_context.log_level = LOG_DEBUG;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path> [ignore_empty=false]\n", argv[0]);
        return EINVAL;
    }

    FC_SET_STRING(path, argv[1]);
    if (path.len >= PATH_MAX) {
        fprintf(stderr, "path length: %d exceeds %d\n", path.len, PATH_MAX);
        return ENAMETOOLONG;
    }

    if (argc > 2) {
        ignore_empty = FAST_INI_STRING_IS_TRUE(argv[2]);
    }

    count = split_string_ex(&path, '/', paths, MAX_PATH_COUNT, ignore_empty);
    if (ignore_empty && (path.len > 0 && path.str[0] == '/')) {
        strcpy(new_path, "/");
        len = 1;
    } else {
        *new_path = '\0';
        len = 0;
    }
    if (count > 0) {
        len += sprintf(new_path + len, "%.*s", paths[0].len, paths[0].str);
        for (i=1; i<count; i++) {
            len += sprintf(new_path + len, "/%.*s", paths[i].len, paths[i].str);
        }
    }

    printf("count: %d, path: %s, length: %d\n",
            count, new_path, len);
	return 0;
}
