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
#include "fastcommon/server_id_func.h"

static int test_open_lseek(const char *filename)
{
    int result;
    int fd;
    int bytes;
    char buff[1024];
    int64_t offset = 1024 * 1024;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, filename,
                result, STRERROR(result));
        return result;
    }

    if (offset > 0) {
        if (lseek(fd, offset, SEEK_SET) < 0) {
            result = errno != 0 ? errno : EACCES;
            logError("file: "__FILE__", line: %d, "
                    "lseek file \"%s\" fail,  offset: %"PRId64", "
                    "errno: %d, error info: %s", __LINE__,
                    filename, offset,
                    result, STRERROR(result));
            return result;
        } else {
            logInfo("lseek %"PRId64" successfully.", offset);
        }
    }

    if ((bytes=read(fd, buff, sizeof(buff))) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "read file \"%s\" fail,  offset: %"PRId64", "
                "errno: %d, error info: %s", __LINE__,
                filename, offset, result, STRERROR(result));
        return result;
    }

    printf("read bytes: %d\n", bytes);

    close(fd);
    return 0;
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

    if (argc > 1) {
        config_filename = argv[1];
    }
	
	log_init();

    {
        union {
            int64_t flags;
            struct {
                union {
                    int flags: 4;
                    struct {
                        bool ns: 1;  //namespace
                        bool pt: 1;  //path
                        bool hc: 1;  //hash code
                    };
                } path_info;
                bool user_data : 1;
                bool extra_data: 1;
                bool mode : 1;
                bool ctime: 1;
                bool mtime: 1;
                bool size : 1;
            };
        } options;

        char *endptr;
        int64_t n;
        endptr = NULL;
        n = strtoll(argv[1], &endptr, 10);
        printf("sizeof(mode_t): %d\n", (int)sizeof(mode_t));

        printf("sizeof(options): %d\n", (int)sizeof(options));

        options.path_info.ns = options.path_info.pt = options.path_info.hc = 1;
        printf("union flags: %d\n", options.path_info.flags);

        printf("n: %"PRId64", endptr: %s(%d)\n", n, endptr, (int)strlen(endptr));

        n = snprintf(NULL, 0, "%"PRId64, n);
        printf("expect len: %d\n", (int)n);

        test_open_lseek(config_filename);
        return 1;
    }

    if ((result=fc_server_load_from_file_ex(&ctx, config_filename,
                    default_port, min_hosts_each_group,
                    share_between_groups)) != 0)
    {
        return result;
    }

    if ((result=fast_buffer_init_ex(&buffer, 1024)) != 0) {
        return result;
    }
    fc_server_to_config_string(&ctx, &buffer);
    printf("%.*s", buffer.length, buffer.data);
    //printf("%.*s\n(%d)", buffer.length, buffer.data, buffer.length);

    fast_buffer_destroy(&buffer);

    //fc_server_to_log(&ctx);
    fc_server_destroy(&ctx);
	return 0;
}
