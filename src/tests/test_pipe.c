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

#define  LOOP  (2000 * 1000)

int main(int argc, char *argv[])
{
    int result;
    int pipe_fds[2];
    int i;
    long n;
    pid_t pid;
    int64_t start_time;

    log_init();

    if (pipe(pipe_fds) != 0) {
        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, "
                "call pipe fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }

    pid = fork();
    if (pid < 0) {
        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, "
                "call fork fail, "
                "errno: %d, error info: %s",
                __LINE__, result, strerror(result));
        return result;
    }
    if (pid == 0) {
        printf("i am the child proccess: %d\n", getpid());
        start_time = get_current_time_ms();
        for (i=0;i <LOOP; i++) {
            if (read(pipe_fds[0], &n, sizeof(n)) != sizeof(n)) {
                result = errno != 0 ? errno : EPERM;
                logError("file: "__FILE__", line: %d, "
                        "call read fail, "
                        "errno: %d, error info: %s",
                        __LINE__, result, strerror(result));
                return result;
            }
        }
        printf("child done, LOOP: %d, time used: %"PRId64" ms\n",
                LOOP, get_current_time_ms() - start_time);
    } else {
        printf("the child proccess: %d\n", pid);
        start_time = get_current_time_ms();
        for (i=0;i <LOOP; i++) {
            n = i + 1;
            if (write(pipe_fds[1], &n, sizeof(n)) != sizeof(n)) {
                result = errno != 0 ? errno : EPERM;
                logError("file: "__FILE__", line: %d, "
                        "call write fail, "
                        "errno: %d, error info: %s",
                        __LINE__, result, strerror(result));
                return result;
            }
        }

        printf("parent done, LOOP: %d, time used: %"PRId64" ms\n",
                LOOP, get_current_time_ms() - start_time);
        sleep(1);
    }

    return 0;
}
