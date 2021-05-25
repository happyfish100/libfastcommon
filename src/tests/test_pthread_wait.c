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
#include "fastcommon/pthread_func.h"

static bool continue_flag = true;
static pthread_lock_cond_pair_t lcp;

static void *thread_func(void *arg)
{
    printf("file: "__FILE__", line: %d, "
            "thread enter ...\n", __LINE__);

    PTHREAD_MUTEX_LOCK(&lcp.lock);
    pthread_cond_wait(&lcp.cond, &lcp.lock);
    PTHREAD_MUTEX_UNLOCK(&lcp.lock);

    printf("file: "__FILE__", line: %d, "
            "thread done! \n", __LINE__);
    return NULL;
}

static void sigQuitHandler(int sig)
{
    if (continue_flag) {
        continue_flag = false;
        printf("file: "__FILE__", line: %d, "
                "catch signal %d, program exiting...\n",
                __LINE__, sig);
    }
}

static void sigHupHandler(int sig)
{
    printf("file: "__FILE__", line: %d, "
            "catch signal %d\n", __LINE__, sig);
}

static int setup_signal_handler()
{
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);

    signal(SIGHUP, sigHupHandler);

    /*
    act.sa_handler = sigHupHandler;
    if(sigaction(SIGHUP, &act, NULL) < 0) {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "call sigaction fail, errno: %d, error info: %s\n",
                __LINE__, errno, strerror(errno));
        return errno;
    }
    */

    act.sa_handler = sigQuitHandler;
    if(sigaction(SIGINT, &act, NULL) < 0 ||
            sigaction(SIGTERM, &act, NULL) < 0 ||
            sigaction(SIGQUIT, &act, NULL) < 0)
    {
        fprintf(stderr, "file: "__FILE__", line: %d, "
                "call sigaction fail, errno: %d, error info: %s\n",
                __LINE__, errno, strerror(errno));
        return errno;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int result;
    int i;
    pthread_t tid;

    log_init();

    if ((result=setup_signal_handler()) != 0) {
        return result;
    }
    if ((result=init_pthread_lock_cond_pair(&lcp)) != 0) {
        return result;
    }

    if ((result=pthread_create(&tid, NULL, thread_func, NULL)) != 0) {
        return result;
    }

    while (continue_flag) {

        /*
        printf("file: "__FILE__", line: %d, "
                "loop before ...\n", __LINE__);
        PTHREAD_MUTEX_LOCK(&lcp.lock);
        pthread_cond_wait(&lcp.cond, &lcp.lock);
        PTHREAD_MUTEX_UNLOCK(&lcp.lock);

        printf("file: "__FILE__", line: %d, "
                "loop after\n", __LINE__);
                */
        sleep(1);
    }

    //pthread_cond_signal(&lcp.cond);
    for (i=0; i<3; i++) {
        sleep(1);
    }

    printf("file: "__FILE__", line: %d, "
            "program exit.\n", __LINE__);
    return 0;
}
