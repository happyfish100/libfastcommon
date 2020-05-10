/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#ifndef PTHREAD_FUNC_H
#define PTHREAD_FUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "common_define.h"

#ifdef __cplusplus
extern "C" {
#endif

int init_pthread_lock(pthread_mutex_t *pthread_lock);
int init_pthread_attr(pthread_attr_t *pattr, const int stack_size);

#define PTHREAD_MUTEX_LOCK(lock) \
    do {  \
        int lock_res;   \
        if ((lock_res=pthread_mutex_lock(lock)) != 0) \
        {  \
            logWarning("file: "__FILE__", line: %d, "  \
                    "call pthread_mutex_lock fail, " \
                    "errno: %d, error info: %s", \
                    __LINE__, lock_res, STRERROR(lock_res)); \
        }  \
    } while (0)


#define PTHREAD_MUTEX_UNLOCK(lock) \
    do {  \
        int unlock_res;   \
        if ((unlock_res=pthread_mutex_unlock(lock)) != 0) \
        {  \
            logWarning("file: "__FILE__", line: %d, "    \
                    "call pthread_mutex_unlock fail, " \
                    "errno: %d, error info: %s", \
                    __LINE__, unlock_res, STRERROR(unlock_res)); \
        }  \
    } while (0)


int create_work_threads(int *count, void *(*start_func)(void *),
		void **args, pthread_t *tids, const int stack_size);

int create_work_threads_ex(int *count, void *(*start_func)(void *),
		void *args, const int elment_size, pthread_t *tids,
        const int stack_size);

int kill_work_threads(pthread_t *tids, const int count);

int fc_create_thread(pthread_t *tid, void *(*start_func)(void *),
        void *args, const int stack_size);

#ifdef __cplusplus
}
#endif

#endif

