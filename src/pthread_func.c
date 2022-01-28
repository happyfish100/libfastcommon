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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include "fc_memory.h"
#include "logger.h"
#include "pthread_func.h"

int init_pthread_lock(pthread_mutex_t *pthread_lock)
{
	pthread_mutexattr_t mat;
	int result;

	if ((result=pthread_mutexattr_init(&mat)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_mutexattr_init fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}
	if ((result=pthread_mutexattr_settype(&mat,
			PTHREAD_MUTEX_ERRORCHECK)) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"call pthread_mutexattr_settype fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}
	if ((result=pthread_mutex_init(pthread_lock, &mat)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_mutex_init fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}
	if ((result=pthread_mutexattr_destroy(&mat)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call thread_mutexattr_destroy fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

	return 0;
}

int init_pthread_rwlock(pthread_rwlock_t *rwlock)
{
    struct {
        pthread_rwlockattr_t holder;
        pthread_rwlockattr_t *ptr;
    } attr;
	int result;


#ifdef WITH_PTHREAD_RWLOCKATTR_SETKIND_NP
    attr.ptr = &attr.holder;
	if ((result=pthread_rwlockattr_init(attr.ptr)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_rwlockattr_init fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

	if ((result=pthread_rwlockattr_setkind_np(attr.ptr,
			PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call pthread_rwlockattr_settype fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }
#else
    attr.ptr = NULL;
#endif

	if ((result=pthread_rwlock_init(rwlock, attr.ptr)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_rwlock_init fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}
    if (attr.ptr != NULL) {
        if ((result=pthread_rwlockattr_destroy(attr.ptr)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "call thread_rwlockattr_destroy fail, "
                    "errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

	return 0;
}

int init_pthread_attr(pthread_attr_t *pattr, const int stack_size)
{
	size_t old_stack_size;
	size_t new_stack_size;
	int result;

	if ((result=pthread_attr_init(pattr)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_attr_init fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

	if ((result=pthread_attr_getstacksize(pattr, &old_stack_size)) != 0) {
		logError("file: "__FILE__", line: %d, "
			"call pthread_attr_getstacksize fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

	if (stack_size > 0) {
		if (old_stack_size != stack_size) {
			new_stack_size = stack_size;
		} else {
			new_stack_size = 0;
		}
	} else if (old_stack_size < 1 * 1024 * 1024) {
		new_stack_size = 1 * 1024 * 1024;
	} else {
		new_stack_size = 0;
	}

	if (new_stack_size > 0) {
		if ((result=pthread_attr_setstacksize(pattr,
				new_stack_size)) != 0)
		{
			logError("file: "__FILE__", line: %d, "
				"call pthread_attr_setstacksize to %d fail, "
				"errno: %d, error info: %s", __LINE__,
                (int)new_stack_size, result, STRERROR(result));
			return result;
		}
	}

	if ((result=pthread_attr_setdetachstate(pattr,
			PTHREAD_CREATE_DETACHED)) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"call pthread_attr_setdetachstate fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

	return 0;
}

int create_work_threads(int *count, void *(*start_func)(void *),
		void **args, pthread_t *tids, const int stack_size)
{
#define FIXED_TID_COUNT   256

	int result;
	pthread_attr_t thread_attr;
    void **current_arg;
    pthread_t fixed_tids[FIXED_TID_COUNT];
    pthread_t *the_tids;
	pthread_t *ptid;
	pthread_t *ptid_end;

	if ((result=init_pthread_attr(&thread_attr, stack_size)) != 0) {
		return result;
	}

    if (tids != NULL) {
        the_tids = tids;
    } else {
        if (*count <= FIXED_TID_COUNT) {
            the_tids = fixed_tids;
        } else {
            int bytes;
            bytes = sizeof(pthread_t) * *count;
            the_tids = (pthread_t *)fc_malloc(bytes);
            if (the_tids == NULL) {
                pthread_attr_destroy(&thread_attr);
                return ENOMEM;
            }
        }
    }

	result = 0;
	ptid_end = the_tids + (*count);
	for (ptid=the_tids,current_arg=args; ptid<ptid_end;
            ptid++,current_arg++)
    {
		if ((result=pthread_create(ptid, &thread_attr,
			start_func, *current_arg)) != 0)
		{
			*count = ptid - the_tids;
			logError("file: "__FILE__", line: %d, "
				"create threads #%d fail, "
				"errno: %d, error info: %s",
				__LINE__, *count,
				result, STRERROR(result));
			break;
		}
	}

    if (the_tids != tids && the_tids != fixed_tids) {
        free(the_tids);
    }

	pthread_attr_destroy(&thread_attr);
	return result;
}

int create_work_threads_ex(int *count, void *(*start_func)(void *),
		void *args, const int elment_size, pthread_t *tids,
        const int stack_size)
{
#define FIXED_ARG_COUNT   256

    void *fixed_args[FIXED_ARG_COUNT];
    void **pp_args;
    char *p;
    int result;
    int i;

    if (*count <= FIXED_ARG_COUNT) {
        pp_args = fixed_args;
    } else {
        int bytes;
        bytes = sizeof(void *) * (*count);
        pp_args = (void **)fc_malloc(bytes);
        if (pp_args == NULL) {
            return ENOMEM;
        }
    }

    p = (char *)args;
    for (i=0; i<*count; i++) {
        pp_args[i] = p;
        p += elment_size;
    }
    result = create_work_threads(count, start_func,
           pp_args, tids, stack_size);
    if (pp_args != fixed_args) {
        free(pp_args);
    }
    return result;
}

int kill_work_threads(pthread_t *tids, const int count)
{
	int result;
	pthread_t *ptid;
	pthread_t *ptid_end;

	ptid_end = tids + count;
	for (ptid=tids; ptid<ptid_end; ptid++) {
		if ((result=pthread_kill(*ptid, SIGINT)) != 0) {
			logError("file: "__FILE__", line: %d, "
				"kill thread failed, "
				"errno: %d, error info: %s",
				__LINE__, result, STRERROR(result));
		}
	}

	return 0;
}

int fc_create_thread(pthread_t *tid, void *(*start_func)(void *),
        void *args, const int stack_size)
{
	int result;
	pthread_attr_t thread_attr;

	if ((result=init_pthread_attr(&thread_attr, stack_size)) != 0) {
		return result;
	}

    if ((result=pthread_create(tid, &thread_attr, start_func, args)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "create thread fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
    }

	pthread_attr_destroy(&thread_attr);
	return result;
}

int init_pthread_lock_cond_pair(pthread_lock_cond_pair_t *lcp)
{
    int result;

	if ((result=init_pthread_lock(&lcp->lock)) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"init_pthread_lock fail, errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

    if ((result=pthread_cond_init(&lcp->cond, NULL)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "pthread_cond_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    return 0;
}

void destroy_pthread_lock_cond_pair(pthread_lock_cond_pair_t *lcp)
{
    pthread_cond_destroy(&lcp->cond);
    pthread_mutex_destroy(&lcp->lock);
}
