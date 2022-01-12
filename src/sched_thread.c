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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "shared_func.h"
#include "pthread_func.h"
#include "logger.h"
#include "fc_memory.h"
#include "sched_thread.h"

volatile int g_schedule_flag = false;
volatile time_t g_current_time = 0;

static ScheduleArray waiting_schedule_array = {NULL, 0};
static int waiting_del_id = -1;

static ScheduleContext *schedule_context = NULL;
static int timer_slot_count = 0;
static int mblock_alloc_once = 0;
static uint32_t next_id = 0;
static bool print_all_entries = false;

static void sched_deal_delay_tasks(ScheduleContext *pContext);
static int sched_dup_array(const ScheduleArray *pSrcArray,
		ScheduleArray *pDestArray);

static int sched_cmp_by_next_call_time(const void *p1, const void *p2)
{
	return ((ScheduleEntry *)p1)->next_call_time -
			((ScheduleEntry *)p2)->next_call_time;
}

time_t sched_make_first_call_time(struct tm *tm_current,
        const TimeInfo *time_base, const int interval)
{
    int remain;
    struct {
        time_t time;
        struct tm tm;
    } base;

    if (time_base->hour == TIME_NONE)
    {
        return g_current_time + interval;
    }

    if (tm_current->tm_hour > time_base->hour ||
            (tm_current->tm_hour == time_base->hour
             && tm_current->tm_min >= time_base->minute))
    {
        base.tm = *tm_current;
    }
    else
    {
        base.time = g_current_time - 24 * 3600;
        localtime_r(&base.time, &base.tm);
    }

    base.tm.tm_hour = time_base->hour;
    base.tm.tm_min = time_base->minute;
    if (time_base->second >= 0 && time_base->second <= 59)
    {
        base.tm.tm_sec = time_base->second;
    }
    else
    {
        base.tm.tm_sec = 0;
    }
    base.time = mktime(&base.tm);
    remain = g_current_time - base.time;
    if (remain > 0)
    {
        return g_current_time + interval - remain % interval;
    }
    else if (remain < 0)
    {
        return g_current_time + (-1 * remain) % interval;
    }
    else
    {
        return g_current_time;
    }
}

static int sched_init_entries(ScheduleEntry *entries, const int count)
{
	ScheduleEntry *pEntry;
	ScheduleEntry *pEnd;
	struct tm tm_current;

	if (count < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"schedule count %d < 0",  \
			__LINE__, count);
		return EINVAL;
	}
	if (count == 0)
	{
		return 0;
	}

	g_current_time = time(NULL);
	localtime_r((time_t *)&g_current_time, &tm_current);
	pEnd = entries + count;
	for (pEntry=entries; pEntry<pEnd; pEntry++)
	{
        if (next_id < pEntry->id)
        {
            next_id = pEntry->id;
        }

		if (pEntry->interval <= 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"shedule interval %d <= 0",  \
				__LINE__, pEntry->interval);
			return EINVAL;
		}

        pEntry->next_call_time = sched_make_first_call_time(
                &tm_current, &pEntry->time_base, pEntry->interval);

        /*
		{
			char buff1[32];
			char buff2[32];
			logInfo("id=%d, current time=%s, first call time=%s",
				pEntry->id, formatDatetime(g_current_time,
				"%Y-%m-%d %H:%M:%S", buff1, sizeof(buff1)),
				formatDatetime(pEntry->next_call_time,
				"%Y-%m-%d %H:%M:%S", buff2, sizeof(buff2)));
		}
        */
	}

	return 0;
}

static void sched_make_chain(ScheduleContext *pContext)
{
	ScheduleArray *pScheduleArray;
	ScheduleEntry *pEntry;

	pScheduleArray = &(pContext->scheduleArray);
	if (pScheduleArray->count == 0)
	{
		pContext->head = NULL;
		pContext->tail = NULL;
		return;
	}

	qsort(pScheduleArray->entries, pScheduleArray->count,
		sizeof(ScheduleEntry), sched_cmp_by_next_call_time);

	pContext->head = pScheduleArray->entries;
	pContext->tail = pScheduleArray->entries + (pScheduleArray->count - 1);
	for (pEntry=pScheduleArray->entries; pEntry<pContext->tail; pEntry++)
	{
		pEntry->next = pEntry + 1;
	}
	pContext->tail->next = NULL;
}

void sched_print_all_entries()
{
    print_all_entries = true;
}

static int sched_cmp_by_id(const void *p1, const void *p2)
{
	return (int64_t)((ScheduleEntry *)p1)->id -
        (int64_t)((ScheduleEntry *)p2)->id;
}

static int print_all_sched_entries(ScheduleArray *pScheduleArray)
{
    ScheduleArray sortedByIdArray;
	ScheduleEntry *pEntry;
	ScheduleEntry *pEnd;
    char timebase[32];
    int result;

    logInfo("schedule entry count: %d", pScheduleArray->count);
	if (pScheduleArray->count == 0)
	{
		return 0;
	}

    if ((result=sched_dup_array(pScheduleArray, &sortedByIdArray)) != 0)
    {
        return result;
    }

    qsort(sortedByIdArray.entries, sortedByIdArray.count,
            sizeof(ScheduleEntry), sched_cmp_by_id);
	pEnd = sortedByIdArray.entries + sortedByIdArray.count;
	for (pEntry=sortedByIdArray.entries; pEntry<pEnd; pEntry++)
	{
        if (pEntry->time_base.hour == TIME_NONE)
        {
            strcpy(timebase, "<startup>");
        }
        else
        {
            sprintf(timebase, "%02d:%02d:%02d", pEntry->time_base.hour,
                pEntry->time_base.minute, pEntry->time_base.second);
        }
        logInfo("id: %u, time_base: %s, interval: %d, "
                "new_thread: %s, task_func: %p, args: %p, "
                "next_call_time: %d", pEntry->id, timebase,
                pEntry->interval, pEntry->new_thread ? "true" : "false",
                pEntry->task_func, pEntry->func_args,
                (int)pEntry->next_call_time);
    }

    free(sortedByIdArray.entries);
    return 0;
}

static int do_check_waiting(ScheduleContext *pContext)
{
	ScheduleArray *pScheduleArray;
	ScheduleEntry *waitingEntries;
	ScheduleEntry *newEntries;
	ScheduleEntry *pWaitingEntry;
	ScheduleEntry *pWaitingEnd;
	ScheduleEntry *pSchedEntry;
	ScheduleEntry *pSchedEnd;
	int allocCount;
	int newCount;
	int deleteCount;
    int waitingCount;

	pScheduleArray = &(pContext->scheduleArray);
	deleteCount = 0;
	if (waiting_del_id >= 0)
	{
		pSchedEnd = pScheduleArray->entries + pScheduleArray->count;
		for (pSchedEntry=pScheduleArray->entries; \
			pSchedEntry<pSchedEnd; pSchedEntry++)
		{
			if (pSchedEntry->id == waiting_del_id)
			{
				break;
			}
		}

		if (pSchedEntry < pSchedEnd)
		{
			pSchedEntry++;
			while (pSchedEntry < pSchedEnd)
			{
				memcpy(pSchedEntry - 1, pSchedEntry, \
					sizeof(ScheduleEntry));
				pSchedEntry++;
			}

			deleteCount++;
			pScheduleArray->count--;

			logDebug("file: "__FILE__", line: %d, " \
				"delete task id: %d, " \
				"current schedule count: %d", __LINE__, \
				waiting_del_id, pScheduleArray->count);
		}

		waiting_del_id = -1;
	}

    PTHREAD_MUTEX_LOCK(&schedule_context->lock);
    waitingCount = waiting_schedule_array.count;
    waitingEntries = waiting_schedule_array.entries;
    if (waiting_schedule_array.entries != NULL)
    {
        waiting_schedule_array.count = 0;
        waiting_schedule_array.entries = NULL;
    }
    PTHREAD_MUTEX_UNLOCK(&schedule_context->lock);

	if (waitingCount == 0)
	{
		if (deleteCount > 0)
		{
			sched_make_chain(pContext);
			return 0;
		}

		return ENOENT;
	}

	allocCount = pScheduleArray->count + waitingCount;
	newEntries = (ScheduleEntry *)fc_malloc(sizeof(ScheduleEntry) * allocCount);
	if (newEntries == NULL)
	{
		if (deleteCount > 0)
		{
			sched_make_chain(pContext);
		}
		return ENOMEM;
	}

	if (pScheduleArray->count > 0)
	{
		memcpy(newEntries, pScheduleArray->entries,
			sizeof(ScheduleEntry) * pScheduleArray->count);
	}
	newCount = pScheduleArray->count;
	pWaitingEnd = waitingEntries + waitingCount;
	for (pWaitingEntry=waitingEntries; pWaitingEntry<pWaitingEnd;
            pWaitingEntry++)
	{
		pSchedEnd = newEntries + newCount;
		for (pSchedEntry=newEntries; pSchedEntry<pSchedEnd; \
			pSchedEntry++)
		{
			if (pWaitingEntry->id == pSchedEntry->id)
            {
                *pSchedEntry = *pWaitingEntry;
                break;
            }
		}

		if (pSchedEntry == pSchedEnd)
		{
			*pSchedEntry = *pWaitingEntry;
			newCount++;
		}
	}

	logDebug("file: "__FILE__", line: %d, " \
		"schedule add entries: %d, replace entries: %d", 
		__LINE__, newCount - pScheduleArray->count, \
		waitingCount - (newCount - pScheduleArray->count));

	if (pScheduleArray->entries != NULL)
	{
		free(pScheduleArray->entries);
	}
	pScheduleArray->entries = newEntries;
	pScheduleArray->count = newCount;
	free(waitingEntries);

	sched_make_chain(pContext);
	return 0;
}

static inline int sched_check_waiting_more(ScheduleContext *pContext)
{
	int result;

    result = do_check_waiting(pContext);
    if (print_all_entries)
    {
        print_all_sched_entries(&pContext->scheduleArray);
        print_all_entries = false;
    }
    return result;
}

static void *sched_call_func(void *args)
{
	ScheduleEntry *pEntry;
    void *func_args;
    TaskFunc task_func;
    int task_id;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "sched-call");
#endif

    pEntry = (ScheduleEntry *)args;
    task_func = pEntry->task_func;
    func_args = pEntry->func_args;
    task_id = pEntry->id;

    logDebug("file: "__FILE__", line: %d, " \
            "thread enter, task id: %d", __LINE__, task_id);

    pEntry->thread_running = true;
    task_func(func_args);

    logDebug("file: "__FILE__", line: %d, " \
            "thread exit, task id: %d", __LINE__, task_id);
    pthread_detach(pthread_self());
	return NULL;
}

static void *sched_thread_entrance(void *args)
{
	ScheduleContext *pContext;
	ScheduleEntry *pPrevious;
	ScheduleEntry *pCurrent;
	ScheduleEntry *pSaveNext;
	ScheduleEntry *pNode;
	ScheduleEntry *pUntil;
	int exec_count;
	int i;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "sched");
#endif

	pContext = (ScheduleContext *)args;
	if (sched_init_entries(pContext->scheduleArray.entries,
                pContext->scheduleArray.count) != 0)
	{
		free(pContext);
		return NULL;
	}
	sched_make_chain(pContext);

    __sync_bool_compare_and_swap(&g_schedule_flag, 0, 1);
	while (*(pContext->pcontinue_flag))
	{
		g_current_time = time(NULL);
        sched_deal_delay_tasks(pContext);

		sched_check_waiting_more(pContext);
		if (pContext->scheduleArray.count == 0)  //no schedule entry
		{
			sleep(1);
			continue;
		}

        /*
        logInfo("task count: %d, next_call_time: %d, g_current_time: %d",
                pContext->scheduleArray.count,
                (int)pContext->head->next_call_time, (int)g_current_time);
                */
        while (pContext->head->next_call_time > g_current_time &&
                *(pContext->pcontinue_flag))
        {
            sleep(1);
            g_current_time = time(NULL);

            sched_deal_delay_tasks(pContext);
            if (sched_check_waiting_more(pContext) == 0)
            {
                break;
            }
        }

		if (!(*(pContext->pcontinue_flag)))
		{
			break;
		}

		exec_count = 0;
		pCurrent = pContext->head;
		while (*(pContext->pcontinue_flag) && (pCurrent != NULL
			&& pCurrent->next_call_time <= g_current_time))
		{
			//logInfo("exec task id: %d", pCurrent->id);
            if (!pCurrent->new_thread)
            {
			    pCurrent->task_func(pCurrent->func_args);
            }
            else
            {
                pthread_t tid;
                int result;

                pCurrent->thread_running = false;
                if ((result=pthread_create(&tid, NULL,
                                sched_call_func, pCurrent)) != 0)
                {
                    logError("file: "__FILE__", line: %d, " \
                            "create thread failed, " \
                            "errno: %d, error info: %s", \
                            __LINE__, result, STRERROR(result));
                }
                else
                {
                    fc_sleep_ms(1);
                    for (i=1; !pCurrent->thread_running && i<100; i++)
                    {
                        logDebug("file: "__FILE__", line: %d, "
                                "task_id: %d, waiting thread ready, count %d",
                                __LINE__, pCurrent->id, i);
                        fc_sleep_ms(1);
                    }
                }
            }

            do
            {
                pCurrent->next_call_time += pCurrent->interval;
            } while (pCurrent->next_call_time <= g_current_time);
			pCurrent = pCurrent->next;
			exec_count++;
		}

		if (exec_count == 0 || pContext->scheduleArray.count == 1)
		{
			continue;
		}

		if (exec_count > pContext->scheduleArray.count / 2)
		{
			sched_make_chain(pContext);
			continue;
		}

		pNode = pContext->head;
		pContext->head = pCurrent;  //new chain head
		for (i=0; i<exec_count; i++)
		{
			if (pNode->next_call_time >= pContext->tail->next_call_time)
			{
				pContext->tail->next = pNode;
				pContext->tail = pNode;
				pNode = pNode->next;
				pContext->tail->next = NULL;
				continue;
			}

			pPrevious = NULL;
			pUntil = pContext->head;
			while (pUntil != NULL && \
				pNode->next_call_time > pUntil->next_call_time)
			{
				pPrevious = pUntil;
				pUntil = pUntil->next;
			}

			pSaveNext = pNode->next;
			if (pPrevious == NULL)
			{
				pContext->head = pNode;
			}
			else
			{
				pPrevious->next = pNode;
			}
			pNode->next = pUntil;

			pNode = pSaveNext;
		}
	}

    __sync_bool_compare_and_swap(&g_schedule_flag, 1, 0);

	logDebug("file: "__FILE__", line: %d, " \
		"schedule thread exit", __LINE__);

	free(pContext);
	return NULL;
}

static int sched_dup_array(const ScheduleArray *pSrcArray, \
		ScheduleArray *pDestArray)
{
	int bytes;

	if (pSrcArray->count == 0)
	{
		pDestArray->entries = NULL;
		pDestArray->count = 0;
		return 0;
	}

	bytes = sizeof(ScheduleEntry) * pSrcArray->count;
	pDestArray->entries = (ScheduleEntry *)fc_malloc(bytes);
	if (pDestArray->entries == NULL)
	{
		return ENOMEM;
	}

	memcpy(pDestArray->entries, pSrcArray->entries, bytes);
	pDestArray->count = pSrcArray->count;
	return 0;
}

static int sched_append_array(const ScheduleArray *pSrcArray,
		ScheduleArray *pDestArray)
{
	int bytes;
    ScheduleEntry *new_entries;

	bytes = sizeof(ScheduleEntry) * (pDestArray->count + pSrcArray->count);
	new_entries = (ScheduleEntry *)fc_malloc(bytes);
	if (new_entries == NULL)
	{
		return ENOMEM;
	}

    if (pDestArray->entries != NULL)
    {
	    memcpy(new_entries, pDestArray->entries,
                sizeof(ScheduleEntry) * pDestArray->count);
        free(pDestArray->entries);
    }
    memcpy(new_entries + pDestArray->count, pSrcArray->entries,
                sizeof(ScheduleEntry) * pSrcArray->count);

    pDestArray->entries = new_entries;
	pDestArray->count += pSrcArray->count;
	return 0;
}

int sched_thread_init_ex(ScheduleContext **ppContext)
{
    int result;

    *ppContext = (ScheduleContext *)fc_malloc(sizeof(ScheduleContext));
    if (*ppContext == NULL)
    {
        return ENOMEM;
    }
    memset(*ppContext, 0, sizeof(ScheduleContext));

    if ((result=init_pthread_lock(&(*ppContext)->lock)) != 0)
    {
        return result;
    }

    return 0;
}

int sched_add_entries(const ScheduleArray *pScheduleArray)
{
    ScheduleEntry *newStart;
    int old_count;
    int result;

    if (pScheduleArray->count <= 0)
    {
        logWarning("file: "__FILE__", line: %d, "
                "no schedule entry", __LINE__);
        return ENOENT;
    }

    if (schedule_context == NULL)
    {
        if ((result=sched_thread_init_ex(&schedule_context)) != 0)
        {
            return result;
        }
    }

    PTHREAD_MUTEX_LOCK(&schedule_context->lock);
    do {
        old_count = waiting_schedule_array.count;
        if ((result=sched_append_array(pScheduleArray,
                        &waiting_schedule_array)) != 0)
        {
            break;
        }

        newStart = waiting_schedule_array.entries + old_count;
        if ((result=sched_init_entries(newStart, pScheduleArray->count)) != 0)
        {
            waiting_schedule_array.count = newStart -
                waiting_schedule_array.entries;   //rollback
            break;
        }
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&schedule_context->lock);

    return result;
}

int sched_del_entry(const int id)
{
	if (id < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"id: %d is invalid!", __LINE__, id);
		return EINVAL;
	}

	while (waiting_del_id >= 0)
	{
		logDebug("file: "__FILE__", line: %d, " \
			"waiting for delete ready ...", __LINE__);
		sleep(1);
	}

	waiting_del_id = id;
	return 0;
}

int sched_start_ex(ScheduleArray *pScheduleArray, pthread_t *ptid,
		const int stack_size, bool * volatile pcontinue_flag,
        ScheduleContext *pContext)
{
	int result;
	pthread_attr_t thread_attr;

	if ((result=init_pthread_attr(&thread_attr, stack_size)) != 0)
	{
		free(pContext);
		return result;
	}

	if ((result=sched_dup_array(pScheduleArray,
			&(pContext->scheduleArray))) != 0)
	{
		free(pContext);
		return result;
	}

    if (timer_slot_count > 0)
    {
        if ((result=fast_mblock_init_ex1(&pContext->delay_task_allocator,
                        "sched-delay-task", sizeof(FastDelayTask),
                        mblock_alloc_once, 0, NULL, NULL, true)) != 0)
        {
	    	free(pContext);
		    return result;
        }

        g_current_time = time(NULL);
        if ((result=fast_timer_init(&pContext->timer, timer_slot_count,
                        g_current_time)) != 0)
    	{
	    	free(pContext);
		    return result;
	    }

        if ((result=fc_queue_init(&pContext->delay_queue, (long)
                        (&((FastDelayTask *)NULL)->next))) != 0)
        {
	    	free(pContext);
		    return result;
        }
        pContext->timer_init = true;
    }

	pContext->pcontinue_flag = pcontinue_flag;
	if ((result=pthread_create(ptid, &thread_attr, \
		sched_thread_entrance, pContext)) != 0)
	{
		free(pContext);
		logError("file: "__FILE__", line: %d, " \
			"create thread failed, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	pthread_attr_destroy(&thread_attr);
	return result;
}

int sched_start(ScheduleArray *pScheduleArray, pthread_t *ptid,
		const int stack_size, bool * volatile pcontinue_flag)
{
    int result;
    if (schedule_context == NULL)
    {
        if ((result=sched_thread_init_ex(&schedule_context)) != 0)
        {
            return result;
        }
    }
    return sched_start_ex(pScheduleArray, ptid, stack_size,
            pcontinue_flag, schedule_context);
}

void sched_set_delay_params(const int slot_count, const int alloc_once)
{
    if (slot_count > 1)
    {
        timer_slot_count = slot_count;
    }
    else
    {
        timer_slot_count = 300;
    }

    if (alloc_once > 0)
    {
        mblock_alloc_once = alloc_once;
    }
    else
    {
        mblock_alloc_once = 4 * 1024;
    }
}

int sched_add_delay_task_ex(ScheduleContext *pContext, TaskFunc task_func,
        void *func_args, const int delay_seconds, const bool new_thread)
{
    FastDelayTask *task;
    bool notify;

    if (!pContext->timer_init)
    {
		logError("file: "__FILE__", line: %d, "
			"NOT support delay tasks, you should call sched_set_delay_params "
            "before sched_start!", __LINE__);
        return EOPNOTSUPP;
    }

    task = (FastDelayTask *)fast_mblock_alloc_object(
            &pContext->delay_task_allocator);
    if (task == NULL)
    {
        return ENOMEM;
    }
    task->task_func = task_func;
    task->func_args = func_args;
    task->new_thread = new_thread;
    task->next = NULL;
    if (delay_seconds > 0)
    {
        task->timer.expires = g_current_time + delay_seconds;
    }
    else
    {
        task->timer.expires = g_current_time;
    }

    fc_queue_push_ex(&pContext->delay_queue, task, &notify);
    return 0;
}

int sched_add_delay_task(TaskFunc task_func, void *func_args,
        const int delay_seconds, const bool new_thread)
{
    return sched_add_delay_task_ex(schedule_context, task_func,
            func_args, delay_seconds, new_thread);
}

static void sched_deal_task_queue(ScheduleContext *pContext)
{
    FastDelayTask *task;
    struct fc_queue_info qinfo;

    fc_queue_try_pop_to_queue(&pContext->delay_queue, &qinfo);
    task = qinfo.head;
    while (task != NULL)
    {
        fast_timer_add(&pContext->timer, (FastTimerEntry *)task);
        task = task->next;
    }
}

struct delay_thread_context {
    ScheduleContext *schedule_context;
    FastDelayTask *task;
};

static void *sched_call_delay_func(void *args)
{
    struct delay_thread_context *delay_context;
    ScheduleContext *pContext;
    FastDelayTask *task;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "sched-delay");
#endif

    delay_context = (struct delay_thread_context *)args;
    task = delay_context->task;
    pContext = delay_context->schedule_context;

    logDebug("file: "__FILE__", line: %d, " \
            "delay thread enter, task args: %p", __LINE__, task->func_args);

    task->thread_running = true;
    task->task_func(task->func_args);

    logDebug("file: "__FILE__", line: %d, " \
            "delay thread exit, task args: %p", __LINE__, task->func_args);

    fast_mblock_free_object(&pContext->delay_task_allocator, task);
    pthread_detach(pthread_self());
	return NULL;
}

static void deal_timeout_tasks(ScheduleContext *pContext, FastTimerEntry *head)
{
	FastTimerEntry *entry;
	FastTimerEntry *current;
    FastDelayTask *task;

	entry = head->next;
	while (entry != NULL)
	{
		current = entry;
		entry = entry->next;

        current->prev = current->next = NULL; //must set NULL because NOT in time wheel

        task = (FastDelayTask *)current;

        if (!task->new_thread)
        {
            task->task_func(task->func_args);
            fast_mblock_free_object(&pContext->delay_task_allocator, task);
        }
        else
        {
            struct delay_thread_context delay_context;
            pthread_t tid;
            int result;
            int i;

            task->thread_running = false;
            delay_context.task = task;
            delay_context.schedule_context = pContext;
            if ((result=pthread_create(&tid, NULL,
                            sched_call_delay_func, &delay_context)) != 0)
            {
                logError("file: "__FILE__", line: %d, " \
                        "create thread failed, " \
                        "errno: %d, error info: %s", \
                        __LINE__, result, STRERROR(result));
            }
            else
            {
               fc_sleep_ms(1);
               for (i=1; !task->thread_running && i<100; i++)
               {
                   logDebug("file: "__FILE__", line: %d, "
                           "task args: %p, waiting thread ready, count %d",
                           __LINE__, task->func_args, i);
                   fc_sleep_ms(1);
               }
            }
        }
    }
}

static void sched_deal_delay_tasks(ScheduleContext *pContext)
{
	FastTimerEntry head;
	int count;

    if (!pContext->timer_init)
    {
        return;
    }

    sched_deal_task_queue(pContext);
    count = fast_timer_timeouts_get(
            &pContext->timer, g_current_time, &head);
    if (count > 0)
    {
        deal_timeout_tasks(pContext, &head);
        //logInfo("deal delay task count: %d", count);
    }
}

uint32_t sched_generate_next_id()
{
    return ++next_id;
}

static int sched_free_ptr_func(void *ptr)
{
    free(ptr);
    return 0;
}

int sched_delay_free_ptr(void *ptr, const int delay_seconds)
{
    const bool new_thread = false;
    return sched_add_delay_task_ex(schedule_context, sched_free_ptr_func,
            ptr, delay_seconds, new_thread);
}
