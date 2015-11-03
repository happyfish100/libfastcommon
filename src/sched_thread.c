/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "shared_func.h"
#include "pthread_func.h"
#include "logger.h"
#include "sched_thread.h"

volatile bool g_schedule_flag = false;
volatile time_t g_current_time = 0;

static ScheduleArray waiting_schedule_array = {NULL, 0};
static int waiting_del_id = -1;

static ScheduleContext *schedule_context = NULL;
static int timer_slot_count = 0;
static int mblock_alloc_once = 0;

static void sched_deal_delay_tasks(ScheduleContext *pContext);

static int sched_cmp_by_next_call_time(const void *p1, const void *p2)
{
	return ((ScheduleEntry *)p1)->next_call_time - \
			((ScheduleEntry *)p2)->next_call_time;
}

static int sched_init_entries(ScheduleArray *pScheduleArray)
{
	ScheduleEntry *pEntry;
	ScheduleEntry *pEnd;
	time_t time_base;
	struct tm tm_current;
	struct tm tm_base;

	if (pScheduleArray->count < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"schedule count %d < 0",  \
			__LINE__, pScheduleArray->count);
		return EINVAL;
	}
	if (pScheduleArray->count == 0)
	{
		return 0;
	}

	g_current_time = time(NULL);
	localtime_r((time_t *)&g_current_time, &tm_current);
	pEnd = pScheduleArray->entries + pScheduleArray->count;
	for (pEntry=pScheduleArray->entries; pEntry<pEnd; pEntry++)
	{
		if (pEntry->interval <= 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"shedule interval %d <= 0",  \
				__LINE__, pEntry->interval);
			return EINVAL;
		}

		if (pEntry->time_base.hour == TIME_NONE)
		{
			pEntry->next_call_time = g_current_time + \
						pEntry->interval;
		}
		else
		{
			if (tm_current.tm_hour > pEntry->time_base.hour || \
				(tm_current.tm_hour == pEntry->time_base.hour \
				&& tm_current.tm_min >= pEntry->time_base.minute))
			{
				memcpy(&tm_base, &tm_current, sizeof(struct tm));
			}
			else
			{
				time_base = g_current_time - 24 * 3600;
				localtime_r(&time_base, &tm_base);
			}

			tm_base.tm_hour = pEntry->time_base.hour;
			tm_base.tm_min = pEntry->time_base.minute;
            if (pEntry->time_base.second >= 0 && pEntry->time_base.second <= 59)
            {
                tm_base.tm_sec = pEntry->time_base.second;
            }
            else
            {
                tm_base.tm_sec = 0;
            }
			time_base = mktime(&tm_base);

			pEntry->next_call_time = g_current_time + \
				pEntry->interval - (g_current_time - \
					time_base) % pEntry->interval;
		}

		/*
		{
			char buff1[32];
			char buff2[32];
			logInfo("id=%d, current time=%s, first call time=%s\n", \
				pEntry->id, formatDatetime(g_current_time, \
				"%Y-%m-%d %H:%M:%S", buff1, sizeof(buff1)), \
				formatDatetime(pEntry->next_call_time, \
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

	qsort(pScheduleArray->entries, pScheduleArray->count, \
		sizeof(ScheduleEntry), sched_cmp_by_next_call_time);

	pContext->head = pScheduleArray->entries;
	pContext->tail = pScheduleArray->entries + (pScheduleArray->count - 1);
	for (pEntry=pScheduleArray->entries; pEntry<pContext->tail; pEntry++)
	{
		pEntry->next = pEntry + 1;
	}
	pContext->tail->next = NULL;
}

static int sched_check_waiting(ScheduleContext *pContext)
{
	ScheduleArray *pScheduleArray;
	ScheduleEntry *newEntries;
	ScheduleEntry *pWaitingEntry;
	ScheduleEntry *pWaitingEnd;
	ScheduleEntry *pSchedEntry;
	ScheduleEntry *pSchedEnd;
	int allocCount;
	int newCount;
	int result;
	int deleteCount;

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

	if (waiting_schedule_array.count == 0)
	{
		if (deleteCount > 0)
		{
			sched_make_chain(pContext);
			return 0;
		}

		return ENOENT;
	}

	allocCount = pScheduleArray->count + waiting_schedule_array.count;
	newEntries = (ScheduleEntry *)malloc(sizeof(ScheduleEntry) * allocCount);
	if (newEntries == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes failed, " \
			"errno: %d, error info: %s", \
			__LINE__, (int)sizeof(ScheduleEntry) * allocCount, \
			result, STRERROR(result));

		if (deleteCount > 0)
		{
			sched_make_chain(pContext);
		}
		return result;
	}

	if (pScheduleArray->count > 0)
	{
		memcpy(newEntries, pScheduleArray->entries, \
			sizeof(ScheduleEntry) * pScheduleArray->count);
	}
	newCount = pScheduleArray->count;
	pWaitingEnd = waiting_schedule_array.entries + waiting_schedule_array.count;
	for (pWaitingEntry=waiting_schedule_array.entries; \
		pWaitingEntry<pWaitingEnd; pWaitingEntry++)
	{
		pSchedEnd = newEntries + newCount;
		for (pSchedEntry=newEntries; pSchedEntry<pSchedEnd; \
			pSchedEntry++)
		{
			if (pWaitingEntry->id == pSchedEntry->id)
			{
				memcpy(pSchedEntry, pWaitingEntry, \
					sizeof(ScheduleEntry));
				break;
			}
		}

		if (pSchedEntry == pSchedEnd)
		{
			memcpy(pSchedEntry, pWaitingEntry, \
				sizeof(ScheduleEntry));
			newCount++;
		}
	}

	logDebug("file: "__FILE__", line: %d, " \
		"schedule add entries: %d, replace entries: %d", 
		__LINE__, newCount - pScheduleArray->count, \
		waiting_schedule_array.count - (newCount - pScheduleArray->count));

	if (pScheduleArray->entries != NULL)
	{
		free(pScheduleArray->entries);
	}
	pScheduleArray->entries = newEntries;
	pScheduleArray->count = newCount;

	free(waiting_schedule_array.entries);
	waiting_schedule_array.count = 0;
	waiting_schedule_array.entries = NULL;

	sched_make_chain(pContext);

	return 0;
}

static void *sched_call_func(void *args)
{
	ScheduleEntry *pEntry;
    void *func_args;
    TaskFunc task_func;
    int task_id;

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

	pContext = (ScheduleContext *)args;
	if (sched_init_entries(&(pContext->scheduleArray)) != 0)
	{
		free(pContext);
		return NULL;
	}
	sched_make_chain(pContext);

	g_schedule_flag = true;
	while (*(pContext->pcontinue_flag))
	{
		g_current_time = time(NULL);
        sched_deal_delay_tasks(pContext);

		sched_check_waiting(pContext);
		if (pContext->scheduleArray.count == 0)  //no schedule entry
		{
			sleep(1);
			continue;
		}

        while (pContext->head->next_call_time > g_current_time &&
                *(pContext->pcontinue_flag))
        {
            sleep(1);
            g_current_time = time(NULL);

            sched_deal_delay_tasks(pContext);
            if (sched_check_waiting(pContext) == 0)
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
		while (*(pContext->pcontinue_flag) && (pCurrent != NULL \
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
                    usleep(1*1000);
                    for (i=1; !pCurrent->thread_running && i<100; i++)
                    {
                        logDebug("file: "__FILE__", line: %d, "
                                "task_id: %d, waiting thread ready, count %d",
                                __LINE__, pCurrent->id, i);
                        usleep(1*1000);
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

	g_schedule_flag = false;

	logDebug("file: "__FILE__", line: %d, " \
		"schedule thread exit", __LINE__);

	free(pContext);
	return NULL;
}

static int sched_dup_array(const ScheduleArray *pSrcArray, \
		ScheduleArray *pDestArray)
{
	int result;
	int bytes;

	if (pSrcArray->count == 0)
	{
		pDestArray->entries = NULL;
		pDestArray->count = 0;
		return 0;
	}

	bytes = sizeof(ScheduleEntry) * pSrcArray->count;
	pDestArray->entries = (ScheduleEntry *)malloc(bytes);
	if (pDestArray->entries == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes failed, " \
			"errno: %d, error info: %s", \
			__LINE__, bytes, result, STRERROR(result));
		return result;
	}

	memcpy(pDestArray->entries, pSrcArray->entries, bytes);
	pDestArray->count = pSrcArray->count;
	return 0;
}

static int sched_append_array(const ScheduleArray *pSrcArray, \
		ScheduleArray *pDestArray)
{
	int result;
	int bytes;
    ScheduleEntry *new_entries;

	if (pSrcArray->count == 0)
	{
		return 0;
	}

	bytes = sizeof(ScheduleEntry) * (pDestArray->count + pSrcArray->count);
	new_entries = (ScheduleEntry *)malloc(bytes);
	if (new_entries == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes failed, " \
			"errno: %d, error info: %s", \
			__LINE__, bytes, result, STRERROR(result));
		return result;
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

int sched_add_entries(const ScheduleArray *pScheduleArray)
{
	int result;

	if (pScheduleArray->count == 0)
	{
		logDebug("file: "__FILE__", line: %d, " \
			"no schedule entry", __LINE__);
		return ENOENT;
	}

    if (waiting_schedule_array.entries != NULL)
    {
        if (g_schedule_flag)
        {
    	    while (waiting_schedule_array.entries != NULL)
	        {
	        	logDebug("file: "__FILE__", line: %d, " \
			        "waiting for schedule array ready ...", __LINE__);
	        	sleep(1);
	        }
        }
    }

	if ((result=sched_append_array(pScheduleArray,
                    &waiting_schedule_array)) != 0)
	{
		return result;
	}

	return sched_init_entries(&waiting_schedule_array);
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
        ScheduleContext **ppContext)
{
	int result;
	pthread_attr_t thread_attr;
	ScheduleContext *pContext;

	pContext = (ScheduleContext *)malloc(sizeof(ScheduleContext));
	if (pContext == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes failed, " \
			"errno: %d, error info: %s", \
			__LINE__, (int)sizeof(ScheduleContext), \
			result, STRERROR(result));
		return result;
	}
    memset(pContext, 0, sizeof(ScheduleContext));

	if ((result=init_pthread_attr(&thread_attr, stack_size)) != 0)
	{
		free(pContext);
		return result;
	}

	if ((result=sched_dup_array(pScheduleArray, \
			&(pContext->scheduleArray))) != 0)
	{
		free(pContext);
		return result;
	}

    if (timer_slot_count > 0)
    {
        if ((result=fast_mblock_init(&pContext->mblock,
                        sizeof(FastDelayTask), mblock_alloc_once)) != 0)
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
        if ((result=init_pthread_lock(&pContext->delay_queue.lock)) != 0)
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

    *ppContext = pContext;
	pthread_attr_destroy(&thread_attr);
	return result;
}

int sched_start(ScheduleArray *pScheduleArray, pthread_t *ptid,
		const int stack_size, bool * volatile pcontinue_flag)
{
    return sched_start_ex(pScheduleArray, ptid, stack_size,
            pcontinue_flag, &schedule_context);
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
    if (!pContext->timer_init)
    {
		logError("file: "__FILE__", line: %d, "
			"NOT support delay tasks, you should call sched_set_delay_params "
            "before sched_start!", __LINE__);
        return EOPNOTSUPP;
    }

    task = (FastDelayTask *)fast_mblock_alloc_object(&pContext->mblock);
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

    pthread_mutex_lock(&pContext->delay_queue.lock);
    if (pContext->delay_queue.head == NULL)
    {
        pContext->delay_queue.head = task;
    }
    else
    {
        pContext->delay_queue.tail->next = task;
    }
    pContext->delay_queue.tail = task;
    pthread_mutex_unlock(&pContext->delay_queue.lock);

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

    pthread_mutex_lock(&pContext->delay_queue.lock);
    if (pContext->delay_queue.head == NULL)
    {
        pthread_mutex_unlock(&pContext->delay_queue.lock);
        return;
    }
    task  = pContext->delay_queue.head;
    pContext->delay_queue.head = NULL;
    pContext->delay_queue.tail = NULL;
    pthread_mutex_unlock(&pContext->delay_queue.lock);

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

    delay_context = (struct delay_thread_context *)args;
    task = delay_context->task;
    pContext = delay_context->schedule_context;

    logDebug("file: "__FILE__", line: %d, " \
            "delay thread enter, task args: %p", __LINE__, task->func_args);

    task->thread_running = true;
    task->task_func(task->func_args);

    logDebug("file: "__FILE__", line: %d, " \
            "delay thread exit, task args: %p", __LINE__, task->func_args);

    fast_mblock_free_object(&pContext->mblock, task);
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
            fast_mblock_free_object(&pContext->mblock, task);
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
               usleep(1*1000);
               for (i=1; !task->thread_running && i<100; i++)
               {
                   logDebug("file: "__FILE__", line: %d, "
                           "task args: %p, waiting thread ready, count %d",
                           __LINE__, task->func_args, i);
                   usleep(1*1000);
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

