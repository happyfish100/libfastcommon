/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#ifndef _SCHED_THREAD_H_
#define _SCHED_THREAD_H_

#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include "common_define.h"
#include "fast_timer.h"
#include "fast_mblock.h"

typedef int (*TaskFunc) (void *args);

typedef struct tagScheduleEntry
{
	uint32_t id;  //the task id

	/* the time base to execute task, such as 00:00, interval is 3600,
           means execute the task every hour as 1:00, 2:00, 3:00 etc. */
	TimeInfo time_base;

	int interval;   //the interval for execute task, unit is second

    bool new_thread;  //run in a new thread

    bool thread_running; //if new thread running, for internal use

	TaskFunc task_func; //callback function
	void *func_args;    //arguments pass to callback function

	/* following are internal fields, do not set manually! */
	time_t next_call_time;  
	struct tagScheduleEntry *next;
} ScheduleEntry;

typedef struct
{
	ScheduleEntry *entries;
	int count;
} ScheduleArray;

typedef struct fast_delay_task {
    FastTimerEntry timer;  //must be first field

    bool new_thread;  //run in a new thread

    bool thread_running; //if new thread running, for internal use

	TaskFunc task_func; //callback function
	void *func_args;    //arguments pass to callback function
    struct fast_delay_task *next;
} FastDelayTask;

typedef struct
{
    FastDelayTask *head;
    FastDelayTask *tail;
    pthread_mutex_t lock;
} FastDelayQueue;

typedef struct
{
	ScheduleArray scheduleArray;
	ScheduleEntry *head;  //schedule chain head
    ScheduleEntry *tail;  //schedule chain tail

    struct fast_mblock_man mblock;  //for timer entry
    FastTimer timer;   //for delay task
    bool timer_init;
    FastDelayQueue delay_queue;

	bool *pcontinue_flag;
} ScheduleContext;

#define INIT_SCHEDULE_ENTRY(schedule_entry, _id, _hour, _minute, _second, \
	_interval,  _task_func, _func_args) \
	(schedule_entry).id = _id; \
	(schedule_entry).time_base.hour = _hour;     \
	(schedule_entry).time_base.minute = _minute; \
	(schedule_entry).time_base.second = _second; \
	(schedule_entry).interval = _interval;   \
	(schedule_entry).task_func = _task_func; \
	(schedule_entry).new_thread = false;     \
	(schedule_entry).func_args = _func_args

#define INIT_SCHEDULE_ENTRY_EX(schedule_entry, _id, _time_base, \
	_interval,  _task_func, _func_args) \
	(schedule_entry).id = _id; \
	(schedule_entry).time_base = _time_base; \
	(schedule_entry).interval = _interval;   \
	(schedule_entry).task_func = _task_func; \
	(schedule_entry).new_thread = false;     \
	(schedule_entry).func_args = _func_args

#ifdef __cplusplus
extern "C" {
#endif

extern volatile bool g_schedule_flag; //schedule continue running flag
extern volatile time_t g_current_time;  //the current time


#define get_current_time() (g_schedule_flag ? g_current_time: time(NULL))

/** generate next id
 * return: next id
*/
uint32_t sched_generate_next_id();

/** add schedule entries
 *  parameters:
 *  	     pScheduleArray: the schedule tasks
 * return: error no, 0 for success, != 0 fail
 * Note: you should call this function after sched_start
*/
int sched_add_entries(const ScheduleArray *pScheduleArray);

/** delete a schedule entry
 *  parameters:
 *  	     id: the task id to delete
 * return: error no, 0 for success, != 0 fail
*/
int sched_del_entry(const int id);

//to enable delay tasks feature
#define sched_enable_delay_task() sched_set_delay_params(0, 0)

/** set dalay parameters
 *  parameters:
 *  	     slot_count: the slot count
 *  	     alloc_once: alloc delay task entry once
 * return: none
*/
void sched_set_delay_params(const int slot_count, const int alloc_once);

/** add a delay task
 *  parameters:
 *  	     pContext: the ScheduleContext pointer
 *  	     task_func: the task function pointer
 *  	     func_args: the task function args pointer
 *  	     delay_seconds: delay seconds to execute the task
 *  	     new_thread: if execute the task in a new thread
 * return: error no, 0 for success, != 0 fail
*/
int sched_add_delay_task_ex(ScheduleContext *pContext, TaskFunc task_func,
        void *func_args, const int delay_seconds, const bool new_thread);

int sched_add_delay_task(TaskFunc task_func, void *func_args,
        const int delay_seconds, const bool new_thread);

/** execute the schedule thread
 *  parameters:
 *  	     pScheduleArray: the schedule tasks
 *  	     ptid: store the schedule thread id
 *  	     stack_size: set thread stack size (byes)
 *  	     pcontinue_flag: main process continue running flag
 *  	     ppContext: store the ScheduleContext pointer 
 * return: error no, 0 for success, != 0 fail
*/
int sched_start_ex(ScheduleArray *pScheduleArray, pthread_t *ptid,
		const int stack_size, bool * volatile pcontinue_flag,
        ScheduleContext **ppContext);

int sched_start(ScheduleArray *pScheduleArray, pthread_t *ptid, \
		const int stack_size, bool * volatile pcontinue_flag);


/** print all schedule entries for debug
 * return: none
*/
void sched_print_all_entries();

#ifdef __cplusplus
}
#endif

#endif
