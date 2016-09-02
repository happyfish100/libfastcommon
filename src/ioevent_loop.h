#ifndef _IOEVENT_LOOP_H
#define _IOEVENT_LOOP_H

#include "fast_task_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

int ioevent_loop(struct nio_thread_data *pThreadData,
	IOEventCallback recv_notify_callback, TaskCleanUpCallback
	clean_up_callback, volatile bool *continue_flag);

//remove entry from ready list
int ioevent_remove(IOEventPoller *ioevent, void *data);

int ioevent_set(struct fast_task_info *pTask, struct nio_thread_data *pThread,
	int sock, short event, IOEventCallback callback, const int timeout);

void iovent_add_to_deleted_list(struct fast_task_info *pTask);

#ifdef __cplusplus
}
#endif

#endif

