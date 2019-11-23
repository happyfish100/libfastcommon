/**
* Copyright (C) 2008 Seapeak.Xu / xvhfeng@gmail.com
*
* FastLib may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastLib source kit.
* Please visit the FastLib Home Page http://www.fastken.com/ for more detail.
**/

#ifndef PTHREAD_POOL_H_
#define PTHREAD_POOL_H_

#include <pthread.h>

/*
 * define the callback function type of thread
 */
typedef void (*callback)(void *);


/*
 * the thread pool state
 * member:
 * 			uninitialized : not initialize the thread pool.
 * 			initializing : initializing the thread pool.
 * 			initialized : the pool can use.
 * 			uninstalling : uninstalling the thread pool.
 * 			uninstalled : uninstall the thread pool is over.
 */
typedef enum threadpool_state
{
	uninitialized,
	initializing,
	initialized,
	uninstalling,
	uninstalled,
}thread_state_t;


/*
 * define the thread type which in the pool
 * members:
 * 			id : the thread id
 * 			mutex_locker : the  mutext locker
 * 			run_locker : the locker for noticing the thread do running or waitting
 * 			func : the callback function for thread
 * 			arg : the callback parameter
 */
typedef struct thread_info
{
	pthread_t id;
	pthread_mutex_t mutex_locker;
	pthread_cond_t run_locker;
	callback func;
	void *arg;
}thread_info_t;

/*
 * the structure for the thread pool
 * member:
 * 			list : the initialazed thread list
 * 			mutex_locker : the mutex locker for the thread operation.
 * 			run_locker : the locker for noticing the thread do running or waitting.
 * 			full_locker : the locker notice the thread is stoping when free the thread pool and the pool is not full .
 * 			empty_Locker : the locker notice the thread waitting for the busy thread work over,then do with the thread.
 * 			state : the pool's current state.
 *          total_size : the pool max size;
 *          current_size : the thread count for the current pool ;
 *          current_index : the busy thread in the  pool index.
 */
typedef struct threadpool_info
{
	thread_info_t **list;
	pthread_mutex_t mutex_locker;
	pthread_cond_t run_locker;
	pthread_cond_t full_locker;
	pthread_cond_t empty_locker;
	thread_state_t state;
	int total_size;
	int current_size;
	int current_index;
}threadpool_info_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * initialize the thread pool
 * parameters:
 * 				size : thread pool max size
 * return:
 * 				0:initialize pool success;
 * 				-1:the size parameter is less 0;
 * 				-2:initialize pool is fail,malloc memory for pool or pool->list is error;
 */
int threadpool_init(int size);

/*
 * run the function with the thread from pool
 * parameter:
 * 				func:the thread callback function
 * 				arg:the parameter of callback function
 * return:
 * 				0 : success
 * 				-1: the pool is NULL;
 * 				-2 : malloc memory for thread is error;
 * 				-3 : create thread is error;
 */
int threadpool_run(callback func,void *arg);

/*
 * free and destroy the thread pool memory
 * return:
 * 				0 : success
 * 				less 0 : fail
 */
int threadpool_destroy();

#ifdef __cplusplus
}
#endif

#endif /* PTHREAD_POOL_H_ */
