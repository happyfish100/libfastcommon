/**
* Copyright (C) 2008 Seapeak.Xu / xvhfeng@gmail.com
*
* FastLib may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastLib source kit.
* Please visit the FastLib Home Page http://www.csource.org/ for more detail.
**/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "pthread_pool.h"

/*
 *the thread pool
 */
static threadpool_info_t *pool;

/*
 * the thread callback function proxy
 * parameters:
 * 				arg:the thread callback function parameter
 */
static void *callback_proxy(void *arg);

/*
 * push the thread into the pool
 * parameters:
 * 				thread:the thread will push into the poolbool
 * return:
 * 				0:success
 * 				>0 : fail
 */
static int push2pool(thread_info_t *thread);

static void *callback_proxy(void *arg)
{
	thread_info_t* thread = (thread_info_t *) arg;
	while(initialized == pool->state)
	{
		thread->func(thread->arg);

		if(pool == NULL || initialized != pool->state) break;

		pthread_mutex_lock(&thread->mutex_locker);

		if(0 == push2pool(thread))
		{
			pthread_cond_wait(&thread->run_locker,&thread->mutex_locker);
			pthread_mutex_unlock(&thread->mutex_locker);
		}
		else
		{
			pthread_mutex_unlock( &thread->mutex_locker );
			pthread_cond_destroy( &thread->run_locker );
			pthread_mutex_destroy( &thread->mutex_locker );

			free( thread );
			break;
		}
	}

	pthread_mutex_lock(&pool->mutex_locker);
	pool->current_size --;
	if(0 >= pool->current_size) pthread_cond_signal(&pool->empty_locker);
	pthread_mutex_unlock(&pool->mutex_locker);
	return NULL;
}

static int push2pool(thread_info_t *thread)
{
	int result = -1;
	do
	{
		pthread_mutex_lock(&pool->mutex_locker);
		if( pool->current_index < pool->total_size )
		{
			pool->list[ pool->current_index ] = thread;
			pool->current_index++;
			result = 0;

			pthread_cond_signal( &pool->run_locker);

			if( pool->current_index >= pool->current_size )
			{
				pthread_cond_signal( &pool->full_locker );
			}
		}
	}while(0);
	pthread_mutex_unlock(&pool->mutex_locker);

	return result;
}

int threadpool_init(int size)
{
	if(0 >= size)
	{
		return -1;
	}

	pool = (threadpool_info_t *) malloc(sizeof(threadpool_info_t));
	if(NULL == pool)
	{
		return -2;
	}
	memset(pool,0,sizeof(threadpool_info_t));
	pool->state = initializing;
	pool->total_size = size;
	pool->current_size = 0;
	pool->current_index = 0;
	pthread_mutex_init(&pool->mutex_locker,NULL);
	pthread_cond_init(&pool->run_locker,NULL);
	pthread_cond_init(&pool->empty_locker,NULL);
	pthread_cond_init(&pool->full_locker,NULL);

	pool->list = (thread_info_t **) malloc(sizeof(thread_info_t*) * size);
	if(NULL == pool->list)
	{
		pthread_cond_destroy(&pool->run_locker);
		pthread_cond_destroy(&pool->empty_locker);
		pthread_cond_destroy(&pool->full_locker);
		pthread_mutex_destroy(&pool->mutex_locker);
		free(pool);
		return -2;
	}

	pool->state = initialized;
	return 0;
}

int threadpool_run(callback func,void *arg)
{
	if(NULL == pool)
	{
		return -1;
	}

	int result = 0;
	do
	{
		pthread_mutex_lock(&pool->mutex_locker);
		if(NULL == pool || initialized != pool->state) //the pool cannot use
		{
			result = -1;
			break;
		}

		//current size is >= the max pool size and all thread are busy now
		while(pool->current_index <= 0 && pool->current_size >= pool->total_size)
		{
			pthread_cond_wait(&pool->run_locker,&pool->mutex_locker);
		}

		if(0 >= pool->current_index)
		{
			thread_info_t * thread = (thread_info_t *) malloc(sizeof(thread_info_t));
			if(NULL == thread)
			{
				result = -2;
				break;
			}
			memset(thread,0,sizeof(thread_info_t));

			pthread_mutex_init(&thread->mutex_locker,NULL);
			pthread_cond_init(&thread->run_locker,NULL);
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);

			thread->arg = arg;
			thread->func = func;

			if(0 == pthread_create(&thread->id,&attr,callback_proxy,thread))
			{
				pool->current_size ++;
			}
			else
			{
				result = -3;
				pthread_mutex_destroy(&thread->mutex_locker);
				pthread_cond_destroy(&thread->run_locker);
				free(thread);
			}
			break;
		}
		else
		{
			pool->current_index --;//because the array begin with 0
			thread_info_t *thread = pool->list[ pool->current_index ];
			pool->list[ pool->current_index ] = NULL;

			thread->func = func;
			thread->arg = arg;

			pthread_mutex_lock( &thread->mutex_locker );
			pthread_cond_signal( &thread->run_locker ) ;
			pthread_mutex_unlock ( &thread->mutex_locker );
		}
	}while(0);
	pthread_mutex_unlock(&pool->mutex_locker);
	return result;

	return 0;
}

int threadpool_free()
{
		if(NULL == pool) return 0;

		pthread_mutex_lock( &pool->mutex_locker);

		if( pool->current_index < pool->current_size )
		{
			pthread_cond_wait( &pool->full_locker, &pool->mutex_locker );
		}

		pool->state = uninstalling;
		int i = 0;
		for( i = 0; i < pool->current_index; i++ )
		{
			thread_info_t *thread = pool->list[i];

			pthread_mutex_lock( &thread->mutex_locker );
			pthread_cond_signal( &thread->run_locker ) ;
			pthread_mutex_unlock ( &thread->mutex_locker );
		}

		if(0 <  pool->current_size)
		{
			pthread_cond_wait( &pool->empty_locker, &pool->mutex_locker);
		}

		for( i = 0; i < pool->current_index; i++ )
		{
			free( pool->list[ i ] );
			pool->list[ i ] = NULL;
		}

		pthread_mutex_unlock( &pool->mutex_locker );

		pool->current_index = 0;

		pthread_mutex_destroy( &pool->mutex_locker );
		pthread_cond_destroy( &pool->run_locker );
		pthread_cond_destroy( &pool->full_locker );
		pthread_cond_destroy( &pool->empty_locker );

		free( pool->list );
		pool->list = NULL;
		free( pool);
		pool = NULL;
		return 0;
}
