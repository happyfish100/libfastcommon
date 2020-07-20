#ifndef FC_THREAD_POOL_H_
#define FC_THREAD_POOL_H_

#include <time.h>
#include <pthread.h>
#include "fast_mblock.h"

typedef void (*fc_thread_pool_callback)(void *arg);

struct fc_thread_pool;
typedef struct fc_thread_info
{
    volatile int inited;
    int index;
    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    fc_thread_pool_callback func;
    void *arg;
    struct fc_thread_pool *pool;
    struct fc_thread_info *next;
} FCThreadInfo;

typedef struct fc_thread_pool
{
	FCThreadInfo *threads;  //all thread info
	FCThreadInfo *freelist;
	pthread_mutex_t lock;
	pthread_cond_t cond;

    int stack_size;
    int max_idle_time;   //in seconds
    int min_idle_count;
    struct {
        int limit;
        volatile int running;  //running thread count
        volatile int dealing;  //dealing task thread count
    } thread_counts;
    bool * volatile pcontinue_flag;
} FCThreadPool;

#ifdef __cplusplus
extern "C" {
#endif

int fc_thread_pool_init(FCThreadPool *pool, const int limit,
        const int stack_size, const int max_idle_time,
        const int min_idle_count, bool * volatile pcontinue_flag);

void fc_thread_pool_destroy(FCThreadPool *pool);

int fc_thread_pool_run(FCThreadPool *pool, fc_thread_pool_callback func,
        void *arg);

#ifdef __cplusplus
}
#endif

#endif
