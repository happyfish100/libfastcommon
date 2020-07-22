#ifndef FC_THREAD_POOL_H_
#define FC_THREAD_POOL_H_

#include <time.h>
#include <pthread.h>
#include "fast_mblock.h"
#include "pthread_func.h"

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

static inline int fc_thread_pool_dealing_count(FCThreadPool *pool)
{
    return __sync_add_and_fetch(&pool->thread_counts.dealing, 0);
}

static inline int fc_thread_pool_avail_count(FCThreadPool *pool)
{
    return pool->thread_counts.limit -
        __sync_add_and_fetch(&pool->thread_counts.dealing, 0);
}

static inline int fc_thread_pool_running_count(FCThreadPool *pool)
{
    int running_count;

    PTHREAD_MUTEX_LOCK(&pool->lock);
    running_count = pool->thread_counts.running;
    PTHREAD_MUTEX_UNLOCK(&pool->lock);

    return running_count;
}

#ifdef __cplusplus
}
#endif

#endif
