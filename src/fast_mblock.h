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

//fast_mblock.h

#ifndef _FAST_MBLOCK_H
#define _FAST_MBLOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "fc_memory.h"
#include "logger.h"

/* following two macros for debug only */
/*
#define FAST_MBLOCK_MAGIC_CHECK    1
#define FAST_MBLOCK_MAGIC_NUMBER   1234567890
*/


#define FAST_MBLOCK_NAME_SIZE 32

#define FAST_MBLOCK_ORDER_BY_ALLOC_BYTES    1
#define FAST_MBLOCK_ORDER_BY_ELEMENT_SIZE   2
#define FAST_MBLOCK_ORDER_BY_USED_RATIO     3

/* free node chain */ 
struct fast_mblock_node
{
    struct fast_mblock_node *next;
    int offset;    //trunk offset
    int recycle_timestamp;
#ifdef FAST_MBLOCK_MAGIC_CHECK
    int index;
    int magic;   //magic number
#endif
    char data[0];   //the data buffer
};

/* malloc chain */
struct fast_mblock_malloc
{
    int64_t ref_count; //refference count
    int alloc_count;   //allocated element count
    int trunk_size;    //trunk bytes
    struct fast_mblock_malloc *prev;
    struct fast_mblock_malloc *next;
};

struct fast_mblock_chain {
	struct fast_mblock_node *head;
	struct fast_mblock_node *tail;
};

/* call by alloc trunk */
typedef int (*fast_mblock_object_init_func)(void *element, void *args);

/* call by free trunk */
typedef void (*fast_mblock_object_destroy_func)(void *element, void *args);

typedef int (*fast_mblock_malloc_trunk_check_func)(
	const int alloc_bytes, void *args);

typedef void (*fast_mblock_malloc_trunk_notify_func)(
	const int alloc_bytes, void *args);

struct fast_mblock_info
{
    char name[FAST_MBLOCK_NAME_SIZE];
    int element_size;         //element size
    int trunk_size;           //trunk size
    int instance_count;       //instance count
    int block_size;
    int64_t element_total_count;  //total element count
    int64_t element_used_count;   //used element count
    int64_t delay_free_elements;  //delay free element count
    int64_t trunk_total_count;    //total trunk count
    int64_t trunk_used_count;     //used trunk count
};

struct fast_mblock_trunks
{
	struct fast_mblock_malloc head; //malloc chain to be freed
};

struct fast_mblock_object_callbacks {
    fast_mblock_object_init_func init_func;
    fast_mblock_object_destroy_func destroy_func;
    void *args;
};

struct fast_mblock_trunk_callbacks
{
    fast_mblock_malloc_trunk_check_func check_func;
    fast_mblock_malloc_trunk_notify_func notify_func;
    void *args;
};

struct fast_mblock_man
{
    struct fast_mblock_info info;
    struct {
        bool need_wait;
        int exceed_log_level;  //for exceed limit
        int once;              //alloc elements once
        int64_t limit;         //<= 0 for no limit
        bool *pcontinue_flag;
    } alloc_elements;
    struct fast_mblock_node *free_chain_head;    //free node chain
    struct fast_mblock_trunks trunks;
    struct fast_mblock_chain delay_free_chain;   //delay free node chain

    struct fast_mblock_object_callbacks object_callbacks;
    struct fast_mblock_trunk_callbacks trunk_callbacks;

    bool need_lock;         //if need mutex lock
    pthread_lock_cond_pair_t lcp;  //for read / write free node chain
    struct fast_mblock_man *prev;  //for stat manager
    struct fast_mblock_man *next;  //for stat manager
};

#define  GET_BLOCK_SIZE(info) \
	(MEM_ALIGN(sizeof(struct fast_mblock_node) + (info).element_size))

#define fast_mblock_get_block_size(mblock) GET_BLOCK_SIZE(mblock->info)

#define fast_mblock_to_node_ptr(data_ptr) \
        (struct fast_mblock_node *)((char *)data_ptr - ((size_t)(char *) \
                    &((struct fast_mblock_node *)0)->data))

#ifdef __cplusplus
extern "C" {
#endif

#define fast_mblock_init(mblock, element_size, alloc_elements_once) \
    fast_mblock_init_ex(mblock, element_size, alloc_elements_once, \
            0, NULL, NULL, true)

/**
mblock init
parameters:
    name: the mblock name
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    alloc_elements_limit: malloc elements limit, <= 0 for no limit
    object_callbacks: the object callback functions and args
    need_lock: if need lock
    trunk_callbacks: the trunk callback functions and args
return error no, 0 for success, != 0 fail
*/
int fast_mblock_init_ex2(struct fast_mblock_man *mblock, const char *name,
        const int element_size, const int alloc_elements_once,
        const int64_t alloc_elements_limit,
        struct fast_mblock_object_callbacks *object_callbacks,
        const bool need_lock, struct fast_mblock_trunk_callbacks
        *trunk_callbacks);

/**
mblock init
parameters:
    name: the mblock name
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    alloc_elements_limit: malloc elements limit, <= 0 for no limit
    init_func: the object init function
    init_args: the args for object init function
    need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
static inline int fast_mblock_init_ex1(struct fast_mblock_man *mblock,
        const char *name, const int element_size,
        const int alloc_elements_once, const int64_t alloc_elements_limit,
        fast_mblock_object_init_func init_func, void *init_args,
        const bool need_lock)
{
    struct fast_mblock_object_callbacks object_callbacks;

    object_callbacks.init_func = init_func;
    object_callbacks.destroy_func = NULL;
    object_callbacks.args = init_args;
    return fast_mblock_init_ex2(mblock, name, element_size,
            alloc_elements_once, alloc_elements_limit,
            &object_callbacks, need_lock, NULL);
}

/**
mblock init
parameters:
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    alloc_elements_limit: malloc elements limit, <= 0 for no limit
    object_callbacks: the object callback functions and args
    need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
static inline int fast_mblock_init_ex(struct fast_mblock_man *mblock,
        const int element_size, const int alloc_elements_once,
        const int64_t alloc_elements_limit,
        fast_mblock_object_init_func init_func, void *init_args,
        const bool need_lock)
{
    return fast_mblock_init_ex1(mblock, NULL, element_size,
            alloc_elements_once, alloc_elements_limit,
            init_func, init_args, need_lock);
}


/**
mblock destroy
parameters:
	mblock: the mblock pointer
*/
void fast_mblock_destroy(struct fast_mblock_man *mblock);

static inline int fast_mblock_set_need_wait(struct fast_mblock_man *mblock,
        const bool need_wait, bool * volatile pcontinue_flag)
{
    if (!mblock->need_lock || mblock->alloc_elements.limit <= 0)
    {
        logError("file: "__FILE__", line: %d, "
                "need_lock: %d != 1 or alloc_elements.limit: %"PRId64" <= 0",
                __LINE__, mblock->need_lock, mblock->alloc_elements.limit);
        return EINVAL;
    }

    mblock->alloc_elements.need_wait = need_wait;
    mblock->alloc_elements.pcontinue_flag = pcontinue_flag;
    if (need_wait)
    {
        mblock->alloc_elements.exceed_log_level = LOG_NOTHING;
    }
    return 0;
}

/**
alloc a node from the mblock
parameters:
	mblock: the mblock pointer
return the alloced node, return NULL if fail
*/
struct fast_mblock_node *fast_mblock_alloc(struct fast_mblock_man *mblock);

/**
free a node (put a node to the mblock)
parameters:
	mblock: the mblock pointer
	pNode: the node to free
return 0 for success, return none zero if fail
*/
int fast_mblock_free(struct fast_mblock_man *mblock,
		     struct fast_mblock_node *pNode);

/**
batch alloc nodes from the mblock
parameters:
	mblock: the mblock pointer
    count: alloc count
    chain: return the mblock node chain
return 0 for success, return none zero if fail
*/
int fast_mblock_batch_alloc(struct fast_mblock_man *mblock,
        const int count, struct fast_mblock_chain *chain);

/**
batch alloc nodes from the mblock
parameters:
	mblock: the mblock pointer
    count: alloc count
return the alloced node head, return NULL if fail
*/
static inline struct fast_mblock_node *fast_mblock_batch_alloc1(
        struct fast_mblock_man *mblock, const int count)
{
    struct fast_mblock_chain chain;
    if (fast_mblock_batch_alloc(mblock, count, &chain) == 0) {
        return chain.head;
    } else {
        return NULL;
    }
}

/**
batch free nodes
parameters:
	mblock: the mblock pointer
	chain: the node chain to free
return 0 for success, return none zero if fail
*/
int fast_mblock_batch_free(struct fast_mblock_man *mblock,
        struct fast_mblock_chain *chain);

/**
delay free a node (put a node to the mblock)
parameters:
	mblock: the mblock pointer
	pNode: the node to free
    delay: delay seconds to free
return 0 for success, return none zero if fail
*/
int fast_mblock_delay_free(struct fast_mblock_man *mblock,
		     struct fast_mblock_node *pNode, const int delay);

/**
alloc a object from the mblock
parameters:
	mblock: the mblock pointer
return the alloced object, return NULL if fail
*/
static inline void *fast_mblock_alloc_object(struct fast_mblock_man *mblock)
{
    struct fast_mblock_node *node;
    node = fast_mblock_alloc(mblock);
    if (node == NULL)
    {
        return NULL;
    }
    return node->data;
}

/**
free a object (put the object to the mblock)
parameters:
	mblock: the mblock pointer
	object: the object to free
return 0 for success, return none zero if fail
*/
static inline int fast_mblock_free_object(struct fast_mblock_man *mblock,
        void *object)
{
    return fast_mblock_free(mblock, fast_mblock_to_node_ptr(object));
}

/**
free objects (put objects to the mblock)
parameters:
	mblock: the mblock pointer
	objs:  the object array to free
    count: the count of the object array
return none
*/
void fast_mblock_free_objects(struct fast_mblock_man *mblock,
        void **objs, const int count);

/**
delay free a object (put a node to the mblock)
parameters:
	mblock: the mblock pointer
	pNode: the node to free
    delay: delay seconds to free
return 0 for success, return none zero if fail
*/
static inline int fast_mblock_delay_free_object(struct fast_mblock_man *mblock,
        void *object, const int delay)
{
    return fast_mblock_delay_free(mblock, fast_mblock_to_node_ptr(object), delay);
}

/**
get node count of the mblock
parameters:
	mblock: the mblock pointer
return the free node count of the mblock, return -1 if fail
*/
int fast_mblock_free_count(struct fast_mblock_man *mblock);

/**
get delay free node count of the mblock
parameters:
	mblock: the mblock pointer
return the delay free node count of the mblock, return -1 if fail
*/
int fast_mblock_delay_free_count(struct fast_mblock_man *mblock);

#define fast_mblock_total_count(mblock) (mblock)->total_count

/**
init mblock manager
parameters:
return error no, 0 for success, != 0 fail
*/
int fast_mblock_manager_init();

/**
get mblock stat
parameters:
    stats: return mblock stats
    size: max size of stats
    count: return mblock stat count
return error no, 0 for success, != 0 fail
*/
int fast_mblock_manager_stat(struct fast_mblock_info *stats,
        const int size, int *count);


/**
print mblock manager stat
parameters:
    hide_empty: if hide empty
    order_by: order by which field
return error no, 0 for success, != 0 fail
*/
int fast_mblock_manager_stat_print_ex(const bool hide_empty, const int order_by);

#define fast_mblock_manager_stat_print(hide_empty) \
        fast_mblock_manager_stat_print_ex(hide_empty, FAST_MBLOCK_ORDER_BY_ALLOC_BYTES)

typedef void (*fast_mblock_free_trunks_func)(struct fast_mblock_man *mblock,
        struct fast_mblock_malloc *freelist);

/**
free the trunks
parameters:
	mblock: the mblock pointer
    freelist: the trunks to free
return error no, 0 for success, != 0 fail
*/
void fast_mblock_free_trunks(struct fast_mblock_man *mblock,
        struct fast_mblock_malloc *freelist);

/**
reclaim the free trunks of the mblock
parameters:
    mblock: the mblock pointer
    reclaim_target: reclaim target trunks, 0 for no limit
    reclaim_count: reclaimed trunk count
    freelist: the free trunks
return error no, 0 for success, != 0 fail
*/
int fast_mblock_reclaim(struct fast_mblock_man *mblock,
        const int reclaim_target, int *reclaim_count,
        fast_mblock_free_trunks_func free_trunks_func);

#ifdef __cplusplus
}
#endif

#endif

