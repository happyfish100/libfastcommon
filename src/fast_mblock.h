/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//fast_mblock.h

#ifndef _FAST_MBLOCK_H
#define _FAST_MBLOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "chain.h"

#define FAST_MBLOCK_NAME_SIZE 32

#define FAST_MBLOCK_ORDER_BY_ALLOC_BYTES    1
#define FAST_MBLOCK_ORDER_BY_ELEMENT_SIZE   2

/* free node chain */ 
struct fast_mblock_node
{
    struct fast_mblock_node *next;
    int offset;    //trunk offset
    int recycle_timestamp;
    char data[0];   //the data buffer
};

/* malloc chain */
struct fast_mblock_malloc
{
    int64_t ref_count;  //refference count
    struct fast_mblock_malloc *prev;
    struct fast_mblock_malloc *next;
};

struct fast_mblock_chain {
	struct fast_mblock_node *head;
	struct fast_mblock_node *tail;
};

typedef int (*fast_mblock_alloc_init_func)(void *element, void *args);

typedef int (*fast_mblock_malloc_trunk_check_func)(
	const int alloc_bytes, void *args);

typedef void (*fast_mblock_malloc_trunk_notify_func)(
	const int alloc_bytes, void *args);

struct fast_mblock_info
{
    char name[FAST_MBLOCK_NAME_SIZE];
    int element_size;         //element size
    int element_total_count;  //total element count
    int element_used_count;   //used element count
    int trunk_size;           //trunk size
    int trunk_total_count;    //total trunk count
    int trunk_used_count;     //used trunk count
    int instance_count;       //instance count
};

struct fast_mblock_trunks
{
	struct fast_mblock_malloc head; //malloc chain to be freed
};

struct fast_mblock_malloc_trunk_callback
{
    fast_mblock_malloc_trunk_check_func check_func;
    fast_mblock_malloc_trunk_notify_func notify_func;
    void *args;
};

struct fast_mblock_man
{
    struct fast_mblock_info info;
    int alloc_elements_once;  //alloc elements once
    struct fast_mblock_node *free_chain_head;    //free node chain
    struct fast_mblock_trunks trunks;
    struct fast_mblock_chain delay_free_chain;   //delay free node chain

    fast_mblock_alloc_init_func alloc_init_func;
    struct fast_mblock_malloc_trunk_callback malloc_trunk_callback;

    bool need_lock;           //if need mutex lock
    pthread_mutex_t lock;     //the lock for read / write free node chain
    struct fast_mblock_man *prev;  //for stat manager
    struct fast_mblock_man *next;  //for stat manager
    void *init_args;          //args for alloc_init_func
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
    fast_mblock_init_ex(mblock, element_size, alloc_elements_once,  \
            NULL, NULL, true)

/**
mblock init
parameters:
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    init_func: the init function
    init_args: the args for init_func
    need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
int fast_mblock_init_ex(struct fast_mblock_man *mblock,
        const int element_size, const int alloc_elements_once,
        fast_mblock_alloc_init_func init_func, void *init_args,
        const bool need_lock);

/**
mblock init
parameters:
    name: the mblock name
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    init_func: the init function
    init_args: the args for init_func
    need_lock: if need lock
    malloc_trunk_check: the malloc trunk check function pointor
    malloc_trunk_notify: the malloc trunk notify function pointor
    malloc_trunk_args: the malloc trunk args
return error no, 0 for success, != 0 fail
*/
int fast_mblock_init_ex2(struct fast_mblock_man *mblock, const char *name,
        const int element_size, const int alloc_elements_once,
        fast_mblock_alloc_init_func init_func,
        void *init_args, const bool need_lock,
        fast_mblock_malloc_trunk_check_func malloc_trunk_check,
        fast_mblock_malloc_trunk_notify_func malloc_trunk_notify,
        void *malloc_trunk_args);

/**
mblock init
parameters:
    name: the mblock name
    mblock: the mblock pointer
    element_size: element size, such as sizeof(struct xxx)
    alloc_elements_once: malloc elements once, 0 for malloc 1MB memory once
    init_func: the init function
    init_args: the args for init_func
    need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
static inline int fast_mblock_init_ex1(struct fast_mblock_man *mblock,
        const char *name, const int element_size, const int alloc_elements_once,
        fast_mblock_alloc_init_func init_func,
        void *init_args, const bool need_lock)
{
    return fast_mblock_init_ex2(mblock, name, element_size,
            alloc_elements_once, init_func, init_args,
            need_lock, NULL, NULL, NULL);
}

/**
mblock destroy
parameters:
	mblock: the mblock pointer
*/
void fast_mblock_destroy(struct fast_mblock_man *mblock);

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

