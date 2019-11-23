/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//fast_mpool.h

#ifndef _FAST_MPOOL_H
#define _FAST_MPOOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"

/* malloc chain */
struct fast_mpool_malloc
{
	int alloc_size;
    char *base_ptr;
    char *end_ptr;
    char *free_ptr;
	struct fast_mpool_malloc *malloc_next;
	struct fast_mpool_malloc *free_next;
};

struct fast_mpool_man
{
	struct fast_mpool_malloc *malloc_chain_head; //malloc chain to be freed
	struct fast_mpool_malloc *free_chain_head;   //free node chain
	int alloc_size_once;  //alloc size once, default: 1MB
	int discard_size;     //discard size, default: 64 bytes
};

struct fast_mpool_stats
{
    int64_t total_bytes;
    int64_t free_bytes;
    int total_trunk_count;
    int free_trunk_count;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
mpool init
parameters:
	mpool: the mpool pointer
	alloc_size_once: malloc elements once, 0 for malloc 1MB memory once
    discard_size: discard when remain size <= discard_size, 0 for 64 bytes
return error no, 0 for success, != 0 fail
*/
int fast_mpool_init(struct fast_mpool_man *mpool,
		const int alloc_size_once, const int discard_size);

/**
mpool destroy
parameters:
	mpool: the mpool pointer
*/
void fast_mpool_destroy(struct fast_mpool_man *mpool);

/**
reset for recycle use
parameters:
	mpool: the mpool pointer
*/
void fast_mpool_reset(struct fast_mpool_man *mpool);

/**
alloc a node from the mpool
parameters:
	mpool: the mpool pointer
    size: alloc bytes
return the alloced ptr, return NULL if fail
*/
void *fast_mpool_alloc(struct fast_mpool_man *mpool, const int size);


/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
    len: the length of the source string
return error no, 0 for success, != 0 fail
*/
int fast_mpool_strdup_ex(struct fast_mpool_man *mpool, string_t *dest,
        const char *src, const int len);

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
return error no, 0 for success, != 0 fail
*/
static inline int fast_mpool_strdup(struct fast_mpool_man *mpool,
        string_t *dest, const char *src)
{
    int len;
    len = (src != NULL) ? strlen(src) : 0;
    return fast_mpool_strdup_ex(mpool, dest, src, len);
}

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
return error no, 0 for success, != 0 fail
*/
static inline int fast_mpool_strdup2(struct fast_mpool_man *mpool,
        string_t *dest, const string_t *src)
{
    return fast_mpool_strdup_ex(mpool, dest, src->str, src->len);
}

/**
get stats
parameters:
	mpool: the mpool pointer
    stats: return the stats
*/
void fast_mpool_stats(struct fast_mpool_man *mpool, struct fast_mpool_stats *stats);

#ifdef __cplusplus
}
#endif

#endif

