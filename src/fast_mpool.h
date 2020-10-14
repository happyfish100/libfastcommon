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
alloc and copy memory from the mpool
parameters:
	mpool: the mpool pointer
	src: the source memory pointer
    len: the length of the source memory
return alloc and duplicate memory pointer, NULL for fail
*/
void *fast_mpool_memdup(struct fast_mpool_man *mpool,
        const void *src, const int len);


/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	src: the source '\0' terminated string
    len: the length of the source string
return alloc and duplicate string pointer, NULL for fail
*/
static inline char *fast_mpool_strdup_ex(struct fast_mpool_man *mpool,
        const char *src, const int len)
{
    return (char *)fast_mpool_memdup(mpool, src, len + 1);
}

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	src: the source '\0' terminated string
    len: the length of the source string
return alloc and duplicate string pointer, NULL for fail
*/
static inline char *fast_mpool_strdup(struct fast_mpool_man *mpool,
        const char *src)
{
    return (char *)fast_mpool_memdup(mpool, src, strlen(src) + 1);
}

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
    len: the length of the source string
return error no, 0 for success, != 0 fail
*/
static inline int fast_mpool_alloc_string_ex(struct fast_mpool_man *mpool,
        string_t *dest, const char *src, const int len)
{
    dest->str = (char *)fast_mpool_memdup(mpool, src, len);
    dest->len = len;
    return dest->str != NULL ? 0 : ENOMEM;
}

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
return error no, 0 for success, != 0 fail
*/
static inline int fast_mpool_alloc_string(struct fast_mpool_man *mpool,
        string_t *dest, const char *src)
{
    int len;
    len = (src != NULL) ? strlen(src) : 0;
    return fast_mpool_alloc_string_ex(mpool, dest, src, len);
}

/**
alloc and copy string from the mpool
parameters:
	mpool: the mpool pointer
	dest: the dest string (return the alloced memory in dest->str)
	src: the source string
return error no, 0 for success, != 0 fail
*/
static inline int fast_mpool_alloc_string_ex2(struct fast_mpool_man *mpool,
        string_t *dest, const string_t *src)
{
    return fast_mpool_alloc_string_ex(mpool, dest, src->str, src->len);
}

/**
get stats
parameters:
	mpool: the mpool pointer
    stats: return the stats
return none
*/
void fast_mpool_stats(struct fast_mpool_man *mpool,
        struct fast_mpool_stats *stats);

/**
log stats info
parameters:
	mpool: the mpool pointer
return none
*/
void fast_mpool_log_stats(struct fast_mpool_man *mpool);

#ifdef __cplusplus
}
#endif

#endif

