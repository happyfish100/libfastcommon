/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//uniq_skiplist.h

#ifndef _UNIQ_SKIPLIST_H
#define _UNIQ_SKIPLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"
#include "skiplist_common.h"
#include "fast_mblock.h"

typedef void (*uniq_skiplist_free_func)(void *ptr, const int delay_seconds);

typedef struct uniq_skiplist_node
{
    void *data;
    int level_index;
    volatile struct uniq_skiplist_node *links[0];
} UniqSkiplistNode;

typedef struct uniq_skiplist_factory
{
    int max_level_count;
    int delay_free_seconds;
    skiplist_compare_func compare_func;
    uniq_skiplist_free_func free_func;
    struct fast_mblock_man skiplist_allocator;
    struct fast_mblock_man *node_allocators;
} UniqSkiplistFactory;

typedef struct uniq_skiplist
{
    UniqSkiplistFactory *factory;
    int top_level_index;
    int element_count;
    UniqSkiplistNode *top;   //the top node
    UniqSkiplistNode *tail;  //the tail node for interator
} UniqSkiplist;

typedef struct uniq_skiplist_iterator {
    volatile UniqSkiplistNode *current;
    volatile UniqSkiplistNode *tail;
} UniqSkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define uniq_skiplist_init(factory, max_level_count, compare_func, free_func) \
    uniq_skiplist_init_ex(factory, max_level_count,  \
            compare_func, free_func, 64 * 1024, \
            SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE, 0)

int uniq_skiplist_init_ex(UniqSkiplistFactory *factory,
        const int max_level_count, skiplist_compare_func compare_func,
        uniq_skiplist_free_func free_func, const int alloc_skiplist_once,
        const int min_alloc_elements_once, const int delay_free_seconds);

void uniq_skiplist_destroy(UniqSkiplistFactory *factory);

UniqSkiplist *uniq_skiplist_new(UniqSkiplistFactory *factory,
        const int level_count);

void uniq_skiplist_free(UniqSkiplist *sl);

int uniq_skiplist_insert(UniqSkiplist *sl, void *data);
int uniq_skiplist_delete(UniqSkiplist *sl, void *data);
void *uniq_skiplist_find(UniqSkiplist *sl, void *data);
int uniq_skiplist_find_all(UniqSkiplist *sl, void *data,
        UniqSkiplistIterator *iterator);
int uniq_skiplist_find_range(UniqSkiplist *sl, void *start_data,
        void *end_data, UniqSkiplistIterator *iterator);

static inline void uniq_skiplist_iterator(UniqSkiplist *sl, UniqSkiplistIterator *iterator)
{
    iterator->current = sl->top->links[0];
    iterator->tail = sl->tail;
}

static inline void *uniq_skiplist_next(UniqSkiplistIterator *iterator)
{
    void *data;

    if (iterator->current == iterator->tail) {
        return NULL;
    }

    data = iterator->current->data;
    iterator->current = iterator->current->links[0];
    return data;
}

static inline bool uniq_skiplist_empty(UniqSkiplist *sl)
{
    return sl->top->links[0] == sl->tail;
}

#ifdef __cplusplus
}
#endif

#endif

