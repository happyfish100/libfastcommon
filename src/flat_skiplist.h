/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//flat_skiplist.h, support stable sort  :)
#ifndef _FLAT_SKIPLIST_H
#define _FLAT_SKIPLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"
#include "skiplist_common.h"
#include "fast_mblock.h"

typedef struct flat_skiplist_node
{
    void *data;
    struct flat_skiplist_node *prev;   //for stable sort
    struct flat_skiplist_node *links[0];
} FlatSkiplistNode;

typedef struct flat_skiplist
{
    int level_count;
    int top_level_index;
    skiplist_compare_func compare_func;
    skiplist_free_func free_func;
    struct fast_mblock_man *mblocks;  //node allocators
    FlatSkiplistNode *top;   //the top node
    FlatSkiplistNode *tail;  //the tail node for interator
} FlatSkiplist;

typedef struct flat_skiplist_iterator {
    FlatSkiplistNode *top;
    FlatSkiplistNode *current;
} FlatSkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define flat_skiplist_init(sl, level_count, compare_func, free_func) \
    flat_skiplist_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE)

int flat_skiplist_init_ex(FlatSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func, skiplist_free_func free_func,
        const int min_alloc_elements_once);

void flat_skiplist_destroy(FlatSkiplist *sl);

int flat_skiplist_insert(FlatSkiplist *sl, void *data);
int flat_skiplist_delete(FlatSkiplist *sl, void *data);
int flat_skiplist_delete_all(FlatSkiplist *sl, void *data, int *delete_count);
void *flat_skiplist_find(FlatSkiplist *sl, void *data);
int flat_skiplist_find_all(FlatSkiplist *sl, void *data, FlatSkiplistIterator *iterator);

static inline void flat_skiplist_iterator(FlatSkiplist *sl, FlatSkiplistIterator *iterator)
{
    iterator->top = sl->top;
    iterator->current = sl->tail->prev;
}

static inline void *flat_skiplist_next(FlatSkiplistIterator *iterator)
{
    void *data;

    if (iterator->current == iterator->top) {
        return NULL;
    }

    data = iterator->current->data;
    iterator->current = iterator->current->prev;
    return data;
}

#ifdef __cplusplus
}
#endif

#endif

