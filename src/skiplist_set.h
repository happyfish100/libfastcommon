/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//a set implemented by skiplist, the entry can occur only once

#ifndef _SKIPLIST_SET_H
#define _SKIPLIST_SET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"
#include "skiplist_common.h"
#include "fast_mblock.h"

typedef struct skiplist_set_node
{
    void *data;
    struct skiplist_set_node *links[0];
} SkiplistSetNode;

typedef struct skiplist_set
{
    int level_count;
    int top_level_index;
    skiplist_compare_func compare_func;
    skiplist_free_func free_func;
    struct fast_mblock_man *mblocks;  //node allocators
    SkiplistSetNode *top;   //the top node
    SkiplistSetNode *tail;  //the tail node for interator
    SkiplistSetNode **tmp_previous;  //thread safe for insert
} SkiplistSet;

typedef struct skiplist_set_iterator {
    SkiplistSetNode *tail;
    SkiplistSetNode *current;
} SkiplistSetIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define skiplist_set_init(sl, level_count, compare_func, free_func) \
    skiplist_set_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE)

int skiplist_set_init_ex(SkiplistSet *sl, const int level_count,
        skiplist_compare_func compare_func, skiplist_free_func free_func,
        const int min_alloc_elements_once);

void skiplist_set_destroy(SkiplistSet *sl);

int skiplist_set_insert(SkiplistSet *sl, void *data);
int skiplist_set_delete(SkiplistSet *sl, void *data);
void *skiplist_set_find(SkiplistSet *sl, void *data);
int skiplist_set_find_all(SkiplistSet *sl, void *data, SkiplistSetIterator *iterator);
int skiplist_set_find_range(SkiplistSet *sl, void *start_data, void *end_data,
        SkiplistSetIterator *iterator);

static inline void skiplist_set_iterator(SkiplistSet *sl, SkiplistSetIterator *iterator)
{
    iterator->current = sl->top->links[0];
    iterator->tail = sl->tail;
}

static inline void *skiplist_set_next(SkiplistSetIterator *iterator)
{
    void *data;

    if (iterator->current == iterator->tail) {
        return NULL;
    }

    data = iterator->current->data;
    iterator->current = iterator->current->links[0];
    return data;
}

static inline bool skiplist_set_empty(SkiplistSet *sl)
{
    return sl->top->links[0] == sl->tail;
}

#ifdef __cplusplus
}
#endif

#endif
