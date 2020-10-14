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

static inline void *skiplist_set_get_first(SkiplistSet *sl)
{
    if (sl->top->links[0] != sl->tail) {
        return sl->top->links[0]->data;
    } else {
        return NULL;
    }
}

static inline bool skiplist_set_empty(SkiplistSet *sl)
{
    return sl->top->links[0] == sl->tail;
}

#ifdef __cplusplus
}
#endif

#endif
