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

//flat_skiplist.h, support duplicated entries, and support stable sort  :)
//you should use multi_skiplist with too many duplicated entries

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
    FlatSkiplistNode **tmp_previous;  //thread safe for insert
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
int flat_skiplist_find_range(FlatSkiplist *sl, void *start_data, void *end_data,
        FlatSkiplistIterator *iterator);
void *flat_skiplist_find_ge(FlatSkiplist *sl, void *data);

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

static inline void *flat_skiplist_get_first(FlatSkiplist *sl)
{
    if (sl->top->links[0] != sl->tail) {
        return sl->top->links[0]->data;
    } else {
        return NULL;
    }
}

static inline bool flat_skiplist_empty(FlatSkiplist *sl)
{
    return sl->top->links[0] == sl->tail;
}

typedef const char * (*flat_skiplist_tostring_func)(void *data, char *buff, const int size);

static inline void flat_skiplist_print(FlatSkiplist *sl, flat_skiplist_tostring_func tostring_func)
{
    int i;
    FlatSkiplistNode *current;
    char buff[1024];

    printf("###################\n");
    for (i=sl->top_level_index; i>=0; i--) {
        printf("level %d: ", i);
        current = sl->top->links[i];
        while (current != sl->tail) {
            printf("%s ", tostring_func(current->data, buff, sizeof(buff)));
            current = current->links[i];
        }
        printf("\n");
    }
    printf("###################\n");
    printf("\n");
}

#ifdef __cplusplus
}
#endif

#endif

