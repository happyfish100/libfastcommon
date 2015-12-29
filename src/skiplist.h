/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//skiplist.h, support stable sort  :)
#ifndef _SKIPLIST_H
#define _SKIPLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"
#include "fast_mblock.h"

typedef int (*skiplist_compare_func)(const void *p1, const void *p2);
typedef void (*skiplist_free_func)(void *ptr);

typedef struct skiplist_node
{
    void *data;
    struct skiplist_node *prev;   //for stable sort
    struct skiplist_node *links[0];
} SkiplistNode;

typedef struct skiplist
{
    int level_count;
    int top_level_index;
    skiplist_compare_func compare_func;
    skiplist_free_func free_func;
    struct fast_mblock_man *mblocks;  //node allocators
    SkiplistNode *top;   //the top node
    SkiplistNode *tail;  //the tail node for interator
} Skiplist;

typedef struct skiplist_iterator {
    SkiplistNode *top;
    SkiplistNode *current;
} SkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE 128

#define skiplist_init(sl, level_count, compare_func, free_func) \
    skiplist_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE)

int skiplist_init_ex(Skiplist *sl, const int level_count,
        skiplist_compare_func compare_func, skiplist_free_func free_func,
        const int min_alloc_elements_once);

void skiplist_destroy(Skiplist *sl);

int skiplist_insert(Skiplist *sl, void *data);
int skiplist_delete(Skiplist *sl, void *data);
int skiplist_delete_all(Skiplist *sl, void *data, int *delete_count);
void *skiplist_find(Skiplist *sl, void *data);
int skiplist_find_all(Skiplist *sl, void *data, SkiplistIterator *iterator);

static inline void skiplist_iterator(Skiplist *sl, SkiplistIterator *iterator)
{
    iterator->top = sl->top;
    iterator->current = sl->tail->prev;
}

static inline void *skiplist_next(SkiplistIterator *iterator)
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

