/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//multi_skiplist.h, support stable sort  :)
#ifndef _MULTI_SKIPLIST_H
#define _MULTI_SKIPLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"
#include "fast_mblock.h"
#include "skiplist_common.h"

typedef struct multi_skiplist_data
{
    void *data;
    struct multi_skiplist_data *next;
} MultiSkiplistData;

typedef struct multi_skiplist_node
{
    MultiSkiplistData *head;
    MultiSkiplistData *tail;
    struct multi_skiplist_node *links[0];
} MultiSkiplistNode;

typedef struct multi_skiplist
{
    int level_count;
    int top_level_index;
    skiplist_compare_func compare_func;
    skiplist_free_func free_func;
    struct fast_mblock_man data_mblock; //data node allocators
    struct fast_mblock_man *mblocks;  //node allocators
    MultiSkiplistNode *top;   //the top node
    MultiSkiplistNode *tail;  //the tail node for terminate
} MultiSkiplist;

typedef struct multi_skiplist_iterator {
    MultiSkiplistNode *tail;
    struct {
        MultiSkiplistNode *node;
        MultiSkiplistData *data;
    } current;
} MultiSkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define multi_skiplist_init(sl, level_count, compare_func, free_func) \
    multi_skiplist_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE)

int multi_skiplist_init_ex(MultiSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func,
        skiplist_free_func free_func,
        const int min_alloc_elements_once);

void multi_skiplist_destroy(MultiSkiplist *sl);

int multi_skiplist_insert(MultiSkiplist *sl, void *data);
int multi_skiplist_delete(MultiSkiplist *sl, void *data);
int multi_skiplist_delete_all(MultiSkiplist *sl, void *data, int *delete_count);
void *multi_skiplist_find(MultiSkiplist *sl, void *data);
int multi_skiplist_find_all(MultiSkiplist *sl, void *data,
        MultiSkiplistIterator *iterator);

static inline void multi_skiplist_iterator(MultiSkiplist *sl,
        MultiSkiplistIterator *iterator)
{
    iterator->tail = sl->tail;
    iterator->current.node = sl->top;
    iterator->current.data = NULL;
}

static inline void *multi_skiplist_next(MultiSkiplistIterator *iterator)
{
    void *data;

    if (iterator->current.data == NULL) {
        if (iterator->current.node == iterator->tail ||
                iterator->current.node->links[0] == iterator->tail)
        {
            return NULL;
        }

        iterator->current.node = iterator->current.node->links[0];
        iterator->current.data = iterator->current.node->head;
    }

    data = iterator->current.data->data;
    iterator->current.data = iterator->current.data->next;
    return data;
}

#ifdef __cplusplus
}
#endif

#endif

