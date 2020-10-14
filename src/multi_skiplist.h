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

//multi_skiplist.h, support duplicated entries, and support stable sort  :)

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
    MultiSkiplistNode **tmp_previous;  //thread safe for insert
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
int multi_skiplist_find_range(MultiSkiplist *sl, void *start_data, void *end_data,
        MultiSkiplistIterator *iterator);
void *multi_skiplist_find_ge(MultiSkiplist *sl, void *data);

static inline void multi_skiplist_iterator(MultiSkiplist *sl,
        MultiSkiplistIterator *iterator)
{
    iterator->tail = sl->tail;
    iterator->current.node = sl->top->links[0];
    if (iterator->current.node != sl->tail) {
        iterator->current.data = iterator->current.node->head;
    }
    else {
        iterator->current.data = NULL;
    }
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

static inline void *multi_skiplist_get_first(MultiSkiplist *sl)
{
    if (sl->top->links[0] != sl->tail) {
        return sl->top->links[0]->head->data;
    } else {
        return NULL;
    }
}

static inline bool multi_skiplist_empty(MultiSkiplist *sl)
{
    return sl->top->links[0] == sl->tail;
}

typedef const char * (*multi_skiplist_tostring_func)(void *data, char *buff, const int size);

static inline void multi_skiplist_print(MultiSkiplist *sl, multi_skiplist_tostring_func tostring_func)
{
    int i;
    MultiSkiplistNode *current;
    char buff[1024];

    printf("###################\n");
    for (i=sl->top_level_index; i>=0; i--) {
        printf("level %d: ", i);
        current = sl->top->links[i];
        while (current != sl->tail) {
            printf("%s ", tostring_func(current->head->data, buff, sizeof(buff)));
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
