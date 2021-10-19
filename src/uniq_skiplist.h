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
    bool bidirection;       //if need reverse iteration for level 0
    skiplist_compare_func compare_func;
    uniq_skiplist_free_func free_func;
    UniqSkiplistNode *tail;  //the tail node for interator
    struct fast_mblock_man skiplist_allocator;
    struct fast_mblock_man *node_allocators;
} UniqSkiplistFactory;

typedef struct uniq_skiplist
{
    UniqSkiplistFactory *factory;
    int top_level_index;
    int element_count;
    UniqSkiplistNode *top;  //the top node
} UniqSkiplist;

typedef struct uniq_skiplist_pair {
    UniqSkiplistFactory factory;
    struct uniq_skiplist *skiplist;
} UniqSkiplistPair;

typedef struct uniq_skiplist_iterator {
    volatile UniqSkiplistNode *current;
    volatile UniqSkiplistNode *tail;
} UniqSkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define uniq_skiplist_count(sl) (sl)->element_count

#define uniq_skiplist_init_ex(factory, max_level_count, compare_func, \
        free_func, alloc_skiplist_once, min_alloc_elements_once, \
        delay_free_seconds) \
    uniq_skiplist_init_ex2(factory, max_level_count, compare_func, \
        free_func, alloc_skiplist_once, min_alloc_elements_once, \
        delay_free_seconds, false, false)

#define uniq_skiplist_init(factory, max_level_count, compare_func, free_func) \
    uniq_skiplist_init_ex(factory, max_level_count,  \
            compare_func, free_func, 64 * 1024, \
            SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE, 0)

#define uniq_skiplist_init_pair(pair, init_level_count, max_level_count, \
        compare_func, free_func, min_alloc_elements_once, delay_free_seconds) \
    uniq_skiplist_init_pair_ex(pair, init_level_count, max_level_count, \
            compare_func, free_func, min_alloc_elements_once, \
            delay_free_seconds, false)

#define uniq_skiplist_delete(sl, data)  \
    uniq_skiplist_delete_ex(sl, data, true)

#define uniq_skiplist_delete_node(sl, previous, node)  \
    uniq_skiplist_delete_node_ex(sl, previous, node, true)

#define uniq_skiplist_replace(sl, data) \
    uniq_skiplist_replace_ex(sl, data, true)


int uniq_skiplist_init_ex2(UniqSkiplistFactory *factory,
        const int max_level_count, skiplist_compare_func compare_func,
        uniq_skiplist_free_func free_func, const int alloc_skiplist_once,
        const int min_alloc_elements_once, const int delay_free_seconds,
        const bool bidirection, const bool allocator_use_lock);

void uniq_skiplist_destroy(UniqSkiplistFactory *factory);

UniqSkiplist *uniq_skiplist_new(UniqSkiplistFactory *factory,
        const int level_count);

void uniq_skiplist_free(UniqSkiplist *sl);

static inline int uniq_skiplist_init_pair_ex(UniqSkiplistPair *pair,
        const int init_level_count, const int max_level_count,
        skiplist_compare_func compare_func, uniq_skiplist_free_func
        free_func, const int min_alloc_elements_once,
        const int delay_free_seconds, const bool bidirection)
{
    const int alloc_skiplist_once = 1;
    const bool allocator_use_lock = false;
    int result;

    if ((result=uniq_skiplist_init_ex2(&pair->factory, max_level_count,
                    compare_func, free_func, alloc_skiplist_once,
                    min_alloc_elements_once, delay_free_seconds,
                    bidirection, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((pair->skiplist=uniq_skiplist_new(&pair->factory,
                    init_level_count)) == NULL)
    {
        uniq_skiplist_destroy(&pair->factory);
        return ENOMEM;
    }

    return 0;
}

static inline UniqSkiplist *uniq_skiplist_new_by_pair(
        UniqSkiplistPair *pair, const int level_count)
{
    if (pair->skiplist == NULL) {
        pair->skiplist = uniq_skiplist_new(&pair->factory, level_count);
    }

    return pair->skiplist;
}

static inline void uniq_skiplist_free_by_pair(UniqSkiplistPair *pair)
{
    if (pair->skiplist != NULL) {
        uniq_skiplist_free(pair->skiplist);
        pair->skiplist = NULL;
    }
}

int uniq_skiplist_insert(UniqSkiplist *sl, void *data);
int uniq_skiplist_delete_ex(UniqSkiplist *sl, void *data,
        const bool need_free);
int uniq_skiplist_replace_ex(UniqSkiplist *sl, void *data,
        const bool need_free_old);
void *uniq_skiplist_find(UniqSkiplist *sl, void *data);
int uniq_skiplist_find_all(UniqSkiplist *sl, void *data,
        UniqSkiplistIterator *iterator);
int uniq_skiplist_find_range(UniqSkiplist *sl, void *start_data,
        void *end_data, UniqSkiplistIterator *iterator);

UniqSkiplistNode *uniq_skiplist_find_node(UniqSkiplist *sl, void *data);

UniqSkiplistNode *uniq_skiplist_find_node_ex(UniqSkiplist *sl, void *data,
        UniqSkiplistNode **previous);

void uniq_skiplist_delete_node_ex(UniqSkiplist *sl,
        UniqSkiplistNode *previous, UniqSkiplistNode *deleted,
        const bool need_free);

UniqSkiplistNode *uniq_skiplist_find_ge_node(UniqSkiplist *sl, void *data);

static inline void *uniq_skiplist_find_ge(UniqSkiplist *sl, void *data)
{
    UniqSkiplistNode *node;
    node = uniq_skiplist_find_ge_node(sl, data);
    if (node == NULL) {
        return NULL;
    }

    return node->data;
}

static inline void uniq_skiplist_iterator(UniqSkiplist *sl,
        UniqSkiplistIterator *iterator)
{
    iterator->current = sl->top->links[0];
    iterator->tail = sl->factory->tail;
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

static inline void uniq_skiplist_iterator_at(UniqSkiplist *sl,
        const int offset, UniqSkiplistIterator *iterator)
{
    int i;

    iterator->current = sl->top->links[0];
    iterator->tail = sl->factory->tail;

    i = 0;
    while (i++ < offset && iterator->current != iterator->tail) {
        iterator->current = iterator->current->links[0];
    }
}

static inline int uniq_skiplist_iterator_count(UniqSkiplistIterator *iterator)
{
    volatile UniqSkiplistNode *current;
    int count;

    count = 0;
    current = iterator->current;
    while (current != iterator->tail) {
        ++count;
        current = current->links[0];
    }

    return count;
}

static inline void *uniq_skiplist_get_first(UniqSkiplist *sl)
{
    if (sl->top->links[0] != sl->factory->tail) {
        return sl->top->links[0]->data;
    } else {
        return NULL;
    }
}

static inline bool uniq_skiplist_empty(UniqSkiplist *sl)
{
    return sl->top->links[0] == sl->factory->tail;
}

#define LEVEL0_DOUBLE_CHAIN_NEXT_LINK(node)  node->links[0]
#define LEVEL0_DOUBLE_CHAIN_PREV_LINK(node)  node->links[node->level_index + 1]
#define LEVEL0_DOUBLE_CHAIN_TAIL(sl)  LEVEL0_DOUBLE_CHAIN_PREV_LINK(sl->top)

#define UNIQ_SKIPLIST_LEVEL0_TAIL_NODE(sl)    ((UniqSkiplistNode *) \
        LEVEL0_DOUBLE_CHAIN_TAIL(sl))

#define UNIQ_SKIPLIST_LEVEL0_PREV_NODE(node)  ((UniqSkiplistNode *) \
        LEVEL0_DOUBLE_CHAIN_PREV_LINK(node))

#define UNIQ_SKIPLIST_LEVEL0_NEXT_NODE(node)  ((UniqSkiplistNode *) \
        LEVEL0_DOUBLE_CHAIN_NEXT_LINK(node))

#ifdef __cplusplus
}
#endif

#endif
