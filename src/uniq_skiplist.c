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

//uniq_skiplist.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "logger.h"
#include "fc_memory.h"
#include "uniq_skiplist.h"

static int best_element_counts[SKIPLIST_MAX_LEVEL_COUNT] = {0};

#define UNIQ_SKIPLIST_FREE_MBLOCK_OBJECT(sl, level_index, deleted) \
    do { \
        if (sl->factory->delay_free_seconds > 0) { \
            fast_mblock_delay_free_object(sl->factory->node_allocators + \
                    level_index, (void *)deleted, \
                    sl->factory->delay_free_seconds); \
        } else {  \
            fast_mblock_free_object(sl->factory->node_allocators + \
                    level_index, (void *)deleted);  \
        } \
    } while (0)

static void init_best_element_counts()
{
    int i;
    int element_count;

    element_count = 1;
    for (i=0; i<SKIPLIST_MAX_LEVEL_COUNT; i++) {
        element_count *= 2;
        best_element_counts[i] = element_count;
    }
}

int uniq_skiplist_init_ex2(UniqSkiplistFactory *factory,
        const int max_level_count, skiplist_compare_func compare_func,
        uniq_skiplist_free_func free_func, const int alloc_skiplist_once,
        const int min_alloc_elements_once, const int delay_free_seconds,
        const bool bidirection, const bool allocator_use_lock)
{
    const int64_t alloc_elements_limit = 0;
    char name[64];
    int bytes;
    int element_size;
    int i;
    int extra_links_count;
    int alloc_elements_once;
    int result;

    if (best_element_counts[0] == 0) {
        init_best_element_counts();
    }

    if (max_level_count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid max level count: %d",
                __LINE__, max_level_count);
        return EINVAL;
    }

    if (max_level_count > SKIPLIST_MAX_LEVEL_COUNT) {
        logError("file: "__FILE__", line: %d, "
                "max level count: %d is too large, exceeds %d",
                __LINE__, max_level_count, SKIPLIST_MAX_LEVEL_COUNT);
        return E2BIG;
    }

    bytes = sizeof(struct fast_mblock_man) * max_level_count;
    factory->node_allocators = (struct fast_mblock_man *)fc_malloc(bytes);
    if (factory->node_allocators == NULL) {
        return ENOMEM;
    }
    memset(factory->node_allocators, 0, bytes);

    alloc_elements_once = min_alloc_elements_once;
    if (alloc_elements_once <= 0) {
        alloc_elements_once = SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE;
    }
    else if (alloc_elements_once > 1024) {
        alloc_elements_once = 1024;
    }

    extra_links_count = bidirection ? 1 : 0;
    for (i=max_level_count-1; i>=0; i--) {
        sprintf(name, "uniq-sl-level%02d", i);
        element_size = sizeof(UniqSkiplistNode) +
            sizeof(UniqSkiplistNode *) * (i + 1 + extra_links_count);
        if ((result=fast_mblock_init_ex1(factory->node_allocators + i,
                        name, element_size, alloc_elements_once,
                        alloc_elements_limit, NULL, NULL,
                        allocator_use_lock)) != 0)
        {
            return result;
        }
        if (i % 2 == 0 && alloc_elements_once < 64 * 1024) {
            alloc_elements_once *= 2;
        }
    }

    if ((result=fast_mblock_init_ex1(&factory->skiplist_allocator,
                    "skiplist", sizeof(UniqSkiplist),
                    alloc_skiplist_once > 0 ?  alloc_skiplist_once :
                    4 * 1024, alloc_elements_limit, NULL, NULL,
                    allocator_use_lock)) != 0)
    {
        return result;
    }

    factory->tail = (UniqSkiplistNode *)fast_mblock_alloc_object(
            factory->node_allocators + 0);
    if (factory->tail == NULL) {
        return ENOMEM;
    }
    memset(factory->tail, 0, factory->node_allocators[0].info.element_size);

    factory->bidirection = bidirection;
    factory->max_level_count = max_level_count;
    factory->compare_func = compare_func;
    factory->free_func = free_func;
    factory->delay_free_seconds = delay_free_seconds;

    srand(time(NULL));
    return 0;
}

void uniq_skiplist_destroy(UniqSkiplistFactory *factory)
{
    int i;

    if (factory->node_allocators == NULL) {
        return;
    }

    fast_mblock_free_object(factory->node_allocators + 0,
            (void *)factory->tail);
    fast_mblock_destroy(&factory->skiplist_allocator);

    for (i=0; i<factory->max_level_count; i++) {
        fast_mblock_destroy(factory->node_allocators + i);
    }

    free(factory->node_allocators);
    factory->node_allocators = NULL;
}

UniqSkiplist *uniq_skiplist_new(UniqSkiplistFactory *factory,
        const int level_count)
{
    UniqSkiplist *sl;
    struct fast_mblock_man *top_mblock;
    int i;

    if (level_count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid level count: %d",
                __LINE__, level_count);
        errno = EINVAL;
        return NULL;
    }

    if (level_count > factory->max_level_count) {
        logError("file: "__FILE__", line: %d, "
                "level count: %d is too large, "
                "exceeds max level count: %d",
                __LINE__, level_count, factory->max_level_count);
        errno = E2BIG;
        return NULL;
    }

    sl = (UniqSkiplist *)fast_mblock_alloc_object(
            &factory->skiplist_allocator);
    sl->element_count = 0;
    sl->factory = factory;

    sl->top_level_index = level_count - 1;
    top_mblock = sl->factory->node_allocators + sl->top_level_index;
    sl->top = (UniqSkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memset(sl->top, 0, top_mblock->info.element_size);
    sl->top->level_index = sl->top_level_index;
    if (sl->factory->bidirection) {
        LEVEL0_DOUBLE_CHAIN_TAIL(sl) = sl->top;
    }

    for (i=0; i<level_count; i++) {
        sl->top->links[i] = sl->factory->tail;
    }

    return sl;
}

static int uniq_skiplist_grow(UniqSkiplist *sl)
{
    int top_level_index; 
    int old_top_level_index; 
    int i;
    struct fast_mblock_man *top_mblock;
    UniqSkiplistNode *old_top;
    UniqSkiplistNode *new_top;

    top_level_index = sl->top_level_index + 1;
    if (top_level_index >= sl->factory->max_level_count) {
        return E2BIG;
    }

    top_mblock = sl->factory->node_allocators + top_level_index;
    new_top = (UniqSkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (new_top == NULL) {
        return ENOMEM;
    }
    memset(new_top, 0, top_mblock->info.element_size);
    new_top->level_index = top_level_index;
    old_top_level_index = sl->top_level_index;
    old_top = sl->top;

    for (i=0; i<=old_top_level_index; i++) {
        new_top->links[i] = old_top->links[i];
    }
    new_top->links[top_level_index] = sl->factory->tail;

    if (sl->factory->bidirection) {
        if (new_top->links[0] != sl->factory->tail) {  //not empty
            LEVEL0_DOUBLE_CHAIN_PREV_LINK(new_top->links[0]) = new_top;
            LEVEL0_DOUBLE_CHAIN_PREV_LINK(new_top) =
                LEVEL0_DOUBLE_CHAIN_PREV_LINK(old_top);
        } else {
            LEVEL0_DOUBLE_CHAIN_PREV_LINK(new_top) = new_top;
        }
    }

    sl->top = new_top;
    compile_barrier();
    sl->top_level_index = top_level_index;

    UNIQ_SKIPLIST_FREE_MBLOCK_OBJECT(sl, old_top_level_index, old_top);
    return 0;
}

void uniq_skiplist_free(UniqSkiplist *sl)
{
    volatile UniqSkiplistNode *node;
    volatile UniqSkiplistNode *deleted;

    if (sl->top == NULL) {
        return;
    }

    node = sl->top->links[0];
    if (sl->factory->free_func != NULL) {
        while (node != sl->factory->tail) {
            deleted = node;
            node = node->links[0];

            sl->factory->free_func(deleted->data, 0);
            fast_mblock_free_object(sl->factory->node_allocators +
                    deleted->level_index, (void *)deleted);
        }
    } else {
        while (node != sl->factory->tail) {
            deleted = node;
            node = node->links[0];

            fast_mblock_free_object(sl->factory->node_allocators +
                    deleted->level_index, (void *)deleted);
        }
    }

    fast_mblock_free_object(sl->factory->node_allocators +
            sl->top_level_index, sl->top);

    sl->top = NULL;
    sl->element_count = 0;
    sl->top_level_index = 0;
    fast_mblock_free_object(&sl->factory->skiplist_allocator, sl);
}

static inline int uniq_skiplist_get_level_index(UniqSkiplist *sl)
{
    int i;

    for (i=0; i<sl->top_level_index; i++) {
        if (rand() < RAND_MAX / 2) {
            break;
        }
    }

    return i;
}

int uniq_skiplist_insert(UniqSkiplist *sl, void *data)
{
    int i;
    int level_index;
    int cmp;
    UniqSkiplistNode *node;
    volatile UniqSkiplistNode *previous;
    volatile UniqSkiplistNode *tmp_previous[SKIPLIST_MAX_LEVEL_COUNT];

    level_index = uniq_skiplist_get_level_index(sl);
    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != sl->factory->tail) {
            cmp = sl->factory->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return EEXIST;
            }

            previous = previous->links[i];
        }
    }

    while (i >= 0) {
        while (previous->links[i] != sl->factory->tail) {
            cmp = sl->factory->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return EEXIST;
            }

            previous = previous->links[i];
        }

        tmp_previous[i] = previous;
        i--;
    }

    node = (UniqSkiplistNode *)fast_mblock_alloc_object(
            sl->factory->node_allocators + level_index);
    if (node == NULL) {
        return ENOMEM;
    }
    node->level_index = level_index;
    node->data = data;

    compile_barrier();

    //thread safe for one write with many read model
    if (sl->factory->bidirection) {
        LEVEL0_DOUBLE_CHAIN_PREV_LINK(node) = tmp_previous[0];
        if (tmp_previous[0]->links[0] == sl->factory->tail) {
            LEVEL0_DOUBLE_CHAIN_TAIL(sl) = node;
        } else {
            LEVEL0_DOUBLE_CHAIN_PREV_LINK(tmp_previous[0]->links[0]) = node;
        }
    }
    for (i=0; i<=level_index; i++) {
        node->links[i] = tmp_previous[i]->links[i];
        tmp_previous[i]->links[i] = node;
    }

    sl->element_count++;
    if (sl->element_count > best_element_counts[sl->top_level_index]) {
        uniq_skiplist_grow(sl);
    }

    return 0;
}

static UniqSkiplistNode *uniq_skiplist_get_equal_previous(UniqSkiplist *sl,
        void *data, int *level_index)
{
    int i;
    int cmp;
    volatile UniqSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->factory->tail) {
            cmp = sl->factory->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                *level_index = i;
                return (UniqSkiplistNode *)previous;
            }

            previous = previous->links[i];
        }
    }

    return NULL;
}

static UniqSkiplistNode *uniq_skiplist_get_first_larger_or_equal(
        UniqSkiplist *sl, void *data)
{
    int i;
    int cmp;
    volatile UniqSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->factory->tail) {
            cmp = sl->factory->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return (UniqSkiplistNode *)previous->links[i];
            }

            previous = previous->links[i];
        }
    }

    return (UniqSkiplistNode *)previous->links[0];
}

static UniqSkiplistNode *uniq_skiplist_get_first_larger(
        UniqSkiplist *sl, void *data)
{
    int i;
    int cmp;
    volatile UniqSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->factory->tail) {
            cmp = sl->factory->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return (UniqSkiplistNode *)previous->links[i]->links[0];
            }

            previous = previous->links[i];
        }
    }

    return (UniqSkiplistNode *)previous->links[0];
}

void uniq_skiplist_delete_node_ex(UniqSkiplist *sl,
        UniqSkiplistNode *previous, UniqSkiplistNode *deleted,
        const bool need_free)
{
    int i;
    for (i=deleted->level_index; i>=0; i--) {
        while (previous->links[i] != sl->factory->tail &&
                previous->links[i] != deleted)
        {
            previous = (UniqSkiplistNode *)previous->links[i];
        }

        previous->links[i] = previous->links[i]->links[i];
    }

    if (sl->factory->bidirection) {
        if (deleted->links[0] == sl->factory->tail) {
            LEVEL0_DOUBLE_CHAIN_TAIL(sl) =
                LEVEL0_DOUBLE_CHAIN_PREV_LINK(deleted);
        } else {
            LEVEL0_DOUBLE_CHAIN_PREV_LINK(deleted->links[0]) =
                LEVEL0_DOUBLE_CHAIN_PREV_LINK(deleted);
        }
    }

    if (need_free && sl->factory->free_func != NULL) {
        sl->factory->free_func(deleted->data,
                sl->factory->delay_free_seconds);
    }

    UNIQ_SKIPLIST_FREE_MBLOCK_OBJECT(sl, deleted->level_index, deleted);
    sl->element_count--;
}

int uniq_skiplist_delete_ex(UniqSkiplist *sl, void *data,
        const bool need_free)
{
    int level_index;
    UniqSkiplistNode *previous;
    UniqSkiplistNode *deleted;

    previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = (UniqSkiplistNode *)previous->links[level_index];
    uniq_skiplist_delete_node_ex(sl, previous, deleted, need_free);
    return 0;
}

int uniq_skiplist_replace_ex(UniqSkiplist *sl, void *data,
        const bool need_free_old)
{
    int level_index;
    UniqSkiplistNode *previous;
    volatile UniqSkiplistNode *current;

    previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    current = previous->links[level_index];
    if (need_free_old && sl->factory->free_func != NULL) {
        void *deleted_data;

        deleted_data = current->data;
        current->data = data;
        sl->factory->free_func(deleted_data, sl->factory->delay_free_seconds);
    } else {
        current->data = data;
    }

    return 0;
}

UniqSkiplistNode *uniq_skiplist_find_node_ex(UniqSkiplist *sl, void *data,
        UniqSkiplistNode **previous)
{
    int level_index;

    *previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    return (*previous != NULL) ? (UniqSkiplistNode *)
        (*previous)->links[level_index] : NULL;
}

UniqSkiplistNode *uniq_skiplist_find_node(UniqSkiplist *sl, void *data)
{
    int level_index;
    UniqSkiplistNode *previous;

    previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    return (previous != NULL) ? (UniqSkiplistNode *)
        previous->links[level_index] : NULL;
}

void *uniq_skiplist_find(UniqSkiplist *sl, void *data)
{
    int level_index;
    UniqSkiplistNode *previous;

    previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->data : NULL;
}

int uniq_skiplist_find_all(UniqSkiplist *sl, void *data,
        UniqSkiplistIterator *iterator)
{
    int level_index;
    UniqSkiplistNode *previous;

    previous = uniq_skiplist_get_equal_previous(sl, data, &level_index);
    if (previous == NULL) {
        iterator->tail = sl->factory->tail;
        iterator->current = sl->factory->tail;
        return ENOENT;
    }

    iterator->current = previous->links[level_index];
    iterator->tail = iterator->current->links[0];
    return 0;
}

UniqSkiplistNode *uniq_skiplist_find_ge_node(UniqSkiplist *sl, void *data)
{
    UniqSkiplistNode *node;
    node = uniq_skiplist_get_first_larger_or_equal(sl, data);
    if (node == sl->factory->tail) {
        return NULL;
    }

    return node;
}

int uniq_skiplist_find_range(UniqSkiplist *sl, void *start_data,
        void *end_data, UniqSkiplistIterator *iterator)
{
    if (sl->factory->compare_func(start_data, end_data) > 0) {
        iterator->current = sl->factory->tail;
        iterator->tail = sl->factory->tail;
        return EINVAL;
    }

    iterator->current = uniq_skiplist_get_first_larger_or_equal(sl, start_data);
    if (iterator->current == sl->factory->tail) {
        iterator->tail = sl->factory->tail;
        return ENOENT;
    }

    iterator->tail = uniq_skiplist_get_first_larger(sl, end_data);
    return iterator->current != iterator->tail ? 0 : ENOENT;
}
