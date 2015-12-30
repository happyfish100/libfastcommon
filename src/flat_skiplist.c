/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//flat_skiplist.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "logger.h"
#include "flat_skiplist.h"

int flat_skiplist_init_ex(FlatSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func, skiplist_free_func free_func,
        const int min_alloc_elements_once)
{
    int bytes;
    int element_size;
    int i;
    int alloc_elements_once;
    int result;
    struct fast_mblock_man *top_mblock;

    if (level_count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid level count: %d",
                __LINE__, level_count);
        return EINVAL;
    }

    if (level_count > 20) {
        logError("file: "__FILE__", line: %d, "
                "level count: %d is too large",
                __LINE__, level_count);
        return E2BIG;
    }

    bytes = sizeof(struct fast_mblock_man) * level_count;
    sl->mblocks = (struct fast_mblock_man *)malloc(bytes);
    if (sl->mblocks == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail, errno: %d, error info: %s",
                __LINE__, bytes, errno, STRERROR(errno));
        return errno != 0 ? errno : ENOMEM;
    }
    memset(sl->mblocks, 0, bytes);

    alloc_elements_once = min_alloc_elements_once;
    if (alloc_elements_once <= 0) {
        alloc_elements_once = SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE;
    }
    else if (alloc_elements_once > 1024) {
        alloc_elements_once = 1024;
    }

    for (i=level_count-1; i>=0; i--) {
        element_size = sizeof(FlatSkiplistNode) + sizeof(FlatSkiplistNode *) * (i + 1);
        if ((result=fast_mblock_init_ex(sl->mblocks + i,
            element_size, alloc_elements_once, NULL, false)) != 0)
        {
            return result;
        }
        if (alloc_elements_once < 1024 * 1024) {
            alloc_elements_once *= 2;
        }
    }

    sl->top_level_index = level_count - 1;
    top_mblock = sl->mblocks + sl->top_level_index;
    sl->top = (FlatSkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        return ENOMEM;
    }
    memset(sl->top, 0, top_mblock->info.element_size);

    sl->tail = (FlatSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + 0);
    if (sl->tail == NULL) {
        return ENOMEM;
    }
    memset(sl->tail, 0, sl->mblocks[0].info.element_size);

    sl->tail->prev = sl->top;
    for (i=0; i<level_count; i++) {
        sl->top->links[i] = sl->tail;
    }

    sl->level_count = level_count;
    sl->compare_func = compare_func;
    sl->free_func = free_func;

    srand(time(NULL));
    return 0;
}

void flat_skiplist_destroy(FlatSkiplist *sl)
{
    int i;
    FlatSkiplistNode *node;
    FlatSkiplistNode *deleted;

    if (sl->mblocks == NULL) {
        return;
    }

    if (sl->free_func != NULL) {
        node = sl->top->links[0];
        while (node != sl->tail) {
            deleted = node;
            node = node->links[0];
            sl->free_func(deleted->data);
        }
    }

    for (i=0; i<sl->level_count; i++) {
        fast_mblock_destroy(sl->mblocks + i);
    }

    free(sl->mblocks);
    sl->mblocks = NULL;
}

static inline int flat_skiplist_get_level_index(FlatSkiplist *sl)
{
    int i;

    for (i=0; i<sl->top_level_index; i++) {
        if (rand() < RAND_MAX / 2) {
            break;
        }
    }

    return i;
}

int flat_skiplist_insert(FlatSkiplist *sl, void *data)
{
    int i;
    int level_index;
    FlatSkiplistNode *node;
    FlatSkiplistNode *previous;
    FlatSkiplistNode *current = NULL;

    level_index = flat_skiplist_get_level_index(sl);
    node = (FlatSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + level_index);
    if (node == NULL) {
        return ENOMEM;
    }

    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->data) < 0)
        {
            previous = previous->links[i];
        }
    }

    while (i >= 0) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->data) < 0)
        {
            previous = previous->links[i];
        }

        current = previous->links[i];
        previous->links[i] = node;
        node->links[i] = current;

        i--;
    }

    node->prev = previous;
    current->prev = node;
    node->data = data;
    return 0;
}

static FlatSkiplistNode *flat_skiplist_get_previous(FlatSkiplist *sl, void *data,
        int *level_index)
{
    int i;
    int cmp;
    FlatSkiplistNode *previous;
    FlatSkiplistNode *found;

    found = NULL;
    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp > 0) {
                break;
            }
            else if (cmp == 0) {
                found = previous;
                *level_index = i;
                goto DONE;
            }

            previous = previous->links[i];
        }
    }

DONE:
    return found;
}

int flat_skiplist_delete(FlatSkiplist *sl, void *data)
{
    int i;
    int level_index;
    FlatSkiplistNode *previous;
    FlatSkiplistNode *deleted;

    previous = flat_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = previous->links[level_index];
    for (i=level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->data) < 0)
        {
            previous = previous->links[i];
        }

        assert(sl->compare_func(data, previous->links[i]->data) == 0);
        previous->links[i] = previous->links[i]->links[i];
    }

    deleted->links[0]->prev = previous;

    if (sl->free_func != NULL) {
        sl->free_func(deleted->data);
    }
    fast_mblock_free_object(sl->mblocks + level_index, deleted);
    return 0;
}

int flat_skiplist_delete_all(FlatSkiplist *sl, void *data, int *delete_count)
{
    *delete_count = 0;
    while (flat_skiplist_delete(sl, data) == 0) {
        (*delete_count)++;
    }

    return *delete_count > 0 ? 0 : ENOENT;
}

void *flat_skiplist_find(FlatSkiplist *sl, void *data)
{
    int level_index;
    FlatSkiplistNode *previous;

    previous = flat_skiplist_get_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->data : NULL;
}

int flat_skiplist_find_all(FlatSkiplist *sl, void *data, FlatSkiplistIterator *iterator)
{
    int level_index;
    FlatSkiplistNode *previous;
    FlatSkiplistNode *last;

    previous = flat_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        iterator->top = sl->top;
        iterator->current = sl->top;
        return ENOENT;
    }

    last = previous->links[0]->links[0];
    while (last != sl->tail && sl->compare_func(data, last->data) == 0) {
        last = last->links[0];
    }

    iterator->top = previous;
    iterator->current = last->prev;
    return 0;
}

