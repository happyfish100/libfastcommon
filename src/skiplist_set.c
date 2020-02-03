/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//skiplist_set.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "logger.h"
#include "skiplist_set.h"

int skiplist_set_init_ex(SkiplistSet *sl, const int level_count,
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

    if (level_count > SKIPLIST_MAX_LEVEL_COUNT) {
        logError("file: "__FILE__", line: %d, "
                "level count: %d is too large exceeds %d",
                __LINE__, level_count, SKIPLIST_MAX_LEVEL_COUNT);
        return E2BIG;
    }

    bytes = sizeof(SkiplistSetNode *) * level_count;
    sl->tmp_previous = (SkiplistSetNode **)malloc(bytes);
    if (sl->tmp_previous == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail, errno: %d, error info: %s",
                __LINE__, bytes, errno, STRERROR(errno));
        return errno != 0 ? errno : ENOMEM;
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
        element_size = sizeof(SkiplistSetNode) +
            sizeof(SkiplistSetNode *) * (i + 1);
        if ((result=fast_mblock_init_ex(sl->mblocks + i,
            element_size, alloc_elements_once, NULL, NULL, false)) != 0)
        {
            return result;
        }
        if (i % 2 == 0 && alloc_elements_once < 64 * 1024) {
            alloc_elements_once *= 2;
        }
    }

    sl->top_level_index = level_count - 1;
    top_mblock = sl->mblocks + sl->top_level_index;
    sl->top = (SkiplistSetNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        return ENOMEM;
    }
    memset(sl->top, 0, top_mblock->info.element_size);

    sl->tail = (SkiplistSetNode *)fast_mblock_alloc_object(sl->mblocks + 0);
    if (sl->tail == NULL) {
        return ENOMEM;
    }
    memset(sl->tail, 0, sl->mblocks[0].info.element_size);

    for (i=0; i<level_count; i++) {
        sl->top->links[i] = sl->tail;
    }

    sl->level_count = level_count;
    sl->compare_func = compare_func;
    sl->free_func = free_func;

    srand(time(NULL));
    return 0;
}

void skiplist_set_destroy(SkiplistSet *sl)
{
    int i;
    SkiplistSetNode *node;
    SkiplistSetNode *deleted;

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

static inline int skiplist_set_get_level_index(SkiplistSet *sl)
{
    int i;

    for (i=0; i<sl->top_level_index; i++) {
        if (rand() < RAND_MAX / 2) {
            break;
        }
    }

    return i;
}

int skiplist_set_insert(SkiplistSet *sl, void *data)
{
    int i;
    int level_index;
    int cmp;
    SkiplistSetNode *node;
    SkiplistSetNode *previous;

    level_index = skiplist_set_get_level_index(sl);
    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
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
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return EEXIST;
            }

            previous = previous->links[i];
        }

        sl->tmp_previous[i] = previous;
        i--;
    }

    node = (SkiplistSetNode *)fast_mblock_alloc_object(sl->mblocks + level_index);
    if (node == NULL) {
        return ENOMEM;
    }
    node->data = data;

    //thread safe for one write with many read model
    for (i=0; i<=level_index; i++) {
        node->links[i] = sl->tmp_previous[i]->links[i];
        sl->tmp_previous[i]->links[i] = node;
    }

    return 0;
}

static SkiplistSetNode *skiplist_set_get_equal_previous(SkiplistSet *sl,
        void *data, int *level_index)
{
    int i;
    int cmp;
    SkiplistSetNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                *level_index = i;
                return previous;
            }

            previous = previous->links[i];
        }
    }

    return NULL;
}

static SkiplistSetNode *skiplist_set_get_first_larger_or_equal(
        SkiplistSet *sl, void *data)
{
    int i;
    int cmp;
    SkiplistSetNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return previous->links[i];
            }

            previous = previous->links[i];
        }
    }

    return previous->links[0];
}

static SkiplistSetNode *skiplist_set_get_first_larger(
        SkiplistSet *sl, void *data)
{
    int i;
    int cmp;
    SkiplistSetNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return previous->links[i]->links[0];
            }

            previous = previous->links[i];
        }
    }

    return previous->links[0];
}

int skiplist_set_delete(SkiplistSet *sl, void *data)
{
    int i;
    int level_index;
    SkiplistSetNode *previous;
    SkiplistSetNode *deleted;

    previous = skiplist_set_get_equal_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = previous->links[level_index];
    for (i=level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail && 
                previous->links[i] != deleted)
        {
            previous = previous->links[i];
        }

        assert(previous->links[i] == deleted);
        previous->links[i] = previous->links[i]->links[i];
    }

    if (sl->free_func != NULL) {
        sl->free_func(deleted->data);
    }
    fast_mblock_free_object(sl->mblocks + level_index, deleted);
    return 0;
}

void *skiplist_set_find(SkiplistSet *sl, void *data)
{
    int level_index;
    SkiplistSetNode *previous;

    previous = skiplist_set_get_equal_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->data : NULL;
}

int skiplist_set_find_all(SkiplistSet *sl, void *data, SkiplistSetIterator *iterator)
{
    int level_index;
    SkiplistSetNode *previous;

    previous = skiplist_set_get_equal_previous(sl, data, &level_index);
    if (previous == NULL) {
        iterator->tail = sl->tail;
        iterator->current = sl->tail;
        return ENOENT;
    }

    iterator->current = previous->links[level_index];
    iterator->tail = iterator->current->links[0];
    return 0;
}

int skiplist_set_find_range(SkiplistSet *sl, void *start_data, void *end_data,
        SkiplistSetIterator *iterator)
{
    if (sl->compare_func(start_data, end_data) > 0) {
        iterator->current = sl->tail;
        iterator->tail = sl->tail;
        return EINVAL;
    }

    iterator->current = skiplist_set_get_first_larger_or_equal(sl, start_data);
    if (iterator->current == sl->tail) {
        iterator->tail = sl->tail;
        return ENOENT;
    }

    iterator->tail = skiplist_set_get_first_larger(sl, end_data);
    return iterator->current != iterator->tail ? 0 : ENOENT;
}
