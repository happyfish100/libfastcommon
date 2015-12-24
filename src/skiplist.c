/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//skiplist.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "logger.h"
#include "skiplist.h"

int skiplist_init_ex(Skiplist *sl, const int level_count,
        skiplist_compare_func compare_func, const int alloc_elements_once)
{
    int bytes;
    int element_size;
    int i;
    int result;
    struct fast_mblock_man *top_mblock;

    if (level_count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid level count: %d",
                __LINE__, level_count);
        return EINVAL;
    }

    if (level_count > 32) {
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

    for (i=0; i<level_count; i++) {
        element_size = sizeof(SkiplistNode) + sizeof(SkiplistNode *) * (i + 1);
        if ((result=fast_mblock_init_ex(sl->mblocks + i, 
            element_size, alloc_elements_once, NULL, false)) != 0)
        {
            return result;
        }
    }

    sl->top_level_index = level_count - 1;
    top_mblock = sl->mblocks + sl->top_level_index;
    sl->top = (SkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        return ENOMEM;
    }
    memset(sl->top, 0, top_mblock->info.element_size);

    sl->level_count = level_count;
    sl->compare_func = compare_func;

    srand(time(NULL));
    return 0;
}

void skiplist_destroy(Skiplist *sl)
{
    int i;

    if (sl->mblocks == NULL) {
        return;
    }

    for (i=0; i<sl->level_count; i++) {
        fast_mblock_destroy(sl->mblocks + i);
    }

    free(sl->mblocks);
    sl->mblocks = NULL;
}

static inline int skiplist_get_previous_level_index(Skiplist *sl)
{
    int i;

    for (i=0; i<sl->level_count; i++) {
        if (rand() < RAND_MAX / 2) {
            break;
        }
    }

    return i;
}

int skiplist_insert(Skiplist *sl, void *data)
{
    int i;
    int level_index;
    SkiplistNode *node;
    SkiplistNode *previous;
    SkiplistNode *current;

    level_index = skiplist_get_previous_level_index(sl);
    node = (SkiplistNode *)fast_mblock_alloc_object(sl->mblocks + level_index);
    if (node == NULL) {
        return ENOMEM;
    }

    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != NULL && sl->compare_func(data,
                    previous->links[i]->data) > 0)
        {
            previous = previous->links[i];
        }
    }

    while (i >= 0) {
        while (previous->links[i] != NULL && sl->compare_func(data,
                    previous->links[i]->data) > 0)
        {
            previous = previous->links[i];
        }

        current = previous->links[i];
        previous->links[i] = node;
        node->links[i] = current;

        i--;
    }

    node->data = data;
    return 0;
}

static SkiplistNode *skiplist_get_previous(Skiplist *sl, void *data,
        int *level_index)
{
    int i;
    int cmp;
    SkiplistNode *previous;
    SkiplistNode *found;

    found = NULL;
    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != NULL) {
            cmp = sl->compare_func(data, previous->links[i]->data);
            if (cmp < 0) {
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

int skiplist_delete(Skiplist *sl, void *data)
{
    int i;
    int level_index;
    SkiplistNode *previous;
    SkiplistNode *deleted;

    previous = skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = previous->links[level_index];
    for (i=level_index; i>=0; i--) {
        while (previous->links[i] != NULL && sl->compare_func(data,
                    previous->links[i]->data) > 0)
        {
            previous = previous->links[i];
        }

        assert(sl->compare_func(data, previous->links[i]->data) == 0);
        previous->links[i] = previous->links[i]->links[i];
    }

    fast_mblock_free_object(sl->mblocks + level_index, deleted);
    return 0;
}

void *skiplist_find(Skiplist *sl, void *data)
{
    int level_index;
    SkiplistNode *previous;

    previous = skiplist_get_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->data : NULL;
}


