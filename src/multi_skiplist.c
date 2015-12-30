/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//multi_skiplist.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "logger.h"
#include "multi_skiplist.h"

int multi_skiplist_init_ex(MultiSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func,
        skiplist_free_func free_func,
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
        element_size = sizeof(MultiSkiplistNode) + sizeof(MultiSkiplistNode *) * (i + 1);
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
    sl->top = (MultiSkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        return ENOMEM;
    }
    memset(sl->top, 0, top_mblock->info.element_size);

    sl->tail = (MultiSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + 0);
    if (sl->tail == NULL) {
        return ENOMEM;
    }
    memset(sl->tail, 0, sl->mblocks[0].info.element_size);

    if ((result=fast_mblock_init_ex(&sl->data_mblock,
                    sizeof(MultiSkiplistData), alloc_elements_once,
                    NULL, false)) != 0)
    {
        return result;
    }

    for (i=0; i<level_count; i++) {
        sl->top->links[i] = sl->tail;
    }

    sl->level_count = level_count;
    sl->compare_func = compare_func;
    sl->free_func = free_func;

    srand(time(NULL));
    return 0;
}

void multi_skiplist_destroy(MultiSkiplist *sl)
{
    int i;
    MultiSkiplistNode *node;
    MultiSkiplistNode *deleted;
    MultiSkiplistData *dataCurrent;
    MultiSkiplistData *dataNode;

    if (sl->mblocks == NULL) {
        return;
    }

    if (sl->free_func != NULL) {
        node = sl->top->links[0];
        while (node != sl->tail) {
            deleted = node;
            node = node->links[0];

            dataCurrent = deleted->head;
            while (dataCurrent != NULL) {
                dataNode = dataCurrent;
                dataCurrent = dataCurrent->next;

                sl->free_func(dataNode->data);
            }
        }
    }

    for (i=0; i<sl->level_count; i++) {
        fast_mblock_destroy(sl->mblocks + i);
    }
    fast_mblock_destroy(&sl->data_mblock);

    free(sl->mblocks);
    sl->mblocks = NULL;
}

static MultiSkiplistNode *multi_skiplist_get_previous(MultiSkiplist *sl, void *data,
        int *level_index)
{
    int i;
    int cmp;
    MultiSkiplistNode *previous;
    MultiSkiplistNode *found;

    found = NULL;
    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->head->data);
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

static inline void multi_skiplist_free_data_node(MultiSkiplist *sl,
        MultiSkiplistData *dataNode)
{
    if (sl->free_func != NULL) {
        sl->free_func(dataNode->data);
    }
    fast_mblock_free_object(&sl->data_mblock, dataNode);
}

static inline int multi_skiplist_get_level_index(MultiSkiplist *sl)
{
    int i;

    for (i=0; i<sl->top_level_index; i++) {
        if (rand() < RAND_MAX / 2) {
            break;
        }
    }

    return i;
}

int multi_skiplist_insert(MultiSkiplist *sl, void *data)
{
    int i;
    int level_index;
    MultiSkiplistData *dataNode;
    MultiSkiplistNode *node;
    MultiSkiplistNode *previous;
    MultiSkiplistNode *current = NULL;

    dataNode = (MultiSkiplistData *)fast_mblock_alloc_object(&sl->data_mblock);
    if (dataNode == NULL) {
        return ENOMEM;
    }
    dataNode->data = data;
    dataNode->next = NULL;

    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous != NULL) {
        node = previous->links[level_index];
        node->tail->next = dataNode;
        node->tail = dataNode;
        return 0;
    }

    level_index = multi_skiplist_get_level_index(sl);
    node = (MultiSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + level_index);
    if (node == NULL) {
        fast_mblock_free_object(&sl->data_mblock, dataNode);
        return ENOMEM;
    }

    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->head->data) > 0)
        {
            previous = previous->links[i];
        }
    }

    while (i >= 0) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->head->data) > 0)
        {
            previous = previous->links[i];
        }

        current = previous->links[i];
        previous->links[i] = node;
        node->links[i] = current;

        i--;
    }

    node->head = dataNode;
    node->tail = dataNode;
    return 0;
}

int multi_skiplist_do_delete(MultiSkiplist *sl, void *data,
        const bool delete_all, int *delete_count)
{
    int i;
    int level_index;
    MultiSkiplistNode *previous;
    MultiSkiplistNode *deleted;
    MultiSkiplistData *dataNode;
    MultiSkiplistData *dataCurrent;

    *delete_count = 0;
    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = previous->links[level_index];
    if (!delete_all) {
        if (deleted->head->next != NULL) {
            dataNode = deleted->head;
            deleted->head = dataNode->next;

            multi_skiplist_free_data_node(sl, dataNode);
            *delete_count = 1;
            return 0;
        }
    }

    for (i=level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->head->data) > 0)
        {
            previous = previous->links[i];
        }

        previous->links[i] = previous->links[i]->links[i];
    }

    dataCurrent = deleted->head;
    while (dataCurrent != NULL) {
        dataNode = dataCurrent;
        dataCurrent = dataCurrent->next;

        (*delete_count)++;
        multi_skiplist_free_data_node(sl, dataNode);
    }

    fast_mblock_free_object(sl->mblocks + level_index, deleted);
    return 0;
}

int multi_skiplist_delete(MultiSkiplist *sl, void *data)
{
    int delete_count;
    return multi_skiplist_do_delete(sl, data, false, &delete_count);
}

int multi_skiplist_delete_all(MultiSkiplist *sl, void *data, int *delete_count)
{
    return multi_skiplist_do_delete(sl, data, true, delete_count);
}

void *multi_skiplist_find(MultiSkiplist *sl, void *data)
{
    int level_index;
    MultiSkiplistNode *previous;

    previous = multi_skiplist_get_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->head->data : NULL;
}

int multi_skiplist_find_all(MultiSkiplist *sl, void *data,
        MultiSkiplistIterator *iterator)
{
    int level_index;
    MultiSkiplistNode *previous;

    iterator->current.data = NULL;
    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        iterator->current.node = sl->tail;
        iterator->tail = sl->tail;
        return ENOENT;
    }
    else {
        iterator->current.node = previous;
        iterator->tail = previous->links[0]->links[0];
        return 0;
    }
}

