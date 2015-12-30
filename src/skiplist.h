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
#include "skiplist_common.h"
#include "flat_skiplist.h"
#include "multi_skiplist.h"

#define SKIPLIST_TYPE_FLAT    0
#define SKIPLIST_TYPE_MULTI   1

typedef struct skiplist
{
    int type;
    union {
        FlatSkiplist flat;
        MultiSkiplist multi;
    } u;
} Skiplist;

typedef struct skiplist_iterator {
    int type;
    union {
        FlatSkiplistIterator flat;
        MultiSkiplistIterator multi;
    } u;
} SkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define skiplist_init(sl, level_count, compare_func, free_func) \
    skiplist_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE, SKIPLIST_TYPE_FLAT)

static inline int skiplist_init_ex(Skiplist *sl, const int level_count,
        skiplist_compare_func compare_func, skiplist_free_func free_func,
        const int min_alloc_elements_once, const int type)
{
    sl->type = type;
    if (type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_init_ex(&sl->u.flat, level_count,
                compare_func, free_func, min_alloc_elements_once);
    }
    else {
        return multi_skiplist_init_ex(&sl->u.multi, level_count,
                compare_func, free_func, min_alloc_elements_once);
    }
}

static inline void skiplist_destroy(Skiplist *sl)
{
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        flat_skiplist_destroy(&sl->u.flat);
    }
    else {
        multi_skiplist_destroy(&sl->u.multi);
    }
}

static inline int skiplist_insert(Skiplist *sl, void *data)
{
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_insert(&sl->u.flat, data);
    }
    else {
        return multi_skiplist_insert(&sl->u.multi, data);
    }
}

static inline int skiplist_delete(Skiplist *sl, void *data)
{
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_delete(&sl->u.flat, data);
    }
    else {
        return multi_skiplist_delete(&sl->u.multi, data);
    }
}

static inline int skiplist_delete_all(Skiplist *sl, void *data, int *delete_count)
{
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_delete_all(&sl->u.flat, data, delete_count);
    }
    else {
        return multi_skiplist_delete_all(&sl->u.multi, data, delete_count);
    }
}

static inline void *skiplist_find(Skiplist *sl, void *data)
{
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_find(&sl->u.flat, data);
    }
    else {
        return multi_skiplist_find(&sl->u.multi, data);
    }
}

static inline int skiplist_find_all(Skiplist *sl, void *data, SkiplistIterator *iterator)
{
    iterator->type = sl->type;
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_find_all(&sl->u.flat, data, &iterator->u.flat);
    }
    else {
        return multi_skiplist_find_all(&sl->u.multi, data, &iterator->u.multi);
    }
}

static inline void skiplist_iterator(Skiplist *sl, SkiplistIterator *iterator)
{
    iterator->type = sl->type;
    if (sl->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_iterator(&sl->u.flat, &iterator->u.flat);
    }
    else {
        return multi_skiplist_iterator(&sl->u.multi, &iterator->u.multi);
    }
}

static inline void *skiplist_next(SkiplistIterator *iterator)
{
    if (iterator->type == SKIPLIST_TYPE_FLAT) {
        return flat_skiplist_next(&iterator->u.flat);
    }
    else {
        return multi_skiplist_next(&iterator->u.multi);
    }
}

#ifdef __cplusplus
}
#endif

#endif

