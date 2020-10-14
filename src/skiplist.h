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
#include "skiplist_set.h"

#define SKIPLIST_TYPE_FLAT    0   //best for small duplicated entries
#define SKIPLIST_TYPE_MULTI   1   //best for large duplicated entries
#define SKIPLIST_TYPE_SET     2   //NO duplicated entries

typedef struct skiplist
{
    int type;
    union {
        FlatSkiplist  flat;
        MultiSkiplist multi;
        SkiplistSet   set;
    } u;
} Skiplist;

typedef struct skiplist_iterator {
    int type;
    union {
        FlatSkiplistIterator  flat;
        MultiSkiplistIterator multi;
        SkiplistSetIterator   set;
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
    switch (type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_init_ex(&sl->u.flat, level_count,
                    compare_func, free_func, min_alloc_elements_once);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_init_ex(&sl->u.multi, level_count,
                    compare_func, free_func, min_alloc_elements_once);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_init_ex(&sl->u.set, level_count,
                    compare_func, free_func, min_alloc_elements_once);
        default:
            return EINVAL;
    }
}

static inline void skiplist_destroy(Skiplist *sl)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            flat_skiplist_destroy(&sl->u.flat);
            break;
        case SKIPLIST_TYPE_MULTI:
            multi_skiplist_destroy(&sl->u.multi);
            break;
        case SKIPLIST_TYPE_SET:
            skiplist_set_destroy(&sl->u.set);
            break;
        default:
            break;
    }
}

static inline int skiplist_insert(Skiplist *sl, void *data)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_insert(&sl->u.flat, data);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_insert(&sl->u.multi, data);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_insert(&sl->u.set, data);
        default:
            return EINVAL;
    }
}

static inline int skiplist_delete(Skiplist *sl, void *data)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_delete(&sl->u.flat, data);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_delete(&sl->u.multi, data);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_delete(&sl->u.set, data);
        default:
            return EINVAL;
    }
}

static inline int skiplist_delete_all(Skiplist *sl, void *data, int *delete_count)
{
    int result;
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_delete_all(&sl->u.flat, data, delete_count);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_delete_all(&sl->u.multi, data, delete_count);
        case SKIPLIST_TYPE_SET:
            result = skiplist_set_delete(&sl->u.set, data);
            *delete_count = (result == 0) ? 1 : 0;
            return result;
        default:
            return EINVAL;
    }
}

static inline void *skiplist_find(Skiplist *sl, void *data)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_find(&sl->u.flat, data);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_find(&sl->u.multi, data);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_find(&sl->u.set, data);
        default:
            return NULL;
    }
}

static inline int skiplist_find_all(Skiplist *sl, void *data, SkiplistIterator *iterator)
{
    iterator->type = sl->type;
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_find_all(&sl->u.flat, data, &iterator->u.flat);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_find_all(&sl->u.multi, data, &iterator->u.multi);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_find_all(&sl->u.set, data, &iterator->u.set);
        default:
            return EINVAL;
    }
}

int skiplist_find_range(Skiplist *sl, void *start_data, void *end_data,
        SkiplistIterator *iterator)
{
    iterator->type = sl->type;
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_find_range(&sl->u.flat,
                    start_data, end_data, &iterator->u.flat);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_find_range(&sl->u.multi,
                    start_data, end_data, &iterator->u.multi);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_find_range(&sl->u.set,
                    start_data, end_data, &iterator->u.set);
        default:
            return EINVAL;
    }
}

static inline void skiplist_iterator(Skiplist *sl, SkiplistIterator *iterator)
{
    iterator->type = sl->type;
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            flat_skiplist_iterator(&sl->u.flat, &iterator->u.flat);
            break;
        case SKIPLIST_TYPE_MULTI:
            multi_skiplist_iterator(&sl->u.multi, &iterator->u.multi);
            break;
        case SKIPLIST_TYPE_SET:
            skiplist_set_iterator(&sl->u.set, &iterator->u.set);
            break;
        default:
            break;
    }
}

static inline void *skiplist_next(SkiplistIterator *iterator)
{
    switch (iterator->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_next(&iterator->u.flat);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_next(&iterator->u.multi);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_next(&iterator->u.set);
        default:
            return NULL;
    }
}

static inline bool skiplist_empty(Skiplist *sl)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return flat_skiplist_empty(&sl->u.flat);
        case SKIPLIST_TYPE_MULTI:
            return multi_skiplist_empty(&sl->u.multi);
        case SKIPLIST_TYPE_SET:
            return skiplist_set_empty(&sl->u.set);
        default:
            return false;
    }
}

static inline const char* skiplist_get_type_caption(Skiplist *sl)
{
    switch (sl->type) {
        case SKIPLIST_TYPE_FLAT:
            return "flat";
        case SKIPLIST_TYPE_MULTI:
            return "multi";
        case SKIPLIST_TYPE_SET:
            return "set";
        default:
            return "unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif

