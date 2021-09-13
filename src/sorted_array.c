/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include "sorted_array.h"

void sorted_array_init(SortedArrayContext *ctx,
        const int element_size, const bool allow_duplicate,
        int (*compare_func)(const void *, const void *))
{
    ctx->element_size = element_size;
    ctx->allow_duplicate = allow_duplicate;
    ctx->compare_func = compare_func;
}

static void *sorted_array_bsearch(SortedArrayContext *ctx, void *base,
        const int count, const void *element, int *insert_pos)
{
    int low;
    int high;
    int mid;
    int compr;

    *insert_pos = 0;
    low = 0;
    high = count - 1;
    while (low <= high) {
        mid = (low + high) / 2;
        compr = ctx->compare_func(base + mid, element);
        if (compr < 0) {
            low = mid + 1;
            *insert_pos = low;
        } else if (compr == 0) {
            return base + mid;
        } else {
            high = mid - 1;
            *insert_pos = mid;
        }
    }

    return NULL;
}

int sorted_array_insert(SortedArrayContext *ctx,
        void *base, int *count, const void *element)
{
    int insert_pos;
    int move_count;
    void *found;
    void *end;

    found = sorted_array_bsearch(ctx, base, *count, element, &insert_pos);
    if (found != NULL) {
        if (!ctx->allow_duplicate) {
            return EEXIST;
        }

        found++;
        end = base + *count;
        while (found < end && ctx->compare_func(found, element) == 0) {
            found++;
        }
        insert_pos = found - base;
    }

    move_count = *count - insert_pos;
    if (move_count > 0) {
        memmove(base + insert_pos + 1, base + insert_pos,
                ctx->element_size * move_count);
    }
    memcpy(base + insert_pos, element, ctx->element_size);
    (*count)++;
    return 0;
}

int sorted_array_delete(SortedArrayContext *ctx,
        void *base, int *count, const void *element)
{
    int move_count;
    struct {
        void *current;
        void *start;
        void *end;
    } found;
    void *array_end;

    if ((found.current=bsearch(element, base, *count, ctx->element_size,
                    ctx->compare_func)) == NULL)
    {
        return ENOENT;
    }

    array_end = base + *count;
    if (ctx->allow_duplicate) {
        found.start = found.current;
        while (found.start > base && ctx->compare_func(
                    found.start - 1, element) == 0)
        {
            found.start--;
        }

        found.end = ++found.current;
        while (found.end < array_end && ctx->compare_func(
                    found.end, element) == 0)
        {
            found.end++;
        }
        *count -= found.end - found.start;
    } else {
        found.start = found.current;
        found.end = found.start + 1;
        (*count)--;
    }

    move_count = array_end - found.end;
    if (move_count > 0) {
        memmove(found.start, found.end, ctx->
                element_size * move_count);
    }
    return 0;
}

int sorted_array_compare_int64(const int64_t *n1, const int64_t *n2)
{
    int64_t sub;
    sub = *n1 - *n2;
    if (sub < 0) {
        return -1;
    } else if (sub > 0) {
        return 1;
    } else {
        return 0;
    }
}

int sorted_array_compare_int32(const int32_t *n1, const int32_t *n2)
{
    return *n1 - *n2;
}
