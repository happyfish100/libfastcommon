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
        const int element_size, const bool allow_duplication,
        int (*compare_func)(const void *, const void *))
{
    ctx->element_size = element_size;
    ctx->allow_duplication = allow_duplication;
    ctx->compare_func = compare_func;
}

static char *sorted_array_bsearch(SortedArrayContext *ctx, char *base,
        const int count, const void *elt, int *insert_pos)
{
    int low;
    int high;
    int mid;
    int compr;
    char *current;

    *insert_pos = 0;
    low = 0;
    high = count - 1;
    while (low <= high) {
        mid = (low + high) / 2;
        current = base + ctx->element_size * mid;
        compr = ctx->compare_func(current, elt);
        if (compr < 0) {
            low = mid + 1;
            *insert_pos = low;
        } else if (compr == 0) {
            *insert_pos = mid;
            return current;
        } else {
            high = mid - 1;
            *insert_pos = mid;
        }
    }

    return NULL;
}

int sorted_array_insert(SortedArrayContext *ctx,
        void *base, int *count, const void *elt)
{
    char *current;

    if (*count == 0 || ctx->compare_func((char *)base +
                ctx->element_size * (*count - 1), elt) < 0)
    {  //fast path
        current = (char *)base + ctx->element_size * (*count);
    } else {
        int insert_pos;
        int move_count;
        char *found;
        char *end;

        found = sorted_array_bsearch(ctx, base, *count, elt, &insert_pos);
        if (found != NULL) {
            if (!ctx->allow_duplication) {
                return EEXIST;
            }

            found += ctx->element_size;
            end = (char *)base + ctx->element_size * (*count);
            while (found < end && ctx->compare_func(found, elt) == 0) {
                insert_pos++;
                found += ctx->element_size;
            }
        }

        current = (char *)base + ctx->element_size * insert_pos;
        move_count = *count - insert_pos;
        if (move_count > 0) {
            memmove((char *)base + ctx->element_size * (insert_pos + 1),
                    current, ctx->element_size * move_count);
        }
    }

    switch (ctx->element_size) {
        case 1:
            *current = *((char *)elt);
            break;
        case 2:
            *((short *)current) = *((short *)elt);
            break;
        case 4:
            *((int32_t *)current) = *((int32_t *)elt);
            break;
        case 8:
            *((int64_t *)current) = *((int64_t *)elt);
            break;
        default:
            memcpy(current, elt, ctx->element_size);
            break;
    }

    (*count)++;
    return 0;
}

void sorted_array_delete_by_index(SortedArrayContext *ctx,
        void *base, int *count, const int index)
{
    int move_count;
    char *start;

    start = (char *)base + ctx->element_size * index;
    move_count = *count - (index + 1);
    if (move_count > 0) {
        memmove(start, start + ctx->element_size,
                ctx->element_size * move_count);
    }
    (*count)--;
}

int sorted_array_delete(SortedArrayContext *ctx,
        void *base, int *count, const void *elt)
{
    int move_count;
    struct {
        char *current;
        char *start;
        char *end;
    } found;
    char *array_end;

    if ((found.current=bsearch(elt, base, *count, ctx->element_size,
                    ctx->compare_func)) == NULL)
    {
        return ENOENT;
    }

    array_end = (char *)base + ctx->element_size * (*count);
    if (ctx->allow_duplication) {
        found.start = found.current;
        while (found.start > (char *)base && ctx->compare_func(
                    found.start - ctx->element_size, elt) == 0)
        {
            found.start -= ctx->element_size;
        }

        found.end = found.current + ctx->element_size;
        while (found.end < array_end && ctx->compare_func(
                    found.end, elt) == 0)
        {
            found.end += ctx->element_size;
        }
        *count -= (found.end - found.start) / ctx->element_size;
    } else {
        found.start = found.current;
        found.end = found.start + ctx->element_size;
        (*count)--;
    }

    move_count = (array_end - found.end) / ctx->element_size;
    if (move_count > 0) {
        memmove(found.start, found.end, ctx->
                element_size * move_count);
    }
    return 0;
}
