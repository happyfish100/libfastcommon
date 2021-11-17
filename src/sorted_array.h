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

#ifndef SORTED_ARRAY_H
#define SORTED_ARRAY_H

#include "array_allocator.h"

typedef struct sorted_array_context
{
    int element_size;
    bool allow_duplication;
    int (*compare_func)(const void *, const void *);
} SortedArrayContext;

#ifdef __cplusplus
extern "C" {
#endif

    /** init the context for sorted array
     *  parameters:
     *      ctx: the context to init
     *      element_size: the size of one array element
     *      allow_duplication: if allow duplication
     *      compare_func: the compare function (comparator)
     *  return: none
     */
    void sorted_array_init(SortedArrayContext *ctx,
            const int element_size, const bool allow_duplication,
            int (*compare_func)(const void *, const void *));


    /** insert an element into the sorted array
     *  parameters:
     *      ctx: the context for sorted array
     *      base: the pointer of the sorted array (the first array element)
     *      count: the count of the sorted array (for input and output)
     *      elt: the element to insert
     *  return: 0 for success, != 0 for error
     */
    int sorted_array_insert(SortedArrayContext *ctx,
            void *base, int *count, const void *elt);


    /** delete an element from the sorted array
     *  parameters:
     *      ctx: the context for sorted array
     *      base: the pointer of the sorted array (the first array element)
     *      count: the count of the sorted array (for input and output)
     *      elt: the element to delete
     *  return: 0 for success, != 0 for error
     */
    int sorted_array_delete(SortedArrayContext *ctx,
            void *base, int *count, const void *elt);

    /** delete an element by index
     *  parameters:
     *      ctx: the context for sorted array
     *      base: the pointer of the sorted array (the first array element)
     *      count: the count of the sorted array (for input and output)
     *      index: the element index to delete
     *  return: 0 for success, != 0 for error
     */
    void sorted_array_delete_by_index(SortedArrayContext *ctx,
            void *base, int *count, const int index);

    /** find element from the sorted array
     *  parameters:
     *      ctx: the context for sorted array
     *      base: the pointer of the sorted array (the first array element)
     *      count: the count of the sorted array
     *      key: the element to find
     *  return: 0 for success, != 0 for error
     */
    static inline void *sorted_array_find(SortedArrayContext *ctx,
            void *base, const int count, const void *key)
    {
        return bsearch(key, base, count, ctx->
                element_size, ctx->compare_func);
    }

#define sorted_i64_array_init(ctx, allow_duplication) \
    sorted_array_init(ctx, sizeof(int64_t), allow_duplication, \
            (int (*)(const void *, const void *))array_compare_element_int64)

#define sorted_i32_array_init(ctx, allow_duplication) \
    sorted_array_init(ctx, sizeof(int32_t), allow_duplication, \
            (int (*)(const void *, const void *))array_compare_element_int32)

#define sorted_id_name_array_init(ctx, allow_duplication) \
    sorted_array_init(ctx, sizeof(id_name_pair_t), allow_duplication, \
            (int (*)(const void *, const void *)) \
            array_compare_element_id_name)


#ifdef __cplusplus
}
#endif

#endif
