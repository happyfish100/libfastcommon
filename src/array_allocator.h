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

#ifndef ARRAY_ALLOCATOR_H
#define ARRAY_ALLOCATOR_H

#include "fast_allocator.h"

typedef struct
{
    int alloc;
    int count;
    char elts[0];
} VoidArray;

typedef struct
{
    int alloc;
    int count;
    int64_t elts[0];
} I64Array;

typedef struct
{
    int alloc;
    int count;
    int32_t elts[0];
} I32Array;

typedef struct
{
    int alloc;
    int count;
    id_name_pair_t elts[0];
} IdNameArray;

typedef struct
{
    int alloc;
    int count;
    void *elts[0];
} PointerArray;

typedef struct array_allocator_context
{
    struct fast_allocator_context allocator;
    int element_size;
    int min_count;
} ArrayAllocatorContext;

#ifdef __cplusplus
extern "C" {
#endif

    int array_allocator_init_ex(ArrayAllocatorContext *ctx,
            const char *name_prefix, const int element_size,
            const int min_bits, const int max_bits,
            const bool need_lock);

    VoidArray *array_allocator_alloc(ArrayAllocatorContext *ctx,
            const int target_count);

    VoidArray *array_allocator_realloc(ArrayAllocatorContext *ctx,
            VoidArray *old_array, const int target_count);

    static inline void array_allocator_free(ArrayAllocatorContext *ctx,
            VoidArray *array)
    {
        array->count = 0;
        fast_allocator_free(&ctx->allocator, array);
    }

    /* comparator for 64 bits integer */
    int array_compare_element_int64(const int64_t *n1, const int64_t *n2);

    /* comparator for 32 bits integer */
    int array_compare_element_int32(const int32_t *n1, const int32_t *n2);

    /* comparator for id name pair (sorted by id) */
    int array_compare_element_id_name(const id_name_pair_t *pair1,
            const id_name_pair_t *pair2);

#define array_allocator_init(ctx, name_prefix, \
        element_size, min_bits, max_bits)      \
    array_allocator_init_ex(ctx, name_prefix,  \
        element_size, min_bits, max_bits, true)

#define i64_array_allocator_init_ex(ctx, min_bits, max_bits, need_lock) \
    array_allocator_init_ex(ctx, "i64", sizeof(int64_t), \
            min_bits, max_bits, need_lock)

#define i64_array_allocator_init(ctx, min_bits, max_bits) \
        i64_array_allocator_init_ex(ctx, min_bits, max_bits, true)

#define i64_array_allocator_alloc(ctx, target_count) \
    (I64Array *)array_allocator_alloc(ctx, target_count)

#define i64_array_allocator_realloc(ctx, old_array, target_count) \
    (I64Array *)array_allocator_realloc(ctx, \
            (VoidArray *)old_array, target_count)

#define i64_array_allocator_free(ctx, array) \
    array_allocator_free(ctx, (VoidArray *)array)


#define i32_array_allocator_init_ex(ctx, min_bits, max_bits, need_lock) \
    array_allocator_init_ex(ctx, "i32", sizeof(int32_t), \
            min_bits, max_bits, need_lock)

#define i32_array_allocator_init(ctx, min_bits, max_bits) \
        i32_array_allocator_init_ex(ctx, min_bits, max_bits, true)

#define i32_array_allocator_alloc(ctx, target_count) \
    (I32Array *)array_allocator_alloc(ctx, target_count)

#define i32_array_allocator_realloc(ctx, old_array, target_count) \
    (I32Array *)array_allocator_realloc(ctx, \
            (VoidArray *)old_array, target_count)

#define i32_array_allocator_free(ctx, array) \
    array_allocator_free(ctx, (VoidArray *)array)


#define id_name_array_allocator_init_ex(ctx, min_bits, max_bits, need_lock) \
    array_allocator_init_ex(ctx, "id_name", sizeof(id_name_pair_t), \
            min_bits, max_bits, need_lock)

#define id_name_array_allocator_init(ctx, min_bits, max_bits) \
    id_name_array_allocator_init_ex(ctx, min_bits, max_bits, true)

#define id_name_array_allocator_alloc(ctx, target_count) \
    (IdNameArray *)array_allocator_alloc(ctx, target_count)

#define id_name_array_allocator_realloc(ctx, old_array, target_count) \
    (IdNameArray *)array_allocator_realloc(ctx, \
            (VoidArray *)old_array, target_count)

#define id_name_array_allocator_free(ctx, array) \
    array_allocator_free(ctx, (VoidArray *)array)


#define ptr_array_allocator_init_ex(ctx, min_bits, max_bits, need_lock) \
    array_allocator_init_ex(ctx, "ptr", sizeof(void *), \
            min_bits, max_bits, need_lock)

#define ptr_array_allocator_init(ctx, min_bits, max_bits) \
        ptr_array_allocator_init_ex(ctx, min_bits, max_bits, true)

#define ptr_array_allocator_alloc(ctx, target_count) \
    (PointerArray *)array_allocator_alloc(ctx, target_count)

#define ptr_array_allocator_realloc(ctx, old_array, target_count) \
    (PointerArray *)array_allocator_realloc(ctx, \
            (VoidArray *)old_array, target_count)

#define ptr_array_allocator_free(ctx, array) \
    array_allocator_free(ctx, (VoidArray *)array)

#ifdef __cplusplus
}
#endif

#endif
