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

#include "shared_func.h"
#include "array_allocator.h"

int array_allocator_init(ArrayAllocatorContext *ctx,
        const char *name_prefix, const int element_size,
        const int min_bits, const int max_bits)
{
    const int reclaim_interval = 0;
    char name[32];
    struct fast_region_info regions[32];
    struct fast_region_info *region;
    int bit;
    int start;
    int end;
    int alloc_elements_once;
    int step;

    ctx->element_size = element_size;
    ctx->min_count = (1 << min_bits);
    start = 0;
    alloc_elements_once = (1 << (max_bits - min_bits + 2));
    for (bit=min_bits, region=regions;
            bit<=max_bits; bit++, region++)
    {
        end = sizeof(VoidArray) + (1 << bit) * ctx->element_size;
        step = end - start;
        FAST_ALLOCATOR_INIT_REGION(*region, start,
                end, step, alloc_elements_once);
        alloc_elements_once /= 2;
        start = end;
    }

    snprintf(name, sizeof(name), "%s-array", name_prefix);
    return fast_allocator_init_ex(&ctx->allocator,
            name, regions, region - regions, 0,
            0.9999, reclaim_interval, true);
}

VoidArray *array_allocator_alloc(ArrayAllocatorContext *ctx,
        const int target_count)
{
    int alloc;
    int bytes;

    if (target_count <= ctx->min_count) {
        alloc = ctx->min_count;
    } else if (is_power2(target_count)) {
        alloc = target_count;
    } else {
        alloc = ctx->min_count;
        while (alloc < target_count) {
            alloc *= 2;
        }
    }

    bytes = sizeof(VoidArray) + alloc * ctx->element_size;
    return (VoidArray *)fast_allocator_alloc(&ctx->allocator, bytes);
}
