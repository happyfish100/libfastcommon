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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include <assert.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/array_allocator.h"
#include "fastcommon/sorted_array.h"

#define  ELEMENT_COUNT  64 * 1024

static bool silence;

static int test_i64()
{
    const int min_bits = 2;
    const int max_bits = 16;
    const bool allow_duplication = false;
    int result;
    int i;
    int index;
    int last_index;
    int64_t tmp;
    int64_t start_time;
    ArrayAllocatorContext allocator_ctx;
    SortedArrayContext sarray_ctx;
    I64Array *input;
    I64Array *output;

    start_time = get_current_time_us();

    sorted_i64_array_init(&sarray_ctx, allow_duplication);
    if ((result=i64_array_allocator_init(&allocator_ctx,
                    min_bits, max_bits)) != 0)
    {
        return result;
    }

    if ((input=i64_array_allocator_alloc(&allocator_ctx,
                    ELEMENT_COUNT)) == NULL)
    {
        return ENOMEM;
    }
    if ((output=i64_array_allocator_alloc(&allocator_ctx,
                    ELEMENT_COUNT)) == NULL)
    {
        return ENOMEM;
    }

    input->count = ELEMENT_COUNT;
    for (i=0; i<input->count; i++) {
        input->elts[i] = i + 1;
    }

    last_index = ELEMENT_COUNT - 1;
    for (i=0; i<ELEMENT_COUNT / 10; i++) {
        index = (int64_t)rand() * last_index / (int64_t)RAND_MAX;
        tmp = input->elts[index];
        input->elts[index] = input->elts[last_index - index];
        input->elts[last_index - index] = tmp;
    }

    for (i=0; i<input->count; i++) {
        sorted_array_insert(&sarray_ctx, output->elts,
                &output->count, input->elts + i);
    }

    assert(output->count == ELEMENT_COUNT);
    for (i=0; i<output->count; i++) {
        assert(output->elts[i] == i + 1);
    }

    for (i=last_index; i>=0; i--) {
        sorted_array_delete(&sarray_ctx, output->elts,
                &output->count, input->elts + i);
    }
    assert(output->count == 0);

    i64_array_allocator_free(&allocator_ctx, input);
    i64_array_allocator_free(&allocator_ctx, output);

    if (!silence) {
        printf("test i64 time used: %"PRId64" us\n",
                get_current_time_us() - start_time);
    }
    return 0;
}

static int test_i32()
{
    const int min_bits = 2;
    const int max_bits = 16;
    const bool allow_duplication = false;
    int result;
    int i;
    int index;
    int last_index;
    int32_t tmp;
    int64_t start_time;
    ArrayAllocatorContext allocator_ctx;
    SortedArrayContext sarray_ctx;
    I32Array *input;
    I32Array *output;

    start_time = get_current_time_us();

    sorted_i32_array_init(&sarray_ctx, allow_duplication);
    if ((result=i32_array_allocator_init(&allocator_ctx,
                    min_bits, max_bits)) != 0)
    {
        return result;
    }

    if ((input=i32_array_allocator_alloc(&allocator_ctx,
                    ELEMENT_COUNT)) == NULL)
    {
        return ENOMEM;
    }
    if ((output=i32_array_allocator_alloc(&allocator_ctx,
                    ELEMENT_COUNT)) == NULL)
    {
        return ENOMEM;
    }

    input->count = ELEMENT_COUNT;
    for (i=0; i<input->count; i++) {
        input->elts[i] = i + 1;
    }

    last_index = ELEMENT_COUNT - 1;
    for (i=0; i<input->count; i++) {
        index = (int64_t)rand() * last_index / (int64_t)RAND_MAX;
        tmp = input->elts[index];
        input->elts[index] = input->elts[last_index - index];
        input->elts[last_index - index] = tmp;
    }

    for (i=0; i<input->count; i++) {
        sorted_array_insert(&sarray_ctx, output->elts,
                &output->count, input->elts + i);
    }

    assert(output->count == ELEMENT_COUNT);
    for (i=0; i<output->count; i++) {
        assert(output->elts[i] == i + 1);
    }

    for (i=last_index; i>=0; i--) {
        sorted_array_delete(&sarray_ctx, output->elts,
                &output->count, input->elts + i);
    }
    assert(output->count == 0);

    i32_array_allocator_free(&allocator_ctx, input);
    i32_array_allocator_free(&allocator_ctx, output);

    if (!silence) {
        printf("test i32 time used: %"PRId64" us\n",
                get_current_time_us() - start_time);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int result;
    int ch;

    srand(time(NULL));
    log_init();

    while ((ch=getopt(argc, argv, "s")) != -1) {
        switch (ch) {
            case 's':
                silence = true;
                break;
            default:
                break;
        }
    }

    if ((result=test_i64()) != 0) {
        return result;
    }

    if ((result=test_i32()) != 0) {
        return result;
    }

    return 0;
}
