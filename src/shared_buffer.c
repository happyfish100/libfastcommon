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
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include "shared_buffer.h"

static int shared_buffer_alloc_init(void *element, void *args)
{
    SharedBuffer *buffer;
    SharedBufferContext *ctx;

    buffer = (SharedBuffer *)element;
    ctx = (SharedBufferContext *)args;
    buffer->ctx = ctx;

    return shared_buffer_check_capacity(buffer,
            ctx->buffer_init_capacity);
}

int shared_buffer_init_ex(SharedBufferContext *context,
        const int alloc_elements_once, const int buffer_init_capacity,
        const bool need_lock)
{
    const int64_t alloc_elements_limit = 0;
    int result;

    context->buffer_init_capacity = buffer_init_capacity;
    if ((result=fast_mblock_init_ex1(&context->allocator, "shared-buffer",
                    sizeof(SharedBuffer), alloc_elements_once,
                    alloc_elements_limit, shared_buffer_alloc_init,
                    context, need_lock)) != 0)
    {
        return result;
    }

    return 0;
}

void shared_buffer_destroy(SharedBufferContext *context)
{
    fast_mblock_destroy(&context->allocator);
}
