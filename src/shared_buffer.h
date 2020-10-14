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

#ifndef __SHARED_BUFFER_H__
#define __SHARED_BUFFER_H__

#include <stdint.h>
#include "common_define.h"
#include "fast_mblock.h"
#include "logger.h"

typedef struct shared_buffer_context {
    struct fast_mblock_man allocator;
    int buffer_init_capacity;
} SharedBufferContext;

typedef struct shared_buffer {
    char *buff;
    int capacity;
    int length;
    volatile int reffer_count;
    SharedBufferContext *ctx;
} SharedBuffer;

#ifdef __cplusplus
extern "C" {
#endif

#define shared_buffer_init(context, alloc_elements_once, buffer_init_capacity) \
    shared_buffer_init_ex(context, alloc_elements_once, \
            buffer_init_capacity, true)

int shared_buffer_init_ex(SharedBufferContext *context,
        const int alloc_elements_once, const int buffer_init_capacity,
        const bool need_lock);

void shared_buffer_destroy(SharedBufferContext *context);

static inline SharedBuffer *shared_buffer_alloc_ex(SharedBufferContext *context,
        const int init_reffer_count)
{
    SharedBuffer *buffer;
    if ((buffer=(SharedBuffer *)fast_mblock_alloc_object(
                    &context->allocator)) != NULL)
    {
        if (init_reffer_count > 0) {
            __sync_add_and_fetch(&buffer->reffer_count, init_reffer_count);
        }
    }
    return buffer;
}

static inline SharedBuffer *shared_buffer_alloc(SharedBufferContext *context)
{
    return (SharedBuffer *)fast_mblock_alloc_object(&context->allocator);
}

static inline void shared_buffer_hold(SharedBuffer *buffer)
{
    __sync_add_and_fetch(&buffer->reffer_count, 1);
}

static inline void shared_buffer_release(SharedBuffer *buffer)
{
    if (__sync_sub_and_fetch(&buffer->reffer_count, 1) == 0) {
        /*
        logDebug("file: "__FILE__", line: %d, "
                "free shared buffer: %p", __LINE__, buffer);
                */
        fast_mblock_free_object(&buffer->ctx->allocator, buffer);
    }
}

static inline int shared_buffer_check_capacity(SharedBuffer *buffer,
        const int target_capacity)
{
    char *buff;
    if (buffer->capacity >= target_capacity) {
        return 0;
    }

    buff = (char *)fc_malloc(target_capacity);
    if (buff == NULL) {
        return ENOMEM;
    }

    if (buffer->buff != NULL) {
        free(buffer->buff);
    }
    buffer->buff = buff;
    buffer->capacity = target_capacity;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif

