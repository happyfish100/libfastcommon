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

#ifndef __FAST_BUFFER_H__
#define __FAST_BUFFER_H__

#include <stdint.h>
#include "shared_func.h"

typedef struct fast_buffer {
    char *data;
    int alloc_size;
    int length;
    bool binary_mode;
    bool check_capacity;
} FastBuffer;

#ifdef __cplusplus
extern "C" {
#endif

static inline int fast_buffer_length(FastBuffer *buffer)
{
    return buffer->length;
}

static inline char *fast_buffer_data(FastBuffer *buffer)
{
    return buffer->data;
}

int fast_buffer_init_ex(FastBuffer *buffer, const int init_capacity,
        const bool binary_mode, const bool check_capacity);

static inline int fast_buffer_init1(FastBuffer *buffer, const int init_capacity)
{
    const bool binary_mode = false;
    const bool check_capacity = true;
    return fast_buffer_init_ex(buffer, init_capacity,
            binary_mode, check_capacity);
}

static inline int fast_buffer_init(FastBuffer *buffer)
{
    const int init_capacity = 0;
    return fast_buffer_init1(buffer, init_capacity);
}

#define fast_buffer_set_null_terminator(buffer)  \
    if (!buffer->binary_mode) *(buffer->data + buffer->length) = '\0'

#define fast_buffer_check(buffer, inc_len)   \
    ((buffer)->check_capacity ? fast_buffer_check_inc_size(buffer, inc_len) : 0)

#define fast_buffer_clear(buffer) fast_buffer_reset(buffer)

static inline void fast_buffer_reset(FastBuffer *buffer)
{
    buffer->length = 0;
    fast_buffer_set_null_terminator(buffer);
}

void fast_buffer_destroy(FastBuffer *buffer);

int fast_buffer_set_capacity(FastBuffer *buffer, const int capacity);

static inline int fast_buffer_check_capacity(FastBuffer *buffer,
        const int capacity)
{
    if (buffer->alloc_size >= capacity)
    {
        return 0;
    }

    return fast_buffer_set_capacity(buffer, capacity);
}

static inline int fast_buffer_check_inc_size(FastBuffer *buffer,
        const int inc_size)
{
    return fast_buffer_check_capacity(buffer, buffer->length + inc_size);
}

int fast_buffer_append(FastBuffer *buffer, const char *format, ...);

int fast_buffer_append_buff(FastBuffer *buffer,
        const char *data, const int len);

int fast_buffer_append_binary(FastBuffer *buffer,
        const void *data, const int len);

static inline int fast_buffer_append_char(FastBuffer *buffer, const char ch)
{
    int result;

    if ((result=fast_buffer_check(buffer, 1)) != 0)
    {
        return result;
    }

    *(buffer->data + buffer->length++) = ch;
    fast_buffer_set_null_terminator(buffer);
    return 0;
}

static inline int fast_buffer_append_int(FastBuffer *buffer, const int n)
{
    int result;

    if ((result=fast_buffer_check(buffer, 16)) != 0)
    {
        return result;
    }

    buffer->length += fc_itoa(n, buffer->data + buffer->length);
    fast_buffer_set_null_terminator(buffer);
    return 0;
}

static inline int fast_buffer_append_int64(FastBuffer *buffer, const int64_t n)
{
    int result;

    if ((result=fast_buffer_check(buffer, 32)) != 0)
    {
        return result;
    }

    buffer->length += fc_itoa(n, buffer->data + buffer->length);
    fast_buffer_set_null_terminator(buffer);
    return 0;
}

int fast_buffer_append_file(FastBuffer *buffer, const char *filename);

static inline int fast_buffer_append_string(FastBuffer *buffer, const char *str)
{
    return fast_buffer_append_buff(buffer, str, strlen(str));
}

static inline int fast_buffer_append_string2(FastBuffer *buffer, const string_t *add)
{
    return fast_buffer_append_buff(buffer, add->str, add->len);
}

static inline int fast_buffer_append_buffer(FastBuffer *buffer, FastBuffer *src)
{
    return fast_buffer_append_buff(buffer, src->data, src->length);
}

#ifdef __cplusplus
}
#endif

#endif
