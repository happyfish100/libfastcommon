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

//json_parser.h

#ifndef _FC_JSON_PARSER_H
#define _FC_JSON_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"
#include "shared_func.h"

#define FC_JSON_TYPE_STRING   1
#define FC_JSON_TYPE_ARRAY    2
#define FC_JSON_TYPE_MAP      3

#define DEFINE_ARRAY_STRUCT(ELEMENT_TYPE, ARRAY_TYPE) \
    typedef struct { \
        ELEMENT_TYPE *elements;  \
        int count;               \
                                 \
        /* for internal use */   \
        int element_size;  \
        int alloc;         \
    } ARRAY_TYPE

DEFINE_ARRAY_STRUCT(void, fc_common_array_t);
DEFINE_ARRAY_STRUCT(string_t, fc_json_array_t);
DEFINE_ARRAY_STRUCT(key_value_pair_t, fc_json_map_t);

typedef struct {
    BufferInfo output;  //for json encode
    string_t element;   //string allocator use output buffer
    int init_buff_size;
    int error_no;
    int error_size;
    char error_holder[256];
    string_t error_info;

    fc_json_array_t jarray;
    fc_json_map_t jmap;

    /* for internal use */
    const char *str;  //input string
    const char *p;    //current
    const char *end;
} fc_json_context_t;

#ifdef __cplusplus
extern "C" {
#endif

    static inline void fc_init_common_array(fc_common_array_t *array,
            const int element_size)
    {
        array->elements = NULL;
        array->element_size = element_size;
        array->count = array->alloc = 0;
    }

    static inline void fc_init_json_array(fc_json_array_t *array)
    {
        fc_init_common_array((fc_common_array_t *)array, sizeof(string_t));
    }

    static inline void fc_init_json_map(fc_json_map_t *array)
    {
        fc_init_common_array((fc_common_array_t *)array,
                sizeof(key_value_pair_t));
    }

    static inline void fc_free_common_array(fc_common_array_t *array)
    {
        if (array->elements != NULL) {
            free(array->elements);
            array->elements = NULL;
            array->count = array->alloc = 0;
        }
    }

    static inline void fc_free_json_array(fc_json_array_t *array)
    {
        fc_free_common_array((fc_common_array_t *)array);
    }

    static inline void fc_free_json_map(fc_json_map_t *array)
    {
        fc_free_common_array((fc_common_array_t *)array);
    }

    static inline void fc_set_json_error_buffer(fc_json_context_t *ctx,
            char *error_info, const int error_size)
    {
        if (error_info != NULL && error_size > 0) {
            ctx->error_info.str = error_info;
            ctx->error_size = error_size;
        } else {
            ctx->error_info.str = ctx->error_holder;
            ctx->error_size = sizeof(ctx->error_holder);
        }

        ctx->error_info.len = 0;
        *ctx->error_info.str = '\0';
    }

    static inline int fc_init_json_context_ex(fc_json_context_t *ctx,
            const int init_buff_size, char *error_info, const int error_size)
    {
        ctx->output.buff = NULL;
        ctx->output.alloc_size = ctx->output.length = 0;
        FC_SET_STRING_NULL(ctx->element);
        if (init_buff_size > 0) {
            ctx->init_buff_size = init_buff_size;
        } else {
            ctx->init_buff_size = 1024;
        }
        fc_init_json_array(&ctx->jarray);
        fc_init_json_map(&ctx->jmap);

        ctx->error_no = 0;
        fc_set_json_error_buffer(ctx, error_info, error_size);
        return 0;
    }

    static inline int fc_init_json_context(fc_json_context_t *ctx)
    {
        const int init_buff_size = 0;
        return fc_init_json_context_ex(ctx, init_buff_size, NULL, 0);
    }

    static inline void fc_destroy_json_context(fc_json_context_t *ctx)
    {
        fc_free_buffer(&ctx->output);
        fc_free_json_array(&ctx->jarray);
        fc_free_json_map(&ctx->jmap);
    }

    static inline int fc_json_parser_get_error_no(fc_json_context_t *ctx)
    {
        return ctx->error_no;
    }

    static inline const string_t *fc_json_parser_get_error_info(
            fc_json_context_t *ctx)
    {
        return &ctx->error_info;
    }

    int fc_detect_json_type(const string_t *input);

    int fc_encode_json_array_ex(fc_json_context_t *context,
            const string_t *elements, const int count,
            BufferInfo *buffer);

    int fc_encode_json_map_ex(fc_json_context_t *context,
            const key_value_pair_t *elements, const int count,
            BufferInfo *buffer);

    static inline const BufferInfo *fc_encode_json_array(fc_json_context_t
            *context, const string_t *elements, const int count)
    {
        if (fc_encode_json_array_ex(context, elements, count,
                    &context->output) == 0)
        {
            return &context->output;
        } else {
            return NULL;
        }
    }

    static inline const BufferInfo *fc_encode_json_map(fc_json_context_t
            *context, const key_value_pair_t *elements, const int count)
    {
        if (fc_encode_json_map_ex(context, elements, count,
                    &context->output) == 0)
        {
            return &context->output;
        } else {
            return NULL;
        }
    }

    const fc_json_array_t *fc_decode_json_array(fc_json_context_t
            *context, const string_t *input);

    const fc_json_map_t *fc_decode_json_map(fc_json_context_t
            *context, const string_t *input);

#ifdef __cplusplus
}
#endif

#endif
