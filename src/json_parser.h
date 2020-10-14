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

#ifndef _JSON_PARSER_H
#define _JSON_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"

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
        char *buff;        \
    } ARRAY_TYPE

DEFINE_ARRAY_STRUCT(void, common_array_t);
DEFINE_ARRAY_STRUCT(string_t, json_array_t);
DEFINE_ARRAY_STRUCT(key_value_pair_t, json_map_t);

#ifdef __cplusplus
extern "C" {
#endif

    void free_common_array(common_array_t *array);

    static inline void free_json_array(json_array_t *array)
    {
        free_common_array((common_array_t *)array);
    }

    static inline void free_json_map(json_map_t *array)
    {
        free_common_array((common_array_t *)array);
    }

    static inline void free_json_string(string_t *buffer)
    {
        if (buffer->str != NULL) {
            free(buffer->str);
            buffer->str = NULL;
            buffer->len = 0;
        }
    }

    int detect_json_type(const string_t *input);

    int decode_json_array(const string_t *input, json_array_t *array,
            char *error_info, const int error_size);

    int encode_json_array(json_array_t *array, string_t *output,
            char *error_info, const int error_size);

    int decode_json_map(const string_t *input, json_map_t *map,
            char *error_info, const int error_size);

    int encode_json_map(json_map_t *map, string_t *output,
            char *error_info, const int error_size);

#ifdef __cplusplus
}
#endif

#endif

