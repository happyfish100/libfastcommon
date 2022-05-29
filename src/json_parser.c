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

#include <unistd.h>
#include <errno.h>
#include "shared_func.h"
#include "fc_memory.h"
#include "json_parser.h"

#define EXPECT_STR_LEN   80

#define JSON_SPACE(ch) \
    (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')

#define JSON_TOKEN(ch) \
    ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || \
     (ch >= '0' && ch <= '9') || (ch == '_' || ch == '-'  || \
         ch == '.'))

int fc_detect_json_type(const string_t *input)
{
    if (input->len < 2) {
        return FC_JSON_TYPE_STRING;
    }

    if (input->str[0] == '[' && input->str[input->len - 1] == ']') {
        return FC_JSON_TYPE_ARRAY;
    }
    if (input->str[0] == '{' && input->str[input->len - 1] == '}') {
        return FC_JSON_TYPE_MAP;
    }

    return FC_JSON_TYPE_STRING;
}

static void set_parse_error(const char *str, const char *current,
        const int expect_len, const char *front,
        string_t *error_info, const int error_size)
{
    const char *show_str;
    int show_len;

    show_len = current - str;
    if (show_len > expect_len) {
        show_len = expect_len;
    }
    show_str = current - show_len;
    error_info->len = snprintf(error_info->str, error_size,
            "%s, input: %.*s", front, show_len, show_str);
}

static int json_escape_string(fc_json_context_t *context,
        const string_t *input, char *output)
{
    const char *src;
    const char *end;
    char *dest;

    dest = output;
    end = input->str + input->len;
    for (src=input->str; src<end; src++) {
        switch (*src) {
            case '\\':
                *dest++ = '\\';
                *dest++ = '\\';
                break;
            case '\t':
                *dest++ = '\\';
                *dest++ = 't';
                break;
            case '\r':
                *dest++ = '\\';
                *dest++ = 'r';
                break;
            case '\n':
                *dest++ = '\\';
                *dest++ = 'n';
                break;
            case '\f':
                *dest++ = '\\';
                *dest++ = 'f';
                break;
            case '\"':
                *dest++ = '\\';
                *dest++ = '\"';
                break;
            case '\'':
                *dest++ = '\\';
                *dest++ = '\'';
                break;
            default:
                *dest++ = *src;
                break;
        }
    }

    return dest - output;
}

static int next_json_element(fc_json_context_t *context)
{
    char *dest;
    char buff[128];
    char quote_ch;

    dest = context->element.str;
    quote_ch = *context->p;
    if (quote_ch == '\"' || quote_ch == '\'') {
        context->p++;
        while (context->p < context->end && *context->p != quote_ch) {
            if (*context->p == '\\') {
                if (++context->p == context->end) {
                    set_parse_error(context->str, context->p,
                            EXPECT_STR_LEN, "expect a character after \\",
                            &context->error_info, context->error_size);
                    return EINVAL;
                }
                switch (*context->p) {
                    case '\\':
                        *dest++ = '\\';
                        break;
                    case '/':
                        *dest++ = '/';
                        break;
                    case 't':
                        *dest++ = '\t';
                        break;
                    case 'r':
                        *dest++ = '\r';
                        break;
                    case 'n':
                        *dest++ = '\n';
                        break;
                    case 'f':
                        *dest++ = '\f';
                        break;
                    case '"':
                        *dest++ = '\"';
                        break;
                    case '\'':
                        *dest++ = '\'';
                        break;
                    default:
                        sprintf(buff, "invalid escaped character: %c(0x%x)",
                                *context->p, (unsigned char)*context->p);
                        set_parse_error(context->str, context->p + 1,
                                EXPECT_STR_LEN, buff, &context->error_info,
                                context->error_size);
                        return EINVAL;
                }
                context->p++;
            } else {
                *dest++ = *context->p++;
            }
        }

        if (context->p == context->end) {
            sprintf(buff, "expect closed character: %c", quote_ch);
            set_parse_error(context->str, context->p, EXPECT_STR_LEN,
                    buff, &context->error_info, context->error_size);
            return EINVAL;
        }
        context->p++; //skip quote char
    } else {
        while (context->p < context->end && JSON_TOKEN(*context->p)) {
            *dest++ = *context->p++;
        }
    }

    *dest = '\0';
    context->element.len = dest - context->element.str;
    return 0;
}

static int check_alloc_array(fc_json_context_t *context,
        fc_common_array_t *array)
{
    int bytes;
    if (array->count < array->alloc) {
        return 0;
    }

    if (array->alloc == 0) {
        array->alloc = 32;
    } else {
        array->alloc *= 2;
    }

    bytes = array->element_size * array->alloc;
    array->elements = fc_realloc(array->elements, bytes);
    if (array->elements == NULL) {
        context->error_info.len = snprintf(context->error_info.str,
                context->error_size, "realloc %d bytes fail", bytes);
        return ENOMEM;
    }

    return 0;
}

static int prepare_json_parse(fc_json_context_t *context,
        const string_t *input, const char lquote,
        const char rquote)
{
    int expect_size;
    int result;

    if (input->len < 2) {
        context->error_info.len = snprintf(context->error_info.str,
                context->error_size, "json string is too short");
        return EINVAL;
    }

    if (input->str[0] != lquote) {
        context->error_info.len = snprintf(context->error_info.str, context->
                error_size, "json array must start with \"%c\"", lquote);
        return EINVAL;
    }
    if (input->str[input->len - 1] != rquote) {
        context->error_info.len = snprintf(context->error_info.str, context->
                error_size, "json array must end with \"%c\"", rquote);
        return EINVAL;
    }

    expect_size = input->len;
    if (context->output.alloc_size < expect_size) {
        if ((result=fc_realloc_buffer(&context->output, context->
                        init_buff_size, expect_size)) != 0)
        {
            context->error_info.len = snprintf(context->error_info.str,
                    context->error_size, "realloc buffer fail");
            return result;
        }
    }

    context->element.str = context->output.buff;
    context->element.len = 0;
    context->str = input->str;
    context->p = input->str + 1;
    context->end = input->str + input->len - 1;
    return 0;
}

static inline void json_quote_string(fc_json_context_t
        *context, const string_t *input, char **buff)
{
    char *p;

    p = *buff;
    *p++ = '"';
    p += json_escape_string(context, input, p);
    *p++ = '"';
    *buff = p;
}

const BufferInfo *fc_encode_json_array(fc_json_context_t
        *context, const fc_json_array_t *array)
{
    string_t *el;
    string_t *end;
    char *p;
    int expect_size;

    expect_size = 3;
    end = array->elements + array->count;
    for (el=array->elements; el<end; el++) {
        expect_size += 2 * el->len + 3;
    }

    if (context->output.alloc_size < expect_size) {
        if ((context->error_no=fc_realloc_buffer(&context->output,
                        context->init_buff_size, expect_size)) != 0)
        {
            context->error_info.len = snprintf(context->error_info.str,
                    context->error_size, "realloc buffer fail");
            return NULL;
        }
    }

    p = context->output.buff;
    *p++ = '[';
    for (el=array->elements; el<end; el++) {
        if (el > array->elements) {
            *p++ = ',';
        }

        json_quote_string(context, el, &p);
    }

    *p++ = ']';
    *p = '\0';
    context->output.length = p - context->output.buff;
    return &context->output;
}

const BufferInfo *fc_encode_json_map(fc_json_context_t
        *context, const fc_json_map_t *map)
{
    key_value_pair_t *pair;
    key_value_pair_t *end;
    char *p;
    int expect_size;

    expect_size = 3;
    end = map->elements + map->count;
    for (pair=map->elements; pair<end; pair++) {
        expect_size += 2 * (pair->key.len + pair->value.len + 2) + 1;
    }

    if (context->output.alloc_size < expect_size) {
        if ((context->error_no=fc_realloc_buffer(&context->output,
                        context->init_buff_size, expect_size)) != 0)
        {
            context->error_info.len = snprintf(context->error_info.str,
                    context->error_size, "realloc buffer fail");
            return NULL;
        }
    }

    p = context->output.buff;
    *p++ = '{';
    for (pair=map->elements; pair<end; pair++) {
        if (pair > map->elements) {
            *p++ = ',';
        }

        json_quote_string(context, &pair->key, &p);
        *p++ = ':';
        json_quote_string(context, &pair->value, &p);
    }

    *p++ = '}';
    *p = '\0';
    context->output.length = p - context->output.buff;
    return &context->output;
}

const fc_json_array_t *fc_decode_json_array(fc_json_context_t
        *context, const string_t *input)
{
    if ((context->error_no=prepare_json_parse(context,
                    input, '[', ']')) != 0)
    {
        return NULL;
    }

    context->jarray.count = 0;
    while (context->p < context->end) {
        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }

        if (context->p == context->end) {
            break;
        }

        if (*context->p == ',') {
            set_parse_error(input->str, context->p + 1,
                    EXPECT_STR_LEN, "unexpect comma \",\"",
                    &context->error_info, context->error_size);
            context->error_no = EINVAL;
            return NULL;
        }

        if ((context->error_no=next_json_element(context)) != 0) {
            return NULL;
        }

        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }
        if (context->p < context->end) {
            if (*context->p == ',') {
                context->p++;   //skip comma
            } else {
                set_parse_error(input->str, context->p,
                        EXPECT_STR_LEN, "expect comma \",\"",
                        &context->error_info, context->error_size);
                context->error_no = EINVAL;
                return NULL;
            }
        }

        if ((context->error_no=check_alloc_array(context,
                        (fc_common_array_t *)
                        &context->jarray)) != 0)
        {
            return NULL;
        }

        context->jarray.elements[context->jarray.count++] = context->element;
        context->element.str += context->element.len + 1;
    }

    return &context->jarray;
}

const fc_json_map_t *fc_decode_json_map(fc_json_context_t
        *context, const string_t *input)
{
    key_value_pair_t kv_pair;

    if ((context->error_no=prepare_json_parse(context,
                    input, '{', '}')) != 0)
    {
        return NULL;
    }

    context->jmap.count = 0;
    while (context->p < context->end) {
        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }

        if (context->p == context->end) {
            break;
        }

        if (*context->p == ',') {
            set_parse_error(input->str, context->p + 1,
                    EXPECT_STR_LEN, "unexpect comma \",\"",
                    &context->error_info, context->error_size);
            context->error_no = EINVAL;
            return NULL;
        }

        if ((context->error_no=next_json_element(context)) != 0) {
            return NULL;
        }
        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }
        if (!(context->p < context->end && *context->p == ':')) {
            set_parse_error(input->str, context->p,
                    EXPECT_STR_LEN, "expect colon \":\"",
                    &context->error_info, context->error_size);
            context->error_no = EINVAL;
            return NULL;
        }
        context->p++;   //skip colon

        kv_pair.key = context->element;
        context->element.str += context->element.len + 1;

        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }
        if ((context->error_no=next_json_element(context)) != 0) {
            return NULL;
        }
        while (context->p < context->end && JSON_SPACE(*context->p)) {
            context->p++;
        }
        if (context->p < context->end) {
            if (*context->p == ',') {
                context->p++;  //skip comma
            } else {
                set_parse_error(input->str, context->p,
                        EXPECT_STR_LEN, "expect comma \",\"",
                        &context->error_info, context->error_size);
                context->error_no = EINVAL;
                return NULL;
            }
        }

        kv_pair.value = context->element;
        context->element.str += context->element.len + 1;

        if ((context->error_no=check_alloc_array(context,
                        (fc_common_array_t *)
                        &context->jmap)) != 0)
        {
            return NULL;
        }
        context->jmap.elements[context->jmap.count++] = kv_pair;
    }

    return &context->jmap;
}
