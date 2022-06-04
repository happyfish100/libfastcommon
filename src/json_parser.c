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
            case '\b':
                *dest++ = '\\';
                *dest++ = 'b';
                break;
            case '\f':
                *dest++ = '\\';
                *dest++ = 'f';
                break;
            case '\"':
                *dest++ = '\\';
                *dest++ = '\"';
                break;
            case '\0':
                *dest++ = '\\';
                *dest++ = 'u';
                *dest++ = '0';
                *dest++ = '0';
                *dest++ = '0';
                *dest++ = '0';
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
    const char *start;
    char buff[128];
    char quote_ch;
    int unicode;
    int i;

    dest = context->decode.element.str;
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

                if (*context->p == 'u') {  //unicode
                    start = ++context->p;  //skip charator 'u'
                    i = 0;
                    while (i < 4 && context->p < context->end &&
                            IS_HEX_CHAR(*context->p))
                    {
                        buff[i++] = *context->p;
                        ++context->p;
                    }
                    if (i != 4) {
                        set_parse_error(context->str, start,
                                EXPECT_STR_LEN, "expect 4 hex characters "
                                "after \\u", &context->error_info,
                                context->error_size);
                        return EINVAL;
                    }

                    buff[i] = '\0';
                    unicode = strtol(buff, NULL, 16);
                    if (unicode < 0x80) {
                        *dest++ = unicode;
                    } else if (unicode < 0x800) {
                        *dest++ = 0xC0 | ((unicode >> 6) & 0x1F);
                        *dest++ = 0x80 | (unicode & 0x3F);
                    } else {
                        *dest++ = 0xE0 | ((unicode >> 12) & 0x0F);
                        *dest++ = 0x80 | ((unicode >> 6) & 0x3F);
                        *dest++ = 0x80 | (unicode & 0x3F);
                    }
                    continue;
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
                    case 'b':
                        *dest++ = '\b';
                        break;
                    case '"':
                        *dest++ = '\"';
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
    context->decode.element.len = dest - context->decode.element.str;
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

    context->decode.element.str = context->output.buff;
    context->decode.element.len = 0;
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

int fc_encode_json_array_ex(fc_json_context_t *context,
        const string_t *elements, const int count,
        BufferInfo *buffer)
{
    const string_t *el;
    const string_t *end;
    char *p;
    int expect_size;

    expect_size = 3;
    end = elements + count;
    for (el=elements; el<end; el++) {
        expect_size += 6 * el->len + 3;
    }

    if (buffer->alloc_size < expect_size) {
        if ((context->error_no=fc_realloc_buffer(buffer, context->
                        init_buff_size, expect_size)) != 0)
        {
            context->error_info.len = snprintf(context->error_info.str,
                    context->error_size, "realloc buffer fail");
            return context->error_no;
        }
    }

    p = buffer->buff;
    *p++ = '[';
    for (el=elements; el<end; el++) {
        if (el > elements) {
            *p++ = ',';
        }

        json_quote_string(context, el, &p);
    }

    *p++ = ']';
    *p = '\0';
    buffer->length = p - buffer->buff;
    return 0;
}

int fc_encode_json_map_ex(fc_json_context_t *context,
        const key_value_pair_t *elements, const int count,
        BufferInfo *buffer)
{
    const key_value_pair_t *pair;
    const key_value_pair_t *end;
    char *p;
    int expect_size;

    expect_size = 3;
    end = elements + count;
    for (pair=elements; pair<end; pair++) {
        expect_size += 6 * (pair->key.len + pair->value.len) + 5;
    }

    if (buffer->alloc_size < expect_size) {
        if ((context->error_no=fc_realloc_buffer(buffer, context->
                        init_buff_size, expect_size)) != 0)
        {
            context->error_info.len = snprintf(context->error_info.str,
                    context->error_size, "realloc buffer fail");
            return context->error_no;
        }
    }

    p = buffer->buff;
    *p++ = '{';
    for (pair=elements; pair<end; pair++) {
        if (pair > elements) {
            *p++ = ',';
        }

        json_quote_string(context, &pair->key, &p);
        *p++ = ':';
        json_quote_string(context, &pair->value, &p);
    }

    *p++ = '}';
    *p = '\0';
    buffer->length = p - buffer->buff;
    return 0;
}

#define JSON_DECODE_COPY_STRING(ctx, input, dest, src) \
    do { \
        if ((context->error_no=fast_mpool_alloc_string_ex2(   \
                        &ctx->decode.mpool, dest, src)) != 0) \
        { \
            set_parse_error(input->str, ctx->p, EXPECT_STR_LEN, \
                    "out of memory", &ctx->error_info, ctx->error_size); \
            return NULL; \
        } \
    } while (0)


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

        if (context->decode.use_mpool) {
            JSON_DECODE_COPY_STRING(context, input, context->jarray.elements +
                    context->jarray.count++, &context->decode.element);
        } else {
            context->jarray.elements[context->jarray.count++] =
                context->decode.element;
        }
        context->decode.element.str += context->decode.element.len + 1;
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

        kv_pair.key = context->decode.element;
        context->decode.element.str += context->decode.element.len + 1;

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

        kv_pair.value = context->decode.element;
        context->decode.element.str += context->decode.element.len + 1;

        if ((context->error_no=check_alloc_array(context,
                        (fc_common_array_t *)
                        &context->jmap)) != 0)
        {
            return NULL;
        }

        if (context->decode.use_mpool) {
            key_value_pair_t *dest;
            dest = context->jmap.elements + context->jmap.count++;
            JSON_DECODE_COPY_STRING(context, input,
                    &dest->key, &kv_pair.key);
            JSON_DECODE_COPY_STRING(context, input,
                    &dest->value, &kv_pair.value);
        } else {
            context->jmap.elements[context->jmap.count++] = kv_pair;
        }
    }

    return &context->jmap;
}
