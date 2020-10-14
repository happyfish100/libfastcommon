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
#include <errno.h>
#include "logger.h"
#include "shared_func.h"
#include "char_converter.h"

int char_converter_init_ex(FastCharConverter *pCharConverter,
        const FastCharPair *charPairs, const int count,
        const unsigned op)
{
    int i;
    unsigned char from;
    unsigned char to;
    if (count > FAST_MAX_CHAR_COUNT)
    {
		logError("file: "__FILE__", line: %d, "
                "count: %d is too large, exceeds %d!", __LINE__,
                count, FAST_MAX_CHAR_COUNT);
        return EINVAL;
    }

    memset(pCharConverter, 0, sizeof(FastCharConverter));
    pCharConverter->count = count;
    for (i=0; i<count; i++)
    {
        from = charPairs[i].src;
        to = charPairs[i].dest;
        pCharConverter->char_table[from].op = op;
        pCharConverter->char_table[from].dest = to;

        pCharConverter->unescape_chars[to].op = op;
        pCharConverter->unescape_chars[to].dest = from;
    }

    return 0;
}

int std_space_char_converter_init(FastCharConverter *pCharConverter,
        const unsigned char dest_base)
{
#define SPACE_CHAR_PAIR_COUNT1 7
    int i;
    FastCharPair pairs[SPACE_CHAR_PAIR_COUNT1];

    pairs[0].src = '\0';
    pairs[1].src = '\t';
    pairs[2].src = '\n';
    pairs[3].src = '\v';
    pairs[4].src = '\f';
    pairs[5].src = '\r';
    pairs[6].src = ' ';

    for (i=0; i<SPACE_CHAR_PAIR_COUNT1; i++) {
        pairs[i].dest = dest_base + i;
    }

    return char_converter_init(pCharConverter, pairs, SPACE_CHAR_PAIR_COUNT1);
}

int std_spaces_add_backslash_converter_init(FastCharConverter *pCharConverter)
{
#define SPACE_CHAR_PAIR_COUNT2 8
    FastCharPair pairs[SPACE_CHAR_PAIR_COUNT2];

    FAST_CHAR_MAKE_PAIR(pairs[0], '\0', '0');
    FAST_CHAR_MAKE_PAIR(pairs[1], '\t', 't');
    FAST_CHAR_MAKE_PAIR(pairs[2], '\n', 'n');
    FAST_CHAR_MAKE_PAIR(pairs[3], '\v', 'v');
    FAST_CHAR_MAKE_PAIR(pairs[4], '\f', 'f');
    FAST_CHAR_MAKE_PAIR(pairs[5], '\r', 'r');
    FAST_CHAR_MAKE_PAIR(pairs[6], ' ',  's');
    FAST_CHAR_MAKE_PAIR(pairs[7], '\\', '\\');

    return char_converter_init_ex(pCharConverter, pairs,
            SPACE_CHAR_PAIR_COUNT2, FAST_CHAR_OP_ADD_BACKSLASH);
}

void char_converter_set_pair(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned char dest)
{
    char_converter_set_pair_ex(pCharConverter, src,
            FAST_CHAR_OP_NO_BACKSLASH, dest);
}

void char_converter_set_pair_ex(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned op, const unsigned char dest)
{
    if (op == FAST_CHAR_OP_NONE) {
        if (pCharConverter->char_table[src].op != FAST_CHAR_OP_NONE) {
            --pCharConverter->count;
        }
    } else {
        if (pCharConverter->char_table[src].op == FAST_CHAR_OP_NONE) {
            ++pCharConverter->count;
        }
    }

    pCharConverter->char_table[src].op = op;
    pCharConverter->char_table[src].dest = dest;
}

int fast_char_convert(FastCharConverter *pCharConverter,
        const char *input, const int input_len,
        char *output, int *out_len, const int out_size)
{
    int count;
    unsigned char *pi;
    unsigned char *po;
    unsigned char *end;
    int out_size_sub1;

    count = 0;
    po = (unsigned char *)output;
    if (out_size >= input_len) {
        end = (unsigned char *)input + input_len;
    } else {
        end = (unsigned char *)input + out_size;
    }
    for (pi=(unsigned char *)input; pi<end; pi++) {
        if (pCharConverter->char_table[*pi].op != FAST_CHAR_OP_NONE) {
            if (pCharConverter->char_table[*pi].op == FAST_CHAR_OP_ADD_BACKSLASH) {
                break;
            }

            *po++ = pCharConverter->char_table[*pi].dest;
            ++count;
        } else {
            *po++ = *pi;
        }
    }

    if (pi == end) {
        *out_len = po - (unsigned char *)output;
        return count;
    }

    out_size_sub1 = out_size - 1;
    for (; pi<end; pi++) {
        if (po - (unsigned char *)output >= out_size_sub1) {
            logWarning("file: "__FILE__", line: %d, "
                    "exceeds max size: %d", __LINE__, out_size);
            break;
        }
        if (pCharConverter->char_table[*pi].op != FAST_CHAR_OP_NONE) {
            if (pCharConverter->char_table[*pi].op == FAST_CHAR_OP_ADD_BACKSLASH) {
                *po++ = '\\';
            }

            *po++ = pCharConverter->char_table[*pi].dest;
            ++count;
        } else {
            *po++ = *pi;
        }
    }

    *out_len = po - (unsigned char *)output;
    return count;
}

int fast_char_unescape(FastCharConverter *pCharConverter, char *str, int *len)
{
    int count;
    unsigned char *backslash;
    unsigned char *p;
    unsigned char *end;
    unsigned char *dest;

    backslash = (unsigned char *)memchr(str, '\\', *len);
    if (backslash == NULL) {
        return 0;
    }

    count = 0;
    end = (unsigned char *)str + *len;
    p = dest = backslash;
    while (p < end) {
        if (*p == '\\') {
            if (p + 1 < end) {
                if (pCharConverter->unescape_chars[p[1]].op ==
                        FAST_CHAR_OP_ADD_BACKSLASH)
                {
                    *dest++ = pCharConverter->unescape_chars[p[1]].dest;
                    p += 2;
                    ++count;
                } else {
                    *dest++ = *p++;
                }
            } else {
                *dest++ = *p++;
            }
        } else if (pCharConverter->unescape_chars[*p].op ==
                FAST_CHAR_OP_NO_BACKSLASH)
        {
            *dest++ = pCharConverter->unescape_chars[*p++].dest;
            ++count;
        } else {
            *dest++ = *p++;
        }
    }

    *len = dest - (unsigned char *)str;
    return count;
}
