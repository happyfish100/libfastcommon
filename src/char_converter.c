/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

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
    unsigned char src;
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
        src = charPairs[i].src;
        pCharConverter->char_table[src].op = op;
        pCharConverter->char_table[src].dest = charPairs[i].dest;
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

    pairs[0].src = '\0'; pairs[0].dest = '0';
    pairs[1].src = '\t'; pairs[1].dest = 't';
    pairs[2].src = '\n'; pairs[2].dest = 'n';
    pairs[3].src = '\v'; pairs[3].dest = 'v';
    pairs[4].src = '\f'; pairs[4].dest = 'f';
    pairs[5].src = '\r'; pairs[5].dest = 'r';
    pairs[6].src = ' ';  pairs[6].dest = '-';
    pairs[7].src = '\\'; pairs[7].dest = '\\';

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
            logDebug("file: "__FILE__", line: %d, "
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

