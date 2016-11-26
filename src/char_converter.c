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

int char_converter_init(FastCharConverter *pCharConverter,
        const FastCharPair *charPairs, const int count)
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
        pCharConverter->char_table[src].op = FAST_CHAR_OP_NO_BACKSLASH;
        pCharConverter->char_table[src].dest = charPairs[i].dest;
    }
    return 0;
}

int std_space_char_converter_init(FastCharConverter *pCharConverter,
        const unsigned char dest_base)
{
#define SPACE_CHAR_PAIR_COUNT 7
    int i;
    FastCharPair pairs[SPACE_CHAR_PAIR_COUNT];

    pairs[0].src = '\0';
    pairs[1].src = '\t';
    pairs[2].src = '\n';
    pairs[3].src = '\v';
    pairs[4].src = '\f';
    pairs[5].src = '\r';
    pairs[6].src = ' ';

    for (i=0; i<SPACE_CHAR_PAIR_COUNT; i++) {
        pairs[i].dest = dest_base + i;
    }

    return char_converter_init(pCharConverter, pairs, SPACE_CHAR_PAIR_COUNT);
}

void char_converter_set_pair(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned char dest)
{
    char_converter_set_pair_ex(pCharConverter, src, FAST_CHAR_OP_NO_BACKSLASH, dest);
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
        char *text, int *text_len, const int max_size)
{
    int count;
    unsigned char *p;
    unsigned char *pi;
    unsigned char *end;
    char fixed_buff[16 * 1024];
    char *buff;
    int max_size_sub1;
    int remain_len;

    if (pCharConverter->count <= 0) {
        return 0;
    }

    count = 0;
    end = (unsigned char *)text + *text_len;
    for (p=(unsigned char *)text; p<end; p++)
    {
        if (pCharConverter->char_table[*p].op != FAST_CHAR_OP_NONE)
        {
            if (pCharConverter->char_table[*p].op == FAST_CHAR_OP_ADD_BACKSLASH) {
                break;
            }

            *p = pCharConverter->char_table[*p].dest;
            ++count;
        }
    }

    remain_len = end - p;
    if (remain_len == 0) {
        return count;
    }

    if (remain_len < sizeof(fixed_buff)) {
        buff = fixed_buff;
    } else {
        buff = (char *)malloc(remain_len);
        if (buff == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, remain_len);
            return count;
        }
    }
    memcpy(buff, p, remain_len);

    max_size_sub1 = max_size - 1;
    end = (unsigned char *)buff + remain_len;
    for (pi=(unsigned char *)buff; pi<end; pi++)
    {
        if (p - (unsigned char *)text >= max_size_sub1)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "exceeds max size: %d", __LINE__, max_size);
            break;
        }
        if (pCharConverter->char_table[*pi].op != FAST_CHAR_OP_NONE)
        {
            if (pCharConverter->char_table[*pi].op == FAST_CHAR_OP_ADD_BACKSLASH)
            {
                *p++ = '\\';
            }

            *p++ = pCharConverter->char_table[*pi].dest;
            ++count;
        }
        else
        {
            *p++ = *pi;
        }
    }

    if (buff != fixed_buff) {
        free(buff);
    }
    *text_len = p - (unsigned char *)text;
    return count;
}

