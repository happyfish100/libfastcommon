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

//char_converter.h
#ifndef CHAR_CONVERTER_H
#define CHAR_CONVERTER_H

#include <syslog.h>
#include <sys/time.h>
#include "common_define.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FAST_MAX_CHAR_COUNT    256

#define FAST_CHAR_OP_NONE           0
#define FAST_CHAR_OP_ADD_BACKSLASH  1
#define FAST_CHAR_OP_NO_BACKSLASH   2

#define FAST_CHAR_MAKE_PAIR(pair, from, to) \
    pair.src = from; pair.dest = to

typedef struct fast_char_pair
{
    unsigned char src;
    unsigned char dest;
} FastCharPair;

typedef struct fast_char_target
{
    unsigned char op;
    unsigned char dest;
} FastCharTarget;

typedef struct fast_char_converter
{
    /*
     * char pairs count
     * */
    int  count;

    /*
     * char table to convert
     * */
    FastCharTarget char_table[FAST_MAX_CHAR_COUNT];

    /*
     * char table to unescape
     * */
    FastCharTarget unescape_chars[FAST_MAX_CHAR_COUNT];
} FastCharConverter;

/**
 *  char converter init function
 *  parameters:
 *           pCharConverter: the char converter
 *           charPairs: the char pairs
 *           count: the count of char pairs
 *           op: the operator type
 *  return: 0 for success, != 0 fail
*/
int char_converter_init_ex(FastCharConverter *pCharConverter,
        const FastCharPair *charPairs, const int count,
        const unsigned op);

/**
 *  char converter init function
 *  parameters:
 *           pCharConverter: the char converter
 *           charPairs: the char pairs
 *           count: the count of char pairs
 *  return: 0 for success, != 0 fail
*/
static inline int char_converter_init(FastCharConverter *pCharConverter,
        const FastCharPair *charPairs, const int count)
{
    return char_converter_init_ex(pCharConverter, charPairs, count,
            FAST_CHAR_OP_NO_BACKSLASH);
}

/**
 *  standard space chars to convert
 *  parameters:
 *           pCharConverter: the char converter
 *           dest_base: the dest base char
 *  return: 0 for success, != 0 fail
*/
int std_space_char_converter_init(FastCharConverter *pCharConverter,
        const unsigned char dest_base);

/**
 *  standard space chars init to add backslash
 *  parameters:
 *           pCharConverter: the char converter
 *  return: 0 for success, != 0 fail
*/
int std_spaces_add_backslash_converter_init(FastCharConverter *pCharConverter);

/**
 *  set char pair to converter
 *  parameters:
 *           pCharConverter: the char converter
 *           src: the src char
 *           dest: the dest char
 *  return: none
*/
void char_converter_set_pair(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned char dest);

/**
 *  set char pair to converter
 *  parameters:
 *           pCharConverter: the char converter
 *           src: the src char
 *           op: the operator type
 *           dest: the dest char
 *  return: none
*/
void char_converter_set_pair_ex(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned op, const unsigned char dest);

/**
 *  char convert function
 *  parameters:
 *           pCharConverter: the char converter
 *           input: the input to convert
 *           input_len: the length of input
 *           output: the input to convert
 *           out_len: the length of output
 *           out_size: output buff size
 *  return: converted char count
*/
int fast_char_convert(FastCharConverter *pCharConverter,
        const char *input, const int input_len,
        char *output, int *out_len, const int out_size);

#define fast_char_escape(pCharConverter, input, input_len, \
        output, out_len, out_size)   \
        fast_char_convert(pCharConverter, input, input_len, \
        output, out_len, out_size)

/**
 *  char unescape function
 *  parameters:
 *           pCharConverter: the char converter
 *           str: the string to unescape
 *           len: the input string length and store the unscaped string length
 *  return: converted char count
*/
int fast_char_unescape(FastCharConverter *pCharConverter, char *str, int *len);

#ifdef __cplusplus
}
#endif

#endif

