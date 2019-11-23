/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

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

#ifdef __cplusplus
}
#endif

#endif

