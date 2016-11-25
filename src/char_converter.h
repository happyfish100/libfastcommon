/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
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

typedef struct fast_char_pair
{
    unsigned char src;
    unsigned char dest;
} FastCharPair;

typedef struct fast_char_converter
{
    /*
     * char pairs count
     * */
    int  count;

    /*
     * char table to convert
     * */
    unsigned char char_table[FAST_MAX_CHAR_COUNT];
} FastCharConverter;

/**
 *  char converter init function
 *  parameters:
 *           pCharConverter: the char converter
 *           charPairs: the char pairs
 *           count: the count of char pairs
 *  return: 0 for success, != 0 fail
*/
int char_converter_init(FastCharConverter *pCharConverter,
        const FastCharPair *charPairs, const int count);

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
 *  standard space chars to convert
 *  parameters:
 *           pCharConverter: the char converter
 *           src: the src char
 *           dest: the dest char
 *  return: none
*/
void char_converter_set_pair(FastCharConverter *pCharConverter,
        const unsigned char src, const unsigned char dest);

/**
 *  char convert function
 *  parameters:
 *           pCharConverter: the char converter
 *           text: the text to convert
 *           text_len: the length of text
 *  return: converted char count
*/
int fast_char_convert(FastCharConverter *pCharConverter,
        char *text, const int text_len);


#ifdef __cplusplus
}
#endif

#endif

