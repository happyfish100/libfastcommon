/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//char_convert_loader.h
#ifndef CHAR_CONVERT_LOADER_H
#define CHAR_CONVERT_LOADER_H

#include <syslog.h>
#include <sys/time.h>
#include "common_define.h"
#include "ini_file_reader.h"
#include "char_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  char converter init function
 *  parameters:
 *           pCharConverter: the char converter
 *           items: the char key value pairs
 *           count: the count of kv pairs
 *  return: 0 for success, != 0 fail
*/
int char_convert_loader_init(FastCharConverter *pCharConverter,
        const IniItem *items, const int count);

/**
 *  char converter init function
 *  parameters:
 *           pCharConverter: the char converter
 *           items: the char key value pairs
 *           count: the count of kv pairs
 *  return: 0 for success, != 0 fail
*/
int char_convert_loader_add(FastCharConverter *pCharConverter,
        const IniItem *items, const int count);

/**
 *  set char src and dest pair
 *  parameters:
 *           pCharConverter: the char converter
 *           src: the src string to parse
 *           dest: the dest string to parse
 *
 *  Note: 
 *    src and dest can be ASCII code as \x##, ## for hex digital,
 *    such as \x20 for the SPACE char
 *
 *    dest can be a printable char, ASCII code as \x##,
 *    or quoted two chars as backslash follow by a char, such as "\t"
 *
 *    extended backslash char pairs:
 *      \0 for the ASCII 0 character
 *      \s for the SPACE character
 *  return: 0 for success, != 0 fail
*/
int char_convert_loader_set_pair(FastCharConverter *pCharConverter,
        const char *src, const char *dest);

#ifdef __cplusplus
}
#endif

#endif

