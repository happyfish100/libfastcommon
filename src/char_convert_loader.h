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

