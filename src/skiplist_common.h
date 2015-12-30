/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//skiplist_common.h
#ifndef _SKIPLIST_COMMON_H
#define _SKIPLIST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"

#define SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE 128

typedef int (*skiplist_compare_func)(const void *p1, const void *p2);
typedef void (*skiplist_free_func)(void *ptr);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif

