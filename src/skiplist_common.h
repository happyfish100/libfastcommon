/**
* Copyright (C) 2015 Happy Fish / YuQing
*
* libfastcommon may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//skiplist_common.h
#ifndef _SKIPLIST_COMMON_H
#define _SKIPLIST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_define.h"

#define SKIPLIST_MAX_LEVEL_COUNT  30
#define SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE 64

typedef int (*skiplist_compare_func)(const void *p1, const void *p2);
typedef void (*skiplist_free_func)(void *ptr);

static inline int skiplist_get_proper_level(const int target_count)
{
    if (target_count < 8) {
        return 2;
    } else if (target_count < 64) {
        return 4;
    } else if (target_count < 256) {
        return 6;
    } else if (target_count < 1024) {
        return 8;
    } else if (target_count < 4096) {
        return 10;
    } else if (target_count < 16 * 1024) {
        return 12;
    } else if (target_count < 64 * 1024) {
        return 14;
    } else if (target_count < 256 * 1024) {
        return 16;
    } else if (target_count < 1024 * 1024) {
        return 18;
    } else {
        return 20;
    }
}

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif

