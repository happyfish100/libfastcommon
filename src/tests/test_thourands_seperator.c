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
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/shared_func.h"

int main(int argc, char *argv[])
{
    int64_t n;
    char buff[32];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <integer>\n", argv[0]);
        return EINVAL;
    }

    n = strtol(argv[1], NULL, 10);
    printf("%s\n", long_to_comma_str(n, buff));
    return 0;
}
