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
#include "fastcommon/shared_func.h"

#define BUFF_SIZE  (4 * 1024 * 1024)

int main(int argc, char *argv[])
{
    char *buff1;
    char *buff2;
    char *dest;
    int64_t start_time, end_time;
    char time_buff[32];
    int i;

    buff1 = malloc(BUFF_SIZE);
    buff2 = malloc(BUFF_SIZE);
    dest = malloc(BUFF_SIZE);

    memset(buff1, 'a', BUFF_SIZE);
    memset(buff2, 'b', BUFF_SIZE);
    memset(dest, 0, BUFF_SIZE);

    start_time = get_current_time_us();
    for (i=0; i<16 * 1024; i++) {
        if (i % 2 == 0) {
            memcpy(buff2, buff1, BUFF_SIZE);
        } else {
            memcpy(dest, buff2, BUFF_SIZE);
        }
    }

    end_time = get_current_time_us();
    printf("time used: %s us\n", long_to_comma_str(
                end_time - start_time, time_buff));
    return 0;
}

