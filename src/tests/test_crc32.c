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
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-o offset=0] [-s size=0] <filename>\n",
            program);
}

int main(int argc, char *argv[])
{
    int result;
    int ch;
    char *filename;
    char *content;
    int64_t offset;
    int64_t file_size;
    int64_t crc32;
    int byte1, byte2;

    if (argc < 2) {
        usage(argv[0]);
        return EINVAL;
    }

    offset = 0;
    file_size = 0;
    while ((ch=getopt(argc, argv, "ho:s:")) != -1) {
        switch (ch) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'o':
                offset = strtoll(optarg, NULL, 10);
                break;
            case 's':
                file_size = strtoll(optarg, NULL, 10);
                break;
            default:
                usage(argv[0]);
                return EINVAL;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return EINVAL;
    }

    filename = argv[optind];
    log_init();

    if (file_size == 0) {
        if ((result=getFileSize(filename, &file_size)) != 0) {
            return result;
        }
    }
    file_size += 1;
    content = (char *)malloc(file_size);
    if (content == NULL) {
        fprintf(stderr, "malloc %"PRId64" bytes fail", file_size);
        return ENOMEM;
    }

    result = getFileContentEx(filename, content,
            offset, &file_size);
    if (result != 0) {
        return result;
    }

    printf("offset: %"PRId64", size: %"PRId64"\n",
            offset, file_size);

    crc32 = CRC32(content, (int)file_size);
    printf("crc32 whole: %x\n", (int)crc32);

    byte1 = (int)(file_size / 2);
    byte2 = (int)(file_size - byte1);
    crc32 = CRC32_XINIT;
    crc32 = CRC32_ex(content, byte1, crc32);
    crc32 = CRC32_ex(content + byte1, byte2, crc32);
    crc32 = CRC32_FINAL(crc32);
    printf("crc32 by 2 parts: %x\n", (int)crc32);

    return 0;
}
