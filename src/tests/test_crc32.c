#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

int main(int argc, char *argv[])
{
    int result;
    char *filename;
    char *content;
    int64_t file_size;
    int64_t crc32;
    int byte1, byte2;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EINVAL;
    }
    filename = argv[1];

    log_init();
    result = getFileContent(filename, &content, &file_size);
    if (result != 0) {
        return result;
    }

    printf("file_size: %"PRId64"\n", file_size);

    crc32 = CRC32(content, (int)file_size);
    printf("crc32: %x\n", (int)crc32);

    byte1 = (int)(file_size / 2);
    byte2 = (int)(file_size - byte1);
    crc32 = CRC32_XINIT;
    crc32 = CRC32_ex(content, byte1, crc32);
    crc32 = CRC32_ex(content + byte1, byte2, crc32);
    crc32 = CRC32_FINAL(crc32);
    printf("crc32: %x\n", (int)crc32);

    return 0;
}
