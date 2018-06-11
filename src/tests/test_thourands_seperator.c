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
