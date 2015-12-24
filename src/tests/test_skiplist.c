#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "skiplist.h"

static int compare_func(const void *p1, const void *p2)
{
    return *((int *)p1) - *((int *)p2);
}

int main(int argc, char *argv[])
{
#define COUNT 1280
#define LAST_INDEX (COUNT - 1)

    Skiplist sl;
    SkiplistIterator iterator;
    int *numbers;
    int i;
    int tmp;
    int index;
    int result;
    void *value;

    numbers = (int *)malloc(sizeof(int) * COUNT);
    srand(time(NULL));
    for (i=0; i<COUNT; i++) {
        numbers[i] = i + 1;
    }

    for (i=0; i<COUNT; i++) {
        index = LAST_INDEX * (int64_t)rand() / (int64_t)RAND_MAX;
        tmp = numbers[index];
        numbers[index] = numbers[LAST_INDEX - index];
        numbers[LAST_INDEX - index] = tmp;
    }

    result = skiplist_init_ex(&sl, 12, compare_func, 128);
    if (result != 0) {
        return result;
    }

    for (i=0; i<COUNT; i++) {
        if ((result=skiplist_insert(&sl, numbers + i)) != 0) {
            return result;
        }
    }

    for (i=1; i<=COUNT; i++) {
        value = skiplist_find(&sl, &i);
        assert(value != NULL && *((int *)value) == i);
    }

    i = 0;
    skiplist_iterator(&sl, &iterator);
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
        assert(i == *((int *)value));
    }
    assert(i==COUNT);
    skiplist_destroy(&sl);

    printf("pass OK\n");
    return 0;
}

