#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/skiplist_set.h"
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

#define COUNT 1000000
#define LEVEL_COUNT 16
#define MIN_ALLOC_ONCE  32
#define LAST_INDEX (COUNT - 1)

static int *numbers;
static SkiplistSet sl;
static SkiplistSetIterator iterator;
static int instance_count = 0;

static void free_test_func(void *ptr)
{
    instance_count--;
}

static int compare_func(const void *p1, const void *p2)
{
    return *((int *)p1) - *((int *)p2);
}

static int test_insert()
{
    int i;
    int result;
    int64_t start_time;
    int64_t end_time;
    void *value;

    instance_count = 0;
    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        if ((result=skiplist_set_insert(&sl, numbers + i)) != 0) {
            return result;
        }
        instance_count++;
    }
    assert(instance_count == COUNT);

    end_time = get_current_time_ms();
    printf("insert time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = skiplist_set_find(&sl, numbers + i);
        assert(value != NULL && *((int *)value) == numbers[i]);
    }
    end_time = get_current_time_ms();
    printf("find time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    i = 0;
    skiplist_set_iterator(&sl, &iterator);
    while ((value=skiplist_set_next(&iterator)) != NULL) {
        i++;
        if (i != *((int *)value)) {
            fprintf(stderr, "i: %d != value: %d\n", i, *((int *)value));
            break;
        }
    }
    assert(i==COUNT);

    end_time = get_current_time_ms();
    printf("iterator time used: %"PRId64" ms\n", end_time - start_time);
    return 0;
}

static void test_delete()
{
    int i;
    int64_t start_time;
    int64_t end_time;
    void *value;

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        assert(skiplist_set_delete(&sl, numbers + i) == 0);
    }
    assert(instance_count == 0);

    end_time = get_current_time_ms();
    printf("delete time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = skiplist_set_find(&sl, numbers + i);
        assert(value == NULL);
    }
    end_time = get_current_time_ms();
    printf("find after delete time used: %"PRId64" ms\n", end_time - start_time);

    i = 0;
    skiplist_set_iterator(&sl, &iterator);
    while ((value=skiplist_set_next(&iterator)) != NULL) {
        i++;
    }
    assert(i==0);
}

int main(int argc, char *argv[])
{
    int i;
    int tmp;
    int index1;
    int index2;
    int result;

    log_init();
    numbers = (int *)malloc(sizeof(int) * COUNT);
    srand(time(NULL));
    for (i=0; i<COUNT; i++) {
        numbers[i] = i + 1;
    }

    for (i=0; i<COUNT; i++) {
        index1 = LAST_INDEX * (int64_t)rand() / (int64_t)RAND_MAX;
        index2 = LAST_INDEX * (int64_t)rand() / (int64_t)RAND_MAX;
        if (index1 == index2) {
            continue;
        }
        tmp = numbers[index1];
        numbers[index1] = numbers[index2];
        numbers[index2] = tmp;
    }

    fast_mblock_manager_init();
    result = skiplist_set_init_ex(&sl, LEVEL_COUNT, compare_func,
            free_test_func, MIN_ALLOC_ONCE);
    if (result != 0) {
        return result;
    }

    test_insert();
    printf("\n");

    fast_mblock_manager_stat_print(false);

    test_delete();
    printf("\n");

    test_insert();
    printf("\n");

    /*
    test_delete();
    printf("\n");
    */

    skiplist_set_destroy(&sl);
    assert(instance_count == 0);

    printf("pass OK\n");
    return 0;
}

