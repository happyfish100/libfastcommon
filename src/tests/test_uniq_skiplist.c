#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/uniq_skiplist.h"
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

#define COUNT 1000000
#define LEVEL_COUNT 16
#define MIN_ALLOC_ONCE  8
#define LAST_INDEX (COUNT - 1)

static int *numbers;
static UniqSkiplistFactory factory;
static UniqSkiplist *sl = NULL;
static UniqSkiplistIterator iterator;
static int instance_count = 0;

static void free_test_func(void *ptr)
{
    instance_count--;
}

static int compare_func(const void *p1, const void *p2)
{
    return *((int *)p1) - *((int *)p2);
}

void set_rand_numbers(const int multiple)
{
    int i;
    int tmp;
    int index1;
    int index2;

    for (i=0; i<COUNT; i++) {
        numbers[i] = multiple * i + 1;
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
}

static int test_insert()
{
    int i;
    int result;
    int64_t start_time;
    int64_t end_time;
    void *value;

    set_rand_numbers(1);

    instance_count = 0;
    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        if ((result=uniq_skiplist_insert(sl, numbers + i)) != 0) {
            return result;
        }
        instance_count++;
    }
    assert(instance_count == COUNT);

    end_time = get_current_time_ms();
    printf("insert time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = uniq_skiplist_find(sl, numbers + i);
        assert(value != NULL && *((int *)value) == numbers[i]);
    }
    end_time = get_current_time_ms();
    printf("find time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    i = 0;
    uniq_skiplist_iterator(sl, &iterator);
    while ((value=uniq_skiplist_next(&iterator)) != NULL) {
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
        assert(uniq_skiplist_delete(sl, numbers + i) == 0);
    }
    assert(instance_count == 0);

    end_time = get_current_time_ms();
    printf("delete time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = uniq_skiplist_find(sl, numbers + i);
        assert(value == NULL);
    }
    end_time = get_current_time_ms();
    printf("find after delete time used: %"PRId64" ms\n", end_time - start_time);

    i = 0;
    uniq_skiplist_iterator(sl, &iterator);
    while ((value=uniq_skiplist_next(&iterator)) != NULL) {
        i++;
    }
    assert(i==0);
}

static void test_find_range()
{
    int n_start;
    int n_end;
    int result;
    int i;
    int *value;
    UniqSkiplistIterator iterator;

    set_rand_numbers(2);

    for (i=0; i<COUNT; i++) {
        if ((result=uniq_skiplist_insert(sl, numbers + i)) != 0) {
            return;
        }
        instance_count++;
    }

    n_start = 10;
    n_end = 1;
    result = uniq_skiplist_find_range(sl, &n_start, &n_end, &iterator);
    assert(result == EINVAL);

    n_start = -1;
    n_end = 0;
    result = uniq_skiplist_find_range(sl, &n_start, &n_end, &iterator);
    assert(result == ENOENT);

    n_start = 0;
    n_end = 10;
    result = uniq_skiplist_find_range(sl, &n_start, &n_end, &iterator);
    assert(result == 0);

    i = 0;
    while ((value=(int *)uniq_skiplist_next(&iterator)) != NULL) {
        printf("value: %d\n", *value);
        i++;
    }
    printf("count: %d\n\n", i);
}

int main(int argc, char *argv[])
{
    int result;
    int64_t start_time;
    int64_t end_time;

    start_time = get_current_time_ms();

    log_init();
    numbers = (int *)malloc(sizeof(int) * COUNT);
    srand(time(NULL));

    fast_mblock_manager_init();
    result = uniq_skiplist_init_ex(&factory, LEVEL_COUNT, compare_func,
            free_test_func, 0, MIN_ALLOC_ONCE, 0);
    if (result != 0) {
        return result;
    }

    sl = uniq_skiplist_new(&factory, 8);
    if (sl == NULL) {
        return ENOMEM;
    }

    test_insert();
    printf("\n");

    fast_mblock_manager_stat_print(false);

    test_delete();
    printf("\n");

    test_find_range();

    test_delete();
    printf("\n");

    test_insert();
    printf("\n");

    /*
    test_delete();
    printf("\n");
    */

    printf("skiplist level_count: %d\n", sl->top_level_index + 1);

    uniq_skiplist_free(sl);
    fast_mblock_manager_stat_print(false);

    uniq_skiplist_destroy(&factory);
    assert(instance_count == 0);

    end_time = get_current_time_ms();
    printf("pass OK, time used: %"PRId64" ms\n", end_time - start_time);
    return 0;
}

