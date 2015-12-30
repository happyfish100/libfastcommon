#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "skiplist.h"
#include "logger.h"
#include "shared_func.h"

#define COUNT 1000000
#define LEVEL_COUNT 16
#define MIN_ALLOC_ONCE  32
#define LAST_INDEX (COUNT - 1)

static int *numbers;
static Skiplist sl;
static SkiplistIterator iterator;
static int skiplist_type = SKIPLIST_TYPE_FLAT;

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
        if ((result=skiplist_insert(&sl, numbers + i)) != 0) {
            return result;
        }
        instance_count++;
    }
    assert(instance_count == COUNT);

    end_time = get_current_time_ms();
    printf("insert time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = skiplist_find(&sl, numbers + i);
        assert(value != NULL && *((int *)value) == numbers[i]);
    }
    end_time = get_current_time_ms();
    printf("find time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    i = 0;
    skiplist_iterator(&sl, &iterator);
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
        assert(i == *((int *)value));
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
        assert(skiplist_delete(&sl, numbers + i) == 0);
    }
    assert(instance_count == 0);

    end_time = get_current_time_ms();
    printf("delete time used: %"PRId64" ms\n", end_time - start_time);

    start_time = get_current_time_ms();
    for (i=0; i<COUNT; i++) {
        value = skiplist_find(&sl, numbers + i);
        assert(value == NULL);
    }
    end_time = get_current_time_ms();
    printf("find after delete time used: %"PRId64" ms\n", end_time - start_time);

    i = 0;
    skiplist_iterator(&sl, &iterator);
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
    }
    assert(i==0);
}

typedef struct record
{
    int line;
    int key;
} Record;

static int compare_record(const void *p1, const void *p2)
{
    return ((Record *)p1)->key - ((Record *)p2)->key;
}

static int test_stable_sort()
{
#define RECORDS 32
    int i;
    int result;
    int index1;
    int index2;
    int delete_count;
    int total_delete_count;
    Skiplist sl;
    SkiplistIterator iterator;
    Record records[RECORDS];
    Record *record;
    Record target;
    void *value;

    instance_count = 0;
    result = skiplist_init_ex(&sl, 12, compare_record,
            free_test_func, 128, skiplist_type);
    if (result != 0) {
        return result;
    }

    for (i=0; i<RECORDS; i++) {
        records[i].line = i + 1;
        records[i].key = i + 1;
    }

    for (i=0; i<RECORDS/4; i++) {
        index1 = (RECORDS - 1) * (int64_t)rand() / (int64_t)RAND_MAX;
        index2 = RECORDS - 1 - index1;
        if (index1 != index2) {
            records[index1].key = records[index2].key;
        }
    }

    for (i=0; i<RECORDS; i++) {
        if ((result=skiplist_insert(&sl, records + i)) != 0) {
            return result;
        }
        instance_count++;
    }
    assert(instance_count == RECORDS);

    for (i=0; i<RECORDS; i++) {
        value = skiplist_find(&sl, records + i);
        assert(value != NULL && ((Record *)value)->key == records[i].key);
    }

    i = 0;
    skiplist_iterator(&sl, &iterator);
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
        record = (Record *)value;
        printf("%d => #%d\n", record->key, record->line);
    }
    assert(i==RECORDS);

    target.key = 10;
    target.line = 0;
    if (skiplist_find_all(&sl, &target, &iterator) == 0) {
        printf("found key: %d\n", target.key);
    }
    i = 0;
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
        record = (Record *)value;
        printf("%d => #%d\n", record->key, record->line);
    }
    printf("found record count: %d\n", i);

    total_delete_count = 0;
    for (i=0; i<RECORDS; i++) {
        if ((result=skiplist_delete_all(&sl, records + i,
                        &delete_count)) == 0)
        {
            total_delete_count += delete_count;
        }
        assert((result == 0 && delete_count > 0) ||
                (result != 0 && delete_count == 0));
    }
    assert(total_delete_count == RECORDS);
    assert(instance_count == 0);

    i = 0;
    skiplist_iterator(&sl, &iterator);
    while ((value=skiplist_next(&iterator)) != NULL) {
        i++;
    }
    assert(i == 0);

    skiplist_destroy(&sl);
    assert(instance_count == 0);

    return 0;
}

int main(int argc, char *argv[])
{
    int i;
    int tmp;
    int index1;
    int index2;
    int result;


    log_init();

    if (argc > 1) {
        if (strcasecmp(argv[1], "multi") == 0 || strcmp(argv[1], "1") == 0) {
            skiplist_type = SKIPLIST_TYPE_MULTI;
        }
    }
    printf("skiplist type: %s\n",
            skiplist_type == SKIPLIST_TYPE_FLAT ? "flat" : "multi");

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
    result = skiplist_init_ex(&sl, LEVEL_COUNT, compare_func,
            free_test_func, MIN_ALLOC_ONCE, skiplist_type);
    if (result != 0) {
        return result;
    }

    test_insert();
    printf("\n");

    fast_mblock_manager_stat_print(false);

    test_delete();
    printf("\n");
    assert(instance_count == 0);

    test_insert();
    printf("\n");

    skiplist_destroy(&sl);
    assert(instance_count == 0);

    test_stable_sort();

    printf("pass OK\n");
    return 0;
}

