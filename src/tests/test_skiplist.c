#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/skiplist.h"
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

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

/*
static const char * skiplist_tostring(void *data, char *buff, const int size)
{
    snprintf(buff, size, "%d(%04x)", ((Record *)data)->key, (int)(((long)data) & 0xFFFFL));
    return buff;
}
*/

static int test_stable_sort()
{
#define RECORDS 32
    int i;
    int result;
    int index1;
    int index2;
    int delete_count;
    int total_delete_count;
    int occur_count;
    int max_occur_count;
    int previous_key;
    int max_occur_key;
    Skiplist sl;
    SkiplistIterator iterator;
    Record records[RECORDS];
    Record tmp_records[RECORDS];
    Record *record;
    Record target;
    Record start;
    Record end;
    void *value;
    int div;

    printf("test_stable_sort ...\n");
    instance_count = 0;
    result = skiplist_init_ex(&sl, 12, compare_record,
            free_test_func, 128, skiplist_type);
    if (result != 0) {
        return result;
    }

    if (skiplist_type == SKIPLIST_TYPE_SET) {
        div = 1;
    }
    else {
        div = 3;
    }
    for (i=0; i<RECORDS; i++) {
        records[i].line = i + 1;
        records[i].key = i / div + 1;
    }

    if (skiplist_type != SKIPLIST_TYPE_SET) {
        for (i=0; i<RECORDS/4; i++) {
            index1 = (RECORDS - 1) * (int64_t)rand() / (int64_t)RAND_MAX;
            index2 = RECORDS - 1 - index1;
            if (index1 != index2) {
                records[index1].key = records[index2].key;
            }
        }
    }

    memcpy(tmp_records, records, sizeof(tmp_records));
    qsort(tmp_records, RECORDS, sizeof(Record), compare_record);
    max_occur_count = 0;
    max_occur_key = 0;
    i = 0;
    while (i < RECORDS) {
        occur_count = 1;
        previous_key = tmp_records[i].key;
        i++;
        while (i < RECORDS && tmp_records[i].key == previous_key) {
            i++;
            occur_count++;
        }
        if (occur_count > max_occur_count) {
            max_occur_key = previous_key;
            max_occur_count = occur_count;
        }
    }
    printf("max_occur_key: %d, max_occur_count: %d\n\n", max_occur_key, max_occur_count);


    for (i=0; i<RECORDS; i++) {
        if ((result=skiplist_insert(&sl, records + i)) != 0) {
            fprintf(stderr, "skiplist_insert insert fail, "
                    "errno: %d, error info: %s\n",
                    result, STRERROR(result));
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

    target.key = max_occur_key;
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

    start.key = 10;
    end.key = 1;
    result = skiplist_find_range(&sl, &start, &end, &iterator);
    assert(result == EINVAL);

    start.key = -1;
    end.key = 0;
    result = skiplist_find_range(&sl, &start, &end, &iterator);
    assert(result == ENOENT);

    start.key = max_occur_key;
    end.key = 100;
    result = skiplist_find_range(&sl, &start, &end, &iterator);
    assert(result == 0);

    i = 0;
    while ((value=skiplist_next(&iterator)) != NULL) {
        record = (Record *)value;
        printf("%d => #%d\n", record->key, record->line);
        i++;
    }
    printf("count: %d\n\n", i);

    /*
    if (skiplist_type == SKIPLIST_TYPE_FLAT) {
        flat_skiplist_print(&sl.u.flat, skiplist_tostring);
    }
    else if (skiplist_type == SKIPLIST_TYPE_MULTI) {
        multi_skiplist_print(&sl.u.multi, skiplist_tostring);
    }
    */

    total_delete_count = 0;
    for (i=0; i<RECORDS; i++) {
        if ((result=skiplist_delete_all(&sl, records + i, &delete_count)) == 0) {
            total_delete_count += delete_count;
        }
        assert((result == 0 && delete_count > 0) ||
                (result != 0 && delete_count == 0));

    }
    assert(total_delete_count == RECORDS);
    assert(instance_count == 0);

    /*
    if (skiplist_type == SKIPLIST_TYPE_FLAT) {
        flat_skiplist_print(&sl.u.flat, skiplist_tostring);
    }
    else if (skiplist_type == SKIPLIST_TYPE_MULTI) {
        multi_skiplist_print(&sl.u.multi, skiplist_tostring);
    }
    */

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

static void test_find_range()
{
    int n_start;
    int n_end;
    int result;
    int i;
    int *value;
    SkiplistIterator iterator;

    set_rand_numbers(2);

    for (i=0; i<COUNT; i++) {
        if ((result=skiplist_insert(&sl, numbers + i)) != 0) {
            return;
        }
        instance_count++;
    }

    n_start = 10;
    n_end = 1;
    result = skiplist_find_range(&sl, &n_start, &n_end, &iterator);
    assert(result == EINVAL);

    n_start = -1;
    n_end = 0;
    result = skiplist_find_range(&sl, &n_start, &n_end, &iterator);
    assert(result == ENOENT);

    n_start = 0;
    n_end = 10;
    result = skiplist_find_range(&sl, &n_start, &n_end, &iterator);
    assert(result == 0);

    i = 0;
    while ((value=(int *)skiplist_next(&iterator)) != NULL) {
        printf("value: %d\n", *value);
        i++;
    }
    printf("count: %d\n\n", i);
}

int main(int argc, char *argv[])
{
    int result;


    log_init();

    if (argc > 1) {
        if (strcasecmp(argv[1], "multi") == 0 || strcmp(argv[1], "1") == 0) {
            skiplist_type = SKIPLIST_TYPE_MULTI;
        }
        else if (strcasecmp(argv[1], "set") == 0 || strcmp(argv[1], "2") == 0) {
            skiplist_type = SKIPLIST_TYPE_SET;
        }
    }

    numbers = (int *)malloc(sizeof(int) * COUNT);
    srand(time(NULL));

    fast_mblock_manager_init();
    result = skiplist_init_ex(&sl, LEVEL_COUNT, compare_func,
            free_test_func, MIN_ALLOC_ONCE, skiplist_type);
    if (result != 0) {
        return result;
    }
    printf("skiplist type: %s\n", skiplist_get_type_caption(&sl));

    test_insert();
    printf("\n");

    fast_mblock_manager_stat_print_ex(false, FAST_MBLOCK_ORDER_BY_ELEMENT_SIZE);

    test_delete();
    printf("\n");
    assert(instance_count == 0);

    test_find_range();
    printf("\n");

    skiplist_destroy(&sl);
    assert(instance_count == 0);

    test_stable_sort();

    printf("pass OK\n");
    return 0;
}

