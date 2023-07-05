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
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fastcommon/sorted_queue.h"
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"

#define COUNT 100
#define LAST_INDEX (COUNT - 1)

typedef struct {
    int n;
    struct fc_list_head dlink;
} DoubleLinkNumber;

static DoubleLinkNumber *numbers;
static struct sorted_queue sq;

static int push_compare_func(const void *p1, const void *p2)
{
    return ((DoubleLinkNumber *)p1)->n - ((DoubleLinkNumber *)p2)->n;
}

static int pop_compare_func(const void *data,
        const void *less_equal, void *arg)
{
    return ((DoubleLinkNumber *)data)->n -
        ((DoubleLinkNumber *)less_equal)->n;
}

void set_rand_numbers(const int multiple)
{
    int i;
    int tmp;
    int index1;
    int index2;

    for (i=0; i<COUNT; i++) {
        numbers[i].n = multiple * i + 1;
    }

    for (i=0; i<COUNT; i++) {
        index1 = (LAST_INDEX * (int64_t)rand()) / (int64_t)RAND_MAX;
        index2 = (LAST_INDEX * (int64_t)rand()) / (int64_t)RAND_MAX;
        if (index1 == index2) {
            continue;
        }
        tmp = numbers[index1].n;
        numbers[index1].n = numbers[index2].n;
        numbers[index2].n = tmp;
    }
}

static void test1()
{
    int i;
    DoubleLinkNumber less_equal;
    DoubleLinkNumber *number;
    struct fc_list_head head;

    set_rand_numbers(1);
    for (i=0; i<COUNT; i++) {
        sorted_queue_push_silence(&sq, numbers + i);
    }

    less_equal.n = COUNT;
    sorted_queue_try_pop_to_chain(&sq, &less_equal, &head);
    assert(sorted_queue_empty(&sq));

    i = 0;
    fc_list_for_each_entry (number, &head, dlink) {
        i++;
        if (i != number->n) {
            fprintf(stderr, "i: %d != value: %d\n", i, number->n);
            break;
        }
    }
    assert(i == COUNT);

    sorted_queue_try_pop_to_chain(&sq, &less_equal, &head);
    assert(fc_list_empty(&head));
}

static void test2()
{
#define  MULTIPLE  2
    int i;
    int n;
    DoubleLinkNumber less_equal;
    DoubleLinkNumber *number;
    struct fc_list_head head;

    set_rand_numbers(MULTIPLE);
    for (i=0; i<COUNT; i++) {
        sorted_queue_push_silence(&sq, numbers + i);
    }

    less_equal.n = 0;
    sorted_queue_try_pop_to_chain(&sq, &less_equal, &head);
    assert(fc_list_empty(&head));

    less_equal.n = COUNT;
    sorted_queue_try_pop_to_chain(&sq, &less_equal, &head);
    assert(!sorted_queue_empty(&sq));

    i = 0;
    fc_list_for_each_entry (number, &head, dlink) {
        n = i++ * MULTIPLE + 1;
        if (n != number->n) {
            fprintf(stderr, "%d. n: %d != value: %d\n", i, n, number->n);
            break;
        }
    }

    less_equal.n = 2 * COUNT + 1;
    sorted_queue_try_pop_to_chain(&sq, &less_equal, &head);
    assert(sorted_queue_empty(&sq));
    fc_list_for_each_entry (number, &head, dlink) {
        n = i++ * MULTIPLE + 1;
        if (n != number->n) {
            fprintf(stderr, "%d. n: %d != value: %d\n", i, n, number->n);
            break;
        }
    }
    assert(i == COUNT);
}

static void test3()
{
    int i;
    DoubleLinkNumber less_equal;
    DoubleLinkNumber *number;

    set_rand_numbers(1);
    for (i=0; i<COUNT; i++) {
        sorted_queue_push_silence(&sq, numbers + i);
    }

    less_equal.n = COUNT;
    for (i=1; i<=COUNT; i++) {
        number = sorted_queue_try_pop(&sq, &less_equal);
        assert(number != NULL);
        if (i != number->n) {
            fprintf(stderr, "i: %d != value: %d\n", i, number->n);
            break;
        }
    }

    assert(sorted_queue_try_pop(&sq, &less_equal) == NULL);
}

int main(int argc, char *argv[])
{
    int result;
    int64_t start_time;
    int64_t end_time;

    start_time = get_current_time_ms();

    log_init();
    numbers = (DoubleLinkNumber *)malloc(sizeof(DoubleLinkNumber) * COUNT);
    srand(time(NULL));

    if ((result=sorted_queue_init(&sq, (long)(&((DoubleLinkNumber *)
                            NULL)->dlink), push_compare_func,
                    pop_compare_func, NULL)) != 0)
    {
        return result;
    }

    test1();
    test2();
    test3();

    end_time = get_current_time_ms();
    printf("pass OK, time used: %"PRId64" ms\n", end_time - start_time);
    return 0;
}
