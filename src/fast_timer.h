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

#ifndef __FAST_TIMER_H__
#define __FAST_TIMER_H__

#include <stdint.h>
#include <pthread.h>
#include "common_define.h"

struct fast_timer_slot;
typedef struct fast_timer_entry {
    int64_t expires;
    struct fast_timer_entry *prev;
    struct fast_timer_entry *next;
    int slot_index;
    bool rehash;
} FastTimerEntry;

typedef struct fast_timer_slot {
    struct fast_timer_entry head;
} FastTimerSlot;

typedef struct fast_timer {
    int slot_count;    //time wheel slot count
    int64_t base_time; //base time for slot 0
    volatile int64_t current_time;
    FastTimerSlot *slots;
} FastTimer;

#ifdef __cplusplus
extern "C" {
#endif

#define fast_timer_add(timer, entry)  \
    fast_timer_add_ex(timer, entry, (entry)->expires, false)

int fast_timer_init(FastTimer *timer, const int slot_count,
    const int64_t current_time);
void fast_timer_destroy(FastTimer *timer);

void fast_timer_add_ex(FastTimer *timer, FastTimerEntry *entry,
        const int64_t expires, const bool set_expires);
int fast_timer_remove(FastTimer *timer, FastTimerEntry *entry);
int fast_timer_modify(FastTimer *timer, FastTimerEntry *entry,
    const int64_t new_expires);

FastTimerSlot *fast_timer_slot_get(FastTimer *timer, const int64_t current_time);
int fast_timer_timeouts_get(FastTimer *timer, const int64_t current_time,
   FastTimerEntry *head);

#ifdef __cplusplus
}
#endif

#endif

