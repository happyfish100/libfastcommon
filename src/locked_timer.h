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

#ifndef __LOCKED_TIMER_H__
#define __LOCKED_TIMER_H__

#include <stdint.h>
#include <pthread.h>
#include "common_define.h"
#include "fc_list.h"

#define FAST_TIMER_STATUS_NONE     0
#define FAST_TIMER_STATUS_NORMAL   1
#define FAST_TIMER_STATUS_MOVING   2
#define FAST_TIMER_STATUS_TIMEOUT  3
#define FAST_TIMER_STATUS_CLEARED  4

#define FAST_TIMER_FLAGS_SET_NOTHING     0
#define FAST_TIMER_FLAGS_SET_EXPIRES     1
#define FAST_TIMER_FLAGS_SET_ENTRY_LOCK  2
#define FAST_TIMER_FLAGS_SET_ALL  (FAST_TIMER_FLAGS_SET_EXPIRES |  \
        FAST_TIMER_FLAGS_SET_ENTRY_LOCK)

typedef struct locked_timer_entry {
    int64_t expires;
    struct fc_list_head dlink;        //for timer slot
    struct locked_timer_entry *next;  //for timeout chain
    uint32_t slot_index;  //for slot lock
    volatile uint16_t lock_index;  //for entry lock
    uint8_t status;
    bool rehash;
} LockedTimerEntry;

typedef struct locked_timer_slot {
    struct fc_list_head head;
    pthread_mutex_t lock;
} LockedTimerSlot;

typedef struct locked_timer_shared_locks {
    bool set_lock_index;
    uint16_t count;
    pthread_mutex_t *locks;
} LockedTimerSharedLocks;

typedef struct locked_timer {
    int slot_count;    //time wheel slot count
    LockedTimerSharedLocks entry_shares;  //shared locks for entry
    int64_t base_time; //base time for slot 0
    volatile int64_t current_time;
    LockedTimerSlot *slots;
} LockedTimer;

#ifdef __cplusplus
extern "C" {
#endif

#define locked_timer_init(timer, slot_count, current_time, shared_lock_count) \
    locked_timer_init_ex(timer, slot_count, current_time, shared_lock_count,  \
            true)

#define locked_timer_add(timer, entry)  \
    locked_timer_add_ex(timer, entry, (entry)->expires, \
            FAST_TIMER_FLAGS_SET_ENTRY_LOCK)

#define locked_timer_remove(timer, entry) \
    locked_timer_remove_ex(timer, entry, FAST_TIMER_STATUS_CLEARED)

int locked_timer_init_ex(LockedTimer *timer, const int slot_count,
        const int64_t current_time, const int shared_lock_count,
        const bool set_lock_index);

void locked_timer_destroy(LockedTimer *timer);

void locked_timer_add_ex(LockedTimer *timer, LockedTimerEntry *entry,
        const int64_t expires, const int flags);

int locked_timer_remove_ex(LockedTimer *timer, LockedTimerEntry *entry,
        const int new_status);

int locked_timer_modify(LockedTimer *timer, LockedTimerEntry *entry,
        const int64_t new_expires);

int locked_timer_timeouts_get(LockedTimer *timer, const int64_t current_time,
   LockedTimerEntry *head);

#ifdef __cplusplus
}
#endif

#endif
