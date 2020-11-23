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
#include <unistd.h>
#include <errno.h>
#include "logger.h"
#include "fc_memory.h"
#include "pthread_func.h"
#include "fast_timer.h"

static int fast_timer_init_locks(FastTimer *timer)
{
    int result;
    FastTimerSlot *slot;
    FastTimerSlot *end;

    end = timer->slots + timer->slot_count;
    for (slot=timer->slots; slot<end; slot++) {
        if ((result=init_pthread_lock(&slot->lock)) != 0) {
            return result;
        }
    }

    return 0;
}

int fast_timer_init_ex(FastTimer *timer, const int slot_count,
    const int64_t current_time, const bool need_lock)
{
    int result;
    int bytes;

    if (slot_count <= 0 || current_time <= 0) {
        return EINVAL;
    }

    timer->need_lock = need_lock;
    timer->slot_count = slot_count;
    timer->base_time = current_time; //base time for slot 0
    timer->current_time = current_time;
    bytes = sizeof(FastTimerSlot) * slot_count;
    timer->slots = (FastTimerSlot *)fc_malloc(bytes);
    if (timer->slots == NULL) {
        return ENOMEM;
    }
    memset(timer->slots, 0, bytes);

    if (need_lock) {
        if ((result=fast_timer_init_locks(timer)) != 0) {
            return result;
        }
    }
    return 0;
}

void fast_timer_destroy(FastTimer *timer)
{
    if (timer->slots != NULL) {
        if (timer->need_lock) {
            FastTimerSlot *slot;
            FastTimerSlot *end;
            end = timer->slots + timer->slot_count;
            for (slot=timer->slots; slot<end; slot++) {
                pthread_mutex_destroy(&slot->lock);
            }
        }

        free(timer->slots);
        timer->slots = NULL;
    }
}

#define TIMER_CHECK_LOCK(timer, slot)  \
    do {  \
        if (timer->need_lock) {  \
            PTHREAD_MUTEX_LOCK(&(slot)->lock);  \
        } \
    } while (0)

#define TIMER_CHECK_UNLOCK(timer, slot)  \
    do {  \
        if (timer->need_lock) {  \
            PTHREAD_MUTEX_UNLOCK(&(slot)->lock);  \
        } \
    } while (0)

#define TIMER_CHECK_LOCK_AND_SET_SLOT(timer, slot, entry)  \
    do {  \
        if (timer->need_lock) {  \
            PTHREAD_MUTEX_LOCK(&(slot)->lock);       \
            entry->slot_index = slot - timer->slots; \
        } \
    } while (0)

#define TIMER_CHECK_LOCK_BY_ENTRY(timer, entry)  \
    do {  \
        if (timer->need_lock && entry->slot_index >= 0) {  \
            PTHREAD_MUTEX_LOCK(&(timer->slots + entry->slot_index)->lock); \
        } \
    } while (0)


#define TIMER_CHECK_UNLOCK_AND_REMOVE_BY_ENTRY(timer, entry)  \
    do {  \
        if (timer->need_lock && entry->slot_index >= 0) {  \
            PTHREAD_MUTEX_UNLOCK(&(timer->slots + entry->slot_index)->lock); \
            entry->slot_index = -1;  \
        } \
    } while (0)

#define TIMER_CHECK_LOCK_BY_SINDEX(timer, slot_index)  \
    do {  \
        if (timer->need_lock) {  \
            PTHREAD_MUTEX_LOCK(&(timer->slots + slot_index)->lock); \
        } \
    } while (0)

#define TIMER_CHECK_UNLOCK_BY_SINDEX(timer, slot_index)  \
    do {  \
        if (timer->need_lock) {  \
            PTHREAD_MUTEX_UNLOCK(&(timer->slots + slot_index)->lock); \
        } \
    } while (0)


#define TIMER_GET_SLOT_INDEX(timer, expires) \
  (((expires) - timer->base_time) % timer->slot_count)

#define TIMER_GET_SLOT_POINTER(timer, expires) \
  (timer->slots + TIMER_GET_SLOT_INDEX(timer, expires))

static inline void add_entry(FastTimer *timer, FastTimerSlot *slot,
        FastTimerEntry *entry, const int64_t expires, const bool set_expires)
{
    TIMER_CHECK_LOCK_AND_SET_SLOT(timer, slot, entry);
    if (set_expires) {
        entry->expires = expires;
    }
    entry->next = slot->head.next;
    if (slot->head.next != NULL) {
        slot->head.next->prev = entry;
    }
    entry->prev = &slot->head;
    slot->head.next = entry;
    entry->rehash = false;
    TIMER_CHECK_UNLOCK(timer, slot);
}

void fast_timer_add_ex(FastTimer *timer, FastTimerEntry *entry,
        const int64_t expires, const bool set_expires)
{
    FastTimerSlot *slot;
    int64_t new_expires;
    bool new_set_expires;

    if (expires > timer->current_time) {
        new_expires = expires;
        new_set_expires = set_expires;
    } else {
        new_expires = timer->current_time;
        new_set_expires = true;
    }
    slot = TIMER_GET_SLOT_POINTER(timer, new_expires);
    add_entry(timer, slot, entry, new_expires, new_set_expires);
}

void fast_timer_modify(FastTimer *timer, FastTimerEntry *entry,
    const int64_t new_expires)
{
    int slot_index;

    if (new_expires > entry->expires) {
        if (timer->need_lock && entry->slot_index >= 0) {
            slot_index = entry->slot_index;
            if (slot_index < 0) {
                slot_index = TIMER_GET_SLOT_INDEX(timer, entry->expires);
            }
        } else {
            slot_index = TIMER_GET_SLOT_INDEX(timer, entry->expires);
        }

        TIMER_CHECK_LOCK_BY_SINDEX(timer, slot_index);
        entry->rehash = TIMER_GET_SLOT_INDEX(timer, new_expires) != slot_index;
        entry->expires = new_expires;  //lazy move
        TIMER_CHECK_UNLOCK_BY_SINDEX(timer, slot_index);
    } else if (new_expires < entry->expires) {
        fast_timer_remove(timer, entry);
        fast_timer_add_ex(timer, entry, new_expires, true);
    }
}

static inline void remove_entry(FastTimerEntry *entry)
{
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
        entry->prev->next = entry->next;
        entry->next = NULL;
    }
    else {
        entry->prev->next = NULL;
    }

    entry->prev = NULL;
}

int fast_timer_remove(FastTimer *timer, FastTimerEntry *entry)
{
    int result;

    TIMER_CHECK_LOCK_BY_ENTRY(timer, entry);
    if (entry->prev == NULL) {
        result = ENOENT;   //already removed
    } else {
        remove_entry(entry);
        result = 0;
    }
    TIMER_CHECK_UNLOCK_AND_REMOVE_BY_ENTRY(timer, entry);
    return result;
}

FastTimerSlot *fast_timer_slot_get(FastTimer *timer, const int64_t current_time)
{
    if (timer->current_time >= current_time) {
        return NULL;
    }

    return TIMER_GET_SLOT_POINTER(timer, timer->current_time++);
}

int fast_timer_timeouts_get(FastTimer *timer, const int64_t current_time,
        FastTimerEntry *head)
{
    FastTimerSlot *slot;
    FastTimerSlot *new_slot;
    FastTimerEntry *entry;
    FastTimerEntry *first;
    FastTimerEntry *last;
    FastTimerEntry *tail;
    int count;

    head->prev = NULL;
    head->next = NULL;
    if (timer->current_time >= current_time) {
        return 0;
    }

    first = NULL;
    last = NULL;
    tail = head;
    count = 0;
    while (timer->current_time < current_time) {
        slot = TIMER_GET_SLOT_POINTER(timer, timer->current_time++);
        TIMER_CHECK_LOCK(timer, slot);
        entry = slot->head.next;
        while (entry != NULL) {
            if (entry->expires >= current_time) {  //not expired
                if (first != NULL) {
                    first->prev->next = entry;
                    entry->prev = first->prev;

                    tail->next = first;
                    first->prev = tail;
                    tail = last;
                    first = NULL;
                }
                if (entry->rehash) {
                    last = entry;
                    entry = entry->next;

                    new_slot = TIMER_GET_SLOT_POINTER(timer, last->expires);
                    if (new_slot != slot) {  //check to avoid deadlock
                        remove_entry(last);
                        add_entry(timer, new_slot, last,
                                last->expires, false);
                    } else {
                        last->rehash = false;
                    }
                    continue;
                }
            } else {  //expired
                count++;
                if (first == NULL) {
                    first = entry;
                }
            }

            last = entry;
            entry = entry->next;
        }

        if (first != NULL) {
            first->prev->next = NULL;

            tail->next = first;
            first->prev = tail;
            tail = last;
            first = NULL;
        }
        TIMER_CHECK_UNLOCK(timer, slot);
    }

    if (count > 0) {
        tail->next = NULL;
    }

    return count;
}
