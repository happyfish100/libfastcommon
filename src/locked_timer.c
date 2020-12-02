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
#include "shared_func.h"
#include "pthread_func.h"
#include "locked_timer.h"

static int locked_timer_init_slots(LockedTimer *timer)
{
    int bytes;
    int result;
    LockedTimerSlot *slot;
    LockedTimerSlot *send;
    pthread_mutex_t *lock;
    pthread_mutex_t *lend;

    bytes = sizeof(LockedTimerSlot) * timer->slot_count;
    timer->slots = (LockedTimerSlot *)fc_malloc(bytes);
    if (timer->slots == NULL) {
        return ENOMEM;
    }
    memset(timer->slots, 0, bytes);

    send = timer->slots + timer->slot_count;
    for (slot=timer->slots; slot<send; slot++) {
        if ((result=init_pthread_lock(&slot->lock)) != 0) {
            return result;
        }
        FC_INIT_LIST_HEAD(&slot->head);
    }

    timer->entry_shares.locks = (pthread_mutex_t *)fc_malloc(
            sizeof(pthread_mutex_t) * timer->entry_shares.count);
    if (timer->entry_shares.locks == NULL) {
        return ENOMEM;
    }

    lend = timer->entry_shares.locks + timer->entry_shares.count;
    for (lock=timer->entry_shares.locks; lock<lend; lock++) {
        if ((result=init_pthread_lock(lock)) != 0) {
            return result;
        }
    }

    return 0;
}

int locked_timer_init_ex(LockedTimer *timer, const int slot_count,
        const int64_t current_time, const int shared_lock_count,
        const bool set_lock_index)
{
    if (slot_count <= 0 || current_time <= 0) {
        return EINVAL;
    }

    timer->slot_count = slot_count;
    timer->entry_shares.count = shared_lock_count;
    timer->entry_shares.set_lock_index = set_lock_index;
    timer->base_time = current_time; //base time for slot 0
    timer->current_time = current_time;
    return locked_timer_init_slots(timer);
}

void locked_timer_destroy(LockedTimer *timer)
{
    LockedTimerSlot *slot;
    LockedTimerSlot *send;
    pthread_mutex_t *lock;
    pthread_mutex_t *lend;

    if (timer->slots == NULL) {
        return;
    }
    send = timer->slots + timer->slot_count;
    for (slot=timer->slots; slot<send; slot++) {
        pthread_mutex_destroy(&slot->lock);
    }

    lend = timer->entry_shares.locks + timer->entry_shares.count;
    for (lock=timer->entry_shares.locks; lock<lend; lock++) {
        pthread_mutex_destroy(lock);
    }
    free(timer->entry_shares.locks);
    timer->entry_shares.locks = NULL;
    timer->entry_shares.count = 0;

    free(timer->slots);
    timer->slots = NULL;
}

#define TIMER_GET_SLOT_INDEX(timer, expires) \
  (((expires) - timer->base_time) % timer->slot_count)

#define TIMER_GET_SLOT_POINTER(timer, expires) \
  (timer->slots + TIMER_GET_SLOT_INDEX(timer, expires))

#define TIMER_ENTRY_LOCK(timer, lock_index) \
    PTHREAD_MUTEX_LOCK(timer->entry_shares.locks + lock_index)

#define TIMER_ENTRY_UNLOCK(timer, lock_index) \
    PTHREAD_MUTEX_UNLOCK(timer->entry_shares.locks + lock_index)

#define TIMER_ENTRY_FETCH_LOCK_INDEX(timer, entry) \
    (timer->entry_shares.set_lock_index ? \
     __sync_add_and_fetch(&entry->lock_index, 0) : entry->lock_index)

#define TIMER_ENTRY_FETCH_AND_LOCK(timer, entry) \
    lock_index = TIMER_ENTRY_FETCH_LOCK_INDEX(timer, entry);  \
    PTHREAD_MUTEX_LOCK(timer->entry_shares.locks + lock_index)

#define TIMER_SET_ENTRY_STATUS_AND_SINDEX(timer, slot, entry, lock_index) \
    do {  \
        TIMER_ENTRY_LOCK(timer, lock_index);      \
        entry->status = FAST_TIMER_STATUS_NORMAL; \
        entry->slot_index = slot - timer->slots;  \
        TIMER_ENTRY_UNLOCK(timer, lock_index);    \
    } while (0)

static inline void add_entry(LockedTimer *timer, LockedTimerSlot *slot,
        LockedTimerEntry *entry, const int64_t expires, const int flags)
{
    int lock_index;
    if ((flags & FAST_TIMER_FLAGS_SET_ENTRY_LOCK) != 0) {
        if (timer->entry_shares.set_lock_index) {
            int old_index;
            /* init the entry on the first call */
            lock_index = ((unsigned long)entry) % timer->entry_shares.count;
            old_index = entry->lock_index;
            while (!__sync_bool_compare_and_swap(&entry->lock_index,
                        old_index, lock_index))
            {
                old_index = __sync_add_and_fetch(&entry->lock_index, 0);
            }
        } else {
            lock_index = entry->lock_index;
        }

        TIMER_SET_ENTRY_STATUS_AND_SINDEX(timer, slot, entry, lock_index);
    } else {
        lock_index = TIMER_ENTRY_FETCH_LOCK_INDEX(timer, entry);
    }

    PTHREAD_MUTEX_LOCK(&slot->lock);
    if ((flags & FAST_TIMER_FLAGS_SET_EXPIRES) != 0) {
        entry->expires = expires;
    }
    fc_list_add_tail(&entry->dlink, &slot->head);
    entry->rehash = false;

    if ((flags & FAST_TIMER_FLAGS_SET_ENTRY_LOCK) == 0) {
        /* MUST set entry status and slot index in the end when entry move */
        TIMER_SET_ENTRY_STATUS_AND_SINDEX(timer, slot, entry, lock_index);
    }
    PTHREAD_MUTEX_UNLOCK(&slot->lock);
}

#define check_entry_status(timer, entry, slot_index) \
    check_set_entry_status(timer, entry, slot_index, \
            FAST_TIMER_STATUS_NONE)

static inline int check_set_entry_status(LockedTimer *timer,
        LockedTimerEntry *entry, int *slot_index, const int new_status)
{
    int result;
    int lock_index;

    lock_index = TIMER_ENTRY_FETCH_LOCK_INDEX(timer, entry);
    while (1) {
        TIMER_ENTRY_LOCK(timer, lock_index);
        switch (entry->status) {
            case FAST_TIMER_STATUS_CLEARED:
                result = ECANCELED;
                break;
            case FAST_TIMER_STATUS_TIMEOUT:
                result = ETIMEDOUT;
                break;
            case FAST_TIMER_STATUS_MOVING:
                result = EAGAIN;
                break;
            case FAST_TIMER_STATUS_NORMAL:
                result = 0;
                if (new_status != FAST_TIMER_STATUS_NONE) {
                    entry->status = new_status;
                }
                break;
            default:
                result = EINVAL;
                break;
        }
        *slot_index = entry->slot_index;
        TIMER_ENTRY_UNLOCK(timer, lock_index);

        if (result != EAGAIN) {
            return result;
        }
        fc_sleep_ms(1);
    }
}

void locked_timer_add_ex(LockedTimer *timer, LockedTimerEntry *entry,
        const int64_t expires, const int flags)
{
    LockedTimerSlot *slot;
    int64_t new_expires;
    bool new_flags;

    if (expires > timer->current_time) {
        new_expires = expires;
        new_flags = flags;
    } else {
        new_expires = timer->current_time + 1; //plus 1 for rare case
        new_flags = flags | FAST_TIMER_FLAGS_SET_EXPIRES;
    }
    slot = TIMER_GET_SLOT_POINTER(timer, new_expires);
    add_entry(timer, slot, entry, new_expires, new_flags);
}

int locked_timer_modify(LockedTimer *timer, LockedTimerEntry *entry,
    const int64_t new_expires)
{
    int result;
    int slot_index;

    if (new_expires > entry->expires) {
        if ((result=check_entry_status(timer, entry, &slot_index)) != 0) {
            return result;
        }

        PTHREAD_MUTEX_LOCK(&(timer->slots + slot_index)->lock);
        entry->rehash = TIMER_GET_SLOT_INDEX(timer,
                new_expires) != slot_index;
        entry->expires = new_expires;  //lazy move
        PTHREAD_MUTEX_UNLOCK(&(timer->slots + slot_index)->lock);
    } else if (new_expires < entry->expires) {
        if ((result=locked_timer_remove_ex(timer, entry,
                        FAST_TIMER_STATUS_MOVING)) == 0)
        {
            locked_timer_add_ex(timer, entry, new_expires,
                    FAST_TIMER_FLAGS_SET_EXPIRES);
        }
        return result;
    }

    return 0;
}

int locked_timer_remove_ex(LockedTimer *timer, LockedTimerEntry *entry,
        const int new_status)
{
    int result;
    int slot_index;

    if ((result=check_set_entry_status(timer, entry,
                    &slot_index, new_status)) != 0)
    {
        return result;
    }

    PTHREAD_MUTEX_LOCK(&(timer->slots + slot_index)->lock);
    fc_list_del_init(&entry->dlink);
    PTHREAD_MUTEX_UNLOCK(&(timer->slots + slot_index)->lock);
    return 0;
}

int locked_timer_timeouts_get(LockedTimer *timer, const int64_t current_time,
        LockedTimerEntry *head)
{
    LockedTimerSlot *slot;
    LockedTimerSlot *new_slot;
    LockedTimerEntry *entry;
    LockedTimerEntry *tmp;
    LockedTimerEntry *tail;
    bool is_valid;
    int lock_index;
    int count;

    if (timer->current_time >= current_time) {
        head->next = NULL;
        return 0;
    }

    tail = head;
    count = 0;
    while (timer->current_time < current_time) {
        slot = TIMER_GET_SLOT_POINTER(timer, timer->current_time++);
        PTHREAD_MUTEX_LOCK(&slot->lock);
        fc_list_for_each_entry_safe(entry, tmp, &slot->head, dlink) {
            if (entry->expires >= current_time) {  //not expired
                if (entry->rehash) {
                    new_slot = TIMER_GET_SLOT_POINTER(timer, entry->expires);
                    if (new_slot != slot) {  //check to avoid deadlock
                        TIMER_ENTRY_FETCH_AND_LOCK(timer, entry);
                        if (entry->status == FAST_TIMER_STATUS_NORMAL) {
                            entry->status = FAST_TIMER_STATUS_MOVING;
                            is_valid = true;
                        } else {
                            is_valid = false;
                        }
                        TIMER_ENTRY_UNLOCK(timer, lock_index);

                        if (is_valid) {
                            fc_list_del_init(&entry->dlink);
                            add_entry(timer, new_slot, entry, entry->expires,
                                    FAST_TIMER_FLAGS_SET_NOTHING);
                        }
                    } else {
                        entry->rehash = false;
                    }
                }
            } else {  //expired
                TIMER_ENTRY_FETCH_AND_LOCK(timer, entry);
                if (entry->status == FAST_TIMER_STATUS_NORMAL) {
                    entry->status = FAST_TIMER_STATUS_TIMEOUT;
                    is_valid = true;
                } else {
                    is_valid = false;
                }
                TIMER_ENTRY_UNLOCK(timer, lock_index);

                if (is_valid) {
                    fc_list_del_init(&entry->dlink);
                    tail->next = entry;
                    tail = entry;
                    count++;
                }
            }
        }

        PTHREAD_MUTEX_UNLOCK(&slot->lock);
    }

    tail->next = NULL;
    return count;
}
