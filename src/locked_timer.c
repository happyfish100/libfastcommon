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

int locked_timer_init(LockedTimer *timer, const int slot_count,
    const int64_t current_time, const int shared_lock_count)
{
    if (slot_count <= 0 || current_time <= 0) {
        return EINVAL;
    }

    timer->slot_count = slot_count;
    timer->entry_shares.count = shared_lock_count;
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

    if (timer->slots != NULL) {
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
}

#define TIMER_GET_SLOT_INDEX(timer, expires) \
  (((expires) - timer->base_time) % timer->slot_count)

#define TIMER_GET_SLOT_POINTER(timer, expires) \
  (timer->slots + TIMER_GET_SLOT_INDEX(timer, expires))

#define LOCKED_TIMER_ENTRY_LOCK(timer, entry) \
    PTHREAD_MUTEX_LOCK(timer->entry_shares.locks + entry->lock_index)

#define LOCKED_TIMER_ENTRY_UNLOCK(timer, entry) \
    PTHREAD_MUTEX_UNLOCK(timer->entry_shares.locks + entry->lock_index)

static inline void add_entry(LockedTimer *timer, LockedTimerSlot *slot,
        LockedTimerEntry *entry, const int64_t expires,
        const bool set_expires, const bool set_entry_lock)
{
    if (set_entry_lock) {
        entry->lock_index = ((unsigned long)entry) %
            timer->entry_shares.count;
    }

    LOCKED_TIMER_ENTRY_LOCK(timer, entry);
    entry->status = FAST_TIMER_STATUS_NORMAL;
    entry->slot_index = slot - timer->slots;
    LOCKED_TIMER_ENTRY_UNLOCK(timer, entry);

    PTHREAD_MUTEX_LOCK(&slot->lock);
    if (set_expires) {
        entry->expires = expires;
    }

    fc_list_add_tail(&entry->dlink, &slot->head);
    entry->rehash = false;
    PTHREAD_MUTEX_UNLOCK(&slot->lock);
}

#define check_entry_status(timer, entry, slot_index) \
    check_set_entry_status(timer, entry, slot_index, \
            FAST_TIMER_STATUS_NONE)

static inline int check_set_entry_status(LockedTimer *timer,
        LockedTimerEntry *entry, int *slot_index, const int new_status)
{
    int result;

    while (1) {
        LOCKED_TIMER_ENTRY_LOCK(timer, entry);
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
            default:
                result = 0;
                if (new_status != FAST_TIMER_STATUS_NONE) {
                    entry->status = new_status;
                }
                break;
        }
        *slot_index = entry->slot_index;
        LOCKED_TIMER_ENTRY_UNLOCK(timer, entry);

        if (result == EAGAIN) {
            fc_sleep_ms(1);
        } else {
            return result;
        }
    }
}

void locked_timer_add_ex(LockedTimer *timer, LockedTimerEntry *entry,
        const int64_t expires, const bool set_expires)
{
    LockedTimerSlot *slot;
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
    add_entry(timer, slot, entry, new_expires, new_set_expires, true);
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
            locked_timer_add_ex(timer, entry, new_expires, true);
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

LockedTimerSlot *locked_timer_slot_get(LockedTimer *timer, const int64_t current_time)
{
    if (timer->current_time >= current_time) {
        return NULL;
    }

    return TIMER_GET_SLOT_POINTER(timer, timer->current_time++);
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
                        LOCKED_TIMER_ENTRY_LOCK(timer, entry);
                        if (entry->status == FAST_TIMER_STATUS_NORMAL) {
                            entry->status = FAST_TIMER_STATUS_MOVING;
                            is_valid = true;
                        } else {
                            is_valid = false;
                        }
                        LOCKED_TIMER_ENTRY_UNLOCK(timer, entry);

                        if (is_valid) {
                            fc_list_del_init(&entry->dlink);
                            add_entry(timer, new_slot, entry,
                                    entry->expires, false, false);
                        }
                    } else {
                        entry->rehash = false;
                    }
                }
            } else {  //expired
                LOCKED_TIMER_ENTRY_LOCK(timer, entry);
                if (entry->status == FAST_TIMER_STATUS_NORMAL) {
                    entry->status = FAST_TIMER_STATUS_TIMEOUT;
                    is_valid = true;
                } else {
                    is_valid = false;
                }
                LOCKED_TIMER_ENTRY_UNLOCK(timer, entry);

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
