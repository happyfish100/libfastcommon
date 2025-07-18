/*
 * Copyright (c) 2025 YuQing <384681@qq.com>
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

#ifndef FC_SPINLOCK_H
#define FC_SPINLOCK_H

#include <pthread.h>
#include "common_define.h"

typedef struct fc_spinlock_t {
#ifdef OS_LINUX
    pthread_spinlock_t mutex;
    int *cond;
#else
    pthread_lock_cond_pair_t lcp;
#endif
} FCSpinlock;

#ifdef __cplusplus
extern "C" {
#endif

int fc_spinlock_init(FCSpinlock *lock, int *cond);

void fc_spinlock_destroy(FCSpinlock *lock);

int fc_spinlock_lock(FCSpinlock *lock);

int fc_spinlock_trylock(FCSpinlock *lock);

int fc_spinlock_unlock(FCSpinlock *lock);

int fc_spinlock_wait(FCSpinlock *lock, const int expected);

int fc_spinlock_wake_ex(FCSpinlock *lock, const int count);

static inline int fc_spinlock_wake(FCSpinlock *lock)
{
    const int count = 1;
    return fc_spinlock_wake_ex(lock, count);
}

#ifdef __cplusplus
}
#endif

#endif
