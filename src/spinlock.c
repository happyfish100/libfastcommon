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

#include "common_define.h"
#ifdef OS_LINUX
#include <sys/syscall.h>
#include <linux/futex.h>
#define FUTEX(ptr, op, val) syscall(SYS_futex, ptr, op, val, NULL, NULL, 0)
#else
#include "pthread_func.h"
#endif

#include "logger.h"
#include "spinlock.h"

#ifdef OS_LINUX
static inline int fc_futex(int *ptr, int op, int val)
{
    if (FUTEX(ptr, op, val) == 0) {
        return 0;
    } else {
        return errno != 0 ? errno : EBUSY;
    }
}
#endif

int fc_spinlock_init(FCSpinlock *lock, int *cond)
{
#ifdef OS_LINUX
    lock->mutex = 0;
    lock->cond = cond;
    return 0;
#else
    return init_pthread_lock_cond_pair(&lock->lcp);
#endif
}

void fc_spinlock_destroy(FCSpinlock *lock)
{
#ifdef OS_LINUX
#else
    destroy_pthread_lock_cond_pair(&lock->lcp);
#endif
}

int fc_spinlock_lock(FCSpinlock *lock)
{
#ifdef OS_LINUX
    return fc_futex(&lock->mutex, FUTEX_LOCK_PI_PRIVATE, 0);
#else
    return pthread_mutex_lock(&lock->lcp.lock);
#endif
}

int fc_spinlock_trylock(FCSpinlock *lock)
{
#ifdef OS_LINUX
    return fc_futex(&lock->mutex, FUTEX_TRYLOCK_PI_PRIVATE, 0);
#else
    return pthread_mutex_trylock(&lock->lcp.lock);
#endif
}

int fc_spinlock_unlock(FCSpinlock *lock)
{
#ifdef OS_LINUX
    return fc_futex(&lock->mutex, FUTEX_UNLOCK_PI_PRIVATE, 0);
#else
    return pthread_mutex_unlock(&lock->lcp.lock);
#endif
}

int fc_spinlock_wait(FCSpinlock *lock, const int expected)
{
#ifdef OS_LINUX
    int result;
    int lock_ret;

    if ((result=fc_futex(&lock->mutex, FUTEX_UNLOCK_PI_PRIVATE, 0)) != 0) {
        return result;
    }
    result = fc_futex(lock->cond, FUTEX_WAIT_PRIVATE, expected);
    lock_ret = fc_futex(&lock->mutex, FUTEX_LOCK_PI_PRIVATE, 0);
    return result == 0 ? lock_ret : result;
#else
    return pthread_cond_wait(&lock->lcp.cond, &lock->lcp.lock);
#endif
}

int fc_spinlock_wake_ex(FCSpinlock *lock, const int count)
{
#ifdef OS_LINUX
    if (FUTEX(lock->cond, FUTEX_WAKE_PRIVATE, count) >= 0) {
        return 0;
    } else {
        return errno != 0 ? errno : EBUSY;
    }
#else
    if (count == 1) {
        return pthread_cond_signal(&lock->lcp.cond);
    } else {
        return pthread_cond_broadcast(&lock->lcp.cond);
    }
#endif
}
