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

#ifndef _FC_ATOMIC_H
#define _FC_ATOMIC_H

#ifdef __cplusplus
extern "C" {
#endif

#define FC_ATOMIC_GET(var) __sync_add_and_fetch(&var, 0)

#define FC_ATOMIC_INC(var) __sync_add_and_fetch(&var, 1)
#define FC_ATOMIC_DEC(var) __sync_sub_and_fetch(&var, 1)

#define FC_ATOMIC_INC_EX(var, n) __sync_add_and_fetch(&var, n)
#define FC_ATOMIC_DEC_EX(var, n) __sync_sub_and_fetch(&var, n)

#define FC_ATOMIC_CAS(var, old_value, new_value) \
    do {  \
        if (__sync_bool_compare_and_swap(&var, old_value, new_value)) { \
            break;  \
        }   \
        old_value = __sync_add_and_fetch(&var, 0); \
    } while (new_value != old_value)


#define FC_ATOMIC_SET(var, new_value) \
    do { \
        typeof(var) _old_value;  \
        _old_value = var;    \
        do {  \
            if (__sync_bool_compare_and_swap(&var, _old_value, new_value)) { \
                break;  \
            }   \
            _old_value = __sync_add_and_fetch(&var, 0); \
        } while (new_value != _old_value);  \
    } while (0)


#define FC_ATOMIC_SET_BY_CONDITION(var, value, skip_operator) \
    do { \
        typeof(var) old;  \
        old = __sync_add_and_fetch(&var, 0); \
        if (value skip_operator old) { \
            break; \
        } \
        if (__sync_bool_compare_and_swap(&var, old, value)) { \
            break; \
        } \
    } while (1)


#define FC_ATOMIC_SET_LARGER(var, value) \
    FC_ATOMIC_SET_BY_CONDITION(var, value, <=)

#define FC_ATOMIC_SET_SMALLER(var, value) \
    FC_ATOMIC_SET_BY_CONDITION(var, value, >=)


#ifdef __cplusplus
}
#endif

#endif
