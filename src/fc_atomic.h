#ifndef _FC_ATOMIC_H
#define _FC_ATOMIC_H

#ifdef __cplusplus
extern "C" {
#endif

#define FC_ATOMIC_CAS(var, old_value, new_value) \
    do {  \
        if (__sync_bool_compare_and_swap(&var, old_value, new_value)) { \
            break;  \
        }   \
        old_value = __sync_add_and_fetch(&var, 0); \
    } while (new_value != old_value)

#ifdef __cplusplus
}
#endif

#endif
