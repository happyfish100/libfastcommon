#ifndef _LOCKED_LIST_H
#define _LOCKED_LIST_H

#include "fc_list.h"
#include "pthread_func.h"

typedef struct fc_locked_list {
    struct fc_list_head head;
    pthread_mutex_t lock;
} FCLockedList;

#ifdef __cplusplus
extern "C" {
#endif

    static inline int locked_list_init(FCLockedList *list)
    {
        int result;
        if ((result=init_pthread_lock(&list->lock)) != 0) {
            return result;
        }

        FC_INIT_LIST_HEAD(&list->head);
        return 0;
    }

    static inline void locked_list_add(struct fc_list_head *_new,
            FCLockedList *list)
    {
        PTHREAD_MUTEX_LOCK(&list->lock);
        fc_list_add(_new, &list->head);
        PTHREAD_MUTEX_UNLOCK(&list->lock);
    }

    static inline void locked_list_add_tail(struct fc_list_head *_new,
            FCLockedList *list)
    {
        PTHREAD_MUTEX_LOCK(&list->lock);
        fc_list_add_tail(_new, &list->head);
        PTHREAD_MUTEX_UNLOCK(&list->lock);
    }

    static inline void locked_list_del(struct fc_list_head *old,
            FCLockedList *list)
    {
        PTHREAD_MUTEX_LOCK(&list->lock);
        fc_list_del_init(old);
        PTHREAD_MUTEX_UNLOCK(&list->lock);
    }

    static inline int locked_list_count(FCLockedList *list)
    {
        int count;
        PTHREAD_MUTEX_LOCK(&list->lock);
        count = fc_list_count(&list->head);
        PTHREAD_MUTEX_UNLOCK(&list->lock);
        return count;
    }

#ifdef __cplusplus
}
#endif

#endif
