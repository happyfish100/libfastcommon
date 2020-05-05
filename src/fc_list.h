#ifndef _FC_LIST_H
#define _FC_LIST_H

struct fc_list_head {
	struct fc_list_head *next;
	struct fc_list_head *prev;
};

#define FC_INIT_LIST_HEAD(head)  \
    do {  \
		(head)->next = (head)->prev = head;	\
	} while (0)

#ifdef __cplusplus
extern "C" {
#endif

static inline void
fc_list_add (struct fc_list_head *_new, struct fc_list_head *head)
{
	_new->prev = head;
	_new->next = head->next;

	_new->prev->next = _new;
	_new->next->prev = _new;
}

static inline void
fc_list_add_tail (struct fc_list_head *_new, struct fc_list_head *head)
{
	_new->next = head;
	_new->prev = head->prev;

	_new->prev->next = _new;
	_new->next->prev = _new;
}

static inline void
fc_list_add_before (struct fc_list_head *_new, struct fc_list_head *current)
{
	_new->prev = current->prev;
	_new->next = current;

	_new->prev->next = _new;
	_new->next->prev = _new;
}

static inline void
fc_list_add_internal (struct fc_list_head *_new, struct fc_list_head *prev,
        struct fc_list_head *next)
{
    next->prev = _new;
    _new->next = next;

    _new->prev = prev;
    prev->next = _new;
}

static inline void
fc_list_del (struct fc_list_head *old)
{
	old->prev->next = old->next;
	old->next->prev = old->prev;

	old->next = (struct fc_list_head *)0xbabebabe;
	old->prev = (struct fc_list_head *)0xcafecafe;
}


static inline void
fc_list_del_init (struct fc_list_head *old)
{
	old->prev->next = old->next;
	old->next->prev = old->prev;

	old->next = old;
	old->prev = old;
}


static inline void
fc_list_move (struct fc_list_head *list, struct fc_list_head *head)
{
	list->prev->next = list->next;
    list->next->prev = list->prev;
	fc_list_add (list, head);
}


static inline void
fc_list_move_tail (struct fc_list_head *list, struct fc_list_head *head)
{
	list->prev->next = list->next;
    list->next->prev = list->prev;
	fc_list_add_tail (list, head);
}


static inline int
fc_list_empty (struct fc_list_head *head)
{
	return (head->next == head);
}


static inline void
__fc_list_splice (struct fc_list_head *list, struct fc_list_head *head)
{
	(list->prev)->next = (head->next);
	(head->next)->prev = (list->prev);

	(head)->next = (list->next);
	(list->next)->prev = (head);
}


static inline void
fc_list_splice (struct fc_list_head *list, struct fc_list_head *head)
{
	if (fc_list_empty (list))
		return;

	__fc_list_splice (list, head);
}


static inline void
fc_list_splice_init (struct fc_list_head *list, struct fc_list_head *head)
{
	if (fc_list_empty (list))
		return;

	__fc_list_splice (list, head);
	FC_INIT_LIST_HEAD (list);
}

static inline int fc_list_is_last(const struct fc_list_head *list,
        const struct fc_list_head *head)
{
    return list->next == head;
}

static inline int fc_list_count(struct fc_list_head *head)
{
    struct fc_list_head *pos;
    int count;

    count = 0;
	for (pos = head->next; pos != head; pos = pos->next) {
        ++count;
    }
    return count;
}

#define fc_list_entry(ptr, type, member)					\
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))


#define fc_list_first_entry(head, type, member)	\
    ((head)->next == head ? NULL : \
     fc_list_entry((head)->next, type, member))

#define fc_list_last_entry(head, type, member)	\
    ((head)->prev == head ? NULL : \
     fc_list_entry((head)->prev, type, member))


#define fc_list_for_each(pos, head)				     \
	for (pos = (head)->next; pos != (head); pos = pos->next)


#define fc_list_for_each_entry(pos, head, member)				\
	for (pos = fc_list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = fc_list_entry(pos->member.next, typeof(*pos), member))


#define fc_list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = fc_list_entry((head)->next, typeof(*pos), member),	\
		n = fc_list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = fc_list_entry(n->member.next, typeof(*n), member))

#define fc_list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#ifdef __cplusplus
}
#endif

#endif
