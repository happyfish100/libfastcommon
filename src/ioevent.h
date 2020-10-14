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

#ifndef __IOEVENT_H__
#define __IOEVENT_H__

#include <stdint.h>
#include <poll.h>
#include <sys/time.h>
#include "_os_define.h"

#define IOEVENT_TIMEOUT  0x8000

#if IOEVENT_USE_EPOLL
#include <sys/epoll.h>
#define IOEVENT_EDGE_TRIGGER EPOLLET

#define IOEVENT_READ  EPOLLIN
#define IOEVENT_WRITE EPOLLOUT
#define IOEVENT_ERROR (EPOLLERR | EPOLLPRI | EPOLLHUP)

#elif IOEVENT_USE_KQUEUE
#include <sys/event.h>
#include <sys/poll.h>
#define IOEVENT_EDGE_TRIGGER EV_CLEAR

#define KPOLLIN    POLLIN
#define KPOLLPRI   POLLPRI
#define KPOLLOUT   POLLOUT
#define KPOLLERR   POLLERR
#define KPOLLHUP   POLLHUP
#define IOEVENT_READ  KPOLLIN
#define IOEVENT_WRITE KPOLLOUT
#define IOEVENT_ERROR (KPOLLERR | KPOLLHUP | POLLNVAL)

#ifdef __cplusplus
extern "C" {
#endif

int kqueue_ev_convert(int16_t event, uint16_t flags);

#ifdef __cplusplus
}
#endif

#elif IOEVENT_USE_PORT
#include <port.h>
#define IOEVENT_EDGE_TRIGGER 0

#define IOEVENT_READ  POLLIN
#define IOEVENT_WRITE POLLOUT
#define IOEVENT_ERROR (POLLERR | POLLPRI | POLLHUP)
#endif

typedef struct ioevent_puller {
    int size;  //max events (fd)
    int extra_events;
    int poll_fd;

    struct {
        int index;
        int count;
    } iterator;  //for deal event loop

#if IOEVENT_USE_EPOLL
    struct epoll_event *events;
    int timeout;
#elif IOEVENT_USE_KQUEUE
    struct kevent *events;
    struct timespec timeout;
#elif IOEVENT_USE_PORT
    port_event_t *events;
    timespec_t timeout;
#endif
} IOEventPoller;

#if IOEVENT_USE_EPOLL
  #define IOEVENT_GET_EVENTS(ioevent, index) \
      (ioevent)->events[index].events
#elif IOEVENT_USE_KQUEUE
  #define IOEVENT_GET_EVENTS(ioevent, index)  kqueue_ev_convert( \
      (ioevent)->events[index].filter, (ioevent)->events[index].flags)
#elif IOEVENT_USE_PORT
  #define IOEVENT_GET_EVENTS(ioevent, index) \
      (ioevent)->events[index].portev_events
#else
#error port me
#endif

#if IOEVENT_USE_EPOLL
  #define IOEVENT_GET_DATA(ioevent, index)  \
      (ioevent)->events[index].data.ptr
#elif IOEVENT_USE_KQUEUE
  #define IOEVENT_GET_DATA(ioevent, index)  \
      (ioevent)->events[index].udata
#elif IOEVENT_USE_PORT
  #define IOEVENT_GET_DATA(ioevent, index)  \
      (ioevent)->events[index].portev_user
#else
#error port me
#endif

#if IOEVENT_USE_EPOLL
  #define IOEVENT_CLEAR_DATA(ioevent, index)  \
      (ioevent)->events[index].data.ptr = NULL
#elif IOEVENT_USE_KQUEUE
  #define IOEVENT_CLEAR_DATA(ioevent, index)  \
      (ioevent)->events[index].udata = NULL
#elif IOEVENT_USE_PORT
  #define IOEVENT_CLEAR_DATA(ioevent, index)  \
      (ioevent)->events[index].portev_user = NULL
#else
#error port me
#endif

#ifdef __cplusplus
extern "C" {
#endif

int ioevent_init(IOEventPoller *ioevent, const int size,
    const int timeout_ms, const int extra_events);
void ioevent_destroy(IOEventPoller *ioevent);

int ioevent_attach(IOEventPoller *ioevent, const int fd, const int e,
    void *data);
int ioevent_modify(IOEventPoller *ioevent, const int fd, const int e,
    void *data);
int ioevent_detach(IOEventPoller *ioevent, const int fd);
int ioevent_poll(IOEventPoller *ioevent);

static inline void ioevent_set_timeout(IOEventPoller *ioevent, const int timeout_ms)
{
#if IOEVENT_USE_EPOLL
  ioevent->timeout = timeout_ms;
#else
  ioevent->timeout.tv_sec = timeout_ms / 1000;
  ioevent->timeout.tv_nsec = 1000000 * (timeout_ms % 1000);
#endif
}

static inline int ioevent_poll_ex(IOEventPoller *ioevent, const int timeout_ms)
{
  ioevent_set_timeout(ioevent, timeout_ms);
  return ioevent_poll(ioevent);
}

#ifdef __cplusplus
}
#endif

#endif

