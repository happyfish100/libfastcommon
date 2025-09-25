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
#include "fc_memory.h"
#include "ioevent.h"

#if IOEVENT_USE_KQUEUE
/* we define these here as numbers, because for kqueue mapping them to a combination of
     * filters / flags is hard to do. */
int kqueue_ev_convert(int16_t event, uint16_t flags)
{
  int r;

  if (event == EVFILT_READ) {
    r = KPOLLIN;
  }
  else if (event == EVFILT_WRITE) {
    r = KPOLLOUT;
  }
  else {
    r = 0;
  }

  if (flags & EV_EOF) {
    r |= KPOLLHUP;
  }
  return r;
}
#endif

int ioevent_init(IOEventPoller *ioevent, const int size,
    const int timeout_ms, const int extra_events)
{
#if IOEVENT_USE_URING
    int result;
#else
    int bytes;

    ioevent->iterator.index = 0;
    ioevent->iterator.count = 0;
#endif

    ioevent->size = size;
    ioevent->extra_events = extra_events;

#if IOEVENT_USE_EPOLL
    ioevent->poll_fd = epoll_create(ioevent->size);
    if (ioevent->poll_fd < 0) {
        return errno != 0 ? errno : ENOMEM;
    }
    bytes = sizeof(struct epoll_event) * size;
    ioevent->events = (struct epoll_event *)fc_malloc(bytes);
#elif IOEVENT_USE_URING
    if ((result=io_uring_queue_init(size, &ioevent->ring, 0)) < 0) {
        return -result;
    }
    ioevent->cqe = NULL;
    ioevent->submmit_count = 0;
#elif IOEVENT_USE_KQUEUE
    ioevent->poll_fd = kqueue();
    if (ioevent->poll_fd < 0) {
        return errno != 0 ? errno : ENOMEM;
    }
    bytes = sizeof(struct kevent) * size;
    ioevent->events = (struct kevent *)fc_malloc(bytes);
#elif IOEVENT_USE_PORT
    ioevent->poll_fd = port_create();
    if (ioevent->poll_fd < 0) {
        return errno != 0 ? errno : ENOMEM;
    }
    bytes = sizeof(port_event_t) * size;
    ioevent->events = (port_event_t *)fc_malloc(bytes);
#endif

#if IOEVENT_USE_URING

#else
    if (ioevent->events == NULL) {
        close(ioevent->poll_fd);
        ioevent->poll_fd = -1;
        return ENOMEM;
    }
#endif

    ioevent_set_timeout(ioevent, timeout_ms);
    return 0;
}

void ioevent_destroy(IOEventPoller *ioevent)
{
#if IOEVENT_USE_URING
    io_uring_queue_exit(&ioevent->ring);
#else
  if (ioevent->events != NULL) {
    free(ioevent->events);
    ioevent->events = NULL;
  }

  if (ioevent->poll_fd >= 0) {
    close(ioevent->poll_fd);
    ioevent->poll_fd = -1;
  }
#endif
}

int ioevent_attach(IOEventPoller *ioevent, const int fd,
        const int e, void *data)
{
#if IOEVENT_USE_EPOLL
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = e | ioevent->extra_events;
  ev.data.ptr = data;
  return epoll_ctl(ioevent->poll_fd, EPOLL_CTL_ADD, fd, &ev);
#elif IOEVENT_USE_URING
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ioevent->ring);
  if (sqe == NULL) {
      return ENOSPC;
  }
  sqe->user_data = (long)data;
  io_uring_prep_poll_multishot(sqe, fd, e | ioevent->extra_events);
  return ioevent_uring_submit(ioevent);
#elif IOEVENT_USE_KQUEUE
  struct kevent ev[2];
  int n = 0;
  if (e & IOEVENT_READ) {
    EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | ioevent->extra_events, 0, 0, data);
  }
  if (e & IOEVENT_WRITE) {
    EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | ioevent->extra_events, 0, 0, data);
  }
  if (n == 0) {
      return ENOENT;
  }
  return kevent(ioevent->poll_fd, ev, n, NULL, 0, NULL);
#elif IOEVENT_USE_PORT
  return port_associate(ioevent->poll_fd, PORT_SOURCE_FD, fd, e, data);
#endif
}

int ioevent_modify(IOEventPoller *ioevent, const int fd,
        const int e, void *data)
{
#if IOEVENT_USE_EPOLL
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = e | ioevent->extra_events;
  ev.data.ptr = data;
  return epoll_ctl(ioevent->poll_fd, EPOLL_CTL_MOD, fd, &ev);
#elif IOEVENT_USE_URING
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ioevent->ring);
  if (sqe == NULL) {
      return ENOSPC;
  }
  sqe->user_data = (long)data;
  io_uring_prep_poll_update(sqe, sqe->user_data, sqe->user_data,
          e | ioevent->extra_events, IORING_POLL_UPDATE_EVENTS);
  return ioevent_uring_submit(ioevent);
#elif IOEVENT_USE_KQUEUE
  struct kevent ev[2];
  int result;
  int n = 0;

  if (e & IOEVENT_READ) {
    EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | ioevent->extra_events, 0, 0, data);
  }
  else {
    EV_SET(&ev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  }

  if (e & IOEVENT_WRITE) {
    EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | ioevent->extra_events, 0, 0, data);
  }
  else {
    EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  }

  result = kevent(ioevent->poll_fd, ev, n, NULL, 0, NULL);
  if (result == -1) {
      result = ioevent_detach(ioevent, fd);
      if (e & (IOEVENT_READ | IOEVENT_WRITE)) {
          result = ioevent_attach(ioevent, fd, e, data);
      }
  }
  return result;
#elif IOEVENT_USE_PORT
  return port_associate(ioevent->poll_fd, PORT_SOURCE_FD, fd, e, data);
#endif
}

int ioevent_detach(IOEventPoller *ioevent, const int fd)
{
#if IOEVENT_USE_EPOLL
  return epoll_ctl(ioevent->poll_fd, EPOLL_CTL_DEL, fd, NULL);
#elif IOEVENT_USE_URING
  struct io_uring_sqe *sqe = io_uring_get_sqe(&ioevent->ring);
  if (sqe == NULL) {
      return ENOSPC;
  }
  sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
  sqe->user_data = 0;
  io_uring_prep_cancel_fd(sqe, fd, 0);
  ioevent->submmit_count++;
  return 0;
#elif IOEVENT_USE_KQUEUE
  struct kevent ev[1];
  int r, w;

  EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  r = kevent(ioevent->poll_fd, ev, 1, NULL, 0, NULL);

  EV_SET(&ev[0], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
  w = kevent(ioevent->poll_fd, ev, 1, NULL, 0, NULL);

  return (r == 0 || w == 0) ? 0 : r;
#elif IOEVENT_USE_PORT
  return port_dissociate(ioevent->poll_fd, PORT_SOURCE_FD, fd);
#endif
}

int ioevent_poll(IOEventPoller *ioevent)
{
#if IOEVENT_USE_EPOLL
  return epoll_wait(ioevent->poll_fd, ioevent->events,
          ioevent->size, ioevent->timeout);
#elif IOEVENT_USE_URING
  int result;
  result = io_uring_wait_cqe_timeout(&ioevent->ring,
          &ioevent->cqe, &ioevent->timeout);
  if (result < 0) {
      errno = -result;
      return -1;
  }
  return 0;
#elif IOEVENT_USE_KQUEUE
  return kevent(ioevent->poll_fd, NULL, 0, ioevent->events,
          ioevent->size, &ioevent->timeout);
#elif IOEVENT_USE_PORT
  int result;
  int retval;
  unsigned int nget = 1;
  if((retval = port_getn(ioevent->poll_fd, ioevent->events,
          ioevent->size, &nget, &ioevent->timeout)) == 0)
  {
    result = (int)nget;
  } else {
    switch(errno) {
      case EINTR:
      case EAGAIN:
      case ETIME:
        if (nget > 0) {
          result = (int)nget;
        }
        else {
          result = 0;
        }
        break;
      default:
        result = -1;
        break;
    }
  }
  return result;
#else
#error port me
#endif
}

