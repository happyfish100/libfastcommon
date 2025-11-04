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
#include "logger.h"

#define IOEVENT_TIMEOUT  (1 << 20)
#define IOEVENT_NOTIFY   (1 << 21)  //for io_uring send_zc done callback

#ifdef OS_LINUX
#include <sys/epoll.h>
#define IOEVENT_EDGE_TRIGGER EPOLLET
#endif

#if IOEVENT_USE_EPOLL
#define IOEVENT_READ  EPOLLIN
#define IOEVENT_WRITE EPOLLOUT
#define IOEVENT_ERROR (EPOLLERR | EPOLLPRI | EPOLLHUP)

#elif IOEVENT_USE_URING
#include <sys/mount.h>
#include <liburing.h>
#define IOEVENT_READ  POLLIN
#define IOEVENT_WRITE POLLOUT
#define IOEVENT_ERROR (POLLERR | POLLPRI | POLLHUP)

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
    const char *service_name;
    int size;  //max events (fd)
    int extra_events;

#if IOEVENT_USE_URING
    struct io_uring ring;
    int submit_count;
    bool send_zc_logged;
    bool send_zc_done_notify; //if callback when send_zc done
    bool use_io_uring;
#endif

    int poll_fd;
    struct {
        int index;
        int count;
    } iterator;  //for deal event loop

#ifdef OS_LINUX
    struct epoll_event *events;
    int timeout_ms;   //for epoll
#if IOEVENT_USE_URING
    struct io_uring_cqe *cqe;
    struct __kernel_timespec timeout;
#endif
    bool zero_timeout;

#elif IOEVENT_USE_KQUEUE
    struct kevent *events;
    struct timespec timeout;
#elif IOEVENT_USE_PORT
    port_event_t *events;
    timespec_t timeout;
#endif

} IOEventPoller;

#if OS_LINUX
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

#ifdef OS_LINUX
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

#ifdef OS_LINUX
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

int ioevent_init(IOEventPoller *ioevent, const char *service_name,
        const bool use_io_uring, const int size, const int timeout_ms,
        const int extra_events);
void ioevent_destroy(IOEventPoller *ioevent);

int ioevent_attach(IOEventPoller *ioevent, const int fd,
        const int e, void *data);
int ioevent_modify(IOEventPoller *ioevent, const int fd,
        const int e, void *data);
int ioevent_detach(IOEventPoller *ioevent, const int fd);
int ioevent_poll(IOEventPoller *ioevent);

static inline void ioevent_set_timeout(IOEventPoller *ioevent,
        const int timeout_ms)
{
#if IOEVENT_USE_EPOLL
    ioevent->timeout_ms = timeout_ms;
#else
#if IOEVENT_USE_URING
    if (!ioevent->use_io_uring) {
        ioevent->timeout_ms = timeout_ms;
    } else {
#endif
        ioevent->timeout.tv_sec = timeout_ms / 1000;
        ioevent->timeout.tv_nsec = 1000000 * (timeout_ms % 1000);

#if IOEVENT_USE_URING
    }
#endif
#endif

#ifdef OS_LINUX
    ioevent->zero_timeout = (timeout_ms == 0);
#endif
}

static inline int ioevent_poll_ex(IOEventPoller *ioevent, const int timeout_ms)
{
  ioevent_set_timeout(ioevent, timeout_ms);
  return ioevent_poll(ioevent);
}

#if IOEVENT_USE_URING
static inline void ioevent_set_send_zc_done_notify(
        IOEventPoller *ioevent, const bool need_notify)
{
    ioevent->send_zc_done_notify = need_notify;
}

static inline int ioevent_uring_submit(IOEventPoller *ioevent)
{
    int result;

    ioevent->submit_count = 0;
    while (1) {
        result = io_uring_submit(&ioevent->ring);
        if (result < 0) {
            if (result != -EINTR) {
                return -result;
            }
        } else {
            return 0;
        }
    }
}

static inline struct io_uring_sqe *ioevent_uring_get_sqe(IOEventPoller *ioevent)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ioevent->ring);
    if (sqe == NULL) {
        logError("file: "__FILE__", line: %d, "
                "io_uring_get_sqe fail", __LINE__);
    }
    return sqe;
}

static inline void ioevent_uring_prep_recv(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int sockfd,
        void *buf, size_t size, void *user_data)
{
    io_uring_prep_recv(sqe, sockfd, buf, size, 0);
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_send(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int sockfd,
        void *buf, size_t len, void *user_data)
{
    io_uring_prep_send(sqe, sockfd, buf, len, 0);
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_writev(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int sockfd, const struct iovec *iovecs,
        unsigned nr_vecs, void *user_data)
{
    io_uring_prep_writev(sqe, sockfd, iovecs, nr_vecs, 0);
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_send_zc(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int sockfd,
        void *buf, size_t len, void *user_data)
{
    io_uring_prep_send_zc(sqe, sockfd, buf, len, 0,
#ifdef IORING_SEND_ZC_REPORT_USAGE
            IORING_SEND_ZC_REPORT_USAGE
#else
            0
#endif
            );
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_close(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int fd, void *user_data)
{
    io_uring_prep_close(sqe, fd);
    if (user_data == NULL) {
        /* set sqe->flags MUST after io_uring_prep_xxx */
        sqe->flags = IOSQE_CQE_SKIP_SUCCESS;
    } else {
        sqe->user_data = (long)user_data;
    }
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_cancel(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, void *user_data)
{
    io_uring_prep_cancel(sqe, user_data, 0);
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

static inline void ioevent_uring_prep_connect(IOEventPoller *ioevent,
        struct io_uring_sqe *sqe, int fd, const struct sockaddr *addr,
        socklen_t addrlen, void *user_data)
{
    io_uring_prep_connect(sqe, fd, addr, addrlen);
    sqe->user_data = (long)user_data;
    ioevent->submit_count++;
}

#endif

#ifdef __cplusplus
}
#endif

#endif

