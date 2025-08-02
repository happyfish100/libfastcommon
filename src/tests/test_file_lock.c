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
#include <math.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/file.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"

#define OneArgument(a) printf("One Argument func is called!\n")
#define TwoArguments(a, b) printf("Two Arguments func is called!\n")
#define TreeArguments(a, b, c) printf("Tree Arguments func is called!\n")
#define MacroKernel(_1, _2, _3, FUNC, ...) FUNC
#define Macro(...) MacroKernel(__VA_ARGS__, TreeArguments, TwoArguments, OneArgument, ...)(__VA_ARGS__)

static inline int get_lock_info(int fd, struct flock *lock)
{
    int result;

    lock->l_whence = SEEK_SET;
    lock->l_type = F_WRLCK;
    lock->l_pid = getpid();
    do {
        if ((result=fcntl(fd, F_GETLK, lock)) != 0)
        {
            result = errno != 0 ? errno : ENOMEM;
            fprintf(stderr, "call fcntl fail, "
                   "errno: %d, error info: %s\n",
                   result, STRERROR(result));
        }
    } while (result == EINTR);

    return result;
}

static inline int set_lock(int fd, const int operation,
        const int start, const int length)
{
    int result;
     struct flock lock;

    memset(&lock, 0, sizeof(struct flock));
    lock.l_whence = SEEK_SET;
    lock.l_type = operation;
    lock.l_start = start;
    lock.l_len = length;
    lock.l_pid = getpid();
    do {
        if ((result=fcntl(fd, F_SETLKW, &lock)) != 0)
        {
            result = errno != 0 ? errno : ENOMEM;
            fprintf(stderr, "line: %d, call fcntl fail, "
                   "errno: %d, error info: %s\n", __LINE__,
                   result, STRERROR(result));
        } else {
            printf("line: %d, call fcntl %d result: %d\n",
                    __LINE__, operation, result);
        }
    } while (result == EINTR);

    return result;
}

static void *unlock_thread(void *args)
{
    char *filename;
    int result;
    int fd;
    struct flock lock;

    filename = (char *)args;
    fd = open(filename, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, "
                "errno: %d, error info: %s",
                __LINE__, filename,
                result, STRERROR(result));
        return NULL;
    }

    memset(&lock, 0, sizeof(struct flock));
    lock.l_start = 100;
    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("lock info: { type: %d, whence: %d, start: %"PRId64", "
                "len: %"PRId64", pid: %d }",
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }

    //set_lock(fd, F_WRLCK, 0, 0);
    sleep(5);
    //set_lock(fd, F_UNLCK, 0, 0);
    close(fd);
    return NULL;
}

int main(int argc, char *argv[])
{
#define SEEK_POS   (2 * 1024)
    char *filename;
    int fd;
    int result;
    int sleep_seconds;
    int n = 0;
    pthread_t tid;
    char buf[1024];
    struct flock lock;

    Macro(1);
    Macro(1, 2);
    Macro(1, 2, 3);

    printf("%0*d\n", 3, 1);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    log_init();
    filename = argv[1];
    if (argc >= 3) {
        sleep_seconds = atoi(argv[2]);
    } else {
        sleep_seconds = 1;
    }

    fd = open(filename, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
            "open file %s fail, "
            "errno: %d, error info: %s",
            __LINE__, filename,
            result, STRERROR(result));
        return result;
    }

    {
    int flags;
    flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0)
    {
        logError("file: "__FILE__", line: %d, " \
            "fcntl failed, errno: %d, error info: %s.", \
            __LINE__, errno, STRERROR(errno));
        return errno != 0 ? errno : EACCES;
    }

    printf("flags: %d, on: %d\n", flags, (flags & FD_CLOEXEC));

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    {
        logError("file: "__FILE__", line: %d, " \
            "fcntl failed, errno: %d, error info: %s.", \
            __LINE__, errno, STRERROR(errno));
        return errno != 0 ? errno : EACCES;
    }
    flags = fcntl(fd, F_GETFD, 0);
    printf("flags: %d, on: %d\n", flags, (flags & FD_CLOEXEC));
    }


    fork();

    memset(&lock, 0, sizeof(struct flock));
    lock.l_start = 1024;
    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("pid: %d, lock info: { type: %d, whence: %d, "
                "start: %"PRId64", len: %"PRId64", pid: %d }", getpid(),
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }

    set_lock(fd, F_WRLCK, 0, 10);
    set_lock(fd, F_WRLCK, 10, 10);
    set_lock(fd, F_WRLCK, 30, 10);
    //set_lock(fd, F_WRLCK, 0, 0);
    //set_lock(fd, F_UNLCK, 0, 10);
    //set_lock(fd, F_UNLCK, 5, 35);

    fc_create_thread(&tid, unlock_thread, filename, 64 * 1024);

    sleep(100);
    memset(&lock, 0, sizeof(struct flock));
    lock.l_start = 100;
    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("lock info: { type: %d, whence: %d, start: %"PRId64", "
                "len: %"PRId64", pid: %d }",
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }

    if (flock(fd, LOCK_EX) < 0) {
        logError("file: "__FILE__", line: %d, "
                "flock file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                filename, errno, STRERROR(errno));
        return errno != 0 ? errno : EIO;
    }

    do {
        if (ftruncate(fd, 102400) < 0) {
            logError("file: "__FILE__", line: %d, "
                    "ftruncate file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, errno, STRERROR(errno));
            result = errno != 0 ? errno : EIO;
            break;
        }

        if (lseek(fd, SEEK_POS, SEEK_SET) < 0) {
            logError("file: "__FILE__", line: %d, "
                    "lseek file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, errno, STRERROR(errno));
            result = errno != 0 ? errno : EIO;
            break;
        }

        memset(buf, '\n', sizeof(buf));
        if ((n=write(fd, buf, sizeof(buf))) <= 0) {
            logError("file: "__FILE__", line: %d, "
                    "write to file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, errno, STRERROR(errno));
            result = errno != 0 ? errno : EIO;
            break;
        }
        result = 0;
        logInfo("pid: %d, write bytes: %d", getpid(), n);
    } while (0);

    sleep(sleep_seconds);

    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("lock info: { type: %d, whence: %d, start: %"PRId64", "
                "len: %"PRId64", pid: %d }",
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }

    if (flock(fd, LOCK_UN) < 0) {
        logError("file: "__FILE__", line: %d, "
                "unlock file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                filename, errno, STRERROR(errno));
        return errno != 0 ? errno : EIO;
    }

    if (result != 0) {
        return result;
    }

    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("lock info: { type: %d, whence: %d, start: %"PRId64", "
                "len: %"PRId64", pid: %d }",
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }


    logInfo("pid: %d, before lock ...", getpid());
    if ((result=file_read_lock(fd)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "lock file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                filename, result, STRERROR(result));
        return result;
    }

    if ((result=get_lock_info(fd, &lock)) == 0) {
        logInfo("lock info: { type: %d, whence: %d, start: %"PRId64", "
                "len: %"PRId64", pid: %d }",
                lock.l_type, lock.l_whence, (int64_t)lock.l_start,
                (int64_t)lock.l_len, lock.l_pid);
    }


    logInfo("pid: %d, after lock.", getpid());
    do {
        if (lseek(fd, 0, SEEK_SET) < 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "lseek file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, result, STRERROR(result));
            break;
        }

        if ((n=read(fd, buf, sizeof(buf))) <= 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "read from file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, result, STRERROR(result));
            break;
        }
    } while (0);

    sleep(sleep_seconds);
    if ((result=file_unlock(fd)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "unlock  file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                filename, result, STRERROR(result));
    }

    logInfo("pid: %d, read bytes: %d, 0 => 0x%02x, %d => 0x%02x\n",
            getpid(), n, (unsigned char)buf[0], n - 1, (unsigned char)buf[n - 1]);
    return result;
}
