/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>
#include "shared_func.h"
#include "pthread_func.h"
#include "sched_thread.h"
#include "logger.h"

#ifndef LINE_MAX
#define LINE_MAX 2048
#endif

#define LOG_BUFF_SIZE    64 * 1024

LogContext g_log_context = {LOG_INFO, STDERR_FILENO, NULL};

static int log_fsync(LogContext *pContext, const bool bNeedLock);

static int check_and_mk_log_dir(const char *base_path)
{
	char data_path[MAX_PATH_SIZE];

	snprintf(data_path, sizeof(data_path), "%s/logs", base_path);
	if (!fileExists(data_path))
	{
		if (mkdir(data_path, 0755) != 0)
		{
			fprintf(stderr, "mkdir \"%s\" fail, " \
				"errno: %d, error info: %s", \
				data_path, errno, STRERROR(errno));
			return errno != 0 ? errno : EPERM;
		}
	}

	return 0;
}

int log_init()
{
	if (g_log_context.log_buff != NULL)
	{
		return 0;
	}

	return log_init_ex(&g_log_context);
}

int log_init2()
{
    int result;
    if ((result=log_init()) != 0) {
        return result;
    }

    log_take_over_stderr();
    log_take_over_stdout();
    return 0;
}

int log_init_ex(LogContext *pContext)
{
	int result;

	memset(pContext, 0, sizeof(LogContext));
	pContext->log_level = LOG_INFO;
	pContext->log_fd = STDERR_FILENO;
	pContext->time_precision = LOG_TIME_PRECISION_SECOND;
    strcpy(pContext->rotate_time_format, "%Y%m%d_%H%M%S");

	pContext->log_buff = (char *)malloc(LOG_BUFF_SIZE);
	if (pContext->log_buff == NULL)
	{
		fprintf(stderr, "malloc %d bytes fail, " \
			"errno: %d, error info: %s", \
			LOG_BUFF_SIZE, errno, STRERROR(errno));
		return errno != 0 ? errno : ENOMEM;
	}
	pContext->pcurrent_buff = pContext->log_buff;

	if ((result=init_pthread_lock(&(pContext->log_thread_lock))) != 0)
	{
		return result;
	}

	return 0;
}

static int do_lock_file(int fd, int cmd)
{
    struct flock lock;

    memset(&lock, 0, sizeof(lock));
    lock.l_type = cmd;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLKW, &lock) != 0)
    {
        fprintf(stderr, "call fcntl fail, "
                "errno: %d, error info: %s\n",
                errno, STRERROR(errno));
        return errno != 0 ? errno : ENOMEM;
    }

    return 0;
}

#define log_file_lock(fd) do_lock_file(fd, F_WRLCK)
#define log_file_unlock(fd) do_lock_file(fd, F_UNLCK)

static int log_print_header(LogContext *pContext)
{
    int result;

    if ((result=log_file_lock(pContext->log_fd)) != 0)
    {
        return result;
    }

    pContext->current_size = lseek(pContext->log_fd, 0, SEEK_END);
    if (pContext->current_size < 0)
    {
        result = errno != 0 ? errno : EACCES;
        log_file_unlock(pContext->log_fd);

        fprintf(stderr, "lseek file \"%s\" fail, " \
                "errno: %d, error info: %s\n", \
                pContext->log_filename, result, STRERROR(result));
        return result;
    }
    if (pContext->current_size == 0)
    {
        pContext->print_header_callback(pContext);
    }
    log_file_unlock(pContext->log_fd);

    return 0;
}

static int log_open(LogContext *pContext)
{
	if ((pContext->log_fd = open(pContext->log_filename, O_WRONLY | \
				O_CREAT | O_APPEND | pContext->fd_flags, 0644)) < 0)
	{
		fprintf(stderr, "open log file \"%s\" to write fail, " \
			"errno: %d, error info: %s\n", \
			pContext->log_filename, errno, STRERROR(errno));
		pContext->log_fd = STDERR_FILENO;
		return errno != 0 ? errno : EACCES;
	}

    if (pContext->take_over_stderr) {
        if (dup2(pContext->log_fd, STDERR_FILENO) < 0) {
            fprintf(stderr, "file: "__FILE__", line: %d, "
                    "call dup2 fail, errno: %d, error info: %s\n",
                    __LINE__, errno, STRERROR(errno));
        }
    }

    if (pContext->take_over_stdout) {
        if (dup2(pContext->log_fd, STDOUT_FILENO) < 0) {
            fprintf(stderr, "file: "__FILE__", line: %d, "
                    "call dup2 fail, errno: %d, error info: %s\n",
                    __LINE__, errno, STRERROR(errno));
        }
    }

	pContext->current_size = lseek(pContext->log_fd, 0, SEEK_END);
	if (pContext->current_size < 0)
	{
		fprintf(stderr, "lseek file \"%s\" fail, " \
			"errno: %d, error info: %s\n", \
			pContext->log_filename, errno, STRERROR(errno));
		return errno != 0 ? errno : EACCES;
	}
    if (pContext->current_size == 0 && pContext->print_header_callback != NULL)
    {
        log_print_header(pContext);
    }

	return 0;
}

int log_reopen_ex(LogContext *pContext)
{
	if (*(pContext->log_filename) == '\0')
	{
		return ENOENT;
	}

    if (pContext->log_fd >= 0 && pContext->log_fd != STDERR_FILENO)
    {
        close(pContext->log_fd);
    }
    return log_open(pContext);
}

int log_set_prefix_ex(LogContext *pContext, const char *base_path, \
		const char *filename_prefix)
{
	int result;

	if ((result=check_and_mk_log_dir(base_path)) != 0)
	{
		return result;
	}

	snprintf(pContext->log_filename, MAX_PATH_SIZE, "%s/logs/%s.log", \
		base_path, filename_prefix);

	return log_open(pContext);
}

int log_set_filename_ex(LogContext *pContext, const char *log_filename)
{
    if (log_filename == NULL) {
		fprintf(stderr, "file: "__FILE__", line: %d, " \
                "log_filename is NULL!\n", __LINE__);
        return EINVAL;
    }
	snprintf(pContext->log_filename, MAX_PATH_SIZE, "%s", log_filename);
	return log_open(pContext);
}

void log_set_cache_ex(LogContext *pContext, const bool bLogCache)
{
	pContext->log_to_cache = bLogCache;
}

void log_set_time_precision(LogContext *pContext, const int time_precision)
{
	pContext->time_precision = time_precision;
}

void log_set_rotate_time_format(LogContext *pContext, const char *time_format)
{
    snprintf(pContext->rotate_time_format,
            sizeof(pContext->rotate_time_format),
            "%s", time_format);
}

void log_set_keep_days(LogContext *pContext, const int keep_days)
{
	pContext->keep_days = keep_days;
}

void log_set_header_callback(LogContext *pContext, LogHeaderCallback header_callback)
{
	pContext->print_header_callback = header_callback;
    if (pContext->print_header_callback != NULL)
    {
        int64_t current_size;

		pthread_mutex_lock(&(pContext->log_thread_lock));
        current_size = pContext->current_size;
		pthread_mutex_unlock(&(pContext->log_thread_lock));
        if (current_size == 0)
        {
            log_print_header(pContext);
        }
    }
}

void log_take_over_stderr_ex(LogContext *pContext)
{
    pContext->take_over_stderr = true;
}

void log_take_over_stdout_ex(LogContext *pContext)
{
    pContext->take_over_stdout = true;
}

void log_set_fd_flags(LogContext *pContext, const int flags)
{
    pContext->fd_flags = flags;
}

void log_destroy_ex(LogContext *pContext)
{
	if (pContext->log_fd >= 0 && pContext->log_fd != STDERR_FILENO)
	{
		log_fsync(pContext, true);

		close(pContext->log_fd);
		pContext->log_fd = STDERR_FILENO;

		pthread_mutex_destroy(&pContext->log_thread_lock);
	}

	if (pContext->log_buff != NULL)
	{
		free(pContext->log_buff);
		pContext->log_buff = NULL;
		pContext->pcurrent_buff = NULL;
	}
}

int log_sync_func(void *args)
{
	if (args == NULL)
	{
		return EINVAL;
	}

	return log_fsync((LogContext *)args, true);
}

int log_notify_rotate(void *args)
{
	if (args == NULL)
	{
		return EINVAL;
	}

	((LogContext *)args)->rotate_immediately = true;
	return 0;
}

static int log_delete_matched_old_files(LogContext *pContext,
        const int prefix_len)
{
    char rotate_time_format_prefix[32];
	char log_filepath[MAX_PATH_SIZE];
	char filename_prefix[MAX_PATH_SIZE + 32];
	char full_filename[MAX_PATH_SIZE + 32];
    int prefix_filename_len;
    int result;
    int len;
    char *p;
    char *log_filename;
    DIR *dir;
    struct dirent ent;
    struct dirent *pEntry;
    time_t the_time;
	struct tm tm;

    p = strrchr(pContext->log_filename, '/');
    if (p == NULL)
    {
        *log_filepath = '.';
        *(log_filepath + 1) = '/';
        *(log_filepath + 2) = '\0';
        log_filename = pContext->log_filename;
    }
    else
    {
        int path_len;
        path_len = (p - pContext->log_filename) + 1;
        memcpy(log_filepath, pContext->log_filename, path_len);
        *(log_filepath + path_len) = '\0';
        log_filename = p + 1;
    }

    memcpy(rotate_time_format_prefix, pContext->rotate_time_format, prefix_len);
    *(rotate_time_format_prefix + prefix_len) = '\0';

    dir = opendir(log_filepath);
    if (dir == NULL)
    {
        fprintf(stderr, "file: "__FILE__", line: %d, " \
                "opendir %s fail, errno: %d, error info: %s\n", \
                __LINE__, log_filepath, errno, STRERROR(errno));
        return errno != 0 ? errno : ENOENT;
    }

    result = 0;
    the_time = get_current_time() - (pContext->keep_days + 1) * 86400;
    localtime_r(&the_time, &tm);
    memset(filename_prefix, 0, sizeof(filename_prefix));
    len = sprintf(filename_prefix, "%s.", log_filename);
    strftime(filename_prefix + len, sizeof(filename_prefix) - len,
            rotate_time_format_prefix, &tm);
    prefix_filename_len = strlen(filename_prefix);
    while (readdir_r(dir, &ent, &pEntry) == 0)
    {
        if (pEntry == NULL)
        {
            break;
        }

        if ((int)strlen(pEntry->d_name) >= prefix_filename_len &&
                memcmp(pEntry->d_name, filename_prefix,
                    prefix_filename_len) == 0)
        {
            snprintf(full_filename, sizeof(full_filename), "%s%s",
                    log_filepath, pEntry->d_name);
            if (unlink(full_filename) != 0)
            {
                if (errno != ENOENT)
                {
                    fprintf(stderr, "file: "__FILE__", line: %d, " \
                            "unlink %s fail, errno: %d, error info: %s\n", \
                            __LINE__, full_filename, errno, STRERROR(errno));
                    result = errno != 0 ? errno : EPERM;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return result;
}

int log_delete_old_files(void *args)
{
    LogContext *pContext;
    char *p;
	char old_filename[MAX_PATH_SIZE + 32];
    int full_len;
    int prefix_len;
    int len;
	struct tm tm;

	if (args == NULL)
	{
		return EINVAL;
	}

	pContext = (LogContext *)args;
	if (*(pContext->log_filename) == '\0' || \
            *(pContext->rotate_time_format) == '\0')
	{
		return EINVAL;
	}

    if (pContext->keep_days <= 0) {
        return 0;
    }

    full_len = strlen(pContext->rotate_time_format);
    p = pContext->rotate_time_format + full_len - 1;
    while (p > pContext->rotate_time_format)
    {
        if (*(p-1) != '%')
        {
            break;
        }
        if (*p == 'd' || *p == 'm' || *p == 'Y' || *p == 'y')
        {
            break;
        }

        p -= 2;
    }

    prefix_len = (p - pContext->rotate_time_format) + 1;
    if (prefix_len == 0)
    {
        return EINVAL;
    }

    if (prefix_len == full_len)
    {
        time_t the_time;

        the_time = get_current_time() - pContext->keep_days * 86400;
        while (1) {
            the_time -= 86400;
            localtime_r(&the_time, &tm);
            memset(old_filename, 0, sizeof(old_filename));
            len = sprintf(old_filename, "%s.", pContext->log_filename);
            strftime(old_filename + len, sizeof(old_filename) - len,
                    pContext->rotate_time_format, &tm);
            if (unlink(old_filename) != 0)
            {
                if (errno != ENOENT)
                {
                    fprintf(stderr, "file: "__FILE__", line: %d, " \
                            "unlink %s fail, errno: %d, error info: %s\n", \
                            __LINE__, old_filename, errno, STRERROR(errno));
                    return errno != 0 ? errno : EPERM;
                }
                else
                {
                    break;
                }
            }
        }

        return 0;
    }
    else
    {
        return log_delete_matched_old_files(pContext, prefix_len);
    }
}

int log_rotate(LogContext *pContext)
{
	struct tm tm;
	time_t current_time;
    int len;
	char old_filename[MAX_PATH_SIZE + 32];

	if (*(pContext->log_filename) == '\0')
	{
		return ENOENT;
	}

	close(pContext->log_fd);

	current_time = get_current_time();
	localtime_r(&current_time, &tm);

    memset(old_filename, 0, sizeof(old_filename));
	len = sprintf(old_filename, "%s.", pContext->log_filename);
    strftime(old_filename + len, sizeof(old_filename) - len,
            pContext->rotate_time_format, &tm);
    if (access(old_filename, F_OK) == 0)
    {
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"file: %s already exist, rotate file fail\n",
			__LINE__, old_filename);
    }
    else if (rename(pContext->log_filename, old_filename) != 0)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"rename %s to %s fail, errno: %d, error info: %s\n", \
			__LINE__, pContext->log_filename, old_filename, \
			errno, STRERROR(errno));
	}

	return log_open(pContext);
}

static int log_check_rotate(LogContext *pContext)
{
	if (pContext->log_fd == STDERR_FILENO)
	{
		if (pContext->current_size > 0)
		{
			pContext->current_size = 0;
		}
		return ENOENT;
	}
	
	if (pContext->rotate_immediately)
	{
		pContext->rotate_immediately = false;
		return log_rotate(pContext);
	}

	return 0;
}

static int log_fsync(LogContext *pContext, const bool bNeedLock)
{
	int result;
	int lock_res;
	int write_bytes;
    int written;

	if (pContext->pcurrent_buff - pContext->log_buff == 0)
	{
		if (!pContext->rotate_immediately)
		{
			return 0;
		}
		else
		{
            if (bNeedLock)
            {
                pthread_mutex_lock(&(pContext->log_thread_lock));
            }
            result = log_check_rotate(pContext);
            if (bNeedLock)
            {
                pthread_mutex_unlock(&(pContext->log_thread_lock));
            }
            return result;
		}
	}

	if (bNeedLock && ((lock_res=pthread_mutex_lock( \
			&(pContext->log_thread_lock))) != 0))
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, lock_res, STRERROR(lock_res));
	}

	write_bytes = pContext->pcurrent_buff - pContext->log_buff;
    pContext->current_size += write_bytes;
	if (pContext->rotate_size > 0)
	{
		if (pContext->current_size > pContext->rotate_size)
		{
			pContext->rotate_immediately = true;
			log_check_rotate(pContext);
		}
	}

	result = 0;
	do
	{
    written = write(pContext->log_fd, pContext->log_buff, write_bytes);
	pContext->pcurrent_buff = pContext->log_buff;
	if (written != write_bytes)
	{
		result = errno != 0 ? errno : EIO;
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"call write fail, errno: %d, error info: %s\n",\
			 __LINE__, result, STRERROR(result));
		break;
	}

	if (pContext->rotate_immediately)
	{
		result = log_check_rotate(pContext);
	}
	} while (0);

	if (bNeedLock && ((lock_res=pthread_mutex_unlock( \
			&(pContext->log_thread_lock))) != 0))
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, lock_res, STRERROR(lock_res));
	}

	return result;
}

static void doLogEx(LogContext *pContext, struct timeval *tv, \
		const char *caption, const char *text, const int text_len, \
		const bool bNeedSync, const bool bNeedLock)
{
	struct tm tm;
	int time_fragment;
	int buff_len;
	int result;

	if (pContext->time_precision == LOG_TIME_PRECISION_SECOND)
	{
		time_fragment = 0;
	}
	else
	{
		if (pContext->time_precision == LOG_TIME_PRECISION_MSECOND)
		{
			time_fragment = tv->tv_usec / 1000;
		}
		else
		{
			time_fragment = tv->tv_usec;
		}
	}

	localtime_r(&tv->tv_sec, &tm);
	if (bNeedLock && (result=pthread_mutex_lock(&pContext->log_thread_lock)) != 0)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	if (text_len + 64 > LOG_BUFF_SIZE)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"log buff size: %d < log text length: %d ", \
			__LINE__, LOG_BUFF_SIZE, text_len + 64);
        if (bNeedLock)
        {
		    pthread_mutex_unlock(&(pContext->log_thread_lock));
        }
		return;
	}

	if ((pContext->pcurrent_buff - pContext->log_buff) + text_len + 64 \
			> LOG_BUFF_SIZE)
	{
		log_fsync(pContext, false);
	}

	if (pContext->time_precision == LOG_TIME_PRECISION_SECOND)
	{
		buff_len = sprintf(pContext->pcurrent_buff, \
			"[%04d-%02d-%02d %02d:%02d:%02d] ", \
			tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, \
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	}
	else
	{
		buff_len = sprintf(pContext->pcurrent_buff, \
			"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ", \
			tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, \
			tm.tm_hour, tm.tm_min, tm.tm_sec, time_fragment);
	}
	pContext->pcurrent_buff += buff_len;

	if (caption != NULL)
	{
		buff_len = sprintf(pContext->pcurrent_buff, "%s - ", caption);
		pContext->pcurrent_buff += buff_len;
	}
	memcpy(pContext->pcurrent_buff, text, text_len);
	pContext->pcurrent_buff += text_len;
	*pContext->pcurrent_buff++ = '\n';

	if (!pContext->log_to_cache || bNeedSync)
	{
		log_fsync(pContext, false);
	}

	if (bNeedLock && (result=pthread_mutex_unlock(&(pContext->log_thread_lock))) != 0)
	{
		fprintf(stderr, "file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}
}

void log_it_ex2(LogContext *pContext, const char *caption, \
		const char *text, const int text_len, \
        const bool bNeedSync, const bool bNeedLock)
{
	struct timeval tv;

	if (pContext->time_precision == LOG_TIME_PRECISION_SECOND)
	{
		tv.tv_sec = get_current_time();
		tv.tv_usec = 0;
	}
	else
	{
		gettimeofday(&tv, NULL);
	}

	doLogEx(pContext, &tv, caption, text, text_len, bNeedSync, bNeedLock);
}

void log_it_ex1(LogContext *pContext, const int priority, \
		const char *text, const int text_len)
{
	bool bNeedSync;
	char *caption;

	switch(priority)
	{
		case LOG_DEBUG:
			bNeedSync = true;
			caption = "DEBUG";
			break;
		case LOG_INFO:
			bNeedSync = true;
			caption = "INFO";
			break;
		case LOG_NOTICE:
			bNeedSync = false;
			caption = "NOTICE";
			break;
		case LOG_WARNING:
			bNeedSync = false;
			caption = "WARNING";
			break;
		case LOG_ERR:
			bNeedSync = false;
			caption = "ERROR";
			break;
		case LOG_CRIT:
			bNeedSync = true;
			caption = "CRIT";
			break;
		case LOG_ALERT:
			bNeedSync = true;
			caption = "ALERT";
			break;
		case LOG_EMERG:
			bNeedSync = true;
			caption = "EMERG";
			break;
		default:
			bNeedSync = false;
			caption = "UNKOWN";
			break;
	}

	log_it_ex2(pContext, caption, text, text_len, bNeedSync, true);
}

void log_it_ex(LogContext *pContext, const int priority, const char *format, ...)
{
	bool bNeedSync;
	char text[LINE_MAX];
	char *caption;
	int len;

	va_list ap;
	va_start(ap, format);
	len = vsnprintf(text, sizeof(text), format, ap);
	va_end(ap);
    if (len >= sizeof(text))
    {
        len = sizeof(text) - 1;
    }

	switch(priority)
	{
		case LOG_DEBUG:
			bNeedSync = true;
			caption = "DEBUG";
			break;
		case LOG_INFO:
			bNeedSync = true;
			caption = "INFO";
			break;
		case LOG_NOTICE:
			bNeedSync = false;
			caption = "NOTICE";
			break;
		case LOG_WARNING:
			bNeedSync = false;
			caption = "WARNING";
			break;
		case LOG_ERR:
			bNeedSync = false;
			caption = "ERROR";
			break;
		case LOG_CRIT:
			bNeedSync = true;
			caption = "CRIT";
			break;
		case LOG_ALERT:
			bNeedSync = true;
			caption = "ALERT";
			break;
		case LOG_EMERG:
			bNeedSync = true;
			caption = "EMERG";
			break;
		default:
			bNeedSync = false;
			caption = "UNKOWN";
			break;
	}

	log_it_ex2(pContext, caption, text, len, bNeedSync, true);
}


#define _DO_LOG(pContext, priority, caption, bNeedSync) \
	char text[LINE_MAX]; \
	int len; \
\
	if (pContext->log_level < priority) \
	{ \
		return; \
	} \
\
	{ \
	va_list ap; \
	va_start(ap, format); \
	len = vsnprintf(text, sizeof(text), format, ap);  \
	va_end(ap); \
    if (len >= sizeof(text)) \
    { \
        len = sizeof(text) - 1; \
    } \
	} \
\
	log_it_ex2(pContext, caption, text, len, bNeedSync, true);


void logEmergEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_EMERG, "EMERG", true)
}

void logAlertEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_ALERT, "ALERT", true)
}

void logCritEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_CRIT, "CRIT", true)
}

void logErrorEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_ERR, "ERROR", false)
}

void logWarningEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_WARNING, "WARNING", false)
}

void logNoticeEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_NOTICE, "NOTICE", false)
}

void logInfoEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_INFO, "INFO", false)
}

void logDebugEx(LogContext *pContext, const char *format, ...)
{
	_DO_LOG(pContext, LOG_DEBUG, "DEBUG", false)
}

void logAccess(LogContext *pContext, struct timeval *tvStart, \
		const char *format, ...)
{
	char text[LINE_MAX];
	int len;
	va_list ap;

	va_start(ap, format);
	len = vsnprintf(text, sizeof(text), format, ap);
	va_end(ap);
    if (len >= sizeof(text))
    {
        len = sizeof(text) - 1;
    }
	doLogEx(pContext, tvStart, NULL, text, len, false, true);
}

#ifndef LOG_FORMAT_CHECK

void logEmerg(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_EMERG, "EMERG", true)
}

void logAlert(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_ALERT, "ALERT", true)
}

void logCrit(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_CRIT, "CRIT", true)
}

void logError(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_ERR, "ERROR", false)
}

void logWarning(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_WARNING, "WARNING", false)
}

void logNotice(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_NOTICE, "NOTICE", false)
}

void logInfo(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_INFO, "INFO", true)
}

void logDebug(const char *format, ...)
{
	_DO_LOG((&g_log_context), LOG_DEBUG, "DEBUG", true)
}

#endif

