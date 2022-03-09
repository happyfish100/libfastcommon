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

//logger.h
#ifndef LOGGER_H
#define LOGGER_H

#include <syslog.h>
#include <sys/time.h>
#include "common_define.h"

#ifdef __cplusplus
extern "C" {
#endif

//log time precision
#define LOG_TIME_PRECISION_SECOND	's'  //second
#define LOG_TIME_PRECISION_MSECOND	'm'  //millisecond
#define LOG_TIME_PRECISION_USECOND	'u'  //microsecond
#define LOG_TIME_PRECISION_NONE 	'0'  //do NOT output timestamp

//log compress flags
#define LOG_COMPRESS_FLAGS_NONE       0
#define LOG_COMPRESS_FLAGS_ENABLED    1
#define LOG_COMPRESS_FLAGS_NEW_THREAD 2

#define LOG_NOTHING    (LOG_DEBUG + 10)

struct log_context;

//log header line callback
typedef void (*LogHeaderCallback)(struct log_context *pContext);

#define FC_LOG_BY_LEVEL(level) \
    (level <= g_log_context.log_level)

typedef struct log_context
{
	/* log level value please see: sys/syslog.h
  	   default value is LOG_INFO */
	int log_level;

	/* default value is STDERR_FILENO */
	int log_fd;

	/* cache buffer */
	char *log_buff;

	/* string end in the cache buffer for next sprintf */
	char *pcurrent_buff;

	/* mutext lock */
	pthread_mutex_t log_thread_lock;

	/*
	rotate the log when the log file exceeds this parameter
	rotate_size > 0 means need rotate log by log file size
	*/
	int64_t rotate_size;

	/* log file current size */
	int64_t current_size;

	/* if write to buffer firstly, then sync to disk.
	   default value is false (no cache) */
	bool log_to_cache;

	/* if rotate the access log */
	bool rotate_immediately;

	/* if stderr to the log file */
    bool take_over_stderr;

	/* if stdout to the log file */
    bool take_over_stdout;

	/* time precision */
	char time_precision;

    /* if use file write lock */
    bool use_file_write_lock;

    /* compress the log file use gzip command */
    short compress_log_flags;

	/* save the log filename */
	char log_filename[MAX_PATH_SIZE];

	/* the time format for rotated filename,
     * default: %Y%m%d_%H%M%S
     * */
    char rotate_time_format[32];

    /* keep days for rotated log files */
    int keep_days;

    /* log fd flags */
    int fd_flags;

    /*
     * log the header (title line) callback
     * */
    LogHeaderCallback print_header_callback;

    /*
     * compress the log files before N days
     * */
    int compress_log_days_before;
} LogContext;

extern LogContext g_log_context;

/** init function using global log context
 *  return: 0 for success, != 0 fail
*/
int log_init();

/** init function using global log context
 *  do nothing when already inited
 *  return: 0 for success, != 0 fail
*/
static inline int log_try_init()
{
    if (g_log_context.log_buff != NULL)
    {
        return 0;
    }
    return log_init();
}

/** init function using global log context, take over stderr and stdout
 *  return: 0 for success, != 0 fail
*/
int log_init2();


#define log_reopen() log_reopen_ex(&g_log_context)

#define log_set_prefix(base_path, filename_prefix) \
	log_set_prefix_ex(&g_log_context, base_path, filename_prefix)

#define log_set_filename(log_filename) \
	log_set_filename_ex(&g_log_context, log_filename)

#define log_set_cache(bLogCache)  log_set_cache_ex(&g_log_context, bLogCache)

#define log_take_over_stderr()  log_take_over_stderr_ex(&g_log_context)
#define log_take_over_stdout()  log_take_over_stdout_ex(&g_log_context)

#define log_set_compress_log_flags(flags) \
    log_set_compress_log_flags_ex(&g_log_context, flags)
#define log_set_compress_log_days_before(days_before) \
    log_set_compress_log_days_before_ex(&g_log_context, days_before)

#define log_set_use_file_write_lock(use_lock)  \
    log_set_use_file_write_lock_ex(&g_log_context, use_lock)

#define log_header(pContext, header, header_len) \
    log_it_ex2(pContext, NULL, header, header_len, false, false)

#define log_destroy()  log_destroy_ex(&g_log_context)

#define log_it1(priority, text, text_len) \
    log_it_ex1(&g_log_context, priority, text, text_len)

#define log_it2(caption, text, text_len, bNeedSync, bNeedLock) \
    log_it_ex2(&g_log_context, caption, text, text_len, bNeedSync, bNeedLock)


/** init function, use stderr for output by default
 *  parameters:
 *           pContext: the log context
 *  return: 0 for success, != 0 fail
*/
int log_init_ex(LogContext *pContext);

/** reopen the log file
 *  parameters:
 *           pContext: the log context
 *  return: 0 for success, != 0 fail
*/
int log_reopen_ex(LogContext *pContext);

/** set log filename prefix, such as "tracker", the log filename will be 
 *  ${base_path}/logs/tracker.log
 *  parameters:
 *           pContext: the log context
 *           base_path: base path
 *           filename_prefix: log filename prefix
 *  return: 0 for success, != 0 fail
*/
int log_set_prefix_ex(LogContext *pContext, const char *base_path,
		const char *filename_prefix);

/** set log filename
 *  parameters:
 *           pContext: the log context
 *           log_filename: log filename
 *  return: 0 for success, != 0 fail
*/
int log_set_filename_ex(LogContext *pContext, const char *log_filename);

/** set if use log cache
 *  parameters:
 *           pContext: the log context
 *           bLogCache: true for cache in buffer, false directly write to disk
 *  return: none
*/
void log_set_cache_ex(LogContext *pContext, const bool bLogCache);

/** set if use file write lock
 *  parameters:
 *           pContext: the log context
 *           use_lock: true for use write lock, false NOT use write lock
 *  return: none
*/
void log_set_use_file_write_lock_ex(LogContext *pContext, const bool use_lock);

/** set time precision
 *  parameters:
 *           pContext: the log context
 *           time_precision: the time precision
 *  return: none
*/
void log_set_time_precision(LogContext *pContext, const int time_precision);

/** set rotate time format, the time format same as function strftime
 *  parameters:
 *           pContext: the log context
 *           time_format: rotate time format
 *  return: none
*/
void log_set_rotate_time_format(LogContext *pContext, const char *time_format);

/** set keep days
 *  parameters:
 *           pContext: the log context
 *           keep_days: the keep days
 *  return: none
*/
void log_set_keep_days(LogContext *pContext, const int keep_days);

/** set print header callback
 *  parameters:
 *           pContext: the log context
 *           header_callback: the callback
 *  return: none
*/
void log_set_header_callback(LogContext *pContext, LogHeaderCallback header_callback);

/** set take_over_stderr to true
 *  parameters:
 *           pContext: the log context
 *  return: none
*/
void log_take_over_stderr_ex(LogContext *pContext);

/** set take_over_stdout to true
 *  parameters:
 *           pContext: the log context
 *  return: none
*/
void log_take_over_stdout_ex(LogContext *pContext);


/** init function using global log context
 *  do nothing when already inited
 *  return: 0 for success, != 0 fail
*/
static inline int log_try_init2()
{
    int result;
    if ((result=log_try_init()) != 0)
    {
        return result;
    }

    log_take_over_stderr();
    log_take_over_stdout();
    return 0;
}

/** set compress_log_flags to true
 *  parameters:
 *           pContext: the log context
 *           flags: the compress log flags
 *  return: none
*/
void log_set_compress_log_flags_ex(LogContext *pContext, const short flags);

/** set compress log file before N days
 *  parameters:
 *           pContext: the log context
 *           days_before: compress log file before N days
 *  return: none
*/
void log_set_compress_log_days_before_ex(LogContext *pContext, const int days_before);

/** set log fd flags
 *  parameters:
 *           pContext: the log context
 *           flags: the fd flags
 *  return: none
*/
void log_set_fd_flags(LogContext *pContext, const int flags);

/** destroy function
 *  parameters:
 *           pContext: the log context
 *           bLogCache: true for cache in buffer, false directly write to disk
 *  return: none
*/
void log_destroy_ex(LogContext *pContext);

/** log to file
 *  parameters:
 *           pContext: the log context
 *           priority: unix priority
 *           format: printf format
 *           ...:    arguments for printf format
 *  return: none
*/
void log_it_ex(LogContext *pContext, const int priority, \
		const char *format, ...) __gcc_attribute__ ((format (printf, 3, 4)));

/** log to file
 *  parameters:
 *           pContext: the log context
 *           priority: unix priority
 *           text: text string to log
 *           text_len: text string length (bytes)
 *  return: none
*/
void log_it_ex1(LogContext *pContext, const int priority, \
		const char *text, const int text_len);

/** log to file
 *  parameters:
 *           pContext: the log context
 *           caption: such as INFO, ERROR, NULL for no caption
 *           text: text string to log
 *           text_len: text string length (bytes)
 *           bNeedSync: if sync to file immediatelly
 *  return: none
*/
void log_it_ex2(LogContext *pContext, const char *caption, \
		const char *text, const int text_len, \
        const bool bNeedSync, const bool bNeedLock);


/** sync log buffer to log file
 *  parameters:
 *           args: should be (LogContext *)
 *  return: error no, 0 for success, != 0 fail
*/
int log_sync_func(void *args);

/** set rotate flag to true
 *  parameters:
 *           args: should be (LogContext *)
 *  return: error no, 0 for success, != 0 fail
*/
int log_notify_rotate(void *args);


/** rotate log file
 *  parameters:
 *           pContext: the log context
 *  return: error no, 0 for success, != 0 fail
*/
int log_rotate(LogContext *pContext);

/** delete old log files
 *  parameters:
 *           args: should be (LogContext *)
 *  return: error no, 0 for success, != 0 fail
*/
int log_delete_old_files(void *args);

/** get log level caption
 *  parameters:
 *           pContext: the log context
 *  return: log level caption
*/
const char *log_get_level_caption_ex(LogContext *pContext);

#define log_get_level_caption() log_get_level_caption_ex(&g_log_context)

void logEmergEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logCritEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logAlertEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logErrorEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logWarningEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logNoticeEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logInfoEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logDebugEx(LogContext *pContext, const char *format, ...)
    __gcc_attribute__ ((format (printf, 2, 3)));

void logAccess(LogContext *pContext, struct timeval *tvStart,
        const char *format, ...) __gcc_attribute__ ((format (printf, 3, 4)));

//#define LOG_FORMAT_CHECK

#ifdef LOG_FORMAT_CHECK  /*only for format check*/

#define logEmerg   printf
#define logCrit    printf
#define logAlert   printf
#define logError   printf
#define logWarning printf
#define logNotice  printf
#define logInfo    printf
#define logDebug   printf

#else

/* following functions use global log context: g_log_context */
void logEmerg(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logCrit(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logAlert(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logError(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logWarning(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logNotice(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logInfo(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

void logDebug(const char *format, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

#endif

#ifdef __cplusplus
}
#endif

#endif
