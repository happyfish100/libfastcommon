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

//common_define.h

#ifndef _COMMON_DEFINE_H_
#define _COMMON_DEFINE_H_

#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#ifdef WIN32

#include <windows.h>
#include <winsock.h>
typedef UINT in_addr_t;
#define FILE_SEPERATOR	"\\"
#define THREAD_ENTRANCE_FUNC_DECLARE  DWORD WINAPI
#define THREAD_RETURN_VALUE	 0
typedef DWORD (WINAPI *ThreadEntranceFunc)(LPVOID lpThreadParameter);
#else

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#define FILE_SEPERATOR	"/"
typedef int SOCKET;
#define closesocket     close
#define INVALID_SOCKET  -1
#define THREAD_ENTRANCE_FUNC_DECLARE  void *
typedef void *LPVOID;
#define THREAD_RETURN_VALUE	 NULL
typedef void * (*ThreadEntranceFunc)(LPVOID lpThreadParameter);

#endif

#ifndef WIN32
extern int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int kind);
#endif

#include "_os_define.h"

#ifdef OS_LINUX
#include <sys/prctl.h>
#endif

#ifdef OS_LINUX
#ifndef PTHREAD_MUTEX_ERRORCHECK
#define PTHREAD_MUTEX_ERRORCHECK PTHREAD_MUTEX_ERRORCHECK_NP
#endif
#endif

#ifdef OS_BITS
  #if OS_BITS == 64
    #define INT64_PRINTF_FORMAT   "%ld"
  #else
    #define INT64_PRINTF_FORMAT   "%lld"
  #endif
#else
  #define INT64_PRINTF_FORMAT   "%lld"
#endif

#ifdef OFF_BITS
  #if OFF_BITS == 64
    #define OFF_PRINTF_FORMAT   INT64_PRINTF_FORMAT
  #else
    #define OFF_PRINTF_FORMAT   "%d"
  #endif
#else
  #define OFF_PRINTF_FORMAT   INT64_PRINTF_FORMAT
#endif

#ifndef WIN32
#define USE_SENDFILE
#endif

#define MAX_PATH_SIZE                  256
#define LOG_FILE_DIR				"logs"
#define CONF_FILE_DIR				"conf"
#define DEFAULT_CONNECT_TIMEOUT			10
#define DEFAULT_NETWORK_TIMEOUT			30
#define DEFAULT_MAX_CONNECTONS         256
#define DEFAULT_WORK_THREADS             4
#define SYNC_LOG_BUFF_DEF_INTERVAL      10
#define TIME_NONE                       -1

#define IP_ADDRESS_SIZE	16
#define INFINITE_FILE_SIZE (256 * 1024LL * 1024 * 1024 * 1024 * 1024LL)

#define FILE_RESOURCE_TAG_STR  "file://"
#define FILE_RESOURCE_TAG_LEN  (sizeof(FILE_RESOURCE_TAG_STR) - 1)

#define IS_FILE_RESOURCE(filename) \
    (strncasecmp(filename, FILE_RESOURCE_TAG_STR,  \
                 FILE_RESOURCE_TAG_LEN) == 0)

#ifndef byte
#define byte signed char
#endif

#ifndef ubyte
#define ubyte unsigned char
#endif

#ifndef WIN32
#ifndef INADDR_NONE
#define  INADDR_NONE  ((in_addr_t) 0xffffffff)
#endif
#endif

#ifndef ECANCELED
#define ECANCELED 125
#endif

#ifndef ENONET
#define ENONET          64      /* Machine is not on the network */
#endif

#define compile_barrier() __asm__ __volatile__("" : : : "memory")

#define IS_UPPER_HEX(ch) ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'))
#define IS_HEX_CHAR(ch)  (IS_UPPER_HEX(ch) || (ch >= 'a' && ch <= 'f'))
#define FC_IS_DIGITAL(ch)  (ch >= '0' && ch <= '9')
#define FC_IS_LETTER(ch)  ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
#define FC_IS_UPPER_LETTER(ch)  (ch >= 'A' && ch <= 'Z')
#define FC_IS_LOWER_LETTER(ch)  (ch >= 'a' && ch <= 'z')
#define FC_MIN(v1, v2) ((v1) < (v2) ? (v1) : (v2))
#define FC_MAX(v1, v2) ((v1) > (v2) ? (v1) : (v2))
#define FC_ABS(n) ((n) >= 0 ? (n) : -1 * (n))
#define FC_NEGATIVE(n) ((n) <= 0 ? (n) : -1 * (n))

#define FC_TIME_UNIT_SECOND   's'  //second
#define FC_TIME_UNIT_MSECOND  'm'  //millisecond
#define FC_TIME_UNIT_USECOND  'u'  //microsecond
#define FC_TIME_UNIT_NSECOND  'n'  //nanosecond

#define STRERROR(no) (strerror(no) != NULL ? strerror(no) : "Unkown error")

#if defined(OS_LINUX)
#if defined __USE_MISC || defined __USE_XOPEN2K8
#define st_atimensec st_atim.tv_nsec
#define st_mtimensec st_mtim.tv_nsec
#define st_ctimensec st_ctim.tv_nsec
#endif
#elif defined(OS_FREEBSD)
#define st_atimensec st_atimespec.tv_nsec
#define st_mtimensec st_mtimespec.tv_nsec
#define st_ctimensec st_ctimespec.tv_nsec
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	byte hour;
	byte minute;
	byte second;
} TimeInfo;

typedef struct
{
	char major;
	char minor;
    char patch;
} Version;

typedef struct
{
    char **strs;
    int count;
} str_ptr_array_t;

typedef struct
{
	char *key;
	char *value;
} KeyValuePair;

typedef struct
{
	char *key;
	char *value;
    int key_len;
    int value_len;
} KeyValuePairEx;

typedef struct
{
	char *buff;
	int alloc_size;
	int length;
} BufferInfo;

typedef struct
{
    char *str;
    int len;
} string_t;

typedef struct
{
    string_t *strings;
    int count;
} string_array_t;

typedef struct
{
    int64_t id;
    string_t name;
} id_name_pair_t;

typedef struct
{
    string_t key;
    string_t value;
} key_value_pair_t;

typedef struct
{
    key_value_pair_t *kv_pairs;
    int count;
} key_value_array_t;

typedef struct
{
    int32_t *elts;
    int count;
} int32_array_t;

typedef struct
{
    int64_t *elts;
    int count;
} int64_array_t;

typedef struct
{
    id_name_pair_t *elts;
    int count;
} id_name_array_t;

typedef struct
{
    void *elts;
    int count;
} void_array_t;

typedef struct
{
    pthread_mutex_t lock;
    pthread_cond_t cond;
} pthread_lock_cond_pair_t;

typedef struct
{
    int alloc;
    int count;
    struct iovec *iovs;
} iovec_array_t;

typedef struct
{
    char buff[PATH_MAX];
    string_t s;
} FilenameString;

typedef struct {
    char *filename;
    char *tmp_filename;
    int fd;
} SafeWriteFileInfo;

typedef void (*FreeDataFunc)(void *ptr);
typedef int (*CompareFunc)(void *p1, void *p2);
typedef void* (*MallocFunc)(size_t size);

#define TO_UPPERCASE(c)  (((c) >= 'a' && (c) <= 'z') ? (c) - 32 : c)

#define MEM_ALIGN_FLOOR(x, align_size) ((x) & (~(align_size - 1)))
#define MEM_ALIGN_CEIL(x, align_size) \
    (((x) + (align_size - 1)) & (~(align_size - 1)))
#define MEM_ALIGN(x)  MEM_ALIGN_CEIL(x, 8)

#define FC_INIT_CHAIN(chain) (chain).head = (chain).tail = NULL
#define FC_IS_CHAIN_EMPTY(chain) ((chain).head == NULL)

#define FC_SET_CHAIN_TAIL_NEXT(chain, type, ptr) \
    ((type *)(chain).tail)->next = ptr

#ifdef WIN32
#define strcasecmp	_stricmp
#endif

#ifndef likely

#if defined(__GNUC__) &&  __GNUC__ >= 3
#define likely(cond)   __builtin_expect ((cond), 1)
#define unlikely(cond) __builtin_expect ((cond), 0)
#else
#define likely(cond)   (cond)
#define unlikely(cond) (cond)
#endif

#endif

#ifdef __GNUC__
  #define __gcc_attribute__ __attribute__
#else
  #define __gcc_attribute__(x)
#endif

#define FC_IS_CHINESE_UTF8_CHAR(p, end) \
    ((p + 2 < end) &&  \
     ((((unsigned char)*p) & 0xF0) == 0xE0) &&       \
     ((((unsigned char)*(p + 1)) & 0xC0) == 0x80) && \
     ((((unsigned char)*(p + 2)) & 0xC0) == 0x80))

//for printf format %.*s
#define FC_PRINTF_STAR_STRING_PARAMS(s)  (s).len, (s).str

#define FC_SET_IOVEC(iovec, buff, len) \
    do {  \
        (iovec).iov_base = buff; \
        (iovec).iov_len = len;   \
    } while (0)

#define FC_SET_STRING(dest, src)  \
    do {  \
        (dest).str = src;         \
        (dest).len = strlen(src); \
    } while (0)

#define FC_SET_STRING_EX(dest, s, l)  \
    do {  \
        (dest).str = s;   \
        (dest).len = l;   \
    } while (0)

#define FC_SET_STRING_NULL(dest)  \
    do {  \
        (dest).str = NULL;   \
        (dest).len = 0;      \
    } while (0)

#define FC_IS_NULL_STRING(s)  ((s)->str == NULL)
#define FC_IS_EMPTY_STRING(s)  ((s)->len == 0)

#define FC_INIT_FILENAME_STRING(filename)  \
    FC_SET_STRING_EX((filename).s, (filename).buff, 0)

#define FC_FILENAME_STRING_OBJ(filename)  ((filename).s)
#define FC_FILENAME_STRING_PTR(filename)  ((filename).buff)
#define FC_FILENAME_BUFFER_SIZE(filename)  sizeof((filename).buff)

#define fc_compare_string(s1, s2) fc_string_compare(s1, s2)

static inline int fc_string_compare(const string_t *s1, const string_t *s2)
{
    int result;
    if (s1->len == s2->len) {
        return memcmp(s1->str, s2->str, s1->len);
    } else if (s1->len < s2->len) {
        result = memcmp(s1->str, s2->str, s1->len);
        return result == 0 ? -1 : result;
    } else {
        result = memcmp(s1->str, s2->str, s2->len);
        return result == 0 ? 1 : result;
    }
}

static inline bool fc_string_equal(const string_t *s1, const string_t *s2)
{
    return (s1->len == s2->len) && (memcmp(s1->str, s2->str, s1->len) == 0);
}

static inline bool fc_string_equal2(const string_t *s1,
        const char *str2, const int len2)
{
    return (s1->len == len2) && (memcmp(s1->str, str2, s1->len) == 0);
}

#define fc_string_equals(s1, s2) fc_string_equal(s1, s2)
#define fc_string_equals2(s1, str2, len2) fc_string_equal2(s1, str2, len2)


#define fc_case_compare_string(s1, s2) fc_string_case_compare(s1, s2)

static inline int fc_string_case_compare(const string_t *s1, const string_t *s2)
{
    int result;
    if (s1->len == s2->len) {
        return strncasecmp(s1->str, s2->str, s1->len);
    } else if (s1->len < s2->len) {
        result = strncasecmp(s1->str, s2->str, s1->len);
        return result == 0 ? -1 : result;
    } else {
        result = strncasecmp(s1->str, s2->str, s2->len);
        return result == 0 ? 1 : result;
    }
}

static inline bool fc_string_case_equal(const string_t *s1, const string_t *s2)
{
    return (s1->len == s2->len) && (strncasecmp(s1->str, s2->str, s1->len) == 0);
}

static inline bool fc_string_case_equal2(const string_t *s1,
        const char *str2, const int len2)
{
    return (s1->len == len2) && (strncasecmp(s1->str, str2, s1->len) == 0);
}

#define fc_string_case_equals(s1, s2) fc_string_case_equal(s1, s2)
#define fc_string_case_equals2(s1, str2, len2) \
    fc_string_case_equal2(s1, str2, len2)


static inline int fc_compare_int64(const int64_t n1, const int64_t n2)
{
    int64_t sub;
    sub = n1 - n2;
    if (sub < 0) {
        return -1;
    } else if (sub > 0) {
        return 1;
    } else {
        return 0;
    }
}

#ifdef OS_LINUX
#define fc_fallocate(fd, size)  fallocate(fd, 0, 0, size)
#else
#define fc_fallocate(fd, size)  ftruncate(fd, size)
#endif


#ifdef __cplusplus
}
#endif

#endif
