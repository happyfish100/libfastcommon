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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "fastcommon/logger.h"
#include "fastcommon/fast_buffer.h"
#include "fastcommon/sched_thread.h"

typedef enum {
    TEST_TYPE_ITOA = 1,
    TEST_TYPE_FTOA,
    TEST_TYPE_MIXED
} TestType;

typedef enum {
    DA_SLICE_TYPE_FILE  = 'F', /* in file slice */
    DA_SLICE_TYPE_CACHE = 'C', /* in memory cache */
    DA_SLICE_TYPE_ALLOC = 'A'  /* allocate slice (index and space allocate only) */
} DASliceType;

typedef struct {
    int64_t version;
    uint64_t trunk_id; //0 for not inited
    uint32_t length;   //data length
    uint32_t offset;   //space offset
    uint32_t size;     //space size
} DAPieceFieldStorage;

typedef struct {
    int64_t version; //for stable sort only
    uint64_t oid;    //object ID
    uint64_t fid;    //field ID (key)
    uint32_t extra;       //such as slice offset
    char op_type;
    DASliceType slice_type;
    DAPieceFieldStorage storage;
} DATrunkSpaceLogRecord;

static inline void log_pack_by_append(const DATrunkSpaceLogRecord
        *record, FastBuffer *buffer, const bool have_extra_field)
{
    fast_buffer_append_int64(buffer, (uint32_t)g_current_time);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->storage.version);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->oid);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->fid);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_char(buffer, record->op_type);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->storage.trunk_id);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->storage.length);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->storage.offset);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_int64(buffer, record->storage.size);
    fast_buffer_append_char(buffer, ' ');
    fast_buffer_append_char(buffer, record->slice_type);

    if (have_extra_field) {
        fast_buffer_append_char(buffer, ' ');
        fast_buffer_append_char(buffer, record->extra);
        fast_buffer_append_char(buffer, '\n');
    } else {
        fast_buffer_append_char(buffer, '\n');
    }
}

static inline void log_pack_by_sprintf(const DATrunkSpaceLogRecord
        *record, FastBuffer *buffer, const bool have_extra_field)
{
    buffer->length += sprintf(buffer->data + buffer->length,
            "%u %"PRId64" %"PRId64" %"PRId64" %c %"PRId64" %u %u %u %c",
            (uint32_t)g_current_time, record->storage.version,
            record->oid, record->fid, record->op_type,
            record->storage.trunk_id, record->storage.length,
            record->storage.offset, record->storage.size,
            record->slice_type);
    if (have_extra_field) {
        buffer->length += sprintf(buffer->data + buffer->length,
                " %u\n", record->extra);
    } else {
        *(buffer->data + buffer->length++) = '\n';
    }
}

#define BINLOG_FILENAME_PREFIX_STR  "binlog."
#define BINLOG_FILENAME_PREFIX_LEN  (sizeof(BINLOG_FILENAME_PREFIX_STR) - 1)

static inline int cache_binlog_filename_by_sprintf(
        const char *data_path, const char *subdir_name,
        const uint32_t subdirs, const uint64_t id,
        char *full_filename, const int size)
{
    int path_index;
    path_index = id % subdirs;
    return sprintf(full_filename, "%s/%s/%02X/%02X/%s%08"PRIX64,
            data_path, subdir_name, path_index, path_index,
            BINLOG_FILENAME_PREFIX_STR, id);
}

static inline int cache_binlog_filename_by_append(
        const char *data_path, const char *subdir_name,
        const uint32_t subdirs, const uint64_t id,
        char *full_filename, const int size)
{
    int path_index;
    int path_len;
    int subdir_len;
    char *p;

    path_index = id % subdirs;
    path_len = strlen(data_path);
    subdir_len = strlen(subdir_name);
    p = full_filename;
    memcpy(p, data_path, path_len);
    p += path_len;
    *p++ = '/';
    memcpy(p, subdir_name, subdir_len);
    p += subdir_len;
    *p++ = '/';
    *p++ = g_upper_hex_chars[(path_index >> 4) & 0x0F];
    *p++ = g_upper_hex_chars[path_index & 0x0F];
    *p++ = '/';
    *p++ = g_upper_hex_chars[(path_index >> 4) & 0x0F];
    *p++ = g_upper_hex_chars[path_index & 0x0F];
    *p++ = '/';
    memcpy(p, BINLOG_FILENAME_PREFIX_STR, BINLOG_FILENAME_PREFIX_LEN);
    p += BINLOG_FILENAME_PREFIX_LEN;
    if (id <= UINT32_MAX) {
        p += int2HEX(id, p, 8);
    } else {
        p += long2HEX(id, p, 8);
    }

    return p - full_filename;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-t {itoa | ftoa | mixed}]\n",
            program);
}

int main(int argc, char *argv[])
{
    const bool binary_mode = true;
    const bool check_capacity = false;
    const bool have_extra_field = false;
    const int LOOP = 10 * 1000 * 1000;
    const char *data_path = "/opt/fastcfs/fdir/data";
    const char *subdir_name = "binlog";
    const uint32_t subdirs = 256;

    int result;
    TestType test_type = TEST_TYPE_ITOA;
    uint64_t id = 123456;
    double d = 123.456;
    int ch;
    int i;
    int64_t start_time_us;
    int append_time_us;
    int sprintf_time_us;
    double ratio;
    FastBuffer buffer;
    DATrunkSpaceLogRecord record;
    char full_filename1[PATH_MAX];
    char full_filename2[PATH_MAX];
    char buff[32] = {0};
    char *caption = "itoa";

	log_init();
    g_current_time = time(NULL);
    if ((result=fast_buffer_init_ex(&buffer, 256,
                    binary_mode, check_capacity)) != 0)
    {
        return result;
    }

    while ((ch=getopt(argc, argv, "ht:")) != -1) {
        switch (ch) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 't':
                if (strcasecmp(optarg, "itoa") == 0) {
                    test_type = TEST_TYPE_ITOA;
                    caption = "itoa";
                } else if (strcasecmp(optarg, "ftoa") == 0) {
                    test_type = TEST_TYPE_FTOA;
                    caption = "ftoa";
                } else if (strcasecmp(optarg, "mixed") == 0) {
                    test_type = TEST_TYPE_MIXED;
                    caption = "append";
                } else {
                    fprintf(stderr, "invalid type: %s\n", optarg);
                    return EINVAL;
                }
                break;
            default:
                usage(argv[0]);
                return EINVAL;
        }
    }

    if (test_type == TEST_TYPE_MIXED) {
        memset(&record, 0, sizeof(record));
        record.op_type = 'C';
        record.slice_type = DA_SLICE_TYPE_FILE;
        record.storage.version = 1111;
        record.oid = 9007211709265131LL;
        record.fid = 0;
        record.storage.trunk_id = 61;
        record.storage.length = 62;
        record.storage.offset = 12345;
        record.storage.size = 64;
    }

    start_time_us = get_current_time_us();
    for (i=0; i<LOOP; i++) {
        switch (test_type) {
            case TEST_TYPE_MIXED:
                cache_binlog_filename_by_sprintf(data_path, subdir_name,
                        subdirs, ++id, full_filename1, sizeof(full_filename1));
                fast_buffer_reset(&buffer);
                log_pack_by_sprintf(&record, &buffer, have_extra_field);
                break;
            case TEST_TYPE_ITOA:
                sprintf(buff, "%"PRId64, id);
                break;
            case TEST_TYPE_FTOA:
                sprintf(buff, "%.2f", d);
                break;
            default:
                break;
        }
    }
    sprintf_time_us = (get_current_time_us() - start_time_us);

    start_time_us = get_current_time_us();
    for (i=0; i<LOOP; i++) {
        switch (test_type) {
            case TEST_TYPE_MIXED:
                cache_binlog_filename_by_append(data_path, subdir_name,
                        subdirs, ++id, full_filename2, sizeof(full_filename2));
                fast_buffer_reset(&buffer);
                log_pack_by_append(&record, &buffer, have_extra_field);
                break;
            case TEST_TYPE_ITOA:
                fc_itoa(id, buff);
                break;
            case TEST_TYPE_FTOA:
                fc_ftoa(d, 2, buff);
                break;
            default:
                break;
        }
    }
    append_time_us = (get_current_time_us() - start_time_us);

    if (append_time_us > 0) {
        ratio = (double)sprintf_time_us / (double)append_time_us;
    } else {
        ratio = 1.0;
    }

    printf("sprintf time: %d ms, %s time: %d ms, "
            "sprintf time / %s time: %d%%\n",
            sprintf_time_us / 1000, caption, append_time_us / 1000,
            caption, (int)(ratio * 100.00));

    fast_buffer_destroy(&buffer);
	return 0;
}
