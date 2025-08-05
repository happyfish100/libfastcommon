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

int main(int argc, char *argv[])
{
    const bool binary_mode = true;
    const bool check_capacity = false;
    const bool have_extra_field = false;
    const int LOOP = 10 * 1000 * 1000;
    int result;
    int i;
    int64_t start_time_us;
    int append_time_ms;
    int sprintf_time_ms;
    double ratio;
    FastBuffer buffer;
    DATrunkSpaceLogRecord record;

	log_init();
    g_current_time = time(NULL);
    if ((result=fast_buffer_init_ex(&buffer, 256,
                    binary_mode, check_capacity)) != 0)
    {
        return result;
    }

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

    start_time_us = get_current_time_us();
    for (i=0; i<LOOP; i++) {
        fast_buffer_reset(&buffer);
        log_pack_by_sprintf(&record, &buffer, have_extra_field);
    }
    sprintf_time_ms = (get_current_time_us() - start_time_us) / 1000;

    start_time_us = get_current_time_us();
    for (i=0; i<LOOP; i++) {
        fast_buffer_reset(&buffer);
        log_pack_by_append(&record, &buffer, have_extra_field);
    }
    append_time_ms = (get_current_time_us() - start_time_us) / 1000;

    if (append_time_ms > 0) {
        ratio = (double)sprintf_time_ms / (double)append_time_ms;
    } else {
        ratio = 1.0;
    }

    printf("sprintf time: %d ms, append time: %d ms, "
            "sprintf time / append time: %d%%\n",
            sprintf_time_ms, append_time_ms,
            (int)(ratio * 100.00));

    fast_buffer_destroy(&buffer);
	return 0;
}
