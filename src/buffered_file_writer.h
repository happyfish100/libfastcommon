/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#ifndef BUFFERED_FILE_WRITER_H
#define BUFFERED_FILE_WRITER_H

#include "common_define.h"

typedef struct
{
    int fd;
    int buffer_size;
    char filename[MAX_PATH_SIZE];
    char *buff;
    char *current;
    char *buff_end;
    char *water_mark;
} BufferedFileWriter;

#ifdef __cplusplus
extern "C" {
#endif

/** open buffered file writer
 *  parameters:
 *         writer: the writer
 *         filename: the filename to write
 *         buffer_size: the buffer size, <= 0 for recommend 64KB
 *         max_written_once: max written bytes per call, <= 0 for 256
 *         mode: the file privilege such as 0644
 *  return: error code, 0 for success, != 0 for errno
 */
int buffered_file_writer_open_ex(BufferedFileWriter *writer,
        const char *filename, const int buffer_size,
        const int max_written_once, const int mode);

static inline int buffered_file_writer_open(BufferedFileWriter *writer,
        const char *filename)
{
    const int buffer_size = 0;
    const int max_written_once = 0;
    const int mode = 0644;
    return buffered_file_writer_open_ex(writer, filename,
            buffer_size, max_written_once, mode);
}

/** close buffered file writer
 * parameters:
 *         writer: the writer
 *  return: error code, 0 for success, != 0 for errno
 */
int buffered_file_writer_close(BufferedFileWriter *writer);

int buffered_file_writer_append(BufferedFileWriter *writer,
        const char *format, ...);

int buffered_file_writer_append_buff(BufferedFileWriter *writer,
        const char *buff, const int len);

int buffered_file_writer_flush(BufferedFileWriter *writer);

#ifdef __cplusplus
}
#endif

#endif

