/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include "shared_func.h"
#include "logger.h"
#include "buffered_file_writer.h"

int buffered_file_writer_open_ex(BufferedFileWriter *writer,
        const char *filename, const int buffer_size,
        const int max_written_once, const int mode)
{
    int result;
    int written_once;

    writer->buffer_size = (buffer_size > 0) ? buffer_size : 64 * 1024;
    written_once = (max_written_once > 0) ? max_written_once : 256;
    if (written_once > writer->buffer_size)
    {
        logError("file: "__FILE__", line: %d, "
                "max_written_once: %d > buffer_size: %d",
                __LINE__, written_once, writer->buffer_size);
        return EINVAL;
    }

    writer->buff = (char *)malloc(writer->buffer_size);
    if (writer->buff == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, writer->buffer_size);
        return ENOMEM;
    }

    snprintf(writer->filename, sizeof(writer->filename), "%s", filename);
    writer->fd = open(writer->filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (writer->fd < 0)
    {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->filename,
                result, STRERROR(result));

        free(writer->buff);
        writer->buff = NULL;
        return result;
    }

    writer->current = writer->buff;
    writer->buff_end = writer->buff + writer->buffer_size;
    writer->water_mark = writer->buff_end - written_once;

    return 0;
}

int buffered_file_writer_close(BufferedFileWriter *writer)
{
    int result;

    if (writer->buff == NULL)
    {
        return EINVAL;
    }

    result = buffered_file_writer_flush(writer);
    if (result == 0 && fsync(writer->fd) != 0)
    {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "fsync file %s fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->filename,
                result, STRERROR(result));
    }

    if (close(writer->fd) != 0)
    {
        if (result == 0)
        {
            result = errno != 0 ? errno : EIO;
        }
        logError("file: "__FILE__", line: %d, "
                "close file %s fail, "
                "errno: %d, error info: %s",
                __LINE__, writer->filename,
                errno, STRERROR(errno));
    }

    free(writer->buff);
    writer->buff = NULL;

    return result;
}

int buffered_file_writer_flush(BufferedFileWriter *writer)
{
    int result;
    int len;

    len = writer->current - writer->buff;
    if (len == 0)
    {
        return 0;
    }

    if (fc_safe_write(writer->fd, writer->buff, len) != len)
    {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "write to file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                writer->filename, result, STRERROR(result));
        return result;
    }

    writer->current = writer->buff;
    return 0;
}

int buffered_file_writer_append(BufferedFileWriter *writer,
        const char *format, ...)
{
    va_list ap;
    int result;
    int remain_size;
    int len;
    int i;

    result = 0;
    for (i=0; i<2; i++)
    {
        remain_size = writer->buff_end - writer->current;
        va_start(ap, format);
        len = vsnprintf(writer->current, remain_size, format, ap);
        va_end(ap);

        if (len  < remain_size)
        {
            writer->current += len;
            if (writer->current > writer->water_mark)
            {
                result = buffered_file_writer_flush(writer);
            }

            break;
        }

        if (len > writer->buffer_size)
        {
            result = ENOSPC;
            logError("file: "__FILE__", line: %d, "
                    "too large output buffer, %d > %d!",
                    __LINE__, len, writer->buffer_size);
            break;
        }

        //maybe full, try again
        if ((result=buffered_file_writer_flush(writer)) != 0)
        {
            break;
        }
    }

    return result;
}

int buffered_file_writer_append_buff(BufferedFileWriter *writer,
        const char *buff, const int len)
{
    int result;

    if (len >= writer->water_mark - writer->current)
    {
        if ((result=buffered_file_writer_flush(writer)) != 0)
        {
            return result;
        }

        if (fc_safe_write(writer->fd, buff, len) != len)
        {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write to file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    writer->filename, result, STRERROR(result));
            return result;
        }

        return 0;
    }

    memcpy(writer->current, buff, len);
    writer->current += len;
    return 0;
}
