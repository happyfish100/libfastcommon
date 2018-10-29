#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include "logger.h"
#include "shared_func.h"
#include "fast_buffer.h"

int fast_buffer_init_ex(FastBuffer *buffer, const int init_capacity)
{
    buffer->length = 0;
    if (init_capacity > 0)
    {
        buffer->alloc_size = init_capacity;
    }
    else
    {
        buffer->alloc_size = 256;
    }
    buffer->data = (char *)malloc(buffer->alloc_size);
    if (buffer->data == NULL)
    {
        logError("file: "__FILE__", line: %d, "
             "malloc %d bytes fail", __LINE__, buffer->alloc_size);
        return ENOMEM;
    }
    *(buffer->data) = '\0';
    return 0;
}

void fast_buffer_destroy(FastBuffer *buffer)
{
    if (buffer->data != NULL)
    {
        free(buffer->data);
        buffer->data = NULL;
        buffer->length = 0;
    }
}

int fast_buffer_check(FastBuffer *buffer, const int inc_len)
{
    int alloc_size;
    char *buff;

    if (buffer->alloc_size > buffer->length + inc_len)
    {
        return 0;
    }
    alloc_size = buffer->alloc_size * 2;
    while (alloc_size <= buffer->length + inc_len)
    {
        alloc_size *= 2;
    }

    buff = (char *)malloc(alloc_size);
    if (buff == NULL)
    {
        logError("file: "__FILE__", line: %d, "
             "malloc %d bytes fail", __LINE__, alloc_size);
        return ENOMEM;
    }

    if (buffer->length > 0)
    {
        memcpy(buff, buffer->data, buffer->length);
    }

    free(buffer->data);
    buffer->data = buff;
    buffer->alloc_size = alloc_size;
    return 0;
}

int fast_buffer_append(FastBuffer *buffer, const char *format, ...)
{
    va_list ap;
    int result;
    int len;

    if ((result=fast_buffer_check(buffer, 64)) != 0)
    {
        return result;
    }

    va_start(ap, format);
    len = vsnprintf(buffer->data + buffer->length,
            buffer->alloc_size - buffer->length, format, ap);
    va_end(ap);
    if (len < buffer->alloc_size - buffer->length)
    {
        buffer->length += len;
    }
    else  //maybe full, realloc and try again
    {
        if ((result=fast_buffer_check(buffer, len)) == 0)
        {
            va_start(ap, format);
            buffer->length += vsnprintf(buffer->data + buffer->length,
                    buffer->alloc_size - buffer->length, format, ap);
            va_end(ap);
        }
        else
        {
            *(buffer->data + buffer->length) = '\0';  //restore
        }
    }
    return result;
}

int fast_buffer_append_buff(FastBuffer *buffer, const char *data, const int len)
{
    int result;

    if (len <= 0)
    {
        return 0;
    }
    if ((result=fast_buffer_check(buffer, len)) != 0)
    {
        return result;
    }

    memcpy(buffer->data + buffer->length, data, len);
    buffer->length += len;
    *(buffer->data + buffer->length) = '\0';
    return 0;
}

int fast_buffer_append_int(FastBuffer *buffer, const int n)
{
    int result;

    if ((result=fast_buffer_check(buffer, 16)) != 0)
    {
        return result;
    }

    buffer->length += sprintf(buffer->data + buffer->length, "%d", n);
    return 0;
}

int fast_buffer_append_int64(FastBuffer *buffer, const int64_t n)
{
    int result;

    if ((result=fast_buffer_check(buffer, 32)) != 0)
    {
        return result;
    }

    buffer->length += sprintf(buffer->data + buffer->length, "%"PRId64, n);
    return 0;
}

int fast_buffer_append_file(FastBuffer *buffer, const char *filename)
{
    struct stat st;
    int result;
    int64_t file_size;

    if (stat(filename, &st) != 0) {
        result = errno != 0 ? errno : ENOENT;
        if (result == ENOENT) {
            logError("file: "__FILE__", line: %d, "
                    "file %s not exist!", __LINE__,
                    filename);
        } else {
            logError("file: "__FILE__", line: %d, "
                    "stat file %s fail, "
                    "result: %d, error info: %s", __LINE__,
                    filename, result, strerror(result));
        }

        return result;
    }

    if (!S_ISREG(st.st_mode)) {
        logError("file: "__FILE__", line: %d, "
                "file %s is NOT a regular file!",
                __LINE__, filename);
        return EINVAL;
    }

    file_size = st.st_size + 1;
    if ((result=fast_buffer_check(buffer, file_size)) != 0) {
        return result;
    }

    if ((result=getFileContentEx(filename, buffer->data + buffer->length,
                    0, &file_size)) != 0)
    {
        return result;
    }

    buffer->length += file_size;
    return 0;
}
