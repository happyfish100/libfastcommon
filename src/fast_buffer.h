#ifndef __FAST_BUFFER_H__
#define __FAST_BUFFER_H__

#include <stdint.h>

typedef struct fast_buffer {
    char *data;
    int alloc_size;
    int length;
} FastBuffer;

#ifdef __cplusplus
extern "C" {
#endif

static inline int fast_buffer_length(FastBuffer *buffer)
{
    return buffer->length;
}

static inline char *fast_buffer_data(FastBuffer *buffer)
{
    return buffer->data;
}

int fast_buffer_init_ex(FastBuffer *buffer, const int init_capacity);

static inline int fast_buffer_init(FastBuffer *buffer)
{
    return fast_buffer_init_ex(buffer, 0);
}

#define fast_buffer_clear(buffer) fast_buffer_reset(buffer)

static inline void fast_buffer_reset(FastBuffer *buffer)
{
    buffer->length = 0;
    *buffer->data = '\0';
}

void fast_buffer_destroy(FastBuffer *buffer);

int fast_buffer_append(FastBuffer *buffer, const char *format, ...);

int fast_buffer_append_buff(FastBuffer *buffer, const char *data, const int len);

int fast_buffer_append_int(FastBuffer *buffer, const int n);

int fast_buffer_append_int64(FastBuffer *buffer, const int64_t n);

static inline int fast_buffer_append_string(FastBuffer *buffer, const char *str)
{
    return fast_buffer_append_buff(buffer, str, strlen(str));
}

static inline int fast_buffer_append_buffer(FastBuffer *buffer, FastBuffer *src)
{
    return fast_buffer_append_buff(buffer, src->data, src->length);
}

#ifdef __cplusplus
}
#endif

#endif

