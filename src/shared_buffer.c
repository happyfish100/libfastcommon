#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include "shared_buffer.h"

static int shared_buffer_alloc_init(void *element, void *args)
{
    SharedBuffer *buffer;
    SharedBufferContext *ctx;

    buffer = (SharedBuffer *)element;
    ctx = (SharedBufferContext *)args;
    buffer->ctx = ctx;

    return shared_buffer_check_capacity(buffer,
            ctx->buffer_init_capacity);
}

int shared_buffer_init_ex(SharedBufferContext *context,
        const int alloc_elements_once, const int buffer_init_capacity,
        const bool need_lock)
{
    int result;

    context->buffer_init_capacity = buffer_init_capacity;
    if ((result=fast_mblock_init_ex2(&context->allocator, "shared_buffer",
                    sizeof(SharedBuffer), alloc_elements_once,
                    shared_buffer_alloc_init, context, need_lock,
                    NULL, NULL, NULL)) != 0)
    {
        return result;
    }

    return 0;
}

void shared_buffer_destroy(SharedBufferContext *context)
{
    fast_mblock_destroy(&context->allocator);
}
