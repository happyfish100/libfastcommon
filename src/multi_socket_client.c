#include "common_define.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "logger.h"
#include "sockopt.h"
#include "sched_thread.h"
#include "fast_buffer.h"
#include "multi_socket_client.h"

int fast_multi_sock_client_init(FastMultiSockClient *client,
        FastMultiSockEntry *entries, const int entry_count,
        const int header_length,
        fast_multi_sock_client_get_body_length_func get_body_length_func,
        const int init_buffer_size, const int timeout)
{
    int result;
    int new_init_buffer_size;
    int i;

    memset(client, 0, sizeof(FastMultiSockClient));
    if (entry_count <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid entry_count: %d <= 0",
                __LINE__, entry_count);
        return EINVAL;
    }

    if (header_length <= 0) {
        logError("file: "__FILE__", line: %d, "
                "invalid header_length: %d <= 0",
                __LINE__, header_length);
        return EINVAL;
    }

    if ((result=ioevent_init(&client->ioevent, entry_count,
                    timeout * 1000, 0)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "ioevent_init fail, errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    if (init_buffer_size <= 0) {
        new_init_buffer_size = 4 * 1024;
    } else {
        new_init_buffer_size = init_buffer_size;
    }

    if (new_init_buffer_size < header_length) {
        new_init_buffer_size = header_length;
    }

    for (i=0; i<entry_count; i++) {
        if ((result=fast_buffer_init_ex(&entries[i].buffer, new_init_buffer_size)) != 0) {
            return result;
        }
    }

    client->entry_count = entry_count;
    client->header_length = header_length;
    client->get_body_length_func = get_body_length_func;
    client->entries = entries;
    client->timeout = timeout;

    return 0;
}

void fast_multi_sock_client_destroy(FastMultiSockClient *client)
{
    int i;

    ioevent_destroy(&client->ioevent);
    for (i=0; i<client->entry_count; i++) {
        fast_buffer_destroy(&client->entries[i].buffer);
    }
}

static int fast_multi_sock_client_send_data(FastMultiSockClient *client,
        FastBuffer *buffer)
{
    int i;

    for (i=0; i<client->entry_count; i++) {
        client->entries[i].remain = client->header_length;
        client->entries[i].done = false;
        client->entries[i].buffer.length = 0;

        client->entries[i].error_no = tcpsenddata(client->entries[i].conn->sock,
                buffer->data, buffer->length, client->timeout);
        if (client->entries[i].error_no != 0) {
            client->entries[i].done = true;
            continue;
        }

        client->entries[i].error_no = ioevent_attach(&client->ioevent,
                client->entries[i].conn->sock, IOEVENT_READ,
                client->entries + i);
        if (client->entries[i].error_no != 0) {
            int result;

            client->entries[i].done = true;
            result = client->entries[i].error_no;
            logError("file: "__FILE__", line: %d, "
                    "ioevent_attach fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            continue;
        }

        client->pulling_count++;
    }

    return client->pulling_count > 0 ? 0 : ENOENT;
}

static inline void fast_multi_sock_client_finish(FastMultiSockClient *client,
        FastMultiSockEntry *entry, const int error_no)
{
    entry->error_no = error_no;
    entry->done = true;
    client->pulling_count--;
    ioevent_detach(&client->ioevent, entry->conn->sock);
    if (error_no == 0) {
        client->success_count++;
    }
}


static int fast_multi_sock_client_do_recv(FastMultiSockClient *client,
        FastMultiSockEntry *entry)
{
    int bytes;
    int result;

    result = 0;
    while (entry->remain > 0) {
        bytes = read(entry->conn->sock, entry->buffer.data +
                entry->buffer.length, entry->remain);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                        "server: %s:%d, ignore interupt signal",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port);
                continue;
            }
            else {
                result = errno != 0 ? errno : ECONNRESET;
                logWarning("file: "__FILE__", line: %d, "
                        "server: %s:%d, recv failed, "
                        "errno: %d, error info: %s",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port,
                        result, strerror(result));

                break;
            }
        }
        else if (bytes == 0) {
            logDebug("file: "__FILE__", line: %d, "
                    "server: %s:%d, sock: %d, recv failed, "
                    "connection disconnected",
                    __LINE__, entry->conn->ip_addr, entry->conn->port,
                    entry->conn->sock);

            result = ECONNRESET;
            break;
        }

        entry->buffer.length += bytes;
        entry->remain -= bytes;
        if (entry->remain == 0 && entry->buffer.length == client->header_length) {
            int body_length;
            body_length = client->get_body_length_func(&entry->buffer);
            if (body_length < 0) {
                logError("file: "__FILE__", line: %d, "
                        "server: %s:%d, body_length: %d < 0",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port, body_length);
                result = EINVAL;
                break;
            }
            if ((result=fast_buffer_check(&entry->buffer, body_length)) != 0) {
                break;
            }
            entry->remain = body_length;  //to recv body
        }
    }

    return result;
}

static int fast_multi_sock_client_recv_data(FastMultiSockClient *client)
{
    int result;
	int event;
    int count;
    int index;
    time_t remain_time;
    FastMultiSockEntry *entry;

    while (client->pulling_count > 0) {
        remain_time = client->deadline_time - get_current_time();
        if (remain_time <= 0) {  //timeout
            break;
        }

        count = ioevent_poll_ex(&client->ioevent, remain_time * 1000);
        for (index=0; index<count; index++) {
            event = IOEVENT_GET_EVENTS(&client->ioevent, index);
            entry = (FastMultiSockEntry *)IOEVENT_GET_DATA(&client->ioevent, index);

            if (event & IOEVENT_ERROR) {
                logDebug("file: "__FILE__", line: %d, "
                        "server: %s:%d, recv error event: %d, "
                        "connection reset", __LINE__,
                        entry->conn->ip_addr, entry->conn->port, event);

                fast_multi_sock_client_finish(client, entry, ECONNRESET);
                continue;
            }

            result = fast_multi_sock_client_do_recv(client, entry);
            if (result != 0 || entry->remain == 0) {
                fast_multi_sock_client_finish(client, entry, result);
            }
        }
    }

    if (client->pulling_count > 0) {
        int i;
        for (i=0; i<client->entry_count; i++) {
            if (!client->entries[i].done) {
                fast_multi_sock_client_finish(client, client->entries + i, ETIMEDOUT);
            }
        }
    }

    return client->success_count > 0 ? 0 : ENOENT;
}

int fast_multi_sock_client_request(FastMultiSockClient *client,
        FastBuffer *buffer)
{
    int result;

    client->deadline_time = get_current_time() + client->timeout;
    client->pulling_count = 0;
    client->success_count = 0;
    if ((result=fast_multi_sock_client_send_data(client, buffer)) != 0) {
        return result;
    }

    return fast_multi_sock_client_recv_data(client);
}
