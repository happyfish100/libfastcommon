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

static int fast_multi_sock_client_do_recv(FastMultiSockClient *client,
        FastMultiSockEntry *entry);

static int64_t fms_get_current_time_ms()
{
    return (int64_t)get_current_time() * 1000LL;
}

int fast_multi_sock_client_init_ex(FastMultiSockClient *client,
        FastMultiSockEntry *entries, const int entry_count,
        const int header_length,
        fms_client_get_body_length_func get_body_length_func,
        fms_client_get_current_time_ms_func get_current_time_ms_func,
        const int init_recv_buffer_size, const int timeout_ms)
{
    int result;
    int new_init_recv_buffer_size;
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
                    timeout_ms, 0)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "ioevent_init fail, errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    if (init_recv_buffer_size <= 0) {
        new_init_recv_buffer_size = 4 * 1024;
    } else {
        new_init_recv_buffer_size = init_recv_buffer_size;
    }

    if (new_init_recv_buffer_size < header_length) {
        new_init_recv_buffer_size = header_length;
    }

    for (i=0; i<entry_count; i++) {
        if ((result=fast_buffer_init_ex(&entries[i].recv_buffer,
                        new_init_recv_buffer_size)) != 0)
        {
            return result;
        }
    }

    client->entry_count = entry_count;
    client->header_length = header_length;
    client->get_body_length_func = get_body_length_func;
    client->get_current_time_ms_func = get_current_time_ms_func;
    client->entries = entries;
    client->timeout_ms = timeout_ms;

    return 0;
}

int fast_multi_sock_client_init(FastMultiSockClient *client,
        FastMultiSockEntry *entries, const int entry_count,
        const int header_length,
        fms_client_get_body_length_func get_body_length_func,
        const int init_recv_buffer_size, const int timeout)
{
    return fast_multi_sock_client_init_ex(client, entries, entry_count,
            header_length, get_body_length_func, fms_get_current_time_ms,
            init_recv_buffer_size, timeout * 1000);
}

void fast_multi_sock_client_destroy(FastMultiSockClient *client)
{
    int i;

    ioevent_destroy(&client->ioevent);
    for (i=0; i<client->entry_count; i++) {
        fast_buffer_destroy(&client->entries[i].recv_buffer);
    }
}

static int fast_multi_sock_client_do_send(FastMultiSockClient *client,
        FastMultiSockEntry *entry)
{
    int bytes;
    int result;

    result = 0;
    while (entry->remain > 0) {
        bytes = write(entry->conn->sock, entry->send_buffer->data +
                (entry->send_buffer->length - entry->remain), entry->remain);

        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                        "server: %s:%u, ignore interupt signal",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port);
                continue;
            } else {
                result = errno != 0 ? errno : ECONNRESET;
                logError("file: "__FILE__", line: %d, "
                        "send to server %s:%u fail, "
                        "errno: %d, error info: %s",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port,
                        result, strerror(result));

                break;
            }
        } else if (bytes == 0) {
            logError("file: "__FILE__", line: %d, "
                    "send to server %s:%u, sock: %d fail, "
                    "connection disconnected",
                    __LINE__, entry->conn->ip_addr, entry->conn->port,
                    entry->conn->sock);

            result = ECONNRESET;
            break;
        }

        entry->remain -= bytes;
        if (entry->remain == 0) {
            entry->remain = client->header_length;   //to recv pkg header
            entry->recv_stage = fms_stage_recv_header;
            entry->io_callback = fast_multi_sock_client_do_recv;
            if (ioevent_modify(&client->ioevent, entry->conn->sock,
                        IOEVENT_READ, entry) != 0)
            {
                result = errno != 0 ? errno : EACCES;
                logError("file: "__FILE__", line: %d, "
                        "ioevent_modify fail, errno: %d, error info: %s",
                        __LINE__, result, STRERROR(result));
            }
            break;
        }
    }

    return result;
}

static int fast_multi_sock_client_send_data(FastMultiSockClient *client,
        FastBuffer *send_buffer)
{
    int i;
    int result;

    for (i=0; i<client->entry_count; i++) {
        client->entries[i].remain = send_buffer->length;
        client->entries[i].done = false;
        client->entries[i].recv_buffer.length = 0;
        client->entries[i].send_buffer = send_buffer;
        client->entries[i].io_callback = fast_multi_sock_client_do_send;

        if (client->entries[i].conn->sock < 0) {
            client->entries[i].error_no = ENOTCONN;
            client->entries[i].done = true;
            logError("file: "__FILE__", line: %d, "
                    "NOT connected to %s:%u",
                    __LINE__, client->entries[i].conn->ip_addr,
                    client->entries[i].conn->port);
            continue;
        }

        if (ioevent_attach(&client->ioevent,
                    client->entries[i].conn->sock, IOEVENT_WRITE,
                    client->entries + i) != 0)
        {
            client->entries[i].error_no = errno != 0 ? errno : EACCES;
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
        bytes = read(entry->conn->sock, entry->recv_buffer.data +
                entry->recv_buffer.length, entry->remain);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno == EINTR) {  //should retry
                logDebug("file: "__FILE__", line: %d, "
                        "server: %s:%u, ignore interupt signal",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port);
                continue;
            } else {
                result = errno != 0 ? errno : ECONNRESET;
                logError("file: "__FILE__", line: %d, "
                        "server: %s:%u, recv failed, "
                        "errno: %d, error info: %s",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port,
                        result, strerror(result));

                break;
            }
        } else if (bytes == 0) {
            logError("file: "__FILE__", line: %d, "
                    "server: %s:%u, sock: %d, recv failed, "
                    "connection disconnected",
                    __LINE__, entry->conn->ip_addr, entry->conn->port,
                    entry->conn->sock);

            result = ECONNRESET;
            break;
        }

        entry->recv_buffer.length += bytes;
        entry->remain -= bytes;
        if (entry->remain == 0 && entry->recv_stage == fms_stage_recv_header) {
            int body_length;

            entry->recv_stage = fms_stage_recv_body;
            body_length = client->get_body_length_func(&entry->recv_buffer);
            if (body_length < 0) {
                logError("file: "__FILE__", line: %d, "
                        "server: %s:%u, body_length: %d < 0",
                        __LINE__, entry->conn->ip_addr,
                        entry->conn->port, body_length);
                result = EPIPE;
                break;
            } else if (body_length == 0) {
                break;
            }

            if ((result=fast_buffer_check(&entry->recv_buffer,
                            body_length)) != 0)
            {
                break;
            }
            entry->remain = body_length;  //to recv body
        }
    }

    logInfo("file: "__FILE__", line: %d, "
            "recv remain: %d", __LINE__, entry->remain);
    return result;
}

static int fast_multi_sock_client_deal_io(FastMultiSockClient *client)
{
    int result;
	int event;
    int count;
    int index;
    int remain_timeout;
    FastMultiSockEntry *entry;

    while (client->pulling_count > 0) {
        remain_timeout = client->deadline_time_ms -
            client->get_current_time_ms_func();
        if (remain_timeout < 0) {  //timeout
            break;
        }

        count = ioevent_poll_ex(&client->ioevent, remain_timeout);
        logInfo("poll count: %d\n", count);
        for (index=0; index<count; index++) {
            event = IOEVENT_GET_EVENTS(&client->ioevent, index);
            entry = (FastMultiSockEntry *)IOEVENT_GET_DATA(
                    &client->ioevent, index);

            if (event & IOEVENT_ERROR) {
                logError("file: "__FILE__", line: %d, "
                        "server: %s:%u, recv error event: %d, "
                        "connection reset", __LINE__,
                        entry->conn->ip_addr, entry->conn->port, event);

                fast_multi_sock_client_finish(client, entry, ECONNRESET);
                continue;
            }

            logInfo("sock: %d, event: %d", entry->conn->sock, event);

            result = entry->io_callback(client, entry);
            if (result != 0 || entry->remain == 0) {
                fast_multi_sock_client_finish(client, entry, result);
            }
        }
    }

/*
    logInfo("file: "__FILE__", line: %d, pulling_count: %d, "
            "success_count: %d\n", __LINE__,
            client->pulling_count, client->success_count);
*/
    if (client->pulling_count > 0) {
        int i;
        for (i=0; i<client->entry_count; i++) {
            if (!client->entries[i].done) {
                fast_multi_sock_client_finish(client,
                        client->entries + i, ETIMEDOUT);
                logError("file: "__FILE__", line: %d, "
                        "recv from %s:%u timedout",
                        __LINE__, client->entries[i].conn->ip_addr,
                        client->entries[i].conn->port);
            }
        }
    }

    logInfo("file: "__FILE__", line: %d, pulling_count: %d, "
            "success_count: %d\n", __LINE__,
            client->pulling_count, client->success_count);
    return client->success_count > 0 ? 0 :
        (remain_timeout > 0 ? ENOENT : ETIMEDOUT);
}

int fast_multi_sock_client_request(FastMultiSockClient *client,
        FastBuffer *send_buffer)
{
    int result;

    client->deadline_time_ms = client->get_current_time_ms_func() +
        client->timeout_ms;
    client->pulling_count = 0;
    client->success_count = 0;
    if ((result=fast_multi_sock_client_send_data(client, send_buffer)) != 0) {
        return result;
    }

    return fast_multi_sock_client_deal_io(client);
}
