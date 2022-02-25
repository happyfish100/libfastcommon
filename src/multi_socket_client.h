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

//multi_socket_client.h

#ifndef _MULTI_SOCKET_CLIENT_H_
#define _MULTI_SOCKET_CLIENT_H_

#include <net/if.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "common_define.h"
#include "connection_pool.h"
#include "fast_buffer.h"
#include "ioevent.h"

typedef enum {
    fms_stage_recv_header = 'H',
    fms_stage_recv_body = 'B'
} FastMultiSockRecvStage;

struct fast_multi_sock_client;
struct fast_multi_sock_entry;

typedef int64_t (*fms_client_get_current_time_ms_func)();

//return the body length
typedef int (*fms_client_get_body_length_func)(const FastBuffer *recv_buffer);

//IO deal fucntion
typedef int (*fast_multi_sock_client_io_func)(struct fast_multi_sock_client *
        client, struct fast_multi_sock_entry *entry);

typedef struct fast_multi_sock_entry {
    ConnectionInfo *conn;     //the connected socket must be non-block socket
    FastBuffer *send_buffer;  //send buffer for internal use
    fast_multi_sock_client_io_func io_callback;  //for internal use
    FastBuffer recv_buffer;   //recv buffer for response package
    int error_no;             //0 for success, != 0 fail
    int remain;               //remain bytes, for internal use
    FastMultiSockRecvStage recv_stage;  //for internal use
    bool done;                //for internal use
} FastMultiSockEntry;

typedef struct fast_multi_sock_client {
    int entry_count;
    int header_length;       //package header size
    int pulling_count;
    int success_count;
    int timeout_ms;
    int64_t deadline_time_ms;
    FastMultiSockEntry *entries;
    fms_client_get_current_time_ms_func get_current_time_ms_func;
    fms_client_get_body_length_func get_body_length_func;
    IOEventPoller ioevent;
} FastMultiSockClient;

#ifdef __cplusplus
extern "C" {
#endif


    /**
      init function
      @param client the client context
      @param entries the socket entries
      @param entry_count the count of socket entries
      @param header_length the header length of a package
      @param get_body_length_func the get body length function
      @param get_current_time_ms_func the get current time in ms function
      @param init_recv_buffer_size the initial size of response buffer
      @param timeout_ms the timeout in milliseconds
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_init_ex(FastMultiSockClient *client,
            FastMultiSockEntry *entries, const int entry_count,
            const int header_length,
            fms_client_get_body_length_func get_body_length_func,
            fms_client_get_current_time_ms_func get_current_time_ms_func,
            const int init_recv_buffer_size, const int timeout_ms);

    /**
      init function
      @param client the client context
      @param entries the socket entries
      @param entry_count the count of socket entries
      @param header_length the header length of a package
      @param get_body_length_func the get body length function
      @param init_recv_buffer_size the initial size of response buffer
      @param timeout the timeout in seconds
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_init(FastMultiSockClient *client,
            FastMultiSockEntry *entries, const int entry_count,
            const int header_length,
            fms_client_get_body_length_func get_body_length_func,
            const int init_recv_buffer_size, const int timeout);

    /**
      destroy function
      @param client the client context
      @return none
      */
    void fast_multi_sock_client_destroy(FastMultiSockClient *client);

    /**
      request function
      @param client the client context
      @param send_buffer the buffer to send
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_request(FastMultiSockClient *client,
            FastBuffer *send_buffer);

#ifdef __cplusplus
}
#endif

#endif
