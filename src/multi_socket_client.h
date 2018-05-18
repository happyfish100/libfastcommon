/**
* Copyright (C) 2018 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//multi_socket_client.h

#ifndef _MULTI_SOCKET_CLIENT_H_
#define _MULTI_SOCKET_CLIENT_H_

#include <net/if.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include "common_define.h"
#include "connection_pool.h"
#include "fast_timer.h"
#include "ioevent.h"

//return the body length
typedef int (*fast_multi_sock_client_get_body_length_func)(const FastBuffer *buffer);

typedef struct fast_multi_sock_entry {
    ConnectionInfo *conn;
    FastBuffer buffer;  //recv buffer
    int remain;         //remain bytes
    int error_no;       //0 for success
    bool done;
} FastMultiSockEntry;

typedef struct fast_multi_sock_client {
    int entry_count;
    int header_length;       //package header size
    int pulling_count;
    int success_count;
    int timeout;
    time_t deadline_time;
    FastMultiSockEntry *entries;
    fast_multi_sock_client_get_body_length_func get_body_length_func;
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
      @param init_buffer_size the initial size of response buffer 
      @param timeout the timeout in seconds
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_init(FastMultiSockClient *client,
            FastMultiSockEntry *entries, const int entry_count,
            const int header_length,
            fast_multi_sock_client_get_body_length_func get_body_length_func,
            const int init_buffer_size, const int timeout);

    /**
      destroy function
      @param client the client context
      @return none
      */
    void fast_multi_sock_client_destroy(FastMultiSockClient *client);

    /**
      request function
      @param client the client context
      @param buffer the buffer to send
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_request(FastMultiSockClient *client,
            FastBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif
