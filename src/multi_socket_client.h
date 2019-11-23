/**
* Copyright (C) 2018 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
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
#include "fast_buffer.h"
#include "ioevent.h"

typedef enum {
    fast_multi_sock_stage_recv_header = 'H',
    fast_multi_sock_stage_recv_body = 'B'
} FastMultiSockRecvStage;

struct fast_multi_sock_client;
struct fast_multi_sock_entry;

//return the body length
typedef int (*fast_multi_sock_client_get_body_length_func)(const FastBuffer *recv_buffer);

//IO deal fucntion
typedef int (*fast_multi_sock_client_io_func)(struct fast_multi_sock_client *client,
         struct fast_multi_sock_entry *entry);

typedef struct fast_multi_sock_entry {
    ConnectionInfo *conn;     //the socket must be non-block socket
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
      @param init_recv_buffer_size the initial size of response buffer 
      @param timeout the timeout in seconds
      @return error no, 0 for success, != 0 fail
      */
    int fast_multi_sock_client_init(FastMultiSockClient *client,
            FastMultiSockEntry *entries, const int entry_count,
            const int header_length,
            fast_multi_sock_client_get_body_length_func get_body_length_func,
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
