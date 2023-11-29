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

//connection_pool.h

#ifndef _CONNECTION_POOL_H
#define _CONNECTION_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"
#include "fast_mblock.h"
#include "ini_file_reader.h"
#include "pthread_func.h"
#include "sockopt.h"
#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FC_CONNECTION_SERVER_EQUAL(conn, target_ip, target_port) \
    (strcmp((conn).ip_addr, target_ip) == 0 && \
     (conn).port == target_port)

#define FC_CONNECTION_SERVER_EQUAL1(conn1, conn2)     \
    (strcmp((conn1).ip_addr, (conn2).ip_addr) == 0 && \
     (conn1).port == (conn2).port)

typedef enum {
    fc_comm_type_sock = 0,
    fc_comm_type_rdma,
    fc_comm_type_both
} FCCommunicationType;

typedef struct {
    int sock;
    uint16_t port;
    short af;  //address family, AF_INET, AF_INET6 or AF_UNSPEC for auto dedect
    FCCommunicationType comm_type;
    bool validate_flag;   //for connection pool
    char ip_addr[IP_ADDRESS_SIZE];
    void *arg1;     //for RDMA
    char args[0];   //for extra data
} ConnectionInfo;

struct fc_server_config;
struct ibv_pd;
typedef void (*fc_set_busy_polling_callback)(const bool busy_polling);
typedef struct ibv_pd *(*fc_alloc_pd_callback)(const char **ip_addrs,
        const int count, const int port);
typedef int (*fc_get_connection_size_callback)();
typedef int (*fc_init_connection_callback)(ConnectionInfo *conn,
        const bool double_buffers, const int buffer_size, void *arg);
typedef int (*fc_make_connection_callback)(ConnectionInfo *conn,
        const char *service_name, const int timeout_ms,
        const char *bind_ipaddr, const bool log_connect_error);
typedef bool (*fc_is_connected_callback)(ConnectionInfo *conn);
typedef bool (*fc_send_done_callback)(ConnectionInfo *conn);
typedef void (*fc_close_connection_callback)(ConnectionInfo *conn);
typedef void (*fc_destroy_connection_callback)(ConnectionInfo *conn);

typedef BufferInfo *(*fc_rdma_get_recv_buffer_callback)(ConnectionInfo *conn);
typedef int (*fc_rdma_request_by_buf1_callback)(ConnectionInfo *conn,
        const char *data, const int length, const int timeout_ms);
typedef int (*fc_rdma_request_by_buf2_callback)(ConnectionInfo *conn,
        const char *data1, const int length1, const char *data2,
        const int length2, const int timeout_ms);
typedef int (*fc_rdma_request_by_iov_callback)(ConnectionInfo *conn,
        const struct iovec *iov, const int iovcnt,
        const int timeout_ms);
typedef int (*fc_rdma_request_by_mix_callback)(ConnectionInfo *conn,
        const char *data, const int length, const struct iovec *iov,
        const int iovcnt, const int timeout_ms);
typedef int (*fc_rdma_send_by_buf1_callback)(ConnectionInfo *conn,
        const char *data, const int length);
typedef int (*fc_rdma_recv_data_callback)(ConnectionInfo *conn,
        const bool call_post_recv, const int timeout_ms);
typedef int (*fc_rdma_post_recv_callback)(ConnectionInfo *conn);

typedef struct {
    fc_make_connection_callback make_connection;
    fc_close_connection_callback close_connection;
    fc_is_connected_callback is_connected;
} CommonConnectionCallbacks;

typedef struct {
    fc_set_busy_polling_callback set_busy_polling;
    fc_alloc_pd_callback alloc_pd;
    fc_get_connection_size_callback get_connection_size;
    fc_init_connection_callback init_connection;
    fc_make_connection_callback make_connection;
    fc_close_connection_callback close_connection;
    fc_destroy_connection_callback destroy_connection;
    fc_is_connected_callback is_connected;
    fc_send_done_callback send_done;

    fc_rdma_get_recv_buffer_callback get_recv_buffer;
    fc_rdma_request_by_buf1_callback request_by_buf1;
    fc_rdma_request_by_buf2_callback request_by_buf2;
    fc_rdma_request_by_iov_callback request_by_iov;
    fc_rdma_request_by_mix_callback request_by_mix;

    fc_rdma_send_by_buf1_callback send_by_buf1;
    fc_rdma_recv_data_callback recv_data;
    fc_rdma_post_recv_callback post_recv;
} RDMAConnectionCallbacks;

typedef struct {
    bool inited;
    CommonConnectionCallbacks common_callbacks[2];
    RDMAConnectionCallbacks rdma_callbacks;
} ConnectionCallbacks;

typedef struct {
    struct {
        bool enabled;
        int htable_capacity;
    } tls;  //for thread local

    struct {
        bool double_buffers;
        int buffer_size;
        struct ibv_pd *pd;
    } rdma;
} ConnectionExtraParams;

typedef int (*fc_connection_callback_func)(ConnectionInfo *conn, void *args);

struct tagConnectionManager;

typedef struct tagConnectionNode {
	ConnectionInfo *conn;
	struct tagConnectionManager *manager;
	struct tagConnectionNode *next;
	time_t atime;  //last access time
} ConnectionNode;

typedef struct tagConnectionManager {
	ConnectionNode *head;
	int total_count;  //total connections
	int free_count;   //free connections
	pthread_mutex_t lock;
} ConnectionManager;

struct tagConnectionPool;

typedef struct {
    ConnectionNode **buckets;
    struct tagConnectionPool *cp;
} ConnectionThreadHashTable;

typedef struct tagConnectionPool {
	HashArray hash_array;  //key is ip-port, value is ConnectionManager
	pthread_mutex_t lock;
	int connect_timeout_ms;
	int max_count_per_entry;  //0 means no limit

	/*
	connections whose idle time exceeds this time will be closed
    unit: second
	*/
	int max_idle_time;

    struct fast_mblock_man manager_allocator;
    struct fast_mblock_man node_allocator;

    struct {
        fc_connection_callback_func func;
        void *args;
    } connect_done_callback;

    struct {
        fc_connection_callback_func func;
        void *args;
    } validate_callback;

    int extra_data_size;
    ConnectionExtraParams extra_params;
    pthread_key_t tls_key;  //for ConnectionThreadHashTable
} ConnectionPool;

extern ConnectionCallbacks g_connection_callbacks;

int conn_pool_global_init_for_rdma();

#define G_COMMON_CONNECTION_CALLBACKS g_connection_callbacks.common_callbacks
#define G_RDMA_CONNECTION_CALLBACKS   g_connection_callbacks.rdma_callbacks

/**
*   init ex function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*      af: the socket domain
*      htable_init_capacity: the init capacity of connection hash table
*      connect_done_func: the connect done connection callback
*      connect_done_args: the args for connect done connection callback
*      validate_func: the validate connection callback
*      validate_args: the args for validate connection callback
*      extra_data_size: the extra data size of connection
*      extra_params: for RDMA
*   return 0 for success, != 0 for error
*/
int conn_pool_init_ex1(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int htable_init_capacity,
    fc_connection_callback_func connect_done_func, void *connect_done_args,
    fc_connection_callback_func validate_func, void *validate_args,
    const int extra_data_size, const ConnectionExtraParams *extra_params);

/**
*   init ex function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_init_ex(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time)
{
    const int htable_init_capacity = 0;
    const int extra_data_size = 0;
    const ConnectionExtraParams *extra_params = NULL;
    return conn_pool_init_ex1(cp, connect_timeout, max_count_per_entry,
            max_idle_time, htable_init_capacity, NULL, NULL, NULL, NULL,
            extra_data_size, extra_params);
}

/**
*   init function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_init(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time)
{
    const int htable_init_capacity = 0;
    const int extra_data_size = 0;
    const ConnectionExtraParams *extra_params = NULL;
    return conn_pool_init_ex1(cp, connect_timeout, max_count_per_entry,
            max_idle_time, htable_init_capacity, NULL, NULL, NULL, NULL,
            extra_data_size, extra_params);
}

/**
*   destroy function
*   parameters:
*      cp: the ConnectionPool
*   return none
**/
void conn_pool_destroy(ConnectionPool *cp);

/**
*   get connection from the pool
*   parameters:
*      cp: the ConnectionPool
*      conn: the connection
*      service_name: the service name to log
*      err_no: return the the errno, 0 for success
*   return != NULL for success, NULL for error
*/
ConnectionInfo *conn_pool_get_connection_ex(ConnectionPool *cp,
	const ConnectionInfo *conn, const char *service_name, int *err_no);

#define conn_pool_get_connection(cp, conn, err_no) \
    conn_pool_get_connection_ex(cp, conn, NULL, err_no)

#define conn_pool_close_connection(cp, conn) \
	conn_pool_close_connection_ex(cp, conn, false)

/**
*   push back the connection to pool
*   parameters:
*      cp: the ConnectionPool
*      conn: the connection
*      bForce: set true to close the socket, else only push back to connection pool
*   return 0 for success, != 0 for error
*/
int conn_pool_close_connection_ex(ConnectionPool *cp,
        ConnectionInfo *conn, const bool bForce);

/**
*   disconnect from the server
*   parameters:
*      conn: the connection
*   return 0 for success, != 0 for error
*/
void conn_pool_disconnect_server(ConnectionInfo *conn);

bool conn_pool_is_connected(ConnectionInfo *conn);

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      service_name: the service name to log
*      connect_timeout_ms: the connect timeout in milliseconds
*      bind_ipaddr: the ip address to bind, NULL or empty for any
*      log_connect_error: if log error info when connect fail
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
int conn_pool_connect_server_ex1(ConnectionInfo *conn,
        const char *service_name, const int connect_timeout_ms,
        const char *bind_ipaddr, const bool log_connect_error);
/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout_ms: the connect timeout in milliseconds
*      bind_ipaddr: the ip address to bind, NULL or empty for any
*      log_connect_error: if log error info when connect fail
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_connect_server_ex(ConnectionInfo *pConnection,
		const int connect_timeout_ms, const char *bind_ipaddr,
        const bool log_connect_error)
{
    const char *service_name = NULL;
    return conn_pool_connect_server_ex1(pConnection, service_name,
            connect_timeout_ms, bind_ipaddr, log_connect_error);
}

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout_ms: the connect timeout in seconds
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_connect_server(ConnectionInfo *pConnection,
		const int connect_timeout_ms)
{
    const char *service_name = NULL;
    const char *bind_ipaddr = NULL;
    return conn_pool_connect_server_ex1(pConnection, service_name,
            connect_timeout_ms, bind_ipaddr, true);
}

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout_ms: the connect timeout in seconds
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_connect_server_anyway(ConnectionInfo *pConnection,
		const int connect_timeout_ms)
{
    const char *service_name = NULL;
    const char *bind_ipaddr = NULL;
    pConnection->sock = -1;
    return conn_pool_connect_server_ex1(pConnection, service_name,
            connect_timeout_ms, bind_ipaddr, true);
}

/**
*   async connect to the server
*   parameters:
*      pConnection: the connection
*      bind_ipaddr: the ip address to bind, NULL or empty for any
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 or EINPROGRESS for success, others for error
*/
int conn_pool_async_connect_server_ex(ConnectionInfo *conn,
        const char *bind_ipaddr);

#define conn_pool_async_connect_server(conn) \
    conn_pool_async_connect_server_ex(conn, NULL)


/**
*   get connection count of the pool
*   parameters:
*      cp: the ConnectionPool
*   return current connection count
*/
int conn_pool_get_connection_count(ConnectionPool *cp);

/**
*   load server info from config file
*   parameters:
*      pIniContext: the ini context
*      filename: the config filename
*      item_name: the item name in config file, format item_name=server:port
*      pServerInfo: store server info
*      default_port: the default port
*   return 0 for success, != 0 for error
*/
int conn_pool_load_server_info(IniContext *pIniContext, const char *filename,
        const char *item_name, ConnectionInfo *pServerInfo,
        const int default_port);

/**
*   parse server info from string
*   parameters:
*      pServerStr: server and port string as server:port
*      pServerInfo: store server info
*      default_port: the default port
*   return 0 for success, != 0 for error
*/
int conn_pool_parse_server_info(const char *pServerStr,
        ConnectionInfo *pServerInfo, const int default_port);

/**
*   set server info with ip address and port
*   parameters:
*      pServerInfo: store server info
*      ip_addr: the ip address
*      port: the port
*   return none
*/
static inline void conn_pool_set_server_info(ConnectionInfo *pServerInfo,
        const char *ip_addr, const int port)
{
    snprintf(pServerInfo->ip_addr, sizeof(pServerInfo->ip_addr),
            "%s", ip_addr);
    pServerInfo->port = port;
    pServerInfo->af = is_ipv6_addr(ip_addr) ? AF_INET6 : AF_INET;
    pServerInfo->sock = -1;
}

static inline int conn_pool_compare_ip_and_port(const char *ip1,
        const int port1, const char *ip2, const int port2)
{
    int result;
    if ((result=strcmp(ip1, ip2)) != 0) {
        return result;
    }
    return port1 - port2;
}

ConnectionInfo *conn_pool_alloc_connection_ex(
        const FCCommunicationType comm_type,
        const int extra_data_size,
        const ConnectionExtraParams *extra_params,
        int *err_no);

static inline ConnectionInfo *conn_pool_alloc_connection(
        const FCCommunicationType comm_type,
        const ConnectionExtraParams *extra_params,
        int *err_no)
{
    const int extra_data_size = 0;
    return conn_pool_alloc_connection_ex(comm_type,
            extra_data_size, extra_params, err_no);
}

static inline void conn_pool_free_connection(ConnectionInfo *conn)
{
    free(conn);
}

int conn_pool_set_rdma_extra_params_ex(ConnectionExtraParams *extra_params,
        struct fc_server_config *server_cfg, const int server_group_index,
        const bool double_buffers);

static inline int conn_pool_set_rdma_extra_params(
        ConnectionExtraParams *extra_params,
        struct fc_server_config *server_cfg,
        const int server_group_index)
{
    const bool double_buffers = false;
    return conn_pool_set_rdma_extra_params_ex(extra_params,
            server_cfg, server_group_index, double_buffers);
}

static inline const char *fc_comm_type_str(const FCCommunicationType type)
{
    switch (type) {
        case fc_comm_type_sock:
            return "socket";
        case fc_comm_type_rdma:
            return "rdma";
        case fc_comm_type_both:
            return "both";
        default:
            return "unkown";
    }
}

#ifdef __cplusplus
}
#endif

#endif

