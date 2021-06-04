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

typedef struct
{
	int sock;
	uint16_t port;
    short socket_domain;  //socket domain, AF_INET, AF_INET6 or AF_UNSPEC for auto dedect
    bool validate_flag;   //for connection pool
	char ip_addr[INET6_ADDRSTRLEN];
    char args[0];   //for extra data
} ConnectionInfo;

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

typedef struct tagConnectionPool {
	HashArray hash_array;  //key is ip:port, value is ConnectionManager
	pthread_mutex_t lock;
	int connect_timeout;
	int max_count_per_entry;  //0 means no limit

	/*
	connections whose idle time exceeds this time will be closed
    unit: second
	*/
	int max_idle_time;
    int socket_domain;  //socket domain

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
} ConnectionPool;

/**
*   init ex function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*      socket_domain: the socket domain
*      htable_init_capacity: the init capacity of connection hash table
*      connect_done_func: the connect done connection callback
*      connect_done_args: the args for connect done connection callback
*      validate_func: the validate connection callback
*      validate_args: the args for validate connection callback
*      extra_data_size: the extra data size of connection
*   return 0 for success, != 0 for error
*/
int conn_pool_init_ex1(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int socket_domain, const int htable_init_capacity,
    fc_connection_callback_func connect_done_func, void *connect_done_args,
    fc_connection_callback_func validate_func, void *validate_args,
    const int extra_data_size);

/**
*   init ex function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*      socket_domain: the socket domain
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_init_ex(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int socket_domain)
{
    const int htable_init_capacity = 0;
    const int extra_data_size = 0;
    return conn_pool_init_ex1(cp, connect_timeout, max_count_per_entry,
            max_idle_time, socket_domain, htable_init_capacity,
            NULL, NULL, NULL, NULL, extra_data_size);
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
    const int socket_domain = AF_INET;
    const int htable_init_capacity = 0;
    const int extra_data_size = 0;
    return conn_pool_init_ex1(cp, connect_timeout, max_count_per_entry,
            max_idle_time, socket_domain, htable_init_capacity,
            NULL, NULL, NULL, NULL, extra_data_size);
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
*      err_no: return the the errno, 0 for success
*   return != NULL for success, NULL for error
*/
ConnectionInfo *conn_pool_get_connection(ConnectionPool *cp, 
	const ConnectionInfo *conn, int *err_no);

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
int conn_pool_close_connection_ex(ConnectionPool *cp, ConnectionInfo *conn, 
	const bool bForce);

/**
*   disconnect from the server
*   parameters:
*      pConnection: the connection
*   return 0 for success, != 0 for error
*/
void conn_pool_disconnect_server(ConnectionInfo *pConnection);

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout: the connect timeout in seconds
*      bind_ipaddr: the ip address to bind, NULL or empty for any
*      log_connect_error: if log error info when connect fail
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
int conn_pool_connect_server_ex(ConnectionInfo *pConnection,
		const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error);

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout: the connect timeout in seconds
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_connect_server(ConnectionInfo *pConnection,
		const int connect_timeout)
{
    const char *bind_ipaddr = NULL;
    return conn_pool_connect_server_ex(pConnection,
            connect_timeout, bind_ipaddr, true);
}

/**
*   connect to the server
*   parameters:
*      pConnection: the connection
*      connect_timeout: the connect timeout in seconds
*   return 0 for success, != 0 for error
*/
static inline int conn_pool_connect_server_anyway(ConnectionInfo *pConnection,
		const int connect_timeout)
{
    const char *bind_ipaddr = NULL;
    pConnection->sock = -1;
    return conn_pool_connect_server_ex(pConnection,
            connect_timeout, bind_ipaddr, true);
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
    pServerInfo->socket_domain = AF_UNSPEC;
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

#ifdef __cplusplus
}
#endif

#endif

