/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//connection_pool.h

#ifndef _CONNECTION_POOL_H
#define _CONNECTION_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"
#include "pthread_func.h"
#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	int sock;
	int port;
	char ip_addr[INET6_ADDRSTRLEN];
    int socket_domain;  //socket domain, AF_INET, AF_INET6 or PF_UNSPEC for auto dedect
} ConnectionInfo;

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
	connections whose the idle time exceeds this time will be closed
    unit: second
	*/
	int max_idle_time;
    int socket_domain;  //socket domain
} ConnectionPool;

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
int conn_pool_init_ex(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int socket_domain);

/**
*   init function
*   parameters:
*      cp: the ConnectionPool
*      connect_timeout: the connect timeout in seconds
*      max_count_per_entry: max connection count per host:port
*      max_idle_time: reconnect the server after max idle time in seconds
*   return 0 for success, != 0 for error
*/
int conn_pool_init(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time);

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
*   NOTE: pConnection->sock will be closed when it >= 0 before connect
*   return 0 for success, != 0 for error
*/
int conn_pool_connect_server(ConnectionInfo *pConnection, \
		const int connect_timeout);

/**
*   get connection count of the pool
*   parameters:
*      cp: the ConnectionPool
*   return current connection count
*/
int conn_pool_get_connection_count(ConnectionPool *cp);

#ifdef __cplusplus
}
#endif

#endif

