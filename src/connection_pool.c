/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "logger.h"
#include "sockopt.h"
#include "shared_func.h"
#include "sched_thread.h"
#include "connection_pool.h"

int conn_pool_init_ex(ConnectionPool *cp, int connect_timeout, \
	const int max_count_per_entry, const int max_idle_time,
    const int socket_domain)
{
	int result;

	if ((result=init_pthread_lock(&cp->lock)) != 0)
	{
		return result;
	}
	cp->connect_timeout = connect_timeout;
	cp->max_count_per_entry = max_count_per_entry;
	cp->max_idle_time = max_idle_time;
	cp->socket_domain = socket_domain;

	return hash_init(&(cp->hash_array), simple_hash, 1024, 0.75);
}

int conn_pool_init(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time)
{
    const int socket_domain = AF_INET;
    return conn_pool_init_ex(cp, connect_timeout, max_count_per_entry,
            max_idle_time, socket_domain);
}

int coon_pool_close_connections(const int index, const HashData *data, void *args)
{
    ConnectionManager *cm;

    cm = (ConnectionManager *)data->value;
    if (cm != NULL)
    {
        ConnectionNode *node;
        ConnectionNode *deleted;

        node = cm->head;
        while (node != NULL)
        {
            deleted = node;
            node = node->next;

            conn_pool_disconnect_server(deleted->conn);
            free(deleted);
        }
        free(cm);
    }

    return 0;
}

void conn_pool_destroy(ConnectionPool *cp)
{
	pthread_mutex_lock(&cp->lock);
    hash_walk(&(cp->hash_array), coon_pool_close_connections, NULL);
	hash_destroy(&(cp->hash_array));
	pthread_mutex_unlock(&cp->lock);

	pthread_mutex_destroy(&cp->lock);
}

void conn_pool_disconnect_server(ConnectionInfo *pConnection)
{
	if (pConnection->sock >= 0)
	{
		close(pConnection->sock);
		pConnection->sock = -1;
	}
}

int conn_pool_connect_server_ex(ConnectionInfo *pConnection,
		const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error)
{
	int result;
    int domain;

	if (pConnection->sock >= 0)
	{
		close(pConnection->sock);
	}

    if (pConnection->socket_domain == AF_INET ||
            pConnection->socket_domain == AF_INET6)
    {
        domain = pConnection->socket_domain;
    }
    else
    {
        domain = is_ipv6_addr(pConnection->ip_addr) ? AF_INET6 : AF_INET;
    }
	pConnection->sock = socket(domain, SOCK_STREAM, 0);
	if(pConnection->sock < 0)
	{
		logError("file: "__FILE__", line: %d, "
			"socket create fail, errno: %d, "
			"error info: %s", __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

    if (bind_ipaddr != NULL && *bind_ipaddr != '\0')
    {
        if ((result=socketBind2(domain, pConnection->sock, bind_ipaddr, 0)) != 0)
        {
            return result;
        }
    }

    SET_SOCKOPT_NOSIGPIPE(pConnection->sock);
	if ((result=tcpsetnonblockopt(pConnection->sock)) != 0)
	{
		close(pConnection->sock);
		pConnection->sock = -1;
		return result;
	}

	if ((result=connectserverbyip_nb(pConnection->sock,
		pConnection->ip_addr, pConnection->port,
		connect_timeout)) != 0)
	{
        if (log_connect_error)
        {
            logError("file: "__FILE__", line: %d, "
                    "connect to server %s:%d fail, errno: %d, "
                    "error info: %s", __LINE__, pConnection->ip_addr,
                    pConnection->port, result, STRERROR(result));
        }

		close(pConnection->sock);
		pConnection->sock = -1;
		return result;
	}

	return 0;
}

static inline void  conn_pool_get_key(const ConnectionInfo *conn, char *key, int *key_len)
{
    *key_len = sprintf(key, "%s_%d", conn->ip_addr, conn->port);
}

ConnectionInfo *conn_pool_get_connection(ConnectionPool *cp, 
	const ConnectionInfo *conn, int *err_no)
{
	char key[INET6_ADDRSTRLEN + 8];
	int key_len;
	int bytes;
	char *p;
	ConnectionManager *cm;
	ConnectionNode *node;
	ConnectionInfo *ci;
	time_t current_time;

	conn_pool_get_key(conn, key, &key_len);

	pthread_mutex_lock(&cp->lock);
	cm = (ConnectionManager *)hash_find(&cp->hash_array, key, key_len);
	if (cm == NULL)
	{
		cm = (ConnectionManager *)malloc(sizeof(ConnectionManager));
		if (cm == NULL)
		{
			*err_no = errno != 0 ? errno : ENOMEM;
			logError("file: "__FILE__", line: %d, " \
				"malloc %d bytes fail, errno: %d, " \
				"error info: %s", __LINE__, \
				(int)sizeof(ConnectionManager), \
				*err_no, STRERROR(*err_no));
			pthread_mutex_unlock(&cp->lock);
			return NULL;
		}

		cm->head = NULL;
		cm->total_count = 0;
		cm->free_count = 0;
		if ((*err_no=init_pthread_lock(&cm->lock)) != 0)
		{
			pthread_mutex_unlock(&cp->lock);
			return NULL;
		}
		hash_insert(&cp->hash_array, key, key_len, cm);
	}
	pthread_mutex_unlock(&cp->lock);

	current_time = get_current_time();
	pthread_mutex_lock(&cm->lock);
	while (1)
	{
		if (cm->head == NULL)
		{
			if ((cp->max_count_per_entry > 0) && 
				(cm->total_count >= cp->max_count_per_entry))
			{
				*err_no = ENOSPC;
				logError("file: "__FILE__", line: %d, " \
					"connections: %d of server %s:%d " \
					"exceed limit: %d", __LINE__, \
					cm->total_count, conn->ip_addr, \
					conn->port, cp->max_count_per_entry);
				pthread_mutex_unlock(&cm->lock);
				return NULL;
			}

			bytes = sizeof(ConnectionNode) + sizeof(ConnectionInfo);
			p = (char *)malloc(bytes);
			if (p == NULL)
			{
				*err_no = errno != 0 ? errno : ENOMEM;
				logError("file: "__FILE__", line: %d, " \
					"malloc %d bytes fail, errno: %d, " \
					"error info: %s", __LINE__, \
					bytes, *err_no, STRERROR(*err_no));
				pthread_mutex_unlock(&cm->lock);
				return NULL;
			}

			node = (ConnectionNode *)p;
			node->conn = (ConnectionInfo *)(p + sizeof(ConnectionNode));
			node->manager = cm;
			node->next = NULL;
			node->atime = 0;

			cm->total_count++;
			pthread_mutex_unlock(&cm->lock);

			memcpy(node->conn, conn, sizeof(ConnectionInfo));
            node->conn->socket_domain = cp->socket_domain;
			node->conn->sock = -1;
			*err_no = conn_pool_connect_server(node->conn, \
					cp->connect_timeout);
			if (*err_no != 0)
			{
                pthread_mutex_lock(&cm->lock);
                cm->total_count--;  //rollback
                pthread_mutex_unlock(&cm->lock);

				free(p);
				return NULL;
			}

			logDebug("file: "__FILE__", line: %d, " \
				"server %s:%d, new connection: %d, " \
				"total_count: %d, free_count: %d",   \
				__LINE__, conn->ip_addr, conn->port, \
				node->conn->sock, cm->total_count, \
				cm->free_count);
			return node->conn;
		}
		else
		{
			node = cm->head;
			ci = node->conn;
			cm->head = node->next;
			cm->free_count--;

			if (current_time - node->atime > cp->max_idle_time)
			{
				cm->total_count--;

				logDebug("file: "__FILE__", line: %d, " \
					"server %s:%d, connection: %d idle " \
					"time: %d exceeds max idle time: %d, "\
					"total_count: %d, free_count: %d", \
					__LINE__, conn->ip_addr, conn->port, \
					ci->sock, \
					(int)(current_time - node->atime), \
					cp->max_idle_time, cm->total_count, \
					cm->free_count);

				conn_pool_disconnect_server(ci);
				free(node);
				continue;
			}

			pthread_mutex_unlock(&cm->lock);
			logDebug("file: "__FILE__", line: %d, " \
				"server %s:%d, reuse connection: %d, " \
				"total_count: %d, free_count: %d", 
				__LINE__, conn->ip_addr, conn->port, 
				ci->sock, cm->total_count, cm->free_count);
            *err_no = 0;
			return ci;
		}
	}
}

int conn_pool_close_connection_ex(ConnectionPool *cp, ConnectionInfo *conn, 
	const bool bForce)
{
	char key[INET6_ADDRSTRLEN + 8];
	int key_len;
	ConnectionManager *cm;
	ConnectionNode *node;

	conn_pool_get_key(conn, key, &key_len);

	pthread_mutex_lock(&cp->lock);
	cm = (ConnectionManager *)hash_find(&cp->hash_array, key, key_len);
	pthread_mutex_unlock(&cp->lock);
	if (cm == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"hash entry of server %s:%d not exist", __LINE__, \
			conn->ip_addr, conn->port);
		return ENOENT;
	}

	node = (ConnectionNode *)(((char *)conn) - sizeof(ConnectionNode));
	if (node->manager != cm)
	{
		logError("file: "__FILE__", line: %d, " \
			"manager of server entry %s:%d is invalid!", \
			__LINE__, conn->ip_addr, conn->port);
		return EINVAL;
	}

	pthread_mutex_lock(&cm->lock);
	if (bForce)
	{
		cm->total_count--;

		logDebug("file: "__FILE__", line: %d, " \
			"server %s:%d, release connection: %d, " \
			"total_count: %d, free_count: %d", 
			__LINE__, conn->ip_addr, conn->port, 
			conn->sock, cm->total_count, cm->free_count);

		conn_pool_disconnect_server(conn);
		free(node);
	}
	else
	{
		node->atime = get_current_time();
		node->next = cm->head;
		cm->head = node;
		cm->free_count++;

		logDebug("file: "__FILE__", line: %d, " \
			"server %s:%d, free connection: %d, " \
			"total_count: %d, free_count: %d", 
			__LINE__, conn->ip_addr, conn->port, 
			conn->sock, cm->total_count, cm->free_count);
	}
	pthread_mutex_unlock(&cm->lock);

	return 0;
}

static int _conn_count_walk(const int index, const HashData *data, void *args)
{
	int *count;
	ConnectionManager *cm;
	ConnectionNode *node;

	count = (int *)args;
	cm = (ConnectionManager *)data->value;
	node = cm->head;
	while (node != NULL)
	{
		(*count)++;
		node = node->next;
	}

	return 0;
}

int conn_pool_get_connection_count(ConnectionPool *cp)
{
	int count;
	count = 0;
	hash_walk(&cp->hash_array, _conn_count_walk, &count);
	return count;
}

int conn_pool_parse_server_info(const char *pServerStr,
        ConnectionInfo *pServerInfo, const int default_port)
{
    char *parts[2];
    char server_info[256];
    int len;
    int count;

    len = strlen(pServerStr);
    if (len == 0) {
        logError("file: "__FILE__", line: %d, "
            "pServerStr \"%s\" is empty!",
            __LINE__, pServerStr);
        return EINVAL;
    }
    if (len >= sizeof(server_info)) {
        logError("file: "__FILE__", line: %d, "
            "pServerStr \"%s\" is too long!",
            __LINE__, pServerStr);
        return ENAMETOOLONG;
    }

    memcpy(server_info, pServerStr, len);
    *(server_info + len) = '\0';

    count = splitEx(server_info, ':', parts, 2);
    if (count == 1) {
        pServerInfo->port = default_port;
    }
    else {
        char *endptr = NULL;
        pServerInfo->port = (int)strtol(parts[1], &endptr, 10);
        if ((endptr != NULL && *endptr != '\0') || pServerInfo->port <= 0) {
            logError("file: "__FILE__", line: %d, "
                "pServerStr: %s, invalid port: %s!",
                __LINE__, pServerStr, parts[1]);
            return EINVAL;
        }
    }

    if (getIpaddrByName(parts[0], pServerInfo->ip_addr,
        sizeof(pServerInfo->ip_addr)) == INADDR_NONE)
    {
        logError("file: "__FILE__", line: %d, "
            "pServerStr: %s, invalid hostname: %s!",
            __LINE__, pServerStr, parts[0]);
        return EINVAL;
    }

    pServerInfo->socket_domain = AF_INET;
    pServerInfo->sock = -1;
    return 0;
}

int conn_pool_load_server_info(IniContext *pIniContext, const char *filename,
        const char *item_name, ConnectionInfo *pServerInfo,
        const int default_port)
{
    char *pServerStr;

	pServerStr = iniGetStrValue(NULL, item_name, pIniContext);
    if (pServerStr == NULL) {
        logError("file: "__FILE__", line: %d, "
                "config file: %s, item \"%s\" not exist!",
                __LINE__, filename, item_name);
        return ENOENT;
    }

    return conn_pool_parse_server_info(pServerStr, pServerInfo, default_port);
}
