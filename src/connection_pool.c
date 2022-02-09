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

#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "logger.h"
#include "sockopt.h"
#include "shared_func.h"
#include "sched_thread.h"
#include "connection_pool.h"

int conn_pool_init_ex1(ConnectionPool *cp, int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int socket_domain, const int htable_init_capacity,
    fc_connection_callback_func connect_done_func, void *connect_done_args,
    fc_connection_callback_func validate_func, void *validate_args,
    const int extra_data_size)
{
    const int64_t alloc_elements_limit = 0;
	int result;
    int init_capacity;

	if ((result=init_pthread_lock(&cp->lock)) != 0)
	{
		return result;
	}
	cp->connect_timeout = connect_timeout;
	cp->max_count_per_entry = max_count_per_entry;
	cp->max_idle_time = max_idle_time;
	cp->socket_domain = socket_domain;
    cp->connect_done_callback.func = connect_done_func;
    cp->connect_done_callback.args = connect_done_args;
    cp->validate_callback.func = validate_func;
    cp->validate_callback.args = validate_args;

    init_capacity = htable_init_capacity > 0 ? htable_init_capacity : 256;
    if ((result=fast_mblock_init_ex1(&cp->manager_allocator, "cpool-manager",
                    sizeof(ConnectionManager), init_capacity,
                    alloc_elements_limit, NULL, NULL, false)) != 0)
    {
        return result;
    }

    if ((result=fast_mblock_init_ex1(&cp->node_allocator, "cpool-node",
                    sizeof(ConnectionNode) + sizeof(ConnectionInfo) +
                    extra_data_size, init_capacity, alloc_elements_limit,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }

	return fc_hash_init(&(cp->hash_array), fc_simple_hash, init_capacity, 0.75);
}

static int coon_pool_close_connections(const int index,
        const HashData *data, void *args)
{
    ConnectionPool *cp;
    ConnectionManager *cm;

    cp = (ConnectionPool *)args;
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
            fast_mblock_free_object(&cp->node_allocator, deleted);
        }

        fast_mblock_free_object(&cp->manager_allocator, cm);
    }

    return 0;
}

void conn_pool_destroy(ConnectionPool *cp)
{
	pthread_mutex_lock(&cp->lock);
    fc_hash_walk(&(cp->hash_array), coon_pool_close_connections, cp);
	fc_hash_destroy(&(cp->hash_array));
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

int conn_pool_connect_server_ex(ConnectionInfo *conn,
		const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error)
{
	int result;

	if (conn->sock >= 0)
	{
		close(conn->sock);
	}

    if ((conn->sock=socketCreateEx2(conn->socket_domain, conn->ip_addr,
                    O_NONBLOCK, bind_ipaddr, &result)) < 0)
    {
        return result;
    }

	if ((result=connectserverbyip_nb(conn->sock, conn->ip_addr,
                    conn->port, connect_timeout)) != 0)
	{
        if (log_connect_error)
        {
            logError("file: "__FILE__", line: %d, "
                    "connect to server %s:%u fail, errno: %d, "
                    "error info: %s", __LINE__, conn->ip_addr,
                    conn->port, result, STRERROR(result));
        }

		close(conn->sock);
		conn->sock = -1;
		return result;
	}

	return 0;
}

int conn_pool_async_connect_server_ex(ConnectionInfo *conn,
        const char *bind_ipaddr)
{
    int result;

    if (conn->sock >= 0)
    {
        close(conn->sock);
    }

    if ((conn->sock=socketCreateEx2(conn->socket_domain,
                    conn->ip_addr, O_NONBLOCK, bind_ipaddr,
                    &result)) < 0)
    {
        return result;
    }

    result = asyncconnectserverbyip(conn->sock, conn->ip_addr, conn->port);
    if (!(result == 0 || result == EINPROGRESS))
    {
        logError("file: "__FILE__", line: %d, "
                "connect to server %s:%u fail, errno: %d, "
                "error info: %s", __LINE__, conn->ip_addr,
                conn->port, result, STRERROR(result));
        close(conn->sock);
        conn->sock = -1;
    }

    return result;
}

static inline void  conn_pool_get_key(const ConnectionInfo *conn, char *key, int *key_len)
{
    *key_len = sprintf(key, "%s_%u", conn->ip_addr, conn->port);
}

ConnectionInfo *conn_pool_get_connection(ConnectionPool *cp, 
	const ConnectionInfo *conn, int *err_no)
{
	char key[INET6_ADDRSTRLEN + 8];
	int key_len;
	ConnectionManager *cm;
	ConnectionNode *node;
	ConnectionInfo *ci;
	time_t current_time;

	conn_pool_get_key(conn, key, &key_len);

	pthread_mutex_lock(&cp->lock);
	cm = (ConnectionManager *)fc_hash_find(&cp->hash_array, key, key_len);
	if (cm == NULL)
	{
		cm = (ConnectionManager *)fast_mblock_alloc_object(
                &cp->manager_allocator);
		if (cm == NULL)
		{
			*err_no = ENOMEM;
			logError("file: "__FILE__", line: %d, "
				"malloc %d bytes fail", __LINE__,
				(int)sizeof(ConnectionManager));
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
		fc_hash_insert(&cp->hash_array, key, key_len, cm);
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
					"connections: %d of server %s:%u " \
					"exceed limit: %d", __LINE__, \
					cm->total_count, conn->ip_addr, \
					conn->port, cp->max_count_per_entry);
				pthread_mutex_unlock(&cm->lock);
				return NULL;
			}

            node = (ConnectionNode *)fast_mblock_alloc_object(
                    &cp->node_allocator);
			if (node == NULL)
            {
                *err_no = ENOMEM;
                logError("file: "__FILE__", line: %d, "
                        "malloc %d bytes fail", __LINE__, (int)
                        (sizeof(ConnectionNode) + sizeof(ConnectionInfo)));
                pthread_mutex_unlock(&cm->lock);
                return NULL;
            }

			node->conn = (ConnectionInfo *)(node + 1);
			node->manager = cm;
			node->next = NULL;
			node->atime = 0;

			cm->total_count++;
			pthread_mutex_unlock(&cm->lock);

			memcpy(node->conn, conn, sizeof(ConnectionInfo));
            node->conn->socket_domain = cp->socket_domain;
			node->conn->sock = -1;
            node->conn->validate_flag = false;
			*err_no = conn_pool_connect_server(node->conn,
					cp->connect_timeout);
            if (*err_no == 0 && cp->connect_done_callback.func != NULL)
            {
                *err_no = cp->connect_done_callback.func(node->conn,
                        cp->connect_done_callback.args);
            }
			if (*err_no != 0)
			{
                if (node->conn->sock >= 0)
                {
                    close(node->conn->sock);
                    node->conn->sock = -1;
                }
                pthread_mutex_lock(&cm->lock);
                cm->total_count--;  //rollback
                fast_mblock_free_object(&cp->node_allocator, node);
                pthread_mutex_unlock(&cm->lock);

				return NULL;
			}

			logDebug("file: "__FILE__", line: %d, " \
				"server %s:%u, new connection: %d, " \
				"total_count: %d, free_count: %d",   \
				__LINE__, conn->ip_addr, conn->port, \
				node->conn->sock, cm->total_count, \
				cm->free_count);
			return node->conn;
		}
		else
		{
            bool invalid;

			node = cm->head;
			ci = node->conn;
			cm->head = node->next;
			cm->free_count--;

			if (current_time - node->atime > cp->max_idle_time)
            {
                if (cp->validate_callback.func != NULL)
                {
                    ci->validate_flag = true;
                }
                invalid = true;
            }
            else
            {
                invalid = false;
            }

            if (ci->validate_flag)
            {
                ci->validate_flag = false;
                if (cp->validate_callback.func != NULL)
                {
                    invalid = cp->validate_callback.func(ci,
                            cp->validate_callback.args) != 0;
                }
                else
                {
                    invalid = false;
                }
            }

            if (invalid)
            {
				cm->total_count--;

				logDebug("file: "__FILE__", line: %d, " \
					"server %s:%u, connection: %d idle " \
					"time: %d exceeds max idle time: %d, "\
					"total_count: %d, free_count: %d", \
					__LINE__, conn->ip_addr, conn->port, \
					ci->sock, \
					(int)(current_time - node->atime), \
					cp->max_idle_time, cm->total_count, \
					cm->free_count);

				conn_pool_disconnect_server(ci);
                fast_mblock_free_object(&cp->node_allocator, node);
				continue;
			}

			pthread_mutex_unlock(&cm->lock);
			logDebug("file: "__FILE__", line: %d, " \
				"server %s:%u, reuse connection: %d, " \
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
	cm = (ConnectionManager *)fc_hash_find(&cp->hash_array, key, key_len);
	pthread_mutex_unlock(&cp->lock);
	if (cm == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"hash entry of server %s:%u not exist", __LINE__, \
			conn->ip_addr, conn->port);
		return ENOENT;
	}

	node = (ConnectionNode *)(((char *)conn) - sizeof(ConnectionNode));
	if (node->manager != cm)
	{
		logError("file: "__FILE__", line: %d, " \
			"manager of server entry %s:%u is invalid!", \
			__LINE__, conn->ip_addr, conn->port);
		return EINVAL;
	}

	pthread_mutex_lock(&cm->lock);
	if (bForce)
    {
        cm->total_count--;

        logDebug("file: "__FILE__", line: %d, "
                "server %s:%u, release connection: %d, "
                "total_count: %d, free_count: %d",
                __LINE__, conn->ip_addr, conn->port,
                conn->sock, cm->total_count, cm->free_count);

        conn_pool_disconnect_server(conn);
        fast_mblock_free_object(&cp->node_allocator, node);

        node = cm->head;
        while (node != NULL)
        {
            node->conn->validate_flag = true;
            node = node->next;
        }
    }
	else
	{
		node->atime = get_current_time();
		node->next = cm->head;
		cm->head = node;
		cm->free_count++;

		logDebug("file: "__FILE__", line: %d, " \
			"server %s:%u, free connection: %d, " \
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
	fc_hash_walk(&cp->hash_array, _conn_count_walk, &count);
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
            "host \"%s\" is empty!",
            __LINE__, pServerStr);
        return EINVAL;
    }
    if (len >= sizeof(server_info)) {
        logError("file: "__FILE__", line: %d, "
            "host \"%s\" is too long!",
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
                "host: %s, invalid port: %s!",
                __LINE__, pServerStr, parts[1]);
            return EINVAL;
        }
    }

    if (getIpaddrByName(parts[0], pServerInfo->ip_addr,
        sizeof(pServerInfo->ip_addr)) == INADDR_NONE)
    {
        logError("file: "__FILE__", line: %d, "
            "host: %s, invalid hostname: %s!",
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
