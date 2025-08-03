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
#include <dlfcn.h>
#include <sys/types.h>
#include "logger.h"
#include "sockopt.h"
#include "shared_func.h"
#include "sched_thread.h"
#include "server_id_func.h"
#include "connection_pool.h"

ConnectionCallbacks g_connection_callbacks = {
    false, {{conn_pool_connect_server_ex1,
        conn_pool_disconnect_server,
        conn_pool_is_connected},
    {NULL, NULL, NULL}}, {NULL}
};

static int node_init_for_socket(ConnectionNode *node,
        ConnectionPool *cp)
{
    node->conn = (ConnectionInfo *)(node + 1);
    return 0;
}

static int node_init_for_rdma(ConnectionNode *node,
        ConnectionPool *cp)
{
    node->conn = (ConnectionInfo *)(node + 1);
    node->conn->arg1 = node->conn->args + cp->extra_data_size;
    return G_RDMA_CONNECTION_CALLBACKS.init_connection(node->conn,
            cp->extra_params.rdma.double_buffers, cp->extra_params.
            rdma.buffer_size, cp->extra_params.rdma.pd);
}

static inline void conn_pool_get_key(const ConnectionInfo *conn,
        char *key, int *key_len)
{
    *key_len = strlen(conn->ip_addr);
    memcpy(key, conn->ip_addr, *key_len);
    *(key + (*key_len)++) = '-';
    *key_len += fc_itoa(conn->port, key + (*key_len));
}

static int close_conn(ConnectionPool *cp, ConnectionManager *cm,
        ConnectionInfo *conn, const bool bForce)
{
	ConnectionNode *node;
    char formatted_ip[FORMATTED_IP_SIZE];

	node = (ConnectionNode *)((char *)conn - sizeof(ConnectionNode));
	if (node->manager != cm)
	{
        format_ip_address(conn->ip_addr, formatted_ip);
		logError("file: "__FILE__", line: %d, "
			"manager of server entry %s:%u is invalid!",
			__LINE__, formatted_ip, conn->port);
		return EINVAL;
	}

	if (bForce)
    {
        cm->total_count--;

        if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
            format_ip_address(conn->ip_addr, formatted_ip);
            logDebug("file: "__FILE__", line: %d, "
                    "server %s:%u, release connection: %d, "
                    "total_count: %d, free_count: %d",
                    __LINE__, formatted_ip, conn->port,
                    conn->sock, cm->total_count, cm->free_count);
        }

        G_COMMON_CONNECTION_CALLBACKS[conn->comm_type].
            close_connection(conn);
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

        if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
            format_ip_address(conn->ip_addr, formatted_ip);
            logDebug("file: "__FILE__", line: %d, "
                    "server %s:%u, free connection: %d, "
                    "total_count: %d, free_count: %d",
                    __LINE__, formatted_ip, conn->port,
                    conn->sock, cm->total_count, cm->free_count);
        }
	}

	return 0;
}

static ConnectionManager *find_manager(ConnectionPool *cp,
        ConnectionBucket *bucket, const string_t *key,
        const bool need_create)
{
    ConnectionManager *cm;

    if (bucket->head != NULL)
    {
        if (fc_string_equal(&bucket->head->key, key))  //fast path
        {
            return bucket->head;
        }
        else
        {
            cm = bucket->head->next;
            while (cm != NULL)
            {
                if (fc_string_equal(&cm->key, key))
                {
                    return cm;
                }
                cm = cm->next;
            }
        }
    }

    if (!need_create)
    {
        return NULL;
    }

    cm = (ConnectionManager *)fast_mblock_alloc_object(
            &cp->manager_allocator);
    if (cm == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__,
                (int)sizeof(ConnectionManager));
        return NULL;
    }

    cm->head = NULL;
    cm->total_count = 0;
    cm->free_count = 0;
    if ((cm->key.str=fc_malloc(key->len + 1)) == NULL)
    {
        return NULL;
    }
    memcpy(cm->key.str, key->str, key->len + 1);
    cm->key.len = key->len;

    //add to manager chain
    cm->next = bucket->head;
    bucket->head = cm;
    return cm;
}

static int close_connection(ConnectionPool *cp, ConnectionInfo *conn,
        const string_t *key, uint32_t hash_code, const bool bForce)
{
    ConnectionBucket *bucket;
    ConnectionManager *cm;
    char formatted_ip[FORMATTED_IP_SIZE];
    int result;

    bucket = cp->hashtable.buckets + hash_code % cp->hashtable.capacity;
    pthread_mutex_lock(&bucket->lock);
    if ((cm=find_manager(cp, bucket, key, false)) != NULL)
    {
        result = close_conn(cp, cm, conn, bForce);
    }
    else
    {
        format_ip_address(conn->ip_addr, formatted_ip);
		logError("file: "__FILE__", line: %d, "
			"hash entry of server %s:%u not exist",
            __LINE__, formatted_ip, conn->port);
		result = ENOENT;
    }
	pthread_mutex_unlock(&bucket->lock);

	return result;
}

static void cp_tls_destroy(void *ptr)
{
    ConnectionThreadHashTable *htable;
    ConnectionNode **pp;
    ConnectionNode **end;
    ConnectionNode *current;
    ConnectionNode *node;
    string_t key;
    uint32_t hash_code;
    char key_buff[INET6_ADDRSTRLEN + 8];

    key.str = key_buff;
    htable = ptr;
    end = htable->buckets + htable->cp->extra_params.tls.htable_capacity;
    for (pp=htable->buckets; pp<end; pp++) {
        if (*pp == NULL) {
            continue;
        }

        node = *pp;
        do {
            current = node;
            node = node->next;

            conn_pool_get_key(current->conn, key.str, &key.len);
            hash_code = fc_simple_hash(key.str, key.len);
            close_connection(htable->cp, current->conn, &key, hash_code, false);
        } while (node != NULL);
    }

    free(ptr);
}

static int init_hashtable(ConnectionPool *cp, const int htable_capacity)
{
    int bytes;
	int result;
    unsigned int *hash_capacity;
    ConnectionBucket *bucket;
    ConnectionBucket *end;

    if (htable_capacity > 0)
    {
        hash_capacity = fc_hash_get_prime_capacity(htable_capacity);
        cp->hashtable.capacity = (hash_capacity != NULL ?
                *hash_capacity : fc_ceil_prime(htable_capacity));
    }
    else
    {
        cp->hashtable.capacity = 163;
    }
    bytes = sizeof(ConnectionBucket) * cp->hashtable.capacity;
    if ((cp->hashtable.buckets=fc_malloc(bytes)) == NULL)
    {
        return ENOMEM;
    }

    end = cp->hashtable.buckets + cp->hashtable.capacity;
    for (bucket=cp->hashtable.buckets; bucket<end; bucket++)
    {
        bucket->head = NULL;
        if ((result=init_pthread_lock(&bucket->lock)) != 0)
        {
            return result;
        }
    }

    return 0;
}

int conn_pool_init_ex1(ConnectionPool *cp, const int connect_timeout,
	const int max_count_per_entry, const int max_idle_time,
    const int htable_capacity, fc_connection_callback_func connect_done_func,
    void *connect_done_args, fc_connection_callback_func validate_func,
    void *validate_args, const int extra_data_size,
    const ConnectionExtraParams *extra_params)
{
    const int64_t alloc_elements_limit = 0;
	int result;
    int extra_connection_size;
    fast_mblock_object_init_func obj_init_func;

	cp->connect_timeout_ms = connect_timeout * 1000;
	cp->max_count_per_entry = max_count_per_entry;
	cp->max_idle_time = max_idle_time;
	cp->extra_data_size = extra_data_size;
    cp->connect_done_callback.func = connect_done_func;
    cp->connect_done_callback.args = connect_done_args;
    cp->validate_callback.func = validate_func;
    cp->validate_callback.args = validate_args;

    if ((result=fast_mblock_init_ex1(&cp->manager_allocator, "cpool-manager",
                    sizeof(ConnectionManager), 256, alloc_elements_limit,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }

    if (extra_params != NULL && extra_params->rdma.pd != NULL) {
        extra_connection_size = G_RDMA_CONNECTION_CALLBACKS.
            get_connection_size();
        obj_init_func = (fast_mblock_object_init_func)node_init_for_rdma;
        cp->extra_params = *extra_params;
    } else {
        extra_connection_size = 0;
        if (extra_params != NULL) {
            cp->extra_params = *extra_params;
        } else {
            cp->extra_params.tls.enabled = false;
            cp->extra_params.tls.htable_capacity = 163;
            cp->extra_params.rdma.buffer_size = 0;
            cp->extra_params.rdma.pd = NULL;
        }
        obj_init_func = (fast_mblock_object_init_func)node_init_for_socket;
    }
    if ((result=fast_mblock_init_ex1(&cp->node_allocator, "cpool-node",
                    sizeof(ConnectionNode) + sizeof(ConnectionInfo) +
                    extra_data_size + extra_connection_size, 256,
                    alloc_elements_limit, obj_init_func, cp, true)) != 0)
    {
        return result;
    }

    logDebug("cp: %p, tls.enabled: %d, htable_capacity: %d",
            cp, cp->extra_params.tls.enabled,
            cp->extra_params.tls.htable_capacity);

    if (cp->extra_params.tls.enabled) {
        if ((result=pthread_key_create(&cp->tls_key, cp_tls_destroy)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "pthread_key_create fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

	return init_hashtable(cp, htable_capacity);
}

typedef void (*cp_hash_walk_callback)(ConnectionPool *cp,
        ConnectionManager *cm, void *args);

static void conn_pool_hash_walk(ConnectionPool *cp,
        cp_hash_walk_callback callback, void *args)
{
    ConnectionBucket *bucket;
    ConnectionBucket *end;
    ConnectionManager *cm;
    ConnectionManager *current;

    end = cp->hashtable.buckets + cp->hashtable.capacity;
    for (bucket=cp->hashtable.buckets; bucket<end; bucket++)
    {
        pthread_mutex_lock(&bucket->lock);
        cm = bucket->head;
        while (cm != NULL)
        {
            current = cm;
            cm = cm->next;
            callback(cp, current, args);
        }
        pthread_mutex_unlock(&bucket->lock);
    }
}

static void cp_destroy_walk_callback(ConnectionPool *cp,
        ConnectionManager *cm, void *args)
{
    ConnectionNode *node;
    ConnectionNode *deleted;

    node = cm->head;
    while (node != NULL)
    {
        deleted = node;
        node = node->next;
        G_COMMON_CONNECTION_CALLBACKS[deleted->conn->comm_type].
            close_connection(deleted->conn);
    }

    free(cm->key.str);
}

void conn_pool_destroy(ConnectionPool *cp)
{
    ConnectionBucket *bucket;
    ConnectionBucket *end;

    if (cp->hashtable.buckets == NULL) {
        return;
    }

    conn_pool_hash_walk(cp, cp_destroy_walk_callback, cp);

    end = cp->hashtable.buckets + cp->hashtable.capacity;
    for (bucket=cp->hashtable.buckets; bucket<end; bucket++) {
        pthread_mutex_destroy(&bucket->lock);
    }
    free(cp->hashtable.buckets);
    cp->hashtable.buckets = NULL;

    if (cp->extra_params.tls.enabled) {
        pthread_key_delete(cp->tls_key);
    }

    fast_mblock_destroy(&cp->manager_allocator);
    fast_mblock_destroy(&cp->node_allocator);
}

void conn_pool_disconnect_server(ConnectionInfo *conn)
{
    if (conn->sock >= 0)
    {
        close(conn->sock);
        conn->sock = -1;
    }
}

bool conn_pool_is_connected(ConnectionInfo *conn)
{
    return (conn->sock >= 0);
}

int conn_pool_connect_server_ex1(ConnectionInfo *conn,
        const char *service_name, const int connect_timeout_ms,
        const char *bind_ipaddr, const bool log_connect_error)
{
	int result;
    char formatted_ip[FORMATTED_IP_SIZE];

	if (conn->sock >= 0)
	{
		close(conn->sock);
	}

    if ((conn->sock=socketCreateEx2(conn->af, conn->ip_addr,
                    O_NONBLOCK, bind_ipaddr, &result)) < 0)
    {
        return result;
    }

	if ((result=connectserverbyip_nb(conn->sock, conn->ip_addr,
                    conn->port, connect_timeout_ms / 1000)) != 0)
	{
        if (log_connect_error)
        {
            format_ip_address(conn->ip_addr, formatted_ip);
            logError("file: "__FILE__", line: %d, "
                    "connect to %s%sserver %s:%u fail, errno: %d, "
                    "error info: %s", __LINE__, service_name != NULL ?
                    service_name : "", service_name != NULL ?  " " : "",
                    formatted_ip, conn->port, result, STRERROR(result));
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
    char formatted_ip[FORMATTED_IP_SIZE];

    if (conn->sock >= 0)
    {
        close(conn->sock);
    }

    if ((conn->sock=socketCreateEx2(conn->af, conn->ip_addr,
                    O_NONBLOCK, bind_ipaddr, &result)) < 0)
    {
        return result;
    }

    result = asyncconnectserverbyip(conn->sock, conn->ip_addr, conn->port);
    if (!(result == 0 || result == EINPROGRESS))
    {
        format_ip_address(conn->ip_addr, formatted_ip);
        logError("file: "__FILE__", line: %d, "
                "connect to server %s:%u fail, errno: %d, "
                "error info: %s", __LINE__, formatted_ip,
                conn->port, result, STRERROR(result));
        close(conn->sock);
        conn->sock = -1;
    }

    return result;
}

static ConnectionInfo *get_conn(ConnectionPool *cp,
	ConnectionManager *cm, pthread_mutex_t *lock,
    const ConnectionInfo *conn, const char *service_name,
    int *err_no)
{
	ConnectionNode *node;
	ConnectionInfo *ci;
    char formatted_ip[FORMATTED_IP_SIZE];
	time_t current_time;

	current_time = get_current_time();
	while (1)
	{
		if (cm->head == NULL)
		{
			if ((cp->max_count_per_entry > 0) && 
				(cm->total_count >= cp->max_count_per_entry))
			{
                format_ip_address(conn->ip_addr, formatted_ip);
				*err_no = ENOSPC;
				logError("file: "__FILE__", line: %d, "
					"connections: %d of %s%sserver %s:%u exceed limit: %d",
                    __LINE__, cm->total_count, service_name != NULL ?
                    service_name : "", service_name != NULL ? " " : "",
                    formatted_ip, conn->port, cp->max_count_per_entry);
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
                return NULL;
            }

			node->manager = cm;
			node->next = NULL;
			node->atime = 0;

			cm->total_count++;
			pthread_mutex_unlock(lock);

			memcpy(node->conn->ip_addr, conn->ip_addr, sizeof(conn->ip_addr));
            node->conn->port = conn->port;
            node->conn->comm_type = conn->comm_type;
            node->conn->af = conn->af;
			node->conn->sock = -1;
            node->conn->validate_flag = false;
			*err_no = G_COMMON_CONNECTION_CALLBACKS[conn->comm_type].
                make_connection(node->conn, service_name,
                        cp->connect_timeout_ms, NULL, true);
            if (*err_no == 0 && cp->connect_done_callback.func != NULL)
            {
                *err_no = cp->connect_done_callback.func(node->conn,
                        cp->connect_done_callback.args);
            }
			if (*err_no != 0)
			{
                G_COMMON_CONNECTION_CALLBACKS[conn->comm_type].
                    close_connection(node->conn);
                fast_mblock_free_object(&cp->node_allocator, node);

                pthread_mutex_lock(lock);
                cm->total_count--;  //rollback
				return NULL;
			}

            if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
                format_ip_address(conn->ip_addr, formatted_ip);
                logDebug("file: "__FILE__", line: %d, "
                        "server %s:%u, new connection: %d, "
                        "total_count: %d, free_count: %d",
                        __LINE__, formatted_ip, conn->port,
                        node->conn->sock, cm->total_count,
                        cm->free_count);
            }

            pthread_mutex_lock(lock);
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

                if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
                    format_ip_address(conn->ip_addr, formatted_ip);
                    logDebug("file: "__FILE__", line: %d, "
                            "server %s:%u, connection: %d idle "
                            "time: %d exceeds max idle time: %d, "
                            "total_count: %d, free_count: %d", __LINE__,
                            formatted_ip, conn->port, ci->sock, (int)
                            (current_time - node->atime), cp->max_idle_time,
                            cm->total_count, cm->free_count);
                }

                G_COMMON_CONNECTION_CALLBACKS[ci->comm_type].
                    close_connection(ci);
                fast_mblock_free_object(&cp->node_allocator, node);
				continue;
			}

            if (FC_LOG_BY_LEVEL(LOG_DEBUG)) {
                format_ip_address(conn->ip_addr, formatted_ip);
                logDebug("file: "__FILE__", line: %d, "
                        "server %s:%u, reuse connection: %d, "
                        "total_count: %d, free_count: %d",
                        __LINE__, formatted_ip, conn->port,
                        ci->sock, cm->total_count, cm->free_count);
            }

            *err_no = 0;
			return ci;
		}
	}
}

static ConnectionInfo *get_connection(ConnectionPool *cp,
	const ConnectionInfo *conn, const string_t *key,
    const uint32_t hash_code, const char *service_name,
    const bool shared, int *err_no)
{
    ConnectionBucket *bucket;
	ConnectionManager *cm;
	ConnectionInfo *ci;

    bucket = cp->hashtable.buckets + hash_code % cp->hashtable.capacity;
	pthread_mutex_lock(&bucket->lock);
    if ((cm=find_manager(cp, bucket, key, true)) != NULL)
    {
        ci = get_conn(cp, cm, &bucket->lock, conn, service_name, err_no);
        if (ci != NULL)
        {
            ci->shared = shared;
        }
    }
    else
    {
        *err_no = ENOMEM;
        ci = NULL;
    }
    pthread_mutex_unlock(&bucket->lock);
    return ci;
}

ConnectionInfo *conn_pool_get_connection_ex(ConnectionPool *cp,
	const ConnectionInfo *conn, const char *service_name,
    const bool shared, int *err_no)
{
    string_t key;
    int bytes;
    uint32_t hash_code;
    ConnectionNode **bucket;
    ConnectionNode *node;
    ConnectionInfo *ci;
    char key_buff[INET6_ADDRSTRLEN + 8];
    ConnectionThreadHashTable *htable;

    key.str = key_buff;
    conn_pool_get_key(conn, key.str, &key.len);
    hash_code = fc_simple_hash(key.str, key.len);
    if (!cp->extra_params.tls.enabled || !shared) {
        return get_connection(cp, conn, &key, hash_code,
                service_name, shared, err_no);
    }

    htable = pthread_getspecific(cp->tls_key);
    if (htable == NULL) {
        bytes = sizeof(ConnectionThreadHashTable) + sizeof(ConnectionNode *) *
            cp->extra_params.tls.htable_capacity;
        htable = fc_malloc(bytes);
        memset(htable, 0, bytes);

        htable->buckets = (ConnectionNode **)(htable + 1);
        htable->cp = cp;
        if ((*err_no=pthread_setspecific(cp->tls_key, htable)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "pthread_setspecific fail, errno: %d, error info: %s",
                    __LINE__, *err_no, STRERROR(*err_no));
            return NULL;
        }
    }

    bucket = htable->buckets + hash_code % cp->
        extra_params.tls.htable_capacity;
    if (*bucket == NULL) {
        node = NULL;
    } else if (FC_CONNECTION_SERVER_EQUAL1(*conn, *(*bucket)->conn)) {
        node = *bucket;
    } else {
        node = (*bucket)->next;
        while (node != NULL) {
            if (FC_CONNECTION_SERVER_EQUAL1(*conn, *node->conn)) {
                break;
            }
            node = node->next;
        }
    }

    if (node != NULL) {
        *err_no = 0;
        return node->conn;
    } else {
        if ((ci=get_connection(cp, conn, &key, hash_code,
                        service_name, shared, err_no)) == NULL)
        {
            return NULL;
        }

        //add to thread local hashtable
        node = (ConnectionNode *)((char *)ci - sizeof(ConnectionNode));
        node->next = *bucket;
        *bucket = node;
        *err_no = 0;
        return ci;
    }
}

int conn_pool_close_connection_ex(ConnectionPool *cp,
        ConnectionInfo *conn, const bool bForce)
{
    string_t key;
    uint32_t hash_code;
    ConnectionNode **bucket;
    ConnectionNode *previous;
    ConnectionNode *node;
    char key_buff[INET6_ADDRSTRLEN + 8];
    ConnectionThreadHashTable *htable;

    key.str = key_buff;
    conn_pool_get_key(conn, key.str, &key.len);
    hash_code = fc_simple_hash(key.str, key.len);
    if (!cp->extra_params.tls.enabled || !conn->shared) {
        return close_connection(cp, conn, &key, hash_code, bForce);
    }

    //thread local logic
    if (!bForce) {
        return 0;
    }

    htable = pthread_getspecific(cp->tls_key);
    if (htable == NULL) {
        logError("file: "__FILE__", line: %d, "
                "the thread local key NOT exist!", __LINE__);
        return close_connection(cp, conn, &key, hash_code, bForce);
    }

    bucket = htable->buckets + hash_code % cp->
        extra_params.tls.htable_capacity;
    if (*bucket == NULL) {
        node = NULL;
        previous = NULL;
    } else if ((*bucket)->conn == conn) {
        node = *bucket;
        previous = NULL;
    } else {
        previous = *bucket;
        node = (*bucket)->next;
        while (node != NULL) {
            if (node->conn == conn) {
                break;
            }
            previous = node;
            node = node->next;
        }
    }

    if (node != NULL) {
        if (previous == NULL) {
            *bucket = node->next;
        } else {
            previous->next = node->next;
        }
    } else {
        logError("file: "__FILE__", line: %d, "
                "%.*s NOT in the thread local hashtable!",
                __LINE__, key.len, key.str);
    }

    return close_connection(cp, conn, &key, hash_code, bForce);
}

static void cp_stat_walk_callback(ConnectionPool *cp,
        ConnectionManager *cm, void *args)
{
    ConnectionPoolStat *stat;

    stat = args;
    stat->server_count++;
    stat->connection.total_count += cm->total_count;
    stat->connection.free_count += cm->free_count;
}

void conn_pool_stat(ConnectionPool *cp, ConnectionPoolStat *stat)
{
    ConnectionBucket *bucket;
    ConnectionBucket *end;

    stat->htable_capacity = cp->hashtable.capacity;
    stat->server_count = 0;
    stat->connection.total_count = 0;
    stat->connection.free_count = 0;
    conn_pool_hash_walk(cp, cp_stat_walk_callback, stat);

    stat->bucket_used = 0;
    end = cp->hashtable.buckets + cp->hashtable.capacity;
    for (bucket=cp->hashtable.buckets; bucket<end; bucket++)
    {
        if (bucket->head != NULL) {
            stat->bucket_used++;
        }
    }
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

    count = parseAddress(server_info, parts);
    if (count == 1) {
        pServerInfo->port = default_port;
    } else {
        char *endptr = NULL;
        pServerInfo->port = (int)strtol(parts[1], &endptr, 10);
        if ((endptr != NULL && *endptr != '\0') || pServerInfo->port <= 0) {
            logError("file: "__FILE__", line: %d, "
                    "host: %s, invalid port: %s!",
                    __LINE__, pServerStr, parts[1]);
            return EINVAL;
        }
    }

    if (getIpaddrByNameEx(parts[0], pServerInfo->ip_addr,
                sizeof(pServerInfo->ip_addr),
                &pServerInfo->af) == INADDR_NONE)
    {
        logError("file: "__FILE__", line: %d, "
                "host: %s, invalid hostname: %s!",
                __LINE__, pServerStr, parts[0]);
        return EINVAL;
    }

    pServerInfo->sock = -1;
    pServerInfo->comm_type = fc_comm_type_sock;
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

#define API_PREFIX_NAME  "fast_rdma_client_"

#define LOAD_API(callbacks, fname) \
    do { \
        callbacks.fname = dlsym(dlhandle, API_PREFIX_NAME#fname); \
        if (callbacks.fname == NULL) {  \
            logError("file: "__FILE__", line: %d, "  \
                    "dlsym api %s fail, error info: %s", \
                    __LINE__, API_PREFIX_NAME#fname, dlerror()); \
            return ENOENT; \
        } \
    } while (0)

int conn_pool_global_init_for_rdma()
{
    const char *library = "libfastrdma.so";
    void *dlhandle;

    if (g_connection_callbacks.inited) {
        return 0;
    }

    dlhandle = dlopen(library, RTLD_LAZY);
    if (dlhandle == NULL) {
        logError("file: "__FILE__", line: %d, "
                "dlopen %s fail, error info: %s",
                __LINE__, library, dlerror());
        return EFAULT;
    }

    LOAD_API(G_COMMON_CONNECTION_CALLBACKS[fc_comm_type_rdma],
            make_connection);
    LOAD_API(G_COMMON_CONNECTION_CALLBACKS[fc_comm_type_rdma],
            close_connection);
    LOAD_API(G_COMMON_CONNECTION_CALLBACKS[fc_comm_type_rdma],
            is_connected);

    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, set_busy_polling);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, alloc_pd);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, get_connection_size);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, init_connection);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, make_connection);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, close_connection);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, destroy_connection);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, is_connected);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, send_done);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, get_recv_buffer);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, request_by_buf1);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, request_by_buf2);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, request_by_iov);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, request_by_mix);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, send_by_buf1);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, recv_data);
    LOAD_API(G_RDMA_CONNECTION_CALLBACKS, post_recv);

    g_connection_callbacks.inited = true;
    return 0;
}

ConnectionInfo *conn_pool_alloc_connection_ex(
        const FCCommunicationType comm_type,
        const int extra_data_size,
        const ConnectionExtraParams *extra_params,
        int *err_no)
{
    ConnectionInfo *conn;
    int bytes;

    if (comm_type == fc_comm_type_rdma) {
        bytes = sizeof(ConnectionInfo) + extra_data_size +
            G_RDMA_CONNECTION_CALLBACKS.get_connection_size();
    } else {
        bytes = sizeof(ConnectionInfo) + extra_data_size;
    }
    if ((conn=fc_malloc(bytes)) == NULL) {
        *err_no = ENOMEM;
        return NULL;
    }
    memset(conn, 0, bytes);

    if (comm_type == fc_comm_type_rdma) {
        conn->arg1 = conn->args + extra_data_size;
        if ((*err_no=G_RDMA_CONNECTION_CALLBACKS.init_connection(
                        conn, extra_params->rdma.double_buffers,
                        extra_params->rdma.buffer_size,
                        extra_params->rdma.pd)) != 0)
        {
            free(conn);
            return NULL;
        }
    } else {
        *err_no = 0;
    }

    conn->comm_type = comm_type;
    conn->sock = -1;
    return conn;
}

int conn_pool_set_rdma_extra_params_ex(ConnectionExtraParams *extra_params,
        struct fc_server_config *server_cfg, const int server_group_index,
        const bool double_buffers)
{
    const int padding_size = 1024;
    FCServerGroupInfo *server_group;
    FCServerInfo *first_server;
    int result;

    if ((server_group=fc_server_get_group_by_index(server_cfg,
                    server_group_index)) == NULL)
    {
        return ENOENT;
    }

    switch (server_cfg->connection_thread_local) {
        case fc_connection_thread_local_auto:
            if (server_group->comm_type == fc_comm_type_sock) {
                extra_params->tls.enabled = false;
            } else {
                extra_params->tls.enabled = (FC_SID_SERVER_COUNT(
                            *server_cfg) <= 64);
            }
            break;
        case fc_connection_thread_local_yes:
            extra_params->tls.enabled = true;
            break;
        default:
            extra_params->tls.enabled = false;
            break;
    }

    if (extra_params->tls.enabled) {
        extra_params->tls.htable_capacity = fc_ceil_prime(
                FC_SID_SERVER_COUNT(*server_cfg));
    } else {
        extra_params->tls.htable_capacity = 0;
    }

    if (server_group->comm_type == fc_comm_type_sock) {
        extra_params->rdma.double_buffers = false;
        extra_params->rdma.buffer_size = 0;
        extra_params->rdma.pd = NULL;
        return 0;
    } else {
        first_server = FC_SID_SERVERS(*server_cfg);
        extra_params->rdma.double_buffers = double_buffers;
        extra_params->rdma.buffer_size = server_cfg->buffer_size + padding_size;
        extra_params->rdma.pd = fc_alloc_rdma_pd(G_RDMA_CONNECTION_CALLBACKS.
                alloc_pd, &first_server->group_addrs[server_group_index].
                address_array, &result);
        return result;
    }
}
