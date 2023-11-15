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

//server_id_func.h

#ifndef _SERVER_ID_FUNC_H
#define _SERVER_ID_FUNC_H 

#include "common_define.h"
#include "connection_pool.h"
#include "ini_file_reader.h"
#include "fast_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FC_MAX_SERVER_IP_COUNT  8
#define FC_MAX_GROUP_COUNT      4

#define FC_SID_SERVER_COUNT(ctx)  (ctx).sorted_server_arrays.by_id.count
#define FC_SID_SERVERS(ctx)       (ctx).sorted_server_arrays.by_id.servers

typedef struct
{
    int net_type;
    ConnectionInfo conn;
} FCAddressInfo;

typedef struct {
    int alloc;
    int count;
    FCAddressInfo *addrs;
} FCAddressArray;

typedef struct {
    int alloc;
    int count;
    int index;
    FCAddressInfo **addrs;
} FCAddressPtrArray;

typedef struct
{
    bool enabled;
    int switch_on_iops;
    int switch_on_count;
} FCSmartPollingConfig;

typedef struct
{
    string_t group_name;
    int port;          //default port
    int server_port;   //port in server section
    FCCommunicationType comm_type;
    FCSmartPollingConfig smart_polling;
    struct {
        int net_type;
        string_t ip_prefix;
        char prefix_buff[IP_ADDRESS_SIZE];
    } filter;
	char name_buff[FAST_INI_ITEM_NAME_SIZE];  //group_name string holder
} FCServerGroupInfo;

typedef struct
{
    int count;
    FCServerGroupInfo groups[FC_MAX_GROUP_COUNT];
} FCServerGroupArray;

typedef struct
{
    FCServerGroupInfo *server_group;
    FCAddressPtrArray address_array;
} FCGroupAddresses;

typedef struct
{
	int id;  //server id
    FCAddressPtrArray uniq_addresses;
    FCGroupAddresses group_addrs[FC_MAX_GROUP_COUNT];
} FCServerInfo;

typedef struct
{
    string_t ip_addr;
    int port;
    FCServerInfo *server;
} FCServerMap;

typedef struct
{
    int alloc;
    int count;
    FCServerInfo *servers;
} FCServerInfoArray;

typedef struct
{
    int alloc;
    int count;
    FCServerInfo **servers;
} FCServerInfoPtrArray;

typedef struct
{
    int count;
    FCServerMap *maps;
} FCServerMapArray;

typedef enum {
    fc_connection_thread_local_auto,
    fc_connection_thread_local_yes,
    fc_connection_thread_local_no
} FCServerConnThreadLocal;

typedef struct fc_server_config
{
    int default_port;
    int min_hosts_each_group;
    bool share_between_groups;  //if an address shared between different groups
    int buffer_size;  //for RDMA
    FCCommunicationType comm_type;
    FCSmartPollingConfig smart_polling;
    FCServerConnThreadLocal connection_thread_local;
    FCServerGroupArray group_array;
    struct {
        FCServerInfoArray by_id;     //sorted by server id
        FCServerMapArray by_ip_port; //sorted by IP and port
    } sorted_server_arrays;
} FCServerConfig;

FCServerInfo *fc_server_get_by_id(FCServerConfig *ctx,
        const int server_id);

FCServerInfo *fc_server_get_by_ip_port_ex(FCServerConfig *ctx,
        const string_t *ip_addr, const int port);

static inline FCServerInfo *fc_server_get_by_ip_port(FCServerConfig *ctx,
        const char *ip_addr, const int port)
{
    string_t saddr;
    FC_SET_STRING(saddr, (char *)ip_addr);
    return fc_server_get_by_ip_port_ex(ctx, &saddr, port);
}

FCServerGroupInfo *fc_server_get_group_by_name(FCServerConfig *ctx,
        const string_t *group_name);

static inline FCServerGroupInfo *fc_server_get_group_by_index(
        FCServerConfig *ctx, const int index)
{
    if (index < 0 || index >= ctx->group_array.count) {
        return NULL;
    }

    return ctx->group_array.groups + index;
}

static inline int fc_server_get_group_index_ex(FCServerConfig *ctx,
        const string_t *group_name)
{
    FCServerGroupInfo *group;
    group = fc_server_get_group_by_name(ctx, group_name);
    if (group != NULL) {
        return group - ctx->group_array.groups;
    } else {
        return -1;
    }
}

static inline int fc_server_get_group_index(FCServerConfig *ctx,
        const char *group_name)
{
    string_t gname;
    FC_SET_STRING(gname, (char *)group_name);
    return fc_server_get_group_index_ex(ctx, &gname);
}

int fc_server_load_from_file_ex(FCServerConfig *ctx,
        const char *config_filename, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups);

static inline int fc_server_load_from_file(FCServerConfig *ctx,
        const char *config_filename)
{
    const int default_port = 0;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = false;
    return fc_server_load_from_file_ex(ctx, config_filename,
            default_port, min_hosts_each_group, share_between_groups);
}

int fc_server_load_from_buffer_ex(FCServerConfig *ctx, char *content,
        const char *caption, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups);

static inline int fc_server_load_from_buffer(FCServerConfig *ctx,
        char *content)
{
    const char *caption = "from-buffer";
    const int default_port = 0;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = false;
    return fc_server_load_from_buffer_ex(ctx, content, caption,
            default_port, min_hosts_each_group, share_between_groups);
}

int fc_server_load_from_ini_context_ex(FCServerConfig *ctx,
        IniContext *ini_context, const char *config_filename,
        const int default_port, const int min_hosts_each_group,
        const bool share_between_groups);

static inline int fc_server_load_from_ini_context(FCServerConfig *ctx,
        IniContext *ini_context, const char *config_filename)
{
    const int default_port = 0;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = false;
    return fc_server_load_from_ini_context_ex(ctx, ini_context,
            config_filename, default_port, min_hosts_each_group,
            share_between_groups);
}

void fc_server_destroy(FCServerConfig *ctx);

int fc_server_to_config_string(FCServerConfig *ctx, FastBuffer *buffer);

void fc_server_to_log(FCServerConfig *ctx);

const FCAddressInfo *fc_server_get_address_by_peer(
        FCAddressPtrArray *addr_array, const char *peer_ip);

int fc_server_make_connection_ex(FCAddressPtrArray *addr_array,
        ConnectionInfo *conn, const char *service_name,
        const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error);

#define fc_server_make_connection(addr_array, \
        conn, service_name, connect_timeout)  \
    fc_server_make_connection_ex(addr_array, conn, \
            service_name, connect_timeout, NULL, true)

static inline void fc_server_close_connection(ConnectionInfo *conn)
{
    G_COMMON_CONNECTION_CALLBACKS[conn->comm_type].close_connection(conn);
}

static inline void fc_server_destroy_connection(ConnectionInfo *conn)
{
    fc_server_close_connection(conn);
    conn_pool_free_connection(conn);
}

struct ibv_pd *fc_alloc_rdma_pd(fc_alloc_pd_callback alloc_pd,
        FCAddressPtrArray *address_array, int *result);

static inline const char *fc_connection_thread_local_str(
        const FCServerConnThreadLocal value)
{
    switch (value) {
        case fc_connection_thread_local_auto:
            return "auto";
        case fc_connection_thread_local_yes:
            return "yes";
        case fc_connection_thread_local_no:
            return "no";
        default:
            return "unkown";
    }
}

#ifdef __cplusplus
}
#endif

#endif

