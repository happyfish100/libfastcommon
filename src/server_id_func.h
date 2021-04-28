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
    string_t group_name;
    int port;          //default port
    int server_port;   //port in server section
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

typedef struct
{
    int default_port;
    int min_hosts_each_group;
    bool share_between_groups;  //if an address shared between different groups
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

ConnectionInfo *fc_server_check_connect_ex(FCAddressPtrArray *addr_array,
        const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error, int *err_no);

#define fc_server_check_connect(addr_array, connect_timeout, err_no) \
    fc_server_check_connect_ex(addr_array, connect_timeout, NULL, true, err_no)

void fc_server_disconnect(FCAddressPtrArray *addr_array);

const FCAddressInfo *fc_server_get_address_by_peer(
        FCAddressPtrArray *addr_array, const char *peer_ip);

int fc_server_make_connection_ex(FCAddressPtrArray *addr_array,
        ConnectionInfo *conn, const int connect_timeout,
        const char *bind_ipaddr, const bool log_connect_error);

#define fc_server_make_connection(addr_array, conn, connect_timeout) \
    fc_server_make_connection_ex(addr_array, conn, connect_timeout, NULL, true)

#ifdef __cplusplus
}
#endif

#endif

