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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <netdb.h>
#include "logger.h"
#include "shared_func.h"
#include "sockopt.h"
#include "server_id_func.h"

#define GROUP_SECTION_PREFIX_STR  "group-"
#define GROUP_SECTION_PREFIX_LEN  (sizeof(GROUP_SECTION_PREFIX_STR) - 1)

#define SERVER_SECTION_PREFIX_STR  "server-"
#define SERVER_SECTION_PREFIX_LEN  (sizeof(SERVER_SECTION_PREFIX_STR) - 1)

#define SERVER_ITEM_PORT_STR        "port"
#define SERVER_ITEM_PORT_LEN        (sizeof(SERVER_ITEM_PORT_STR) - 1)

#define SERVER_ITEM_HOST_STR        "host"
#define SERVER_ITEM_HOST_LEN        (sizeof(SERVER_ITEM_HOST_STR) - 1)

#define SERVER_ITEM_HOST_AFFIX_STR  "-host"
#define SERVER_ITEM_HOST_AFFIX_LEN  (sizeof(SERVER_ITEM_HOST_AFFIX_STR) - 1)

#define SERVER_ITEM_PORT_AFFIX_STR  "-port"
#define SERVER_ITEM_PORT_AFFIX_LEN  (sizeof(SERVER_ITEM_PORT_AFFIX_STR) - 1)

#define IP_PORT_MAP_COUNT(ctx)  ctx->sorted_server_arrays.by_ip_port.count
#define IP_PORT_MAPS(ctx)       ctx->sorted_server_arrays.by_ip_port.maps

#define FC_SERVER_GROUP_PORT(group) \
    (group->server_port > 0 ? group->server_port : group->port)

static int fc_server_cmp_server_id(const void *p1, const void *p2)
{
	return ((FCServerInfo *)p1)->id - ((FCServerInfo *)p2)->id;
}

static int fc_server_cmp_ip_and_port(const void *p1, const void *p2)
{
    FCServerMap *m1;
    FCServerMap *m2;
	int result;
    int sub;
    int min;

    m1 = (FCServerMap *)p1;
    m2 = (FCServerMap *)p2;

    sub = m1->ip_addr.len - m2->ip_addr.len; 
    if (sub < 0) {
        min = m1->ip_addr.len;
    } else {
        min = m2->ip_addr.len;
    }

    if (min > 0) {
        result = memcmp(m1->ip_addr.str, m2->ip_addr.str, min);
        if (result != 0) {
            return result;
        }
    }
    if (sub != 0) {
        return sub;
    }

    return m1->port - m2->port;
}

static int fc_server_cmp_address_ptr(const void *p1, const void *p2)
{
    FCAddressInfo **addr1;
    FCAddressInfo **addr2;
    int result;

    addr1 = (FCAddressInfo **)p1;
    addr2 = (FCAddressInfo **)p2;
    if ((result=strcmp((*addr1)->conn.ip_addr, (*addr2)->conn.ip_addr)) != 0) {
        return result;
    }
    return (*addr1)->conn.port - (*addr2)->conn.port;
}

FCServerInfo *fc_server_get_by_id(FCServerConfig *ctx,
        const int server_id)
{
	FCServerInfo target;

	target.id = server_id;
	return (FCServerInfo *)bsearch(&target, FC_SID_SERVERS(*ctx),
            FC_SID_SERVER_COUNT(*ctx), sizeof(FCServerInfo),
            fc_server_cmp_server_id);
}

static int fc_server_calc_ip_port_count(FCServerConfig *ctx)
{
	FCServerInfo *server;
	FCServerInfo *send;
    int count;

    count = 0;
    send = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    for (server=FC_SID_SERVERS(*ctx); server<send; server++) {
        count += server->uniq_addresses.count;
    }

    return count;
}

static int fc_server_check_alloc_group_addresses(FCAddressPtrArray *array)
{
    int new_alloc;
    int bytes;
    FCAddressInfo **new_addrs;

    if (array->count < array->alloc) {
        return 0;
    }

    new_alloc = array->alloc > 0 ? 2 * array->alloc : 2;
    bytes = sizeof(FCAddressInfo *) * new_alloc;
    new_addrs = (FCAddressInfo **)fc_malloc(bytes);
    if (new_addrs == NULL) {
        return ENOMEM;
    }
    memset(new_addrs, 0, bytes);

    if (array->addrs != NULL) {
        memcpy(new_addrs, array->addrs, sizeof(FCAddressInfo *) * array->count);
        free(array->addrs);
    }

    array->addrs = new_addrs;
    array->alloc = new_alloc;
    return 0;
}

static FCAddressInfo *fc_server_add_to_uniq_addresses(
        FCAddressPtrArray *addr_ptr_array, const FCAddressInfo *addr)
{
    FCAddressInfo *p;
    FCAddressInfo **pp;
    FCAddressInfo **end;

    end = addr_ptr_array->addrs + addr_ptr_array->count;
    for (pp=addr_ptr_array->addrs; pp<end; pp++) {
        if (FC_CONNECTION_SERVER_EQUAL1(addr->conn, (*pp)->conn)) {
            return *pp;
        }
    }

    if (fc_server_check_alloc_group_addresses(addr_ptr_array) != 0) {
        return NULL;
    }
    p = (FCAddressInfo *)fc_malloc(sizeof(FCAddressInfo));
    if (p == NULL) {
        return NULL;
    }

    *p = *addr;
    addr_ptr_array->addrs[addr_ptr_array->count++] = p;
    return p;
}

static int fc_server_init_ip_port_array(FCServerConfig *ctx)
{
    int count;
	int bytes;
    FCServerMapArray *map_array;
    FCServerMap *map;
	FCServerInfo *server;
	FCServerInfo *send;
    FCAddressInfo **paddr;
    FCAddressInfo **pend;

    map_array = &ctx->sorted_server_arrays.by_ip_port;

    count = fc_server_calc_ip_port_count(ctx);
    bytes = sizeof(FCServerMap) * count;
    map_array->maps = (FCServerMap *)fc_malloc(bytes);
    if (map_array->maps == NULL) {
        return ENOMEM;
    }
    memset(map_array->maps, 0, bytes);

    send = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    map = map_array->maps;
    for (server=FC_SID_SERVERS(*ctx); server<send; server++) {
        pend = server->uniq_addresses.addrs + server->uniq_addresses.count;
        for (paddr=server->uniq_addresses.addrs; paddr<pend; paddr++) {
            map->server = server;
            FC_SET_STRING(map->ip_addr, (*paddr)->conn.ip_addr);
            map->port = (*paddr)->conn.port;
            map++;
        }
    }

    map_array->count = map - map_array->maps;
    qsort(map_array->maps, map_array->count, sizeof(FCServerMap),
            fc_server_cmp_ip_and_port);
    return 0;
}

static int fc_server_check_id_duplicated(FCServerConfig *ctx,
        const char *config_filename)
{
    FCServerInfo *previous;
	FCServerInfo *current;
	FCServerInfo *send;

    previous = FC_SID_SERVERS(*ctx) + 0;
    send = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    for (current=FC_SID_SERVERS(*ctx) + 1; current<send; current++) {
        if (current->id == previous->id) {
            logError("file: "__FILE__", line: %d, "
                    "config file: %s, duplicate server id: %d",
                    __LINE__, config_filename, current->id);
            return EEXIST;
        }
        previous = current;
    }

    return 0;
}

static int fc_server_check_ip_port(FCServerConfig *ctx,
        const char *config_filename)
{
    FCServerMap *previous;
    FCServerMap *current;
    FCServerMap *end;
    int id1;
    int id2;

    previous = IP_PORT_MAPS(ctx) + 0;
    end = IP_PORT_MAPS(ctx) + IP_PORT_MAP_COUNT(ctx);
    for (current=IP_PORT_MAPS(ctx)+1; current<end; current++) {
        if (fc_server_cmp_ip_and_port(current, previous) == 0) {
            if (previous->server->id < current->server->id) {
                id1 = previous->server->id;
                id2 = current->server->id;
            } else {
                id1 = current->server->id;
                id2 = previous->server->id;
            }
            logError("file: "__FILE__", line: %d, "
                    "config file: %s, duplicate ip:port %s:%u, "
                    "the server ids: %d, %d", __LINE__,
                    config_filename, previous->ip_addr.str,
                    previous->port, id1, id2);
            return EEXIST;
        }

        previous = current;
    }

    return 0;
}

FCServerInfo *fc_server_get_by_ip_port_ex(FCServerConfig *ctx,
        const string_t *ip_addr, const int port)
{
    FCServerMap target;
    FCServerMap *found;

    target.ip_addr = *ip_addr;
    target.port = port;
    found = (FCServerMap *)bsearch(&target, IP_PORT_MAPS(ctx),
            IP_PORT_MAP_COUNT(ctx), sizeof(FCServerMap),
            fc_server_cmp_ip_and_port);
    if (found != NULL) {
        return found->server;
    }

    return NULL;
}

static inline void fc_server_set_group_ptr_name(FCServerGroupInfo *ginfo,
        const char *group_name)
{
    ginfo->group_name.str = ginfo->name_buff;
    ginfo->group_name.len = snprintf(ginfo->name_buff,
            sizeof(ginfo->name_buff) - 1, "%s", group_name);
    if (ginfo->group_name.len == 0) {
        return;
    }

    fc_trim(ginfo->group_name.str);
    ginfo->group_name.len = strlen(ginfo->group_name.str);
}

static inline void fc_server_set_ip_prefix(FCServerGroupInfo *ginfo,
        const char *ip_prefix)
{
    ginfo->filter.ip_prefix.str = ginfo->filter.prefix_buff;
    if (ip_prefix != NULL) {
        ginfo->filter.ip_prefix.len = snprintf(ginfo->filter.prefix_buff,
                sizeof(ginfo->filter.prefix_buff) - 1, "%s", ip_prefix);
    }
}

static int fc_server_load_one_group(FCServerConfig *ctx,
        const char *config_filename, IniContext *ini_context,
        const int group_count, const char *section_name)
{
    FCServerGroupInfo *group;
    char new_name[FAST_INI_ITEM_NAME_SIZE];
    char *port_str;
    char *net_type;
    char *ip_prefix;

    strcpy(new_name, section_name);
    group = ctx->group_array.groups + ctx->group_array.count;
    fc_server_set_group_ptr_name(group, new_name + GROUP_SECTION_PREFIX_LEN);

    if (group->group_name.len == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, no group name!",
                __LINE__, config_filename, section_name);
        return EINVAL;
    }

    port_str = iniGetStrValue(section_name, SERVER_ITEM_PORT_STR, ini_context);
    if (port_str == NULL) {
        if (group_count == 1) {
            group->port = ctx->default_port;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, section: %s, no item: %s!",
                    __LINE__, config_filename, section_name,
                    SERVER_ITEM_PORT_STR);
            return ENOENT;
        }
    } else {
        char *endptr = NULL;
        group->port = strtol(port_str, &endptr, 10);
        if (group->port <= 0 || (endptr != NULL && *endptr != '\0')) {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, section: %s, item: %s, "
                    "invalid port: %s", __LINE__, config_filename,
                    section_name, SERVER_ITEM_PORT_STR, port_str);
            return EINVAL;
        }
    }

    net_type = iniGetStrValue(section_name, "net_type", ini_context);
    group->filter.net_type = fc_get_net_type_by_name(net_type);
    if (group->filter.net_type == FC_NET_TYPE_NONE) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, invalid net_type: %s",
                __LINE__, config_filename, group->group_name.str, net_type);
        return EINVAL;
    }

    ip_prefix = iniGetStrValue(section_name, "ip_prefix", ini_context);
    fc_server_set_ip_prefix(group, ip_prefix);

    ctx->group_array.count++;
    return 0;
}

static int check_group_ports_duplicate(FCServerConfig *ctx,
        const char *config_filename)
{
    FCServerGroupInfo *g1;
    FCServerGroupInfo *g2;
    FCServerGroupInfo *end;
    int port1;
    int port2;

    end = ctx->group_array.groups + ctx->group_array.count;
    for (g1=ctx->group_array.groups; g1<end; g1++) {
        port1 = FC_SERVER_GROUP_PORT(g1);
        for (g2=g1+1; g2<end; g2++) {
            port2 = FC_SERVER_GROUP_PORT(g2);
            if (port1 == port2) {
                logError("file: "__FILE__", line: %d, "
                    "config filename: %s, the port: %d of group: %.*s "
                    "is same to group: %.*s", __LINE__, config_filename,
                    port1, g1->group_name.len, g1->group_name.str,
                    g2->group_name.len, g2->group_name.str);
                return EEXIST;
            }
        }
    }

    return 0;
}

static int fc_server_cmp_group_info(const void *p1, const void *p2)
{
    return strcmp(((FCServerGroupInfo *)p1)->name_buff,
            ((FCServerGroupInfo *)p2)->name_buff);
}

static void fc_server_sort_groups(FCServerConfig *ctx)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;

    if (ctx->group_array.count <= 1) {
        return;
    }

    qsort(ctx->group_array.groups, ctx->group_array.count,
            sizeof(FCServerGroupInfo), fc_server_cmp_group_info);

    //must reset stirng_t pointer
    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        group->group_name.str = group->name_buff;
        group->filter.ip_prefix.str = group->filter.prefix_buff;
    }
}

static int fc_server_load_groups(FCServerConfig *ctx,
        const char *config_filename, IniContext *ini_context)
{
	int result;
    int count;
    IniSectionInfo sections[FC_MAX_GROUP_COUNT];
    IniSectionInfo *section;
    IniSectionInfo *end;

    if ((result=iniGetSectionNamesByPrefix(ini_context,
                    GROUP_SECTION_PREFIX_STR, sections,
                    FC_MAX_GROUP_COUNT, &count)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, get sections by prefix %s fail, "
                "errno: %d, error info: %s", __LINE__, config_filename,
                GROUP_SECTION_PREFIX_STR, result, STRERROR(result));
        return result;
    }

    if (count == 0) {
        ctx->group_array.count = 1;
        fc_server_set_group_ptr_name(ctx->group_array.groups + 0, "");
        ctx->group_array.groups[0].port = iniGetIntValue(NULL, "port",
            ini_context, ctx->default_port);
        return 0;
    }

    end = sections + count;
    for (section=sections; section<end; section++) {
        if ((result=fc_server_load_one_group(ctx, config_filename,
                        ini_context, count, section->section_name)) != 0)
        {
            return result;
        }
    }

    fc_server_sort_groups(ctx);
    return 0;
}

static int fc_server_alloc_servers(FCServerInfoArray *array,
        const int target_count)
{
    int bytes;

    bytes = sizeof(FCServerInfo) * target_count;
    array->servers = (FCServerInfo *)fc_malloc(bytes);
    if (array->servers == NULL) {
        return ENOMEM;
    }
    memset(array->servers, 0, bytes);

    array->alloc = target_count;
    return 0;
}

static int fc_server_check_alloc_group_address_ptrs(FCAddressPtrArray *array)
{
    int new_alloc;
    int bytes;
    FCAddressInfo **new_addrs;

    if (array->count < array->alloc) {
        return 0;
    }

    new_alloc = array->alloc > 0 ? 2 * array->alloc : 1;
    bytes = sizeof(FCAddressInfo *) * new_alloc;
    new_addrs = (FCAddressInfo **)fc_malloc(bytes);
    if (new_addrs == NULL) {
        return ENOMEM;
    }
    memset(new_addrs, 0, bytes);

    if (array->addrs != NULL) {
        memcpy(new_addrs, array->addrs, sizeof(FCAddressInfo *) * array->count);
        free(array->addrs);
    }

    array->addrs = new_addrs;
    array->alloc = new_alloc;
    return 0;
}

static inline void fc_server_clear_server_port(FCServerGroupArray *array)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;

    end = array->groups + array->count;
    for (group=array->groups; group<end; group++) {
        group->server_port = 0;
    }
}

FCServerGroupInfo *fc_server_get_group_by_name(FCServerConfig *ctx,
        const string_t *group_name)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;

    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        if (fc_string_equal(&group->group_name, group_name)) {
            return group;
        }
    }

    return NULL;
}

static int fc_server_load_group_port(FCServerConfig *ctx,
        const char *config_filename, const char *section_name,
        const string_t *group_name, IniItem *port_item)
{
    FCServerGroupInfo *group;
    char *endptr;

    if ((group=fc_server_get_group_by_name(ctx, group_name)) == NULL) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, group: %.*s "
                "in item: %s not found!", __LINE__, config_filename,
                section_name, group_name->len, group_name->str,
                port_item->name);
        return ENOENT;
    }

    endptr = NULL;
    group->server_port = strtol(port_item->value, &endptr, 10);
    if (group->server_port <= 0 || (endptr != NULL && *endptr != '\0')) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, item: %s, "
                "invalid port: %s", __LINE__, config_filename,
                section_name, port_item->name, port_item->value);
        return EINVAL;
    }

    return 0;
}

static int check_server_addresses_duplicate(FCServerConfig *ctx,
        const char *config_filename, const char *section_name,
        FCAddressInfo *addresses, const int count)
{
    FCAddressInfo *addr1;
    FCAddressInfo *addr2;
    FCAddressInfo *end;
    char port_caption[32];
    char port_prompt[16];

    if (count <= 1) {
        return 0;
    }

    end = addresses + count;
    for (addr1=addresses; addr1<end; addr1++) {
        for (addr2=addr1+1; addr2<end; addr2++) {
            if (FC_CONNECTION_SERVER_EQUAL1(addr1->conn, addr2->conn)) {
                if (addr1->conn.port > 0) {
                    strcpy(port_caption, " and port");
                    sprintf(port_prompt, ":%d", addr1->conn.port);
                } else {
                    *port_caption = *port_prompt = '\0';
                }
                logError("file: "__FILE__", line: %d, "
                        "config filename: %s, section: %s, duplicate ip%s %s%s",
                        __LINE__, config_filename, section_name, port_caption,
                        addr1->conn.ip_addr, port_prompt);
                return EEXIST;
            }
        }
    }

    return 0;
}

static int check_addresses_duplicate(FCServerConfig *ctx,
        const char *config_filename, const char *section_name,
        FCGroupAddresses *group_addr)
{
    FCAddressInfo **ppaddr;
    FCAddressInfo **ppend;
    FCAddressInfo **pprevious;

    if (group_addr->address_array.count <= 1) {
        return 0;
    }

	qsort(group_addr->address_array.addrs, group_addr->address_array.count,
            sizeof(FCAddressInfo *), fc_server_cmp_address_ptr);
    pprevious = group_addr->address_array.addrs;
    ppend = group_addr->address_array.addrs + group_addr->address_array.count;
    for (ppaddr=group_addr->address_array.addrs+1; ppaddr<ppend; ppaddr++) {
        if (fc_server_cmp_address_ptr(ppaddr, pprevious) == 0) {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, section: %s, group: %.*s, "
                    "duplicate ip and port: %s:%u", __LINE__,
                    config_filename, section_name,
                    group_addr->server_group->group_name.len,
                    group_addr->server_group->group_name.str,
                    (*ppaddr)->conn.ip_addr, (*ppaddr)->conn.port);
            return EEXIST;
        }
        pprevious = ppaddr;
    }

    return 0;
}

static int check_server_group_addresses_duplicate(FCServerConfig *ctx,
        FCServerInfo *server, const char *config_filename,
        const char *section_name)
{
    int result;
    FCGroupAddresses *gaddr;
    FCGroupAddresses *end;

    end = server->group_addrs + ctx->group_array.count;
    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        if ((result=check_addresses_duplicate(ctx, config_filename,
                        section_name, gaddr)) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int check_server_group_min_hosts(FCServerConfig *ctx,
        FCServerInfo *server, const char *config_filename,
        const char *section_name)
{
    FCGroupAddresses *gaddr;
    FCGroupAddresses *end;

    end = server->group_addrs + ctx->group_array.count;
    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        if (gaddr->address_array.count < ctx->min_hosts_each_group) {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, section: %s, group: %.*s, "
                    "host count: %d < %d!", __LINE__, config_filename,
                    section_name, gaddr->server_group->group_name.len,
                    gaddr->server_group->group_name.str,
                    gaddr->address_array.count,
                    ctx->min_hosts_each_group);
            return ENOENT;
        }
    }

    return 0;
}

static bool fc_server_group_match(const FCServerGroupInfo *group,
        const FCAddressInfo *addr)
{
    int ip_len;

    if ((addr->conn.port > 0) && (addr->conn.port !=
                FC_SERVER_GROUP_PORT(group)))
    {
        return false;
    }

    if ((group->filter.net_type != FC_NET_TYPE_ANY) &&
            ((addr->net_type & group->filter.net_type) !=
            group->filter.net_type))
    {
        return false;
    }

    if (group->filter.ip_prefix.len > 0) {
        ip_len = strlen(addr->conn.ip_addr);
        if (!(ip_len >= group->filter.ip_prefix.len &&
                    memcmp(addr->conn.ip_addr,
                        group->filter.ip_prefix.str,
                        group->filter.ip_prefix.len) == 0))
        {
            return false;
        }
    }

    return true;
}

static int fc_server_set_address(FCServerConfig *ctx,
        FCAddressInfo *addr, const char *config_filename,
        const char *section_name, const char *item_name,
        const char *host, const int default_port)
{
    int result;

    if ((result=conn_pool_parse_server_info(host, &addr->conn,
                    default_port)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, "
                "item: %s, invalid host: %s", __LINE__,
                config_filename, section_name, item_name, host);
        return result;
    }

    addr->net_type = fc_get_net_type_by_ip(addr->conn.ip_addr);
    return 0;
}

static int fc_server_set_group_server_address(FCServerInfo *server,
        FCGroupAddresses *group_addr, const FCAddressInfo *address)
{
    FCAddressInfo *addr;
    int result;

    addr = fc_server_add_to_uniq_addresses(&server->uniq_addresses, address);
    if (addr == NULL) {
        return ENOMEM;
    }

    if ((result=fc_server_check_alloc_group_address_ptrs(
                    &group_addr->address_array)) != 0)
    {
        return result;
    }

    group_addr->address_array.addrs[group_addr->address_array.count++] = addr;
    return 0;
}

static int fc_server_load_group_server(FCServerConfig *ctx,
        FCServerInfo *server, const char *config_filename,
        const char *section_name, const string_t *group_name,
        IniItem *host_item)
{
    FCServerGroupInfo *group;
    FCGroupAddresses *group_addr;
    FCAddressInfo address;
    int result;
    int group_index;

    if ((group=fc_server_get_group_by_name(ctx, group_name)) == NULL) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, group: %.*s "
                "in item: %s not found!", __LINE__, config_filename,
                section_name, group_name->len, group_name->str,
                host_item->name);
        return ENOENT;
    }

    group_index = group - ctx->group_array.groups;
    group_addr = server->group_addrs + group_index;
    if (group_addr->address_array.count >= FC_MAX_SERVER_IP_COUNT) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, "
                "too many %s items exceeds %d", __LINE__,
                config_filename, section_name,
                host_item->name, FC_MAX_SERVER_IP_COUNT);
        return ENOSPC;
    }

    if ((result=fc_server_set_address(ctx, &address, config_filename,
                    section_name, host_item->name, host_item->value,
                    FC_SERVER_GROUP_PORT(group))) != 0)
    {
        return result;
    }

    if ((result=fc_server_set_group_server_address(server,
                    group_addr, &address)) != 0)
    {
        return result;
    }

    return 0;
}

static int fc_server_set_host(FCServerConfig *ctx, FCServerInfo *server,
        const char *config_filename, const char *section_name,
        const FCAddressInfo *addr)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;
    FCGroupAddresses *group_addr;
    const FCAddressInfo *new_addr;
    FCAddressInfo addr_holder;
    int result;
    int count;
    int group_index;

    count = 0;
    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        if (fc_server_group_match(group, addr)) {
            group_index = group - ctx->group_array.groups;
            group_addr = server->group_addrs + group_index;
            if (group_addr->address_array.count >= FC_MAX_SERVER_IP_COUNT) {
                logError("file: "__FILE__", line: %d, "
                        "config filename: %s, section: %s, "
                        "too many %s items for group %.*s exceeds %d",
                        __LINE__, config_filename, section_name,
                        SERVER_ITEM_HOST_STR, group->group_name.len,
                        group->group_name.str, FC_MAX_SERVER_IP_COUNT);
                return ENOSPC;
            }

            if (addr->conn.port == 0) {
                addr_holder = *addr;
                addr_holder.conn.port = FC_SERVER_GROUP_PORT(group);
                new_addr = &addr_holder;
            } else {
                new_addr = addr;
            }

            if ((result=fc_server_set_group_server_address(server,
                            group_addr, new_addr)) != 0)
            {
                return result;
            }

            count++;
        }
    }

    if (count == 0) {
        char port_prompt[16];
        if (addr->conn.port > 0) {
            sprintf(port_prompt, ":%d", addr->conn.port);
        } else {
            *port_prompt = '\0';
        }
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, "
                "host %s%s not belong to any group",
                __LINE__, config_filename, section_name,
                addr->conn.ip_addr, port_prompt);
        return ENOENT;
    }

    if (!ctx->share_between_groups && (count > 1 && addr->conn.port > 0)) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, "
                "host %s:%u belongs to %d groups",
                __LINE__, config_filename, section_name,
                addr->conn.ip_addr, addr->conn.port, count);
        return EEXIST;
    }

    return 0;
}

static int fc_server_set_hosts(FCServerConfig *ctx, FCServerInfo *server,
        const char *config_filename, const char *section_name,
        char **hosts, const int host_count)
{
    int result;
    FCAddressInfo addresses[FC_MAX_SERVER_IP_COUNT];
    FCAddressInfo *addr;
    FCAddressInfo *addr_end;
    char **host;
    char **hend;
    int no_port_count;

    no_port_count = 0;
    addr = addresses;
    hend = hosts + host_count;
    for (host=hosts; host<hend; host++) {
        if ((result=fc_server_set_address(ctx, addr, config_filename,
                        section_name, SERVER_ITEM_HOST_STR, *host, 0)) != 0)
        {
            return result;
        }

        if (addr->conn.port == 0) {
            no_port_count++;
        }
        addr++;
    }

    if ((result=check_server_addresses_duplicate(ctx, config_filename,
                    section_name, addresses, host_count)) != 0)
    {
        return result;
    }

    if (no_port_count > 0 && !ctx->share_between_groups) {
        if ((result=check_group_ports_duplicate(ctx, config_filename)) != 0) {
            return result;
        }
    }

    addr_end = addresses + host_count;
    for (addr=addresses; addr<addr_end; addr++) {
        if ((result=fc_server_set_host(ctx, server, config_filename,
                        section_name, addr)) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int fc_server_load_hosts(FCServerConfig *ctx, FCServerInfo *server,
        const char *config_filename, IniContext *ini_context,
        const char *section_name)
{
    IniItem *items;
    IniItem *it;
    IniItem *end;
    char *hosts[FC_MAX_SERVER_IP_COUNT];
    int item_count;
    int host_count;
    int group_host_count;
    int name_len;
    int result;
    string_t group_name;

    items = iniGetSectionItems(section_name, ini_context, &item_count);
    if (item_count == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, no items!",
                __LINE__, config_filename, section_name);
        return EINVAL;
    }

    fc_server_clear_server_port(&ctx->group_array);

    host_count = group_host_count = 0;
    end = items + item_count;
    for (it=items; it<end; it++) {
        name_len = strlen(it->name);
        if (name_len > SERVER_ITEM_PORT_AFFIX_LEN &&
                memcmp(it->name + name_len - SERVER_ITEM_PORT_AFFIX_LEN,
                    SERVER_ITEM_PORT_AFFIX_STR, SERVER_ITEM_PORT_AFFIX_LEN) == 0)
        {
            group_name.str = it->name;
            group_name.len = name_len - SERVER_ITEM_PORT_AFFIX_LEN;
            if ((result=fc_server_load_group_port(ctx, config_filename,
                            section_name, &group_name, it)) != 0)
            {
                return result;
            }
        } else if (name_len > SERVER_ITEM_HOST_AFFIX_LEN &&
                memcmp(it->name + name_len - SERVER_ITEM_HOST_AFFIX_LEN,
                    SERVER_ITEM_HOST_AFFIX_STR, SERVER_ITEM_HOST_AFFIX_LEN) == 0)
        {
            group_name.str = it->name;
            group_name.len = name_len - SERVER_ITEM_HOST_AFFIX_LEN;
            if ((result=fc_server_load_group_server(ctx, server,
                            config_filename, section_name,
                            &group_name, it)) != 0)
            {
                return result;
            }
            group_host_count++;
        } else if (name_len == SERVER_ITEM_HOST_LEN && memcmp(it->name,
                    SERVER_ITEM_HOST_STR, SERVER_ITEM_HOST_LEN) == 0)
        {
            if (host_count >= FC_MAX_SERVER_IP_COUNT) {
                logError("file: "__FILE__", line: %d, "
                        "config filename: %s, section: %s, "
                        "too many %s items exceeds %d", __LINE__,
                        config_filename, section_name,
                        SERVER_ITEM_HOST_STR, FC_MAX_SERVER_IP_COUNT);
                return ENOSPC;
            }

            hosts[host_count++] = it->value;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, section: %s, unkown item name: %s",
                    __LINE__, config_filename, section_name, it->name);
            return EINVAL;
        }
    }

    if (host_count == 0 && group_host_count == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, no item: %s or *%s!",
                __LINE__, config_filename, section_name,
                SERVER_ITEM_HOST_STR, SERVER_ITEM_HOST_AFFIX_STR);
        return ENOENT;
    }

    if (host_count > 0) {
        if ((result=fc_server_set_hosts(ctx, server, config_filename,
                        section_name, hosts, host_count)) != 0)
        {
            return result;
        }
    }

    if ((result=check_server_group_addresses_duplicate(ctx, server,
                    config_filename, section_name)) != 0)
    {
        return result;
    }

    if (ctx->min_hosts_each_group > 0) {
        if ((result=check_server_group_min_hosts(ctx, server,
                        config_filename, section_name)) != 0)
        {
            return result;
        }
    }
    return 0;
}

static void fc_server_set_group_ptr(FCServerConfig *ctx, FCServerInfo *server)
{
    FCGroupAddresses *gaddr;
    FCGroupAddresses *end;

    end = server->group_addrs + ctx->group_array.count;
    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        gaddr->server_group = ctx->group_array.groups + (gaddr -
                server->group_addrs);
    }
}

static int fc_server_load_one_server(FCServerConfig *ctx,
        const char *config_filename, IniContext *ini_context,
        const char *section_name)
{
    FCServerInfo *server;
    char *endptr;
    int result;

    server = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    endptr = NULL;
    server->id = strtol(section_name + SERVER_SECTION_PREFIX_LEN,
            &endptr, 10);
    if (server->id <= 0 || (endptr != NULL && *endptr != '\0')) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, invalid server id! "
                "server section format is [%s$id]",
                __LINE__, config_filename, section_name,
                SERVER_SECTION_PREFIX_STR);
        return EINVAL;
    }

    fc_server_set_group_ptr(ctx, server);
    if ((result=fc_server_load_hosts(ctx, server, config_filename,
                    ini_context, section_name)) != 0)
    {
        return result;
    }

    FC_SID_SERVER_COUNT(*ctx)++;
    return 0;
}

static int fc_server_load_servers(FCServerConfig *ctx,
        const char *config_filename, IniContext *ini_context)
{
#define FIXED_SECTION_COUNT  16
	int result;
    int section_count;
    int server_count;
    IniSectionInfo *sections;
    IniSectionInfo fixed[FIXED_SECTION_COUNT];
    IniSectionInfo *section;
    IniSectionInfo *end;
	int alloc_bytes;

    section_count = iniGetSectionCountByPrefix(ini_context,
            SERVER_SECTION_PREFIX_STR);
    if (section_count == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, no server section such as [%s$id]",
                __LINE__, config_filename, SERVER_SECTION_PREFIX_STR);
        return ENOENT;
    }

    if (section_count < FIXED_SECTION_COUNT) {
        sections = fixed;
    } else {
        alloc_bytes = sizeof(IniSectionInfo) * section_count;
        sections = (IniSectionInfo *)fc_malloc(alloc_bytes);
        if (sections == NULL) {
            return ENOMEM;
        }
    }

    do {
        if ((result=iniGetSectionNamesByPrefix(ini_context,
                        SERVER_SECTION_PREFIX_STR, sections,
                        section_count, &section_count)) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, get sections by prefix %s fail, "
                    "errno: %d, error info: %s", __LINE__, config_filename,
                    SERVER_SECTION_PREFIX_STR, result, STRERROR(result));
            break;
        }

        end = sections + section_count;
        server_count = 0;
        for (section=sections; section<end; section++) {
            if (is_digital_string(section->section_name +
                        SERVER_SECTION_PREFIX_LEN))
            {
                ++server_count;
            }
        }
        if (server_count == 0) {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, no server section such as [%s$id]",
                    __LINE__, config_filename, SERVER_SECTION_PREFIX_STR);
            return ENOENT;
        }

        if ((result=fc_server_alloc_servers(&ctx->sorted_server_arrays.
                        by_id, server_count)) != 0)
        {
            return result;
        }

        for (section=sections; section<end; section++) {
            if (!is_digital_string(section->section_name +
                        SERVER_SECTION_PREFIX_LEN))
            {
                continue;
            }

            if ((result=fc_server_load_one_server(ctx, config_filename,
                            ini_context, section->section_name)) != 0)
            {
                break;
            }
        }
    } while (0);

    if (sections != fixed) {
        free(sections);
    }

    return result;
}

static int fc_server_load_data(FCServerConfig *ctx,
        IniContext *ini_context, const char *config_filename)
{
	int result;

    if ((result=fc_server_load_groups(ctx, config_filename,
                    ini_context)) != 0)
    {
        return result;
    }

    if ((result=fc_server_load_servers(ctx, config_filename,
                    ini_context)) != 0)
    {
        return result;
    }

	qsort(FC_SID_SERVERS(*ctx), FC_SID_SERVER_COUNT(*ctx),
            sizeof(FCServerInfo), fc_server_cmp_server_id);
    if ((result=fc_server_check_id_duplicated(ctx, config_filename)) != 0) {
        return result;
    }

    if ((result=fc_server_init_ip_port_array(ctx)) != 0) {
        return result;
    }

	return fc_server_check_ip_port(ctx, config_filename);
}

#define FC_SERVER_INIT_CONTEXT(ctx, port, min_hosts, shared) \
    do {  \
        memset(ctx, 0, sizeof(FCServerConfig));  \
        ctx->default_port = port;  \
        ctx->min_hosts_each_group = min_hosts; \
        ctx->share_between_groups = shared; \
    } while (0)

int fc_server_load_from_file_ex(FCServerConfig *ctx,
        const char *config_filename, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups)
{
    IniContext ini_context;
    int result;

    FC_SERVER_INIT_CONTEXT(ctx, default_port, min_hosts_each_group,
            share_between_groups);

    if ((result=iniLoadFromFile1(config_filename, &ini_context,
            FAST_INI_FLAGS_DISABLE_SAME_SECTION_MERGE)) != 0)
    {
        return result;
    }

	result = fc_server_load_data(ctx, &ini_context, config_filename);
    iniFreeContext(&ini_context);
	return result;
}

int fc_server_load_from_buffer_ex(FCServerConfig *ctx, char *content,
        const char *caption, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups)
{
    IniContext ini_context;
    int result;

    FC_SERVER_INIT_CONTEXT(ctx, default_port, min_hosts_each_group,
            share_between_groups);
    if ((result=iniLoadFromBuffer1(content, &ini_context,
            FAST_INI_FLAGS_DISABLE_SAME_SECTION_MERGE)) != 0)
    {
        return result;
    }

	result = fc_server_load_data(ctx, &ini_context, caption);
    iniFreeContext(&ini_context);
	return result;
}

int fc_server_load_from_ini_context_ex(FCServerConfig *ctx,
        IniContext *ini_context, const char *config_filename,
        const int default_port, const int min_hosts_each_group,
        const bool share_between_groups)
{
    FC_SERVER_INIT_CONTEXT(ctx, default_port, min_hosts_each_group,
            share_between_groups);
    return fc_server_load_data(ctx, ini_context, config_filename);
}

static void fc_server_free_addresses(FCServerConfig *ctx)
{
	FCServerInfo *server;
	FCServerInfo *send;
    FCGroupAddresses *gaddr;
    FCGroupAddresses *gend;

    send = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    for (server=FC_SID_SERVERS(*ctx); server<send; server++) {
        gend = server->group_addrs + ctx->group_array.count;
        for (gaddr=server->group_addrs; gaddr<gend; gaddr++) {
            if (gaddr->address_array.addrs != NULL) {
                free(gaddr->address_array.addrs);
                gaddr->address_array.addrs = NULL;
                gaddr->address_array.count = gaddr->address_array.alloc = 0;
            }
        }
        if (server->uniq_addresses.addrs != NULL) {
            free(server->uniq_addresses.addrs);
            server->uniq_addresses.addrs = NULL;
            server->uniq_addresses.count = server->uniq_addresses.alloc = 0;
        }
    }
}

void fc_server_destroy(FCServerConfig *ctx)
{
    if (IP_PORT_MAPS(ctx) != NULL) {
        free(IP_PORT_MAPS(ctx));
        IP_PORT_MAPS(ctx) = NULL;
        IP_PORT_MAP_COUNT(ctx) = 0;
    }

    if (FC_SID_SERVERS(*ctx) != NULL) {
        fc_server_free_addresses(ctx);

        free(FC_SID_SERVERS(*ctx));
        FC_SID_SERVERS(*ctx) = NULL;
        FC_SID_SERVER_COUNT(*ctx) = 0;
    }
}

static FCServerGroupInfo *address_uniq_match_group(FCServerConfig *ctx,
        const FCAddressInfo *addr)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;
    FCServerGroupInfo *matched;

    matched = NULL;
    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        if (fc_server_group_match(group, addr)) {
            if (matched != NULL) {
                return NULL;
            } else {
                matched = group;
            }
        }
    }

    return matched;
}

static int fc_groups_to_string(FCServerConfig *ctx, FastBuffer *buffer)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;
    const char *net_type_caption;
    int result;

    if ((result=fast_buffer_check(buffer, FC_MAX_GROUP_COUNT * 256)) != 0) {
        return result;
    }

    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        net_type_caption = get_net_type_caption(group->filter.net_type);
        if (strcmp(net_type_caption, NET_TYPE_ANY_STR) == 0) {
            net_type_caption = "";
        }

        fast_buffer_append(buffer,
                "[%s%.*s]\n"
                "port = %d\n"
                "net_type = %s\n"
                "ip_prefix = %.*s\n\n",
                GROUP_SECTION_PREFIX_STR,
                group->group_name.len, group->group_name.str,
                group->port, net_type_caption,
                group->filter.ip_prefix.len,
                group->filter.ip_prefix.str);
    }
    return 0;
}

static void fc_group_servers_to_string(FCServerConfig *ctx,
        FCGroupAddresses *gaddr, FastBuffer *buffer)
{
    FCAddressInfo **addr;
    FCAddressInfo **end;

    end = gaddr->address_array.addrs + gaddr->address_array.count;
    for (addr=gaddr->address_array.addrs; addr<end; addr++) {
        if (address_uniq_match_group(ctx, *addr) == gaddr->server_group) {
            fast_buffer_append_buff(buffer, SERVER_ITEM_HOST_STR,
                    SERVER_ITEM_HOST_LEN);
        } else {
            fast_buffer_append(buffer, "%.*s%s",
                    gaddr->server_group->group_name.len,
                    gaddr->server_group->group_name.str,
                    SERVER_ITEM_HOST_AFFIX_STR);
        }
        fast_buffer_append(buffer, " = %s:%u\n",
                (*addr)->conn.ip_addr, (*addr)->conn.port);
    }
}

static int fc_one_server_to_string(FCServerConfig *ctx,
        FCServerInfo *server, FastBuffer *buffer)
{
    FCGroupAddresses *gaddr;
    FCGroupAddresses *end;
    int bytes;
    int result;

    bytes = 32;
    end = server->group_addrs + ctx->group_array.count;
    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        bytes += (IP_ADDRESS_SIZE + 128) * gaddr->address_array.count;
    }

    if ((result=fast_buffer_check(buffer, bytes)) != 0) {
        return result;
    }

    fast_buffer_append(buffer, "[%s%d]\n",
            SERVER_SECTION_PREFIX_STR, server->id);

    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        fc_group_servers_to_string(ctx, gaddr, buffer);
    }

    fast_buffer_append_buff(buffer, "\n", 1);
    return 0;
}

static int fc_servers_to_string(FCServerConfig *ctx, FastBuffer *buffer)
{
    FCServerInfo *server;
    FCServerInfo *end;
    int result;

    end = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    for (server=FC_SID_SERVERS(*ctx); server<end; server++) {
        if ((result=fc_one_server_to_string(ctx, server, buffer)) != 0) {
            return result;
        }
    }

    return 0;
}

int fc_server_to_config_string(FCServerConfig *ctx, FastBuffer *buffer)
{
    int result;

    fc_server_clear_server_port(&ctx->group_array);
    if ((result=fc_groups_to_string(ctx, buffer)) != 0) {
        return result;
    }

    return fc_servers_to_string(ctx, buffer);
}

static void fc_server_log_groups(FCServerConfig *ctx)
{
    FCServerGroupInfo *group;
    FCServerGroupInfo *end;

    end = ctx->group_array.groups + ctx->group_array.count;
    for (group=ctx->group_array.groups; group<end; group++) {
        logInfo("group_name: %.*s, port: %d, net_type: %s, ip_prefix: %.*s",
                group->group_name.len, group->group_name.str, group->port,
                get_net_type_caption(group->filter.net_type),
                group->filter.ip_prefix.len, group->filter.ip_prefix.str);
    }
}

static void fc_server_log_group_servers(FCGroupAddresses *gaddr)
{
    FCAddressInfo **addr;
    FCAddressInfo **end;

    end = gaddr->address_array.addrs + gaddr->address_array.count;
    for (addr=gaddr->address_array.addrs; addr<end; addr++) {
        logInfo("    %d. %s:%u", (int)(addr - gaddr->address_array.addrs + 1),
                (*addr)->conn.ip_addr, (*addr)->conn.port);
    }
}

static void fc_server_log_one_server(FCServerConfig *ctx, FCServerInfo *server)
{
    FCGroupAddresses *gaddr;
    FCGroupAddresses *end;

    logInfo("server id: %d", server->id);

    end = server->group_addrs + ctx->group_array.count;
    for (gaddr=server->group_addrs; gaddr<end; gaddr++) {
        logInfo("[group-%.*s] ip count: %d", FC_PRINTF_STAR_STRING_PARAMS(
                    gaddr->server_group->group_name),
                gaddr->address_array.count);
        fc_server_log_group_servers(gaddr);
    }
    logInfo(" ");
}

static void fc_server_log_servers(FCServerConfig *ctx)
{
    FCServerInfo *server;
    FCServerInfo *end;

    logInfo("server count: %d, unique ip and port count: %d",
            FC_SID_SERVER_COUNT(*ctx),
            IP_PORT_MAP_COUNT(ctx));

    end = FC_SID_SERVERS(*ctx) + FC_SID_SERVER_COUNT(*ctx);
    for (server=FC_SID_SERVERS(*ctx); server<end; server++) {
        fc_server_log_one_server(ctx, server);
    }
}

void fc_server_to_log(FCServerConfig *ctx)
{
    fc_server_log_groups(ctx);
    fc_server_log_servers(ctx);
}

ConnectionInfo *fc_server_check_connect_ex(FCAddressPtrArray *addr_array,
        const int connect_timeout, const char *bind_ipaddr,
        const bool log_connect_error, int *err_no)
{
    FCAddressInfo **current;
    FCAddressInfo **addr;
    FCAddressInfo **end;

    if (addr_array->count <= 0) {
        *err_no = ENOENT;
        return NULL;
    }

    current = addr_array->addrs + addr_array->index;
    if ((*current)->conn.sock >= 0) {
        return &(*current)->conn;
    }

    if ((*err_no=conn_pool_connect_server_ex(&(*current)->conn,
                    connect_timeout, bind_ipaddr, log_connect_error)) == 0)
    {
        return &(*current)->conn;
    }

    if (addr_array->count == 1) {
        return NULL;
    }

    end = addr_array->addrs + addr_array->count;
    for (addr=addr_array->addrs; addr<end; addr++) {
        if (addr == current) {
            continue;
        }
        if ((*err_no=conn_pool_connect_server_ex(&(*addr)->conn,
                        connect_timeout, bind_ipaddr,
                        log_connect_error)) == 0)
        {
            addr_array->index = addr - addr_array->addrs;
            return &(*addr)->conn;
        }
    }

    return NULL;
}

void fc_server_disconnect(FCAddressPtrArray *addr_array)
{
    FCAddressInfo **current;

    current = addr_array->addrs + addr_array->index;
    if ((*current)->conn.sock >= 0) {
        close((*current)->conn.sock);
        (*current)->conn.sock = -1;
    }
}

int fc_server_make_connection_ex(FCAddressPtrArray *addr_array,
        ConnectionInfo *conn, const int connect_timeout,
        const char *bind_ipaddr, const bool log_connect_error)
{
    FCAddressInfo **current;
    FCAddressInfo **addr;
    FCAddressInfo **end;
    int result;

    if (addr_array->count <= 0) {
        return ENOENT;
    }

    current = addr_array->addrs + addr_array->index;
    *conn = (*current)->conn;
    conn->sock = -1;
    if ((result=conn_pool_connect_server_ex(conn, connect_timeout,
                    bind_ipaddr, log_connect_error)) == 0)
    {
        return 0;
    }

    if (addr_array->count == 1) {
        return result;
    }

    end = addr_array->addrs + addr_array->count;
    for (addr=addr_array->addrs; addr<end; addr++) {
        if (addr == current) {
            continue;
        }

        *conn = (*addr)->conn;
        conn->sock = -1;
        if ((result=conn_pool_connect_server_ex(conn, connect_timeout,
                        bind_ipaddr, log_connect_error)) == 0)
        {
            addr_array->index = addr - addr_array->addrs;
            return 0;
        }
    }

    return result;
}

const FCAddressInfo *fc_server_get_address_by_peer(
        FCAddressPtrArray *addr_array, const char *peer_ip)
{
    FCAddressInfo **addr;
    FCAddressInfo **end;
    int net_type;

    if (addr_array->count == 1) {
        return *(addr_array->addrs);
    }
    if (addr_array->count == 0) {
        return NULL;
    }

    net_type = fc_get_net_type_by_ip(peer_ip);
    end = addr_array->addrs + addr_array->count;
    for (addr=addr_array->addrs; addr<end; addr++) {
        if ((*addr)->net_type == net_type) {
            return *addr;
        }
    }

    return *(addr_array->addrs);
}
