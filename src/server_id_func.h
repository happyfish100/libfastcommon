//server_id_func.h

#ifndef _SERVER_ID_FUNC_H
#define _SERVER_ID_FUNC_H 

#include "common_define.h"
#include "connection_pool.h"
#include "ini_file_reader.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FC_MAX_SERVER_IP_COUNT  8
#define FC_MAX_GROUP_COUNT      4

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
    FCAddressArray address_array;
} FCGroupAddresses;

typedef struct
{
	int id;  //server id
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
        FCServerInfoArray by_id;    //sorted by server id
        FCServerMapArray by_ip_port; //sorted by IP and port
    } sorted_server_arrays;
} FCServerContext;

FCServerInfo *fc_server_get_by_id(FCServerContext *ctx,
        const int server_id);

FCServerInfo *fc_server_get_by_ip_port_ex(FCServerContext *ctx,
        const string_t *ip_addr, const int port);

static inline FCServerInfo *fc_server_get_by_ip_port(FCServerContext *ctx,
        const char *ip_addr, const int port)
{
    string_t saddr;
    FC_SET_STRING(saddr, (char *)ip_addr);
    return fc_server_get_by_ip_port_ex(ctx, &saddr, port);
}

FCServerGroupInfo *fc_server_get_group_by_name(FCServerContext *ctx,
        const string_t *group_name);

static inline int fc_server_get_group_index_ex(FCServerContext *ctx,
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

static inline int fc_server_get_group_index(FCServerContext *ctx,
        const char *group_name)
{
    string_t gname;
    FC_SET_STRING(gname, (char *)group_name);
    return fc_server_get_group_index_ex(ctx, &gname);
}

int fc_server_load_from_file_ex(FCServerContext *ctx,
        const char *config_filename, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups);

static inline int fc_server_load_from_file(FCServerContext *ctx,
        const char *config_filename)
{
    const int default_port = 0;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = false;
    return fc_server_load_from_file_ex(ctx, config_filename,
            default_port, min_hosts_each_group, share_between_groups);
}

int fc_server_load_from_buffer_ex(FCServerContext *ctx, char *content,
        const char *caption, const int default_port,
        const int min_hosts_each_group, const bool share_between_groups);

static inline int fc_server_load_from_buffer(FCServerContext *ctx,
        char *content)
{
    const char *caption = "from-buffer";
    const int default_port = 0;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = false;
    return fc_server_load_from_buffer_ex(ctx, content, caption,
            default_port, min_hosts_each_group, share_between_groups);
}

void fc_server_destroy(FCServerContext *ctx);

void fc_server_to_log(FCServerContext *ctx);

#ifdef __cplusplus
}
#endif

#endif

