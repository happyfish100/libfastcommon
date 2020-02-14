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

#define SERVER_ITEM_HOST_STR        "host"
#define SERVER_ITEM_HOST_LEN        (sizeof(SERVER_ITEM_HOST_STR) - 1)

#define SERVER_ITEM_PORT_AFFIX_STR  "-port"
#define SERVER_ITEM_PORT_AFFIX_LEN  (sizeof(SERVER_ITEM_PORT_AFFIX_STR) - 1)

#define NET_TYPE_OUTER_STR          "outer"
#define NET_TYPE_INNER_STR          "inner"

#define SUB_NET_TYPE_INNER_10_STR1  "inner-10"
#define SUB_NET_TYPE_INNER_172_STR1 "inner-172"
#define SUB_NET_TYPE_INNER_192_STR1 "inner-192"

#define SUB_NET_TYPE_INNER_10_STR2  "inner_10"
#define SUB_NET_TYPE_INNER_172_STR2 "inner_172"
#define SUB_NET_TYPE_INNER_192_STR2 "inner_192"

#define SUB_NET_TYPE_INNER_10_STR3  "inner10"
#define SUB_NET_TYPE_INNER_172_STR3 "inner172"
#define SUB_NET_TYPE_INNER_192_STR3 "inner192"

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

FCServerInfo *fc_server_get_by_id(FCServerContext *ctx,
        const int server_id)
{
	FCServerInfo target;

	target.id = server_id;
	return (FCServerInfo *)bsearch(&target,
            ctx->sorted_server_arrays.by_id.servers,
            ctx->sorted_server_arrays.by_id.count,
            sizeof(FCServerInfo), fc_server_cmp_server_id);
}

static int fc_server_calc_ip_port_count(FCServerContext *ctx)
{
	FCServerInfo *server;
	FCServerInfo *send;
    FCGroupAddresses *gaddr;
    FCGroupAddresses *gend;
    int count;

    count = 0;
    send = ctx->sorted_server_arrays.by_id.servers +
        ctx->sorted_server_arrays.by_id.count;
    for (server=ctx->sorted_server_arrays.by_id.servers;
            server<send; server++)
    {
        gend = server->group_array.group_addrs + server->group_array.count;
        for (gaddr=server->group_array.group_addrs; gaddr<gend; gaddr++) {
            count += gaddr->address_array.count;
        }
    }

    return count;
}

static int fc_server_init_ip_port_array(FCServerContext *ctx)
{
	int result;
	int alloc_bytes;
    int i;
    FCServerMapArray *map_array;
    FCServerMap *map;
	FCServerInfo *server;
	FCServerInfo *send;
    FCGroupAddresses *gaddr;
    FCGroupAddresses *gend;

    map_array = &ctx->sorted_server_arrays.by_ip_port;

    map_array->count = fc_server_calc_ip_port_count(ctx);
    alloc_bytes = sizeof(FCServerMap) * map_array->count;
    map_array->maps = (FCServerMap *)malloc(alloc_bytes);
    if (map_array->maps == NULL) {
        result = errno != 0 ? errno : ENOMEM;
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail, "
                "errno: %d, error info: %s", __LINE__,
                alloc_bytes, result, STRERROR(result));
        return result;
    }
    memset(map_array->maps, 0, alloc_bytes);

    send = ctx->sorted_server_arrays.by_id.servers +
        ctx->sorted_server_arrays.by_id.count;
    map = map_array->maps;
    for (server=ctx->sorted_server_arrays.by_id.servers;
            server<send; server++)
    {
        gend = server->group_array.group_addrs + server->group_array.count;
        for (gaddr=server->group_array.group_addrs; gaddr<gend; gaddr++) {
            for (i=0; i<gaddr->address_array.count; i++) {
                map->server = server;
                FC_SET_STRING(map->ip_addr, gaddr->address_array.
                        addrs[i].conn.ip_addr);
                map->port = gaddr->address_array.addrs[i].conn.port;
                map++;
            }
        }
    }

    qsort(map_array->maps, map_array->count, sizeof(FCServerMap),
            fc_server_cmp_ip_and_port);
    return 0;
}

static int fc_server_check_id_duplicated(FCServerContext *ctx,
        const char *config_filename)
{
    FCServerInfo *previous;
	FCServerInfo *current;
	FCServerInfo *send;

    previous = ctx->sorted_server_arrays.by_id.servers + 0;
    send = ctx->sorted_server_arrays.by_id.servers +
        ctx->sorted_server_arrays.by_id.count;
    for (current=ctx->sorted_server_arrays.by_id.servers + 1;
            current<send; current++)
    {
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

static int fc_server_check_ip_port(FCServerContext *ctx,
        const char *config_filename)
{
    FCServerMap *previous;
    FCServerMap *current;
    FCServerMap *end;

    previous = ctx->sorted_server_arrays.by_ip_port.maps + 0;
    end = ctx->sorted_server_arrays.by_ip_port.maps +
        ctx->sorted_server_arrays.by_ip_port.count;
    for (current=ctx->sorted_server_arrays.by_ip_port.maps+1;
            current<end; current++)
    {
        if (fc_server_cmp_ip_and_port(current, previous) == 0) {
            logError("file: "__FILE__", line: %d, "
                    "config file: %s, duplicate ip:port %s:%d, "
                    "the server ids are %d and %d", __LINE__,
                    config_filename, previous->ip_addr.str, previous->port,
                    previous->server->id, current->server->id);

            return EEXIST;
        }

        previous = current;
    }

    return 0;
}

FCServerInfo *fc_server_get_by_ip_port_ex(FCServerContext *ctx,
        const string_t *ip_addr, const int port)
{
    FCServerMap target;
    FCServerMap *found;

    target.ip_addr = *ip_addr;
    target.port = port;
    found = (FCServerMap *)bsearch(&target,
            ctx->sorted_server_arrays.by_ip_port.maps,
            ctx->sorted_server_arrays.by_ip_port.count,
            sizeof(FCServerMap), fc_server_cmp_ip_and_port);
    if (found != NULL) {
        return found->server;
    }

    return NULL;
}

static inline void fc_server_set_group_name(FCServerGroupInfo *ginfo,
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

static int fc_server_set_net_type(const char *config_filename,
        FCServerGroupInfo *ginfo, const char *net_type)
{
    if (net_type == NULL || *net_type == '\0') {
        ginfo->filter.net_type = FC_NET_TYPE_NONE;
        return 0;
    }

    if (strcasecmp(net_type, NET_TYPE_OUTER_STR) == 0) {
        ginfo->filter.net_type = FC_NET_TYPE_OUTER;
    } else if (strcasecmp(net_type, NET_TYPE_INNER_STR) == 0) {
        ginfo->filter.net_type = FC_NET_TYPE_INNER;
    } else if (strcasecmp(net_type, SUB_NET_TYPE_INNER_10_STR1) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_10_STR2) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_10_STR3) == 0)
    {
        ginfo->filter.net_type = FC_SUB_NET_TYPE_INNER_10;
    } else if (strcasecmp(net_type, SUB_NET_TYPE_INNER_172_STR1) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_172_STR2) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_172_STR3) == 0)
    {
        ginfo->filter.net_type = FC_SUB_NET_TYPE_INNER_172;
    } else if (strcasecmp(net_type, SUB_NET_TYPE_INNER_192_STR1) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_192_STR2) == 0 ||
            strcasecmp(net_type, SUB_NET_TYPE_INNER_192_STR3) == 0)
    {
        ginfo->filter.net_type = FC_SUB_NET_TYPE_INNER_192;
    } else {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, invalid net_type: %s",
                __LINE__, config_filename, ginfo->group_name.str, net_type);
        return EINVAL;
    }

    return 0;
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

static int fc_server_load_one_group(FCServerContext *ctx,
        const char *config_filename, IniContext *ini_context,
        const char *section_name)
{
    FCServerGroupInfo *current;
    char new_name[FAST_INI_ITEM_NAME_SIZE];
    char *net_type;
    char *ip_prefix;
    int result;

    strcpy(new_name, section_name);
    current = ctx->group_array.groups + ctx->group_array.count;
    fc_server_set_group_name(current, new_name + GROUP_SECTION_PREFIX_LEN);

    if (current->group_name.len == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, no group name!",
                __LINE__, config_filename, section_name);
        return EINVAL;
    }

    current->port = iniGetIntValue(section_name, "port",
            ini_context, ctx->default_port);

    net_type = iniGetStrValue(section_name, "net_type", ini_context);
    if ((result=fc_server_set_net_type(config_filename,
                    current, net_type)) != 0)
    {
        return result;
    }

    ip_prefix = iniGetStrValue(section_name, "ip_prefix", ini_context);
    fc_server_set_ip_prefix(current, ip_prefix);

    ctx->group_array.count++;
    return 0;
}

static int fc_server_load_groups(FCServerContext *ctx,
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
        fc_server_set_group_name(ctx->group_array.groups + 0, "");
        ctx->group_array.groups[0].port = iniGetIntValue(NULL, "port",
            ini_context, ctx->default_port);
        return 0;
    }

    end = sections + count;
    for (section=sections; section<end; section++) {
        if ((result=fc_server_load_one_group(ctx, config_filename,
                        ini_context, section->section_name)) != 0)
        {
            return result;
        }
    }

    return 0;
}

static int fc_server_check_alloc_servers(FCServerInfoArray *array)
{
    int new_alloc;
    int bytes;
    FCServerInfo *new_servers;

    if (array->count < array->alloc) {
        return 0;
    }

    new_alloc = array->alloc > 0 ? 2 * array->alloc : 2;
    bytes = sizeof(FCServerInfo) * new_alloc;
    new_servers = (FCServerInfo *)malloc(bytes);
    if (new_servers == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    if (array->servers != NULL) {
        memcpy(new_servers, array->servers,
                sizeof(FCServerInfo) * array->count);
        free(array->servers);
    }

    array->servers = new_servers;
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

static int fc_server_load_group_port(FCServerContext *ctx,
        const string_t *group_name, char *port_str)
{
    //TODO
    return 0;
}

static int fc_server_load_hosts(FCServerContext *ctx, FCServerInfo *server,
        const char *config_filename, IniContext *ini_context,
        const char *section_name)
{
    IniItem *items;
    IniItem *it;
    IniItem *end;
    char *hosts[FC_MAX_SERVER_IP_COUNT];
    int item_count;
    int host_count;
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

    host_count = 0;
    end = items + item_count;
    for (it=items; it<end; it++) {
        name_len = strlen(it->name);
        if (name_len > SERVER_ITEM_PORT_AFFIX_LEN &&
                memcmp(it->name + name_len - SERVER_ITEM_PORT_AFFIX_LEN,
                    SERVER_ITEM_PORT_AFFIX_STR, SERVER_ITEM_PORT_AFFIX_LEN) == 0)
        {
            group_name.str = it->name;
            group_name.len = name_len - SERVER_ITEM_PORT_AFFIX_LEN;
            if ((result=fc_server_load_group_port(ctx,
                            &group_name, it->value)) != 0)
            {
                return result;
            }
        } else if (name_len > SERVER_ITEM_HOST_LEN && memcmp(it->name,
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

    if (host_count == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, no item: %s!",
                __LINE__, config_filename, section_name,
                SERVER_ITEM_HOST_STR);
        return ENOENT;
    }

    /*
inner-port = 5106
outer-port = 5107

    current->port = iniGetIntValue(section_name, "port",
            ini_context, ctx->default_port);

    */

    return 0;
}

static int fc_server_load_one_server(FCServerContext *ctx,
        const char *config_filename, IniContext *ini_context,
        const char *section_name)
{
    FCServerInfo *current;
    char *endptr;
    int result;

    if ((result=fc_server_check_alloc_servers(&ctx->
                    sorted_server_arrays.by_id)) != 0)
    {
        return result;
    }

    current = ctx->sorted_server_arrays.by_id.servers +
        ctx->sorted_server_arrays.by_id.count;

    endptr = NULL;
    current->id = strtol(section_name + SERVER_SECTION_PREFIX_LEN, &endptr, 10);
    if (current->id <= 0 || endptr != NULL) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, section: %s, invalid server id! "
                "server section format is [%s$id]",
                __LINE__, config_filename, section_name,
                SERVER_SECTION_PREFIX_STR);
        return EINVAL;
    }

    if ((result=fc_server_load_hosts(ctx, current, config_filename,
                    ini_context, section_name)) != 0)
    {
        return result;
    }

    ctx->sorted_server_arrays.by_id.count++;
    return 0;
}

static int fc_server_load_servers(FCServerContext *ctx,
        const char *config_filename, IniContext *ini_context)
{
#define FIXED_SECTION_COUNT  16
	int result;
    int count;
    IniSectionInfo *sections;
    IniSectionInfo fixed[FIXED_SECTION_COUNT];
    IniSectionInfo *section;
    IniSectionInfo *end;
	int alloc_bytes;

    count = iniGetSectionCountByPrefix(ini_context, SERVER_SECTION_PREFIX_STR);
    if (count == 0) {
        logError("file: "__FILE__", line: %d, "
                "config filename: %s, no server section such as [%s$id]",
                __LINE__, config_filename, SERVER_SECTION_PREFIX_STR);
        return ENOENT;
    }

    if (count < FIXED_SECTION_COUNT) {
        sections = fixed;
    } else {
        alloc_bytes = sizeof(IniSectionInfo) * count;
        sections = (IniSectionInfo *)malloc(alloc_bytes);
        if (sections == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, alloc_bytes);
            return ENOMEM;
        }
    }

    do {
        if ((result=iniGetSectionNamesByPrefix(ini_context,
                        SERVER_SECTION_PREFIX_STR, sections,
                        count, &count)) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "config filename: %s, get sections by prefix %s fail, "
                    "errno: %d, error info: %s", __LINE__, config_filename,
                    SERVER_SECTION_PREFIX_STR, result, STRERROR(result));
            break;
        }

        end = sections + count;
        for (section=sections; section<end; section++) {
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

int fc_server_load_data(FCServerContext *ctx, IniContext *ini_context,
        const char *config_filename)
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

	qsort(ctx->sorted_server_arrays.by_id.servers,
            ctx->sorted_server_arrays.by_id.count,
            sizeof(FCServerInfo), fc_server_cmp_server_id);
    if ((result=fc_server_check_id_duplicated(ctx, config_filename)) != 0) {
        return result;
    }

    if ((result=fc_server_init_ip_port_array(ctx)) != 0) {
        return result;
    }

	return fc_server_check_ip_port(ctx, config_filename);
}

#define FC_SERVER_INIT_CONTEXT(ctx, port) \
    do {  \
        memset(ctx, 0, sizeof(FCServerContext));  \
        ctx->default_port = port;  \
    } while (0)

int fc_server_load_from_file_ex(FCServerContext *ctx,
        const char *config_filename, const int default_port)
{
    IniContext ini_context;
    int result;

    FC_SERVER_INIT_CONTEXT(ctx, default_port);
    if ((result=iniLoadFromFile(config_filename, &ini_context)) != 0) {
        return result;
    }

	result = fc_server_load_data(ctx, &ini_context, config_filename);
    iniFreeContext(&ini_context);
	return result;
}

int fc_server_load_from_buffer_ex(FCServerContext *ctx, char *content,
        const char *caption, const int default_port)
{
    IniContext ini_context;
    int result;

    FC_SERVER_INIT_CONTEXT(ctx, default_port);
    if ((result=iniLoadFromBuffer(content, &ini_context)) != 0) {
        return result;
    }

	result = fc_server_load_data(ctx, &ini_context, caption);
    iniFreeContext(&ini_context);
	return result;
}

void fc_server_destroy(FCServerContext *ctx)
{
    if (ctx->sorted_server_arrays.by_ip_port.maps != NULL) {
        free(ctx->sorted_server_arrays.by_ip_port.maps);
        ctx->sorted_server_arrays.by_ip_port.maps = NULL;
        ctx->sorted_server_arrays.by_ip_port.count = 0;
    }

    if (ctx->sorted_server_arrays.by_id.servers != NULL) {
        free(ctx->sorted_server_arrays.by_id.servers);
        ctx->sorted_server_arrays.by_id.servers = NULL;
        ctx->sorted_server_arrays.by_id.count = 0;
    }
}
