#include "php7_ext_wrapper.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "ext/standard/flock_compat.h"
#include <zend_extensions.h>
#include <zend_exceptions.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include "common_define.h"
#include "local_ip_func.h"
#include "logger.h"
#include "hash.h"
#include "sockopt.h"
#include "shared_func.h"
#include "id_generator.h"
#include "system_info.h"
#include "fastcommon.h"

#define MAJOR_VERSION  1
#define MINOR_VERSION  0
#define PATCH_VERSION  8

#define PHP_IDG_RESOURCE_NAME "fastcommon_idg"
#define DEFAULT_SN_FILENAME  "/tmp/fastcommon_id_generator.sn"

typedef struct {
    struct idg_context idg_context;
} PHPIDGContext;

static int le_consumer;

static PHPIDGContext *last_idg_context = NULL;

typedef struct {
    int alloc;
    int count;
    LogContext *contexts;
} PHPLoggerArray;

typedef struct {
    char *filename;
    int fd;
} PHPFileContext;

typedef struct {
    int alloc;
    int count;
    PHPFileContext *contexts;
} PHPFileArray;

static PHPLoggerArray logger_array = {0, 0, NULL};
static PHPFileArray file_array = {0, 0, NULL};
static zval php_error_log;
static zval php_file_put_contents;
static zval *error_log_func = NULL;
static zval *file_put_contents_func = NULL;

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
const zend_fcall_info empty_fcall_info = { 0, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0 };
#undef ZEND_BEGIN_ARG_INFO_EX
#define ZEND_BEGIN_ARG_INFO_EX(name, pass_rest_by_reference, return_reference, required_num_args) \
    static zend_arg_info name[] = {                                                               \
        { NULL, 0, NULL, 0, 0, 0, pass_rest_by_reference, return_reference, required_num_args },
#endif

// Every user visible function must have an entry in fastcommon_functions[].
	zend_function_entry fastcommon_functions[] = {
		ZEND_FE(fastcommon_version, NULL)
		ZEND_FE(fastcommon_gethostaddrs, NULL)
		ZEND_FE(fastcommon_time33_hash, NULL)
		ZEND_FE(fastcommon_simple_hash, NULL)
		ZEND_FE(fastcommon_get_line_distance_km, NULL)
		ZEND_FE(fastcommon_get_first_local_ip, NULL)
		ZEND_FE(fastcommon_get_next_local_ip, NULL)
		ZEND_FE(fastcommon_is_private_ip, NULL)
		ZEND_FE(fastcommon_id_generator_init, NULL)
		ZEND_FE(fastcommon_id_generator_next, NULL)
		ZEND_FE(fastcommon_id_generator_get_extra, NULL)
		ZEND_FE(fastcommon_id_generator_get_timestamp, NULL)
		ZEND_FE(fastcommon_id_generator_destroy, NULL)
		ZEND_FE(fastcommon_get_ifconfigs, NULL)
		ZEND_FE(fastcommon_get_cpu_count, NULL)
		ZEND_FE(fastcommon_get_sysinfo, NULL)
		ZEND_FE(fastcommon_error_log, NULL)
		ZEND_FE(fastcommon_file_put_contents, NULL)
		{NULL, NULL, NULL}  /* Must be the last line */
	};

zend_module_entry fastcommon_module_entry = {
	STANDARD_MODULE_HEADER,
	"fastcommon",
	fastcommon_functions,
	PHP_MINIT(fastcommon),
	PHP_MSHUTDOWN(fastcommon),
	NULL,//PHP_RINIT(fastcommon),
	NULL,//PHP_RSHUTDOWN(fastcommon),
	PHP_MINFO(fastcommon),
	"1.08",
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_FASTCOMMON
	ZEND_GET_MODULE(fastcommon)
#endif

ZEND_RSRC_DTOR_FUNC(id_generator_dtor)
{
#if PHP_MAJOR_VERSION < 7
    if (rsrc->ptr != NULL)
    {
        PHPIDGContext *php_idg_context = (PHPIDGContext *)rsrc->ptr;
        id_generator_destroy(&php_idg_context->idg_context);
        if (last_idg_context == php_idg_context)
        {
            last_idg_context = NULL;
        }
        efree(php_idg_context);
        rsrc->ptr = NULL;
    }
#else
    if (res->ptr != NULL)
    {
        PHPIDGContext *php_idg_context = (PHPIDGContext *)res->ptr;
        id_generator_destroy(&php_idg_context->idg_context);
        if (last_idg_context == php_idg_context)
        {
            last_idg_context = NULL;
        }
        efree(php_idg_context);
        res->ptr = NULL;
    }
#endif

}

#define FASTCOMMON_REGISTER_CHAR_STR_CONSTANT(key, c, buff) \
    *(buff) = c;   \
    REGISTER_STRING_CONSTANT(key, buff, CONST_CS | CONST_PERSISTENT)

PHP_MINIT_FUNCTION(fastcommon)
{
    static char buff[16];

    log_init();
    le_consumer = zend_register_list_destructors_ex(id_generator_dtor, NULL,
            PHP_IDG_RESOURCE_NAME, module_number);

    memset(buff, 0, sizeof(buff));
    FASTCOMMON_REGISTER_CHAR_STR_CONSTANT("FASTCOMMON_LOG_TIME_PRECISION_SECOND",
            LOG_TIME_PRECISION_SECOND, buff);
    FASTCOMMON_REGISTER_CHAR_STR_CONSTANT("FASTCOMMON_LOG_TIME_PRECISION_MSECOND",
            LOG_TIME_PRECISION_MSECOND, buff + 2);
    FASTCOMMON_REGISTER_CHAR_STR_CONSTANT("FASTCOMMON_LOG_TIME_PRECISION_USECOND",
            LOG_TIME_PRECISION_USECOND, buff + 4);
    FASTCOMMON_REGISTER_CHAR_STR_CONSTANT("FASTCOMMON_LOG_TIME_PRECISION_NONE",
            LOG_TIME_PRECISION_NONE, buff + 6);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(fastcommon)
{
    if (logger_array.count > 0) {
        LogContext *lctx;
        LogContext *lend;
        lend = logger_array.contexts + logger_array.count;
        for (lctx=logger_array.contexts; lctx<lend; lctx++) {
            log_destroy_ex(lctx);
        }
    }

    if (file_array.count > 0) {
        PHPFileContext *fctx;
        PHPFileContext *fend;
        fend = file_array.contexts + file_array.count;
        for (fctx=file_array.contexts; fctx<fend; fctx++) {
            if (fctx->fd >= 0) {
                close(fctx->fd);
                fctx->fd = -1;
            }
        }
    }

	log_destroy();
	return SUCCESS;
}

PHP_RINIT_FUNCTION(fastcommon)
{
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(fastcommon)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(fastcommon)
{
	char mc_info[64];
	sprintf(mc_info, "fastcommon v%d.%02d support", 
		MAJOR_VERSION, MINOR_VERSION);

	php_info_print_table_start();
	php_info_print_table_header(2, mc_info, "enabled");
	php_info_print_table_end();
}

/*
string fastcommon_version()
return client library version
*/
ZEND_FUNCTION(fastcommon_version)
{
	char szVersion[16];
	int len;

	len = sprintf(szVersion, "%d.%d.%d",
		MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);

	ZEND_RETURN_STRINGL(szVersion, len, 1);
}

/*
array fastcommon_gethostaddrs([string if_alias_prefix]);
return false for fail, array for success
*/
ZEND_FUNCTION(fastcommon_gethostaddrs)
{
	int argc;
    char *if_alias_prefix;
    zend_size_t if_prefix_len;
	int count;
    int uniq_count;
    int i;
	int k;
	int alias_count;
	char ip_addresses[FAST_MAX_LOCAL_IP_ADDRS][IP_ADDRESS_SIZE];
	char *uniq_ips[FAST_MAX_LOCAL_IP_ADDRS];
	char *if_alias_prefixes[1];

	argc = ZEND_NUM_ARGS();
	if (argc > 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_gethostaddrs parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	if_alias_prefix = NULL;
	if_prefix_len = 0;
	if (zend_parse_parameters(argc TSRMLS_CC, "|s", &if_alias_prefix,
                &if_prefix_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}


	if (if_alias_prefix == NULL || if_prefix_len == 0) {
		alias_count = 0;
        if_alias_prefixes[0] = NULL;
	}
	else
	{
		alias_count = 1;
        if_alias_prefixes[0] = if_alias_prefix;
	}

    count = 0;
	if (gethostaddrs(if_alias_prefixes, alias_count, ip_addresses,
			FAST_MAX_LOCAL_IP_ADDRS, &count) != 0)
	{
		RETURN_BOOL(false);
	}

    uniq_count = 0;
	for (k=0; k<count; k++) {
        for (i=0; i<uniq_count; i++) {
            if (strcmp(ip_addresses[k], uniq_ips[i]) == 0) {
                break;
            }
        }

        if (i == uniq_count) {  //not found
            uniq_ips[uniq_count++] = ip_addresses[k];
        }
	}

	array_init(return_value);
	for (k=0; k<uniq_count; k++) {
		zend_add_index_string(return_value, k, uniq_ips[k], 1);
	}
}

/*
long fastcommon_time33_hash(string str)
return unsigned hash code
*/
ZEND_FUNCTION(fastcommon_time33_hash)
{
	int argc;
    char *str;
    zend_size_t str_len;

	argc = ZEND_NUM_ARGS();
	if (argc != 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_time33_hash parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	str = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "s", &str,
                &str_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    RETURN_LONG(Time33Hash(str, str_len) & 0x7FFFFFFF);
}

/*
long fastcommon_simple_hash(string str)
return unsigned hash code
*/
ZEND_FUNCTION(fastcommon_simple_hash)
{
	int argc;
    char *str;
    zend_size_t str_len;

	argc = ZEND_NUM_ARGS();
	if (argc != 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_simple_hash parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    str = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "s", &str,
                &str_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    RETURN_LONG(simple_hash(str, str_len) & 0x7FFFFFFF);
}

/*
double fastcommon_get_line_distance_km(double lat1, double lon1,
        double lat2, double lon2)
return line distance in KM
*/
ZEND_FUNCTION(fastcommon_get_line_distance_km)
{
	int argc;
    double lat1;
    double lon1;
    double lat2;
    double lon2;

	argc = ZEND_NUM_ARGS();
	if (argc != 4) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_line_distance_km parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	if (zend_parse_parameters(argc TSRMLS_CC, "dddd", &lat1, &lon1,
                &lat2, &lon2) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    RETURN_DOUBLE(get_line_distance_km(lat1, lon1, lat2, lon2));
}

/*
string fastcommon_get_first_local_ip()
return the first local ip
*/
ZEND_FUNCTION(fastcommon_get_first_local_ip)
{
	int argc;

	argc = ZEND_NUM_ARGS();
	if (argc != 0) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_first_local_ip parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	ZEND_RETURN_STRING(get_first_local_ip(), 1);
}

/*
string fastcommon_get_next_local_ip(string previous_ip)
return the next local ip, false for fail
*/
ZEND_FUNCTION(fastcommon_get_next_local_ip)
{
	int argc;
    zend_size_t previous_len;
    char *previous_ip;
    const char *next_ip;

	argc = ZEND_NUM_ARGS();
	if (argc != 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_next_local_ip parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	if (zend_parse_parameters(argc TSRMLS_CC, "s", &previous_ip,
                &previous_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    if (previous_len == 0)
    {
        previous_ip = NULL;
    }
    next_ip = get_next_local_ip(previous_ip);
    if (next_ip == NULL)
    {
		RETURN_BOOL(false);
    }

    ZEND_RETURN_STRING(next_ip , 1);
}

/*
string fastcommon_is_private_ip(string ip)
return true for private ip, otherwise false
*/
ZEND_FUNCTION(fastcommon_is_private_ip)
{
    int argc;
    zend_size_t ip_len;
    char *ip;

	argc = ZEND_NUM_ARGS();
	if (argc != 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_is_private_ip parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	if (zend_parse_parameters(argc TSRMLS_CC, "s", &ip,
                &ip_len) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    RETURN_BOOL(is_private_ip(ip));
}

/*
resource fastcommon_id_generator_init([string filename = "/tmp/fastcommon_id_generator.sn",
	int machine_id = 0, int mid_bits = 16, int extra_bits = 0, int sn_bits = 16, int mode = 0644])
return resource handle for success, false for fail
*/
ZEND_FUNCTION(fastcommon_id_generator_init)
{
    int argc;
    zend_size_t filename_len;
    long machine_id;
    long mid_bits;
    long extra_bits;
    long sn_bits;
    long mode;
    char *filename;
    PHPIDGContext *php_idg_context;

	argc = ZEND_NUM_ARGS();
	if (argc > 6) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_id_generator_init parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

	filename = DEFAULT_SN_FILENAME;
    filename_len = 0;
	machine_id = 0;
	mid_bits = 16;
    extra_bits = 0;
    sn_bits = 16;
    mode = ID_GENERATOR_DEFAULT_FILE_MODE;
	if (zend_parse_parameters(argc TSRMLS_CC, "|slllll", &filename,
                &filename_len, &machine_id, &mid_bits, &extra_bits,
                &sn_bits, &mode) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    php_idg_context = (PHPIDGContext *)emalloc(sizeof(PHPIDGContext));
    if (php_idg_context == NULL)
    {
		logError("file: "__FILE__", line: %d, "
			"emalloc %d bytes fail!", __LINE__, (int)sizeof(PHPIDGContext));
		RETURN_BOOL(false);
    }

	if (id_generator_init_extra_ex(&php_idg_context->idg_context, filename,
			machine_id, mid_bits, extra_bits, sn_bits, mode) != 0)
	{
		RETURN_BOOL(false);
	}

    last_idg_context = php_idg_context;
    ZEND_REGISTER_RESOURCE(return_value, php_idg_context, le_consumer);
}

/*
long/string fastcommon_id_generator_next([int extra  = 0, $handle = NULL])
return id for success, false for fail
return long in 64 bits OS, return string in 32 bits Os
*/
ZEND_FUNCTION(fastcommon_id_generator_next)
{
    int argc;
    long extra;
    int64_t id;
    zval *zhandle;
    PHPIDGContext *php_idg_context;
    struct idg_context *context;

	argc = ZEND_NUM_ARGS();
	if (argc > 2) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_id_generator_next parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}
    extra = 0;
    zhandle = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "|lz", &extra, &zhandle) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    if (zhandle != NULL && !ZVAL_IS_NULL(zhandle))
    {
        ZEND_FETCH_RESOURCE(php_idg_context, PHPIDGContext *, &zhandle, -1,
                PHP_IDG_RESOURCE_NAME, le_consumer);
        context = &php_idg_context->idg_context;
    }
    else
    {
        if (last_idg_context == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "must call fastcommon_id_generator_init first", __LINE__);
            RETURN_BOOL(false);
        }

        context = &last_idg_context->idg_context;
    }

	if (id_generator_next_extra(context, extra, &id) != 0) {
		RETURN_BOOL(false);
	}

#if OS_BITS == 64
	RETURN_LONG(id);
#else
	{
		char buff[32];
		int len;
		len = sprintf(buff, "%"PRId64, id);
		ZEND_RETURN_STRINGL(buff, len, 1);
	}
#endif
}

/*
int fastcommon_id_generator_get_extra(long id [, $handle = NULL])
return the extra data
*/
ZEND_FUNCTION(fastcommon_id_generator_get_extra)
{
    int argc;
    long id;
    zval *zhandle;
    PHPIDGContext *php_idg_context;
    struct idg_context *context;

	argc = ZEND_NUM_ARGS();
	if (argc > 2) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_id_generator_get_extra parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    zhandle = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "l|z", &id, &zhandle) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    if (zhandle != NULL && !ZVAL_IS_NULL(zhandle))
    {
        ZEND_FETCH_RESOURCE(php_idg_context, PHPIDGContext *, &zhandle, -1,
                PHP_IDG_RESOURCE_NAME, le_consumer);
        context = &php_idg_context->idg_context;
    }
    else
    {
        if (last_idg_context == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "must call fastcommon_id_generator_init first", __LINE__);
            RETURN_BOOL(false);
        }
        context = &last_idg_context->idg_context;
    }

	if (context->fd < 0) {
		logError("file: "__FILE__", line: %d, "
                "must call fastcommon_id_generator_init first", __LINE__);
        RETURN_BOOL(false);
	}

	RETURN_LONG(id_generator_get_extra(context, id));
}

/*
bool fastcommon_id_generator_destroy([resource handle = NULL])
return true for success, false for fail
*/
ZEND_FUNCTION(fastcommon_id_generator_destroy)
{
    int argc;
    zval *zhandle;
    PHPIDGContext *php_idg_context;
    struct idg_context *context;

	argc = ZEND_NUM_ARGS();
	if (argc > 1) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_id_generator_destroy parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    zhandle = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "|z", &zhandle) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    if (zhandle != NULL && !ZVAL_IS_NULL(zhandle))
    {
        ZEND_FETCH_RESOURCE(php_idg_context, PHPIDGContext *, &zhandle, -1,
                PHP_IDG_RESOURCE_NAME, le_consumer);
        context = &php_idg_context->idg_context;
    }
    else
    {
        if (last_idg_context == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "must call fastcommon_id_generator_init first", __LINE__);
            RETURN_BOOL(false);
        }
        context = &last_idg_context->idg_context;
        last_idg_context = NULL;
    }

	id_generator_destroy(context);
	RETURN_BOOL(true);
}

/*
long fastcommon_id_generator_get_timestamp(long id [, $handle = NULL])
return the timestamp
*/
ZEND_FUNCTION(fastcommon_id_generator_get_timestamp)
{
    int argc;
    long id;
    zval *zhandle;
    PHPIDGContext *php_idg_context;
    struct idg_context *context;

	argc = ZEND_NUM_ARGS();
	if (argc > 2) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_id_generator_get_timestamp parameters count: %d is invalid",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    zhandle = NULL;
	if (zend_parse_parameters(argc TSRMLS_CC, "l|z", &id, &zhandle) == FAILURE)
	{
		logError("file: "__FILE__", line: %d, "
			"zend_parse_parameters fail!", __LINE__);
		RETURN_BOOL(false);
	}

    if (zhandle != NULL && !ZVAL_IS_NULL(zhandle))
    {
        ZEND_FETCH_RESOURCE(php_idg_context, PHPIDGContext *, &zhandle, -1,
                PHP_IDG_RESOURCE_NAME, le_consumer);
        context = &php_idg_context->idg_context;
    }
    else
    {
        if (last_idg_context == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "must call fastcommon_id_generator_init first", __LINE__);
            RETURN_BOOL(false);
        }
        context = &last_idg_context->idg_context;
    }

	if (context->fd < 0) {
		logError("file: "__FILE__", line: %d, "
                "must call fastcommon_id_generator_init first", __LINE__);
        RETURN_BOOL(false);
	}

	RETURN_LONG(id_generator_get_timestamp(context, id));
}

/*
array fastcommon_get_ifconfigs()
return the ifconfig array, return false for error
*/
ZEND_FUNCTION(fastcommon_get_ifconfigs)
{
#define MAX_IFCONFIGS  16
    int argc;
    int count;
    int i;
    FastIFConfig if_configs[MAX_IFCONFIGS];
    zval *ifconfig_array;

	argc = ZEND_NUM_ARGS();
	if (argc != 0) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_ifconfigs parameters count: %d is invalid, expect 0",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    if ((getifconfigs(if_configs, MAX_IFCONFIGS, &count)) != 0) {
		RETURN_BOOL(false);
    }

	array_init(return_value);
    for (i=0; i<count; i++) {
        ALLOC_INIT_ZVAL(ifconfig_array);
        array_init(ifconfig_array);
        add_index_zval(return_value, i, ifconfig_array);
        zend_add_assoc_stringl_ex(ifconfig_array, "name", sizeof("name"),
                  if_configs[i].name, strlen(if_configs[i].name), 1);
        zend_add_assoc_stringl_ex(ifconfig_array, "mac", sizeof("mac"),
                  if_configs[i].mac, strlen(if_configs[i].mac), 1);
        zend_add_assoc_stringl_ex(ifconfig_array, "ipv4", sizeof("ipv4"),
                  if_configs[i].ipv4, strlen(if_configs[i].ipv4), 1);
        zend_add_assoc_stringl_ex(ifconfig_array, "ipv6", sizeof("ipv6"),
                  if_configs[i].ipv6, strlen(if_configs[i].ipv6), 1);
    }
}

/*
long fastcommon_get_cpu_count()
return the cpu count
*/
ZEND_FUNCTION(fastcommon_get_cpu_count)
{
    int argc;

	argc = ZEND_NUM_ARGS();
	if (argc != 0) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_cpu_count parameters count: %d is invalid, expect 0",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

     RETURN_LONG(get_sys_cpu_count());
}

/*
array fastcommon_get_sysinfo()
return system info array
*/
ZEND_FUNCTION(fastcommon_get_sysinfo)
{
    int argc;
    int i;
    struct fast_sysinfo info;
    zval *load_array;

	argc = ZEND_NUM_ARGS();
	if (argc != 0) {
		logError("file: "__FILE__", line: %d, "
			"fastcommon_get_sysinfo parameters count: %d is invalid, expect 0",
			__LINE__, argc);
		RETURN_BOOL(false);
	}

    if ((get_sysinfo(&info)) != 0) {
		RETURN_BOOL(false);
    }

	array_init(return_value);
    zend_add_assoc_long_ex(return_value, "boot_time", sizeof("boot_time"),
            info.boot_time.tv_sec);

    ALLOC_INIT_ZVAL(load_array);
    array_init(load_array);
    add_assoc_zval_ex(return_value, "load", sizeof("load"), load_array);
    for (i=0; i<3; i++) {
        add_index_double(load_array, i, info.loads[i]);
    }

    zend_add_assoc_long_ex(return_value, "totalram", sizeof("totalram"),
            info.totalram);
    zend_add_assoc_long_ex(return_value, "freeram", sizeof("freeram"),
            info.freeram);
    zend_add_assoc_long_ex(return_value, "sharedram", sizeof("sharedram"),
            info.sharedram);
    zend_add_assoc_long_ex(return_value, "bufferram", sizeof("bufferram"),
            info.bufferram);
    zend_add_assoc_long_ex(return_value, "totalswap", sizeof("totalswap"),
            info.totalswap);
    zend_add_assoc_long_ex(return_value, "freeswap", sizeof("freeswap"),
            info.freeswap);
    zend_add_assoc_long_ex(return_value, "procs", sizeof("procs"),
            info.procs);
}

static LogContext *fetch_logger_context(const char *filename)
{
    LogContext *ctx;
    LogContext *end;

    if (logger_array.count == 0) {
        return NULL;
    }

    end = logger_array.contexts + logger_array.count;
    for (ctx=logger_array.contexts; ctx<end; ctx++) {
        if (strcmp(ctx->log_filename, filename) == 0) {
            return ctx;
        }
    }
    return NULL;
}

static LogContext *alloc_logger_context(const char *filename, const int time_precision)
{
    LogContext *ctx;
    if (logger_array.alloc <= logger_array.count) {
        int alloc;
        int bytes;
        LogContext *contexts;

        alloc = logger_array.alloc == 0 ? 2 : 2 * logger_array.alloc;
        bytes = sizeof(LogContext) * alloc;
        contexts = (LogContext *)malloc(bytes);
        if (contexts == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            return NULL;
        }

        if (logger_array.count > 0) {
            memcpy(contexts, logger_array.contexts,
                    sizeof(LogContext) * logger_array.count);
            free(logger_array.contexts);
        }
        logger_array.contexts = contexts;
        logger_array.alloc = alloc;
    }

    ctx = logger_array.contexts + logger_array.count;
    if (log_init_ex(ctx) != 0) {
        return NULL;
    }
    if (log_set_filename_ex(ctx, filename) != 0) {
        return NULL;
    }
    log_set_time_precision(ctx, time_precision);

    logger_array.count++;
    return ctx;
}

static LogContext *get_logger_context(const char *filename, const int time_precision)
{
    LogContext *ctx;
    if ((ctx=fetch_logger_context(filename)) != NULL) {
        return ctx;
    }

    return alloc_logger_context(filename, time_precision);
}

#if PHP_MAJOR_VERSION < 7

#define FASTCOMMON_INIT_ZSTRING(z, s, len) \
    do { \
        INIT_ZVAL(z); \
         if (s == NULL) { \
             ZVAL_NULL(&z); \
         } else { \
             ZVAL_STRINGL(&z, s, len, 0); \
         } \
    } while (0)

#else

#define FASTCOMMON_INIT_ZSTRING(z, s, len) \
    do { \
         if (s == NULL) { \
             INIT_ZVAL(z); \
             ZVAL_NULL(&z); \
         } else { \
             ZSTR_ALLOCA_INIT(sz_##s, s, len, use_heap_##s); \
             ZVAL_NEW_STR(&z, sz_##s); \
         } \
    } while (0)

#define FASTCOMMON_ALLOCA_FREE(s) \
    do { \
        if (sz_##s != NULL) { \
            ZSTR_ALLOCA_FREE(sz_##s, use_heap_##s); \
        } \
    } while (0)

#endif

/*
boolean fastcommon_error_log(string $message [, int $message_type = 0,
    string $destination = null, string $headers = null])
return true on success, false on failure
*/
ZEND_FUNCTION(fastcommon_error_log)
{
    int argc;
    long message_type;
    char *message;
    char *filename;
    char *headers;
    zend_size_t msg_len;
    zend_size_t filename_len;
    zend_size_t header_len;

    argc = ZEND_NUM_ARGS();
    if (argc == 0) {
        logError("file: "__FILE__", line: %d, "
                "fastcommon_error_log parameters count: %d is invalid",
                __LINE__, argc);
        RETURN_BOOL(false);
    }

    message = NULL;
    message_type = 0;
    filename = NULL;
    headers = NULL;
    msg_len = 0;
    filename_len = 0;
    header_len = 0;
    if (zend_parse_parameters(argc TSRMLS_CC, "s|lss", &message, &msg_len,
                &message_type, &filename, &filename_len,
                &headers, &header_len) == FAILURE)
    {
        logError("file: "__FILE__", line: %d, "
                "zend_parse_parameters fail!", __LINE__);
        RETURN_BOOL(false);
    }

    if (message_type == 3 && filename != NULL) {
        LogContext *ctx;
        int time_precision;

        if (headers == NULL) {
            time_precision = LOG_TIME_PRECISION_NONE;
        } else {
            time_precision = headers[0];
        }

        if ((ctx=get_logger_context(filename, time_precision)) != NULL) {
            if (msg_len > 0 && message[msg_len - 1] == '\n') {
                --msg_len;
            }
            log_it_ex2(ctx, NULL, message, msg_len, false, false);
            RETURN_BOOL(true);
        }
    }

    {
        int result;
        zval *args[4];
        zval zmessage;
        zval ztype;
        zval zfilename;
        zval zheaders;
#if PHP_MAJOR_VERSION >= 7
        zend_string *sz_message = NULL;
        zend_string *sz_filename = NULL;
        zend_string *sz_headers = NULL;
        bool use_heap_message = false;
        bool use_heap_filename = false;
        bool use_heap_headers = false;
#endif

        if (error_log_func == NULL) {
            error_log_func = &php_error_log;
            INIT_ZVAL(php_error_log);
            ZEND_ZVAL_STRINGL(&php_error_log, "error_log",
                    sizeof("error_log") - 1, 1);
        }

        FASTCOMMON_INIT_ZSTRING(zmessage, message, msg_len);

        INIT_ZVAL(ztype);
        ZVAL_LONG(&ztype, message_type);

        FASTCOMMON_INIT_ZSTRING(zfilename, filename, filename_len);
        FASTCOMMON_INIT_ZSTRING(zheaders, headers, header_len);

        args[0] = &zmessage;
        args[1] = &ztype;
        args[2] = &zfilename;
        args[3] = &zheaders;
        result = zend_call_user_function_wrapper(EG(function_table), NULL,
                    error_log_func, return_value, 4, args TSRMLS_CC);
#if PHP_MAJOR_VERSION >= 7
        FASTCOMMON_ALLOCA_FREE(message);
        FASTCOMMON_ALLOCA_FREE(filename);
        FASTCOMMON_ALLOCA_FREE(headers);
#endif
        if (result == FAILURE) {
            logError("file: "__FILE__", line: %d, "
                    "call function: %s fail", __LINE__,
                    Z_STRVAL_P(error_log_func));
            RETURN_BOOL(false);
        }
    }
}

static PHPFileContext *fetch_file_context(const char *filename)
{
    PHPFileContext *ctx;
    PHPFileContext *end;

    if (file_array.count == 0) {
        return NULL;
    }

    end = file_array.contexts + file_array.count;
    for (ctx=file_array.contexts; ctx<end; ctx++) {
        if (strcmp(ctx->filename, filename) == 0) {
            return ctx;
        }
    }
    return NULL;
}

static int fc_open_file(PHPFileContext *ctx)
{
	if ((ctx->fd = open(ctx->filename, O_WRONLY |
				O_CREAT | O_APPEND, 0644)) < 0)
    {
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" to write fail, "
                "errno: %d, error info: %s", __LINE__,
                ctx->filename, errno, strerror(errno));
		return errno != 0 ? errno : EACCES;
	}

    return 0;
}

static PHPFileContext *alloc_file_context(const char *filename)
{
    PHPFileContext *ctx;
    if (file_array.alloc <= file_array.count) {
        int alloc;
        int bytes;
        PHPFileContext *contexts;

        alloc = file_array.alloc == 0 ? 4 : 2 * file_array.alloc;
        bytes = sizeof(PHPFileContext) * alloc;
        contexts = (PHPFileContext *)malloc(bytes);
        if (contexts == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            return NULL;
        }

        if (file_array.count > 0) {
            memcpy(contexts, file_array.contexts,
                    sizeof(PHPFileContext) * file_array.count);
            free(file_array.contexts);
        }
        file_array.contexts = contexts;
        file_array.alloc = alloc;
    }

    ctx = file_array.contexts + file_array.count;
    ctx->filename = strdup(filename);
    if (ctx->filename == NULL) {
        logError("file: "__FILE__", line: %d, "
                "strdup %d bytes fail",
                __LINE__, (int)strlen(filename));
        return NULL;
    }
    file_array.count++;

    if (fc_open_file(ctx) != 0) {
        return NULL;
    }
    return ctx;
}

static PHPFileContext *fc_get_file_context(const char *filename)
{
    PHPFileContext *ctx;
    if ((ctx=fetch_file_context(filename)) != NULL) {
        if (ctx->fd < 0) {
            if (fc_open_file(ctx) != 0) {
                return NULL;
            }
        }
        return ctx;
    }

    return alloc_file_context(filename);
}

static ssize_t fc_file_put_contents(const char *filename,
        const char *data, const int data_len, const long flags)
{
    PHPFileContext *ctx;
    ssize_t bytes;

    ctx = fc_get_file_context(filename);
    if (ctx == NULL) {
        return -1;
    }

    if ((flags & PHP_LOCK_EX) != 0) {
        bytes = fc_lock_write(ctx->fd, data, data_len);
    } else {
        bytes = fc_safe_write(ctx->fd, data, data_len);
    }
    if (bytes < 0) {
        logError("file: "__FILE__", line: %d, "
                "write to file %s fail, errno: %d, error info: %s",
                __LINE__, filename, errno, strerror(errno));
        close(ctx->fd);
        ctx->fd = -1;
    }
    return bytes;
}

/*
int fastcommon_file_put_contents(string $filename , mixed $data
        [, int $flags = 0, resource $context])
return the number of bytes that were written to the file, or FALSE on failure
*/
ZEND_FUNCTION(fastcommon_file_put_contents)
{
    int argc;
    long flags;
    zval *zdata;
    char *filename;
    zval *zcontext;
    zend_size_t filename_len;

    argc = ZEND_NUM_ARGS();
    if (argc < 2) {
        logError("file: "__FILE__", line: %d, "
                "fastcommon_file_put_contents parameters count: %d is invalid",
                __LINE__, argc);
        RETURN_BOOL(false);
    }

    flags = 0;
    zcontext = NULL;
    if (zend_parse_parameters(argc TSRMLS_CC, "sz|lz",
                &filename, &filename_len, &zdata,
                &flags, &zcontext) == FAILURE)
    {
        logError("file: "__FILE__", line: %d, "
                "zend_parse_parameters fail!", __LINE__);
        RETURN_BOOL(false);
    }

    if ((flags == PHP_FILE_APPEND || flags == (PHP_FILE_APPEND | PHP_LOCK_EX))
        && (Z_TYPE_P(zdata) == IS_STRING) && (zcontext == NULL))
    {
        ssize_t bytes;
        if ((bytes=fc_file_put_contents(filename, Z_STRVAL_P(zdata),
                    Z_STRLEN_P(zdata), flags)) >= 0)
        {
            RETURN_LONG(bytes);
        } else {
            RETURN_BOOL(false);
        }
    }

    {
        int result;
        zval *args[4];
        zval zflags;
        zval zfilename;
#if PHP_MAJOR_VERSION >= 7
        zend_string *sz_filename = NULL;
        bool use_heap_filename = false;
#endif

        if (file_put_contents_func == NULL) {
            file_put_contents_func = &php_file_put_contents;
            INIT_ZVAL(php_file_put_contents);
            ZEND_ZVAL_STRINGL(&php_file_put_contents, "file_put_contents",
                    sizeof("file_put_contents") - 1, 1);
        }

        FASTCOMMON_INIT_ZSTRING(zfilename, filename, filename_len);

        INIT_ZVAL(zflags);
        ZVAL_LONG(&zflags, flags);

        if (zcontext == NULL) {
            zval ctx;
            zcontext = &ctx;
            INIT_ZVAL(*zcontext);
            ZVAL_NULL(zcontext);
        }

        args[0] = &zfilename;
        args[1] = zdata;
        args[2] = &zflags;
        args[3] = zcontext;
        result = zend_call_user_function_wrapper(EG(function_table), NULL,
                    file_put_contents_func, return_value, 4, args TSRMLS_CC);
#if PHP_MAJOR_VERSION >= 7
        FASTCOMMON_ALLOCA_FREE(filename);
#endif
        if (result == FAILURE) {
            logError("file: "__FILE__", line: %d, "
                    "call function: %s fail", __LINE__,
                    Z_STRVAL_P(file_put_contents_func));
            RETURN_BOOL(false);
        }
    }
}
