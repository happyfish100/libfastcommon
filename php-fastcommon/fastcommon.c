#include "php7_ext_wrapper.h"
#include "ext/standard/info.h"
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
#include "fastcommon.h"

#define MAJOR_VERSION  1
#define MINOR_VERSION  0
#define PATCH_VERSION  7

#define PHP_IDG_RESOURCE_NAME "fastcommon_idg"
#define DEFAULT_SN_FILENAME  "/tmp/fastcommon_id_generator.sn"

typedef struct {
    struct idg_context idg_context;
} PHPIDGContext;

static int le_consumer;

static PHPIDGContext *last_idg_context = NULL;

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
	"1.00", 
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

PHP_MINIT_FUNCTION(fastcommon)
{
	log_init();
    le_consumer = zend_register_list_destructors_ex(id_generator_dtor, NULL,
            PHP_IDG_RESOURCE_NAME, module_number);
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(fastcommon)
{
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
	int machine_id = 0, int mid_bits = 16, int extra_bits = 0, int sn_bits = 16])
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
    char *filename;
    PHPIDGContext *php_idg_context;

	argc = ZEND_NUM_ARGS();
	if (argc > 5) {
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
	if (zend_parse_parameters(argc TSRMLS_CC, "|sllll", &filename,
                &filename_len, &machine_id, &mid_bits, &extra_bits,
                &sn_bits) == FAILURE)
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

	if (id_generator_init_extra(&php_idg_context->idg_context, filename,
			machine_id, mid_bits, extra_bits, sn_bits) != 0)
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

