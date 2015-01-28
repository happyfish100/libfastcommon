#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <php.h>

#ifdef ZTS
#include "TSRM.h"
#endif

#include <SAPI.h>
#include <php_ini.h>
#include "ext/standard/info.h"
#include <zend_extensions.h>
#include <zend_exceptions.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include "local_ip_func.h"
#include "logger.h"
#include "hash.h"
#include "sockopt.h"
#include "fastcommon.h"

#define MAJOR_VERSION  1
#define MINOR_VERSION  0

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

PHP_MINIT_FUNCTION(fastcommon)
{
	log_init();
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

	len = sprintf(szVersion, "%d.%02d",
		MAJOR_VERSION, MINOR_VERSION);

	RETURN_STRINGL(szVersion, len, 1);
}

/*
array fastcommon_gethostaddrs([string if_alias_prefix]);
return false for fail, array for success
*/
ZEND_FUNCTION(fastcommon_gethostaddrs)
{
	int argc;
    char *if_alias_prefix;
    int if_prefix_len;
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
        add_index_string(return_value, k, uniq_ips[k], 1);
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
    int str_len;

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
    int str_len;

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

