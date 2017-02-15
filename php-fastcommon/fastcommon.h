#ifndef FASTCOMMON_H
#define FASTCOMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PHP_WIN32
#define PHP_FASTDFS_API __declspec(dllexport)
#else
#define PHP_FASTDFS_API
#endif

PHP_MINIT_FUNCTION(fastcommon);
PHP_RINIT_FUNCTION(fastcommon);
PHP_MSHUTDOWN_FUNCTION(fastcommon);
PHP_RSHUTDOWN_FUNCTION(fastcommon);
PHP_MINFO_FUNCTION(fastcommon);

ZEND_FUNCTION(fastcommon_version);
ZEND_FUNCTION(fastcommon_gethostaddrs);
ZEND_FUNCTION(fastcommon_time33_hash);
ZEND_FUNCTION(fastcommon_simple_hash);
ZEND_FUNCTION(fastcommon_get_line_distance_km);
ZEND_FUNCTION(fastcommon_get_first_local_ip);
ZEND_FUNCTION(fastcommon_get_next_local_ip);
ZEND_FUNCTION(fastcommon_is_private_ip);

ZEND_FUNCTION(fastcommon_id_generator_init);
ZEND_FUNCTION(fastcommon_id_generator_next);
ZEND_FUNCTION(fastcommon_id_generator_get_extra);
ZEND_FUNCTION(fastcommon_id_generator_get_timestamp);
ZEND_FUNCTION(fastcommon_id_generator_destroy);

ZEND_FUNCTION(fastcommon_get_ifconfigs);
ZEND_FUNCTION(fastcommon_get_cpu_count);
ZEND_FUNCTION(fastcommon_get_sysinfo);

ZEND_FUNCTION(fastcommon_error_log);
ZEND_FUNCTION(fastcommon_file_put_contents);

#ifdef __cplusplus
}
#endif

#endif	/* FASTCOMMON_H */
