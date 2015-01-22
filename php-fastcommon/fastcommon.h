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

#ifdef __cplusplus
}
#endif

#endif	/* FASTCOMMON_H */
