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

/* php7 extension wrapper
 * for compatibility, these wrapper functions are designed for old php version.
 */

#ifndef _PHP7_EXT_WRAPPER_H
#define _PHP7_EXT_WRAPPER_H

#include <stdbool.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>

#ifdef ZTS
#include "TSRM.h"
#endif

#include <SAPI.h>
#include <php_ini.h>

#ifndef TSRMLS_DC
#define TSRMLS_DC
#endif

#ifndef TSRMLS_C
#define TSRMLS_C
#endif

#ifndef TSRMLS_CC
#define TSRMLS_CC
#endif

#ifndef TSRMLS_FETCH
#define TSRMLS_FETCH()
#endif

#if PHP_MAJOR_VERSION < 7
typedef int zend_size_t;
#define ZEND_RETURN_STRING(s, dup) RETURN_STRING(s, dup)
#define ZEND_RETURN_STRINGL(s, l, dup) RETURN_STRINGL(s, l, dup)
#define ZEND_RETURN_STRINGL_CALLBACK(s, l, callback)  \
	do { \
		RETVAL_STRINGL(s, l, 1);  \
		callback(s); /* generally for free the pointer */   \
		return;   \
	} while (0)

#define ZEND_TYPE_OF(z)  (z)->type
#define ZEND_IS_BOOL(z) (ZEND_TYPE_OF(z) == IS_BOOL)
#define ZEND_IS_TRUE(z) (ZEND_IS_BOOL(z) && (z)->value.lval != 0)
#define ZEND_IS_FALSE(z) (ZEND_IS_BOOL(z) && (z)->value.lval == 0)
#define Z_CE_P(z)  ((zend_class_entry *)(z))
#define ZEND_ZVAL_STRINGL   ZVAL_STRINGL
//#define zend_get_object_wrapper(obj) zend_object_store_get_object(obj)

#define zend_hash_update_wrapper   zend_hash_update
#define zend_call_user_function_wrapper call_user_function
#define zend_zval_ptr_dtor  zval_ptr_dtor

#define zend_add_assoc_long_ex(z, key, key_len, n) \
	add_assoc_long_ex(z, key, key_len, n)

#define zend_add_assoc_double_ex(z, key, key_len, n) \
	add_assoc_double_ex(z, key, key_len, n)

#define zend_add_assoc_stringl_ex(z, key, key_len, str, length, dup) \
	add_assoc_stringl_ex(z, key, key_len, str, length, dup)

#define zend_add_assoc_zval_ex(z, key, key_len, value) \
	add_assoc_zval_ex(z, key, key_len, value)

#define zend_add_assoc_bool_ex(z, key, key_len, b) \
	add_assoc_bool_ex(z, key, key_len, b)

#define zend_add_index_stringl(z, index, value, length, dup) \
	add_index_stringl(z, index, value, length, dup)

#define zend_add_index_string(z, index, value, dup) \
	add_index_string(z, index, value, dup)

#define zend_add_assoc_stringl(z, key, str, length, dup) \
	add_assoc_stringl(z, key, str, length, dup)

#define zend_add_assoc_string(z, key, str, dup) \
	add_assoc_string(z, key, str, dup)

#define zend_add_next_index_stringl(z, str, length, dup) \
	add_next_index_stringl(z, str, length, dup)

#define zend_add_next_index_string(z, str, dup) \
	add_next_index_string(z, str, dup)

static inline int zend_hash_find_wrapper(HashTable *ht, char *key, int key_len,
        zval **value)
{
	zval **pp;

	pp = NULL;
	if (zend_hash_find(ht, key, key_len, (void **)&pp) == SUCCESS)
	{
		*value = *pp;
		return SUCCESS;
	}
	else
	{
		*value = NULL;
		return FAILURE;
	}
}

static inline int zend_hash_index_find_wrapper(HashTable *ht, int index, zval **value)
{
    zval **pp = NULL;
    if (zend_hash_index_find(ht, index, (void**)&pp) == SUCCESS) {
        *value =  *pp;
        return SUCCESS;
    } else {
        *value = NULL;
        return FAILURE;
    }
}

static inline int zend_get_configuration_directive_wrapper(char *name, int len,
        zval **value)
{
	return zend_get_configuration_directive(name, len, *value);
}

#else   //php 7

typedef size_t zend_size_t;
#define ZEND_RETURN_STRING(s, dup) RETURN_STRING(s)
#define ZEND_RETURN_STRINGL(s, l, dup) RETURN_STRINGL(s, l)
#define ZEND_RETURN_STRINGL_CALLBACK(s, l, callback)  \
	do { \
		RETVAL_STRINGL(s, l);  \
		callback(s);    \
		return;   \
	} while (0)

#define ZEND_TYPE_OF(z)  Z_TYPE_P(z)
#define ZEND_IS_BOOL(z) (Z_TYPE_P(z) == IS_TRUE || Z_TYPE_P(z) == IS_FALSE)
#define ZEND_IS_TRUE(z) (Z_TYPE_P(z) == IS_TRUE)
#define ZEND_IS_FALSE(z) (Z_TYPE_P(z) == IS_FALSE)
#define Z_STRVAL_PP(s)   Z_STRVAL_P(*s)
#define Z_STRLEN_PP(s)   Z_STRLEN_P(*s)
#define ZEND_ZVAL_STRINGL(z, s, l, dup)  ZVAL_STRINGL(z, s, l)

//#define zend_get_object_wrapper(obj) (void *)((char *)(Z_OBJ_P(obj)) - XtOffsetOf(php_fdfs_t, zo))

#define MAKE_STD_ZVAL(p) zval _stack_zval_##p; p = &(_stack_zval_##p)
#define ALLOC_INIT_ZVAL(p) MAKE_STD_ZVAL(p)
#define INIT_ZVAL(z)

#define ZEND_REGISTER_RESOURCE(return_value, result, le_result)  ZVAL_RES(return_value,zend_register_resource(result, le_result))

#define ZEND_FETCH_RESOURCE(rsrc, rsrc_type, passed_id, default_id, resource_type_name, resource_type) \
        (rsrc = (rsrc_type) zend_fetch_resource(Z_RES_P(*passed_id), resource_type_name, resource_type))

#define zend_zval_ptr_dtor(p)  zval_ptr_dtor(*p)

#define zend_add_assoc_long_ex(z, key, key_len, n) \
	add_assoc_long_ex(z, key, key_len - 1, n)

#define zend_add_assoc_double_ex(z, key, key_len, n) \
	add_assoc_double_ex(z, key, key_len - 1, n)

#define zend_add_assoc_stringl_ex(z, key, key_len, str, length, dup) \
	add_assoc_stringl_ex(z, key, key_len - 1, str, length)

#define zend_add_assoc_zval_ex(z, key, key_len, value) \
	add_assoc_zval_ex(z, key, key_len - 1, value)

#define zend_add_assoc_bool_ex(z, key, key_len, b) \
	add_assoc_bool_ex(z, key, key_len - 1, b)

#define zend_add_index_stringl(z, index, value, length, dup) \
	add_index_stringl(z, index, value, length)

#define zend_add_index_string(z, index, value, dup) \
	add_index_string(z, index, value)

#define zend_add_assoc_stringl(z, key, str, length, dup) \
	add_assoc_stringl(z, key, str, length)

#define zend_add_assoc_string(z, key, str, dup) \
	add_assoc_string(z, key, str)

#define zend_add_next_index_stringl(z, str, length, dup) \
	add_next_index_stringl(z, str, length)

#define zend_add_next_index_string(z, str, dup) \
	add_next_index_string(z, str)

static inline int zend_hash_find_wrapper(HashTable *ht, char *key, int key_len,
        zval **value)
{
	*value = zend_hash_str_find(ht, key, key_len - 1);
	return (*value != NULL ? SUCCESS : FAILURE);
}

static inline int zend_hash_index_find_wrapper(HashTable *ht, int index,
        zval **value)
{
    *value = zend_hash_index_find(ht, index);
	return (*value != NULL ? SUCCESS : FAILURE);
}

static inline int zend_hash_update_wrapper(HashTable *ht, char *k, int len,
        zval **val, int size, void *ptr)
{
	return zend_hash_str_update(ht, k, len - 1, *val) ? SUCCESS : FAILURE;
}

static inline int zend_call_user_function_wrapper(HashTable *function_table,
        zval *object, zval *function_name, zval *retval_ptr,
        uint32_t param_count, zval **params TSRMLS_DC)
{
	int i;
	zval real_params[64];

	if (param_count > 64)
	{
		return FAILURE;
	}

	for(i=0; i<param_count; i++)
	{
		real_params[i] = *params[i];
	}
	return call_user_function(function_table, object, function_name, retval_ptr,
			param_count, real_params);
}

static inline int zend_get_configuration_directive_wrapper(char *name, int len,
        zval **value)
{
	zend_string *key;
    bool use_heap;

    ZSTR_ALLOCA_INIT(key, name, len - 1, use_heap);
	*value = zend_get_configuration_directive(key);
    ZSTR_ALLOCA_FREE(key, use_heap);
	return (*value != NULL ? SUCCESS : FAILURE);
}

#endif

#endif

