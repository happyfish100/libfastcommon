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

#ifndef _HTTP_FUNC_H
#define _HTTP_FUNC_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "common_define.h"

#define IS_URL_RESOURCE(str)  \
    ((strncasecmp(str, "http://", 7) == 0) || \
     (strncasecmp(str, "https://", 8) == 0))

#ifdef __cplusplus
extern "C" {
#endif

/**
get content from url
params:
	url: the url to fetch, must start as: "http://"
	connect_timeout: connect timeout in seconds
	network_timeout: network timeout in seconds
	http_status: return http status code, 200 for Ok
	content: return the content (HTTP body only, not including HTTP header),
		 *content should be freed by caller when input *content is NULL for auto malloc 
	content_len: input for *content buffer size when *content is NOT NULL,
         output for content length (bytes)
return: 0 for success, != 0 for error
**/
int get_url_content_ex(const char *url, const int url_len,
        const int connect_timeout, const int network_timeout,
        int *http_status, char **content, int *content_len, char *error_info);


/**
get content from url
params:
	url: the url to fetch, must start as: "http://"
	connect_timeout: connect timeout in seconds
	network_timeout: network timeout in seconds
	http_status: return http status code, 200 for Ok
	content: return the content (HTTP body only, not including HTTP header),
		 *content should be freed by caller
	content_len: return content length (bytes)
return: 0 for success, != 0 for error
**/
int get_url_content(const char *url, const int connect_timeout, \
	const int network_timeout, int *http_status, \
	char **content, int *content_len, char *error_info);

/**
parse url
params:
	url: the url to parse, the url be modified after parse
	params: params array to store param and it's value
	max_count: max param count
return: param count
**/
int http_parse_query(char *url, KeyValuePair *params, const int max_count);

/**
parse url ex
params:
	url: the url to parse, the url be modified after parse
    url_len: the length of url
    uri_len: return the uri length (not including ? and parameters)
	params: params array to store param and it's value
	max_count: max param count
return: param count
**/
int http_parse_query_ex(char *url, const int url_len,
        int *uri_len, KeyValuePairEx *params, const int max_count);

/**
parse url params
params:
	param_str: the url params to parse, the params be modified after parse
    param_len: the length of url params
	params: params array to store param and it's value
	max_count: max param count
return: param count
**/
int http_parse_url_params(char *param_str, const int param_len,
        KeyValuePairEx *params, const int max_count);

#ifdef __cplusplus
}
#endif

#endif

