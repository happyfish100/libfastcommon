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


/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "sockopt.h"
#include "logger.h"
#include "shared_func.h"
#include "fc_memory.h"
#include "http_func.h"

#ifdef USE_LIBCURL
#include <curl/curl.h>

static bool curl_inited = false;

typedef struct {
    char *buff;
    int length;
    int alloc_size;
    bool dynamic_alloc;
} CurlCallbackArg;

static size_t curl_write_data(void *ptr, size_t size,
        size_t nmemb, void *userdata)
{
    size_t len;
    int alloc_size;
    char *new_buff;
    CurlCallbackArg *cbarg;

    cbarg = (CurlCallbackArg *)userdata;
    len = size * nmemb;
    if ((cbarg->alloc_size - cbarg->length) < len) {
        if (!cbarg->dynamic_alloc) {
            return 0;
        }

        alloc_size = 2 * cbarg->alloc_size;
        while ((alloc_size - cbarg->length) < len) {
            alloc_size *= 2;
        }

        new_buff = (char *)fc_malloc(alloc_size);
        if (new_buff == NULL) {
            return 0;
        }

        if (cbarg->length > 0) {
            memcpy(new_buff, cbarg->buff, cbarg->length);
        }
        free(cbarg->buff);

        cbarg->buff = new_buff;
        cbarg->alloc_size = alloc_size;
    }

    memcpy(cbarg->buff + cbarg->length, ptr, len);
    cbarg->length += len;
    return len;
}

int get_url_content_ex(const char *url, const int url_len,
        const int connect_timeout, const int network_timeout,
        int *http_status, char **content, int *content_len,
        char *error_info)
{
    CURLcode result;
    long response_code;
    CURL *curl;
    CurlCallbackArg cbarg;

    *error_info = '\0';
	*http_status = 0;
    if (!curl_inited) {
        if ((result=curl_global_init(CURL_GLOBAL_ALL)) != 0) {
            sprintf(error_info, "curl_global_init fail "
                    "with code: %d", result);
            return errno != 0 ? errno : EBUSY;
        }
        curl_inited = true;
    }

    if ((curl=curl_easy_init()) == NULL) {
        sprintf(error_info, "curl_easy_init fail");
        return errno != 0 ? errno : EBUSY;
    }

    if (*content == NULL) {
        cbarg.dynamic_alloc = true;
        cbarg.alloc_size = 16 * 1024;
        cbarg.buff = (char *)fc_malloc(cbarg.alloc_size);
        if (cbarg.buff == NULL) {
            return ENOMEM;
        }
    } else {
        cbarg.dynamic_alloc = false;
        cbarg.alloc_size = *content_len;
        cbarg.buff = *content;
    }
    cbarg.length = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, connect_timeout + network_timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cbarg);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

    result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(curl);

    *http_status = response_code;
    if (result == CURLE_OK) {
        if (cbarg.dynamic_alloc) {
            *content = cbarg.buff;
        }
        *content_len = cbarg.length;
        *(*content + *content_len) = '\0';
        return 0;
    } else {
        sprintf(error_info, "curl_easy_perform fail with code: %d, %s",
                result, curl_easy_strerror(result));
        if (cbarg.dynamic_alloc && cbarg.buff != NULL) {
            free(cbarg.buff);
        }
        *content_len = 0;
        return EACCES;
    }
}

#else

int get_url_content_ex(const char *url, const int url_len,
        const int connect_timeout, const int network_timeout,
        int *http_status, char **content, int *content_len, char *error_info)
{
	char domain_name[256];
	char ip_addr[IP_ADDRESS_SIZE];
	char out_buff[4096];
	int domain_len;
	int out_len;
	int alloc_size;
	int recv_bytes;
	int result;
	int sock;
	int port;
    bool bNeedAlloc;
	const char *pDomain;
	const char *pContent;
	const char *pURI;
	char *pPort;
	char *pSpace;

    *error_info = '\0';
	*http_status = 0;
    if (*content == NULL)
    {
        bNeedAlloc = true;
        alloc_size = 64 * 1024;
    }
    else
    {
        bNeedAlloc = false;
        alloc_size = *content_len - 1;
    }
	*content_len = 0;
    if (url_len > sizeof(out_buff) - 128)
    {
		sprintf(error_info, "file: "__FILE__", line: %d, "
                "url too long, url length: %d > %d", __LINE__,
                url_len, (int)(sizeof(out_buff) - 128));

		return ENAMETOOLONG;
    }

	if (url_len <= 7 || strncasecmp(url, "http://", 7) != 0)
	{
		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"invalid url.", __LINE__);
		return EINVAL;
	}

	pDomain = url + 7;
	pURI = strchr(pDomain, '/');
	if (pURI == NULL)
	{
		domain_len = url_len - 7;
		pURI = "/";
	}
	else
	{
		domain_len = pURI - pDomain;
	}

	if (domain_len >= sizeof(domain_name))
	{
		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"domain is too large, exceed %d.", \
			__LINE__, (int)sizeof(domain_name));
		return EINVAL;
	}

	memcpy(domain_name, pDomain, domain_len);
	*(domain_name + domain_len) = '\0';
	pPort = strchr(domain_name, ':');
	if (pPort == NULL)
	{
		port = 80;
	}
	else
	{
		*pPort = '\0';
		port = atoi(pPort + 1);
	}

	if (getIpaddrByName(domain_name, ip_addr, \
		sizeof(ip_addr)) == INADDR_NONE)
	{
		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"resolve domain \"%s\" fail.", \
			__LINE__, domain_name);
		return EINVAL;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0)
	{
		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"socket create failed, errno: %d, " \
			"error info: %s", __LINE__, \
			errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

	if ((result=connectserverbyip_nb_auto(sock, ip_addr, port, \
			connect_timeout)) != 0)
	{
		close(sock);

		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"connect to %s:%u fail, errno: %d, " \
			"error info: %s", __LINE__, domain_name, \
			port, result, STRERROR(result));

		return result;
	}

	out_len = snprintf(out_buff, sizeof(out_buff), \
		"GET %s HTTP/1.0\r\n" \
		"Host: %s:%u\r\n" \
		"Connection: close\r\n" \
		"\r\n", pURI, domain_name, port);
	if ((result=tcpsenddata(sock, out_buff, out_len, network_timeout)) != 0)
	{
		close(sock);

		sprintf(error_info, "file: "__FILE__", line: %d, " \
			"send data to %s:%u fail, errno: %d, " \
			"error info: %s", __LINE__, domain_name, \
			port, result, STRERROR(result));

		return result;
	}

    if (bNeedAlloc)
    {
        *content = (char *)fc_malloc(alloc_size + 1);
        if (*content == NULL)
        {
            close(sock);
            return ENOMEM;
        }
    }

	do
	{
		recv_bytes = alloc_size - *content_len;
		if (recv_bytes <= 0)
		{
            if (bNeedAlloc)
            {
                alloc_size *= 2;
                *content = (char *)fc_realloc(*content, alloc_size + 1);
                if (*content == NULL)
                {
                    *content_len = 0;
                    close(sock);
                    return ENOMEM;
                }

                recv_bytes = alloc_size - *content_len;
            }
            else
            {
                    sprintf(error_info, "file: "__FILE__", line: %d, " \
                            "buffer size: %d is too small", \
                            __LINE__, alloc_size);
                    return ENOSPC;
            }
		}

		result = tcprecvdata_ex(sock, *content + *content_len, \
				recv_bytes, network_timeout, &recv_bytes);

		*content_len += recv_bytes;
	} while (result == 0);

    do
    {
        if (result == ENOTCONN)
        {
            result = 0;
        }
        else {
            sprintf(error_info, "file: "__FILE__", line: %d, " \
                    "recv data from %s:%u fail, errno: %d, " \
                    "error info: %s", __LINE__, domain_name, \
                    port, result, STRERROR(result));

            break;
        }

        *(*content + *content_len) = '\0';
        pContent = strstr(*content, "\r\n\r\n");
        if (pContent == NULL)
        {
            sprintf(error_info, "file: "__FILE__", line: %d, " \
                    "response data from %s:%u is invalid", \
                    __LINE__, domain_name, port);

            result = EINVAL;
            break;
        }

        pContent += 4;
        pSpace = strchr(*content, ' ');
        if (pSpace == NULL || pSpace >= pContent)
        {
            sprintf(error_info, "file: "__FILE__", line: %d, " \
                    "response data from %s:%u is invalid", \
                    __LINE__, domain_name, port);

            result = EINVAL;
            break;
        }

        *http_status = atoi(pSpace + 1);
        *content_len -= pContent - *content;
        memmove(*content, pContent, *content_len);
        *(*content + *content_len) = '\0';
    } while (0);

	close(sock);
    if (result != 0 && bNeedAlloc)
    {
        free(*content);
        *content = NULL;
        *content_len = 0;
    }

	return result;
}

#endif

int get_url_content(const char *url, const int connect_timeout, \
	const int network_timeout, int *http_status, \
	char **content, int *content_len, char *error_info)
{
    *content = NULL;
    return get_url_content_ex(url, strlen(url), connect_timeout, network_timeout,
            http_status, content, content_len, error_info);
}

int http_parse_query(char *url, KeyValuePair *params, const int max_count)
{
	KeyValuePair *pCurrent;
	KeyValuePair *pEnd;
	char *pParamStart;
	char *p;
	char *pKeyEnd;
	char *pValueEnd;
    int value_len;

	pParamStart = strchr(url, '?');
	if (pParamStart == NULL)
	{
		return 0;
	}

	*pParamStart = '\0';

	pEnd = params + max_count;
	pCurrent = params;
	p = pParamStart + 1;
	while (p != NULL && *p != '\0')
	{
		if (pCurrent >= pEnd)
		{
			return pCurrent - params;
		}

		pCurrent->key = p;
		pValueEnd = strchr(p, '&');
		if (pValueEnd == NULL)
		{
            pValueEnd = p + strlen(p);
			p = NULL;
		}
		else
		{
			*pValueEnd = '\0';
			p = pValueEnd + 1;
		}

		pKeyEnd = strchr(pCurrent->key, '=');
		if (pKeyEnd == NULL)  //no =
		{
			continue;
		}

		*pKeyEnd = '\0';
		if (*pCurrent->key == '\0') //empty key
		{
			continue;
		}

		pCurrent->value = pKeyEnd + 1;
		urldecode(pCurrent->value, (int)(pValueEnd - pCurrent->value),
			pCurrent->value, &value_len);
		pCurrent++;
	}

	return pCurrent - params;
}

int http_parse_url_params(char *param_str, const int param_len,
        KeyValuePairEx *params, const int max_count)
{
	KeyValuePairEx *pCurrent;
	KeyValuePairEx *pEnd;
	char *p;
	char *pStrEnd;
	char *pKeyEnd;
	char *pValueEnd;

    pStrEnd = param_str + param_len;
	pEnd = params + max_count;
	pCurrent = params;
	p = param_str;
	while (p < pStrEnd)
	{
		if (pCurrent >= pEnd)
		{
			return pCurrent - params;
		}

		pCurrent->key = p;
		pValueEnd = (char *)memchr(p, '&', pStrEnd - p);
		if (pValueEnd == NULL)
		{
            pValueEnd = pStrEnd;
			p = pStrEnd;
		}
		else
		{
			p = pValueEnd + 1;
		}

		pKeyEnd = (char *)memchr(pCurrent->key, '=',
                pStrEnd - pCurrent->key);
		if (pKeyEnd == NULL)  //no =
		{
			continue;
		}

        *pKeyEnd = '\0';
        pCurrent->key_len = (int)(pKeyEnd - pCurrent->key);
		if (pCurrent->key_len == 0) //empty key
		{
			continue;
		}

		pCurrent->value = pKeyEnd + 1;
		urldecode_ex(pCurrent->value, (int)(pValueEnd - pCurrent->value),
			pCurrent->value, &pCurrent->value_len);
		pCurrent++;
	}

	return pCurrent - params;
}

int http_parse_query_ex(char *url, const int url_len,
        int *uri_len, KeyValuePairEx *params, const int max_count)
{
    char *pParamStart;
    int param_len;

    pParamStart = (char *)memchr(url, '?', url_len);
    if (pParamStart == NULL)
    {
        *uri_len = url_len;
        return 0;
    }

    *uri_len = pParamStart - url;
    param_len = url_len - (*uri_len + 1);
    return http_parse_url_params(pParamStart + 1, param_len,
            params, max_count);
}

