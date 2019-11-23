/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//ini_file_reader.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dlfcn.h>
#include "shared_func.h"
#include "logger.h"
#include "http_func.h"
#include "local_ip_func.h"
#include "ini_file_reader.h"

#define _LINE_BUFFER_SIZE	   512
#define _INIT_ALLOC_ITEM_COUNT	32

#define _PREPROCESS_TAG_STR_IF  "#@if "
#define _PREPROCESS_TAG_STR_ELSE "#@else"
#define _PREPROCESS_TAG_STR_ENDIF "#@endif"
#define _PREPROCESS_TAG_STR_FOR "#@for "
#define _PREPROCESS_TAG_STR_ENDFOR "#@endfor"
#define _PREPROCESS_TAG_STR_SET "#@set "

#define _PREPROCESS_TAG_LEN_IF (sizeof(_PREPROCESS_TAG_STR_IF) - 1)
#define _PREPROCESS_TAG_LEN_ELSE (sizeof(_PREPROCESS_TAG_STR_ELSE) - 1)
#define _PREPROCESS_TAG_LEN_ENDIF (sizeof(_PREPROCESS_TAG_STR_ENDIF) - 1)
#define _PREPROCESS_TAG_LEN_FOR (sizeof(_PREPROCESS_TAG_STR_FOR) - 1)
#define _PREPROCESS_TAG_LEN_ENDFOR (sizeof(_PREPROCESS_TAG_STR_ENDFOR) - 1)
#define _PREPROCESS_TAG_LEN_SET (sizeof(_PREPROCESS_TAG_STR_SET) - 1)

#define _PREPROCESS_VARIABLE_STR_LOCAL_IP "%{LOCAL_IP}"
#define _PREPROCESS_VARIABLE_STR_LOCAL_HOST "%{LOCAL_HOST}"

#define _PREPROCESS_VARIABLE_LEN_LOCAL_IP \
    (sizeof(_PREPROCESS_VARIABLE_STR_LOCAL_IP) - 1)
#define _PREPROCESS_VARIABLE_LEN_LOCAL_HOST \
    (sizeof(_PREPROCESS_VARIABLE_STR_LOCAL_HOST) - 1)

#define _PREPROCESS_TAG_STR_FOR_FROM   "from"
#define _PREPROCESS_TAG_LEN_FOR_FROM   (sizeof(_PREPROCESS_TAG_STR_FOR_FROM) - 1)
#define _PREPROCESS_TAG_STR_FOR_TO     "to"
#define _PREPROCESS_TAG_LEN_FOR_TO     (sizeof(_PREPROCESS_TAG_STR_FOR_TO) - 1)
#define _PREPROCESS_TAG_STR_FOR_STEP   "step"
#define _PREPROCESS_TAG_LEN_FOR_STEP   (sizeof(_PREPROCESS_TAG_STR_FOR_STEP) - 1)

#define _MAX_DYNAMIC_CONTENTS     8
#define _BUILTIN_ANNOTATION_COUNT 3

static AnnotationEntry *g_annotations = NULL;
static int g_annotation_count = 0;

typedef struct {
    int count;
    int alloc_count;
    char **contents;
} DynamicContents;

typedef struct {
    int offset;  //deal offset
    HashArray *vars;  //variables with #@set
} SetDirectiveVars;

typedef struct {
    int count;
    int alloc_count;
    AnnotationEntry *annotations;
} DynamicAnnotations;

typedef struct {
    bool used;
    IniContext *context;
    DynamicContents dynamicContents;
    SetDirectiveVars set;
    DynamicAnnotations dynamicAnnotations;
} CDCPair;

//dynamic alloced contents which will be freed when destroy
static int g_dynamic_content_count = 0;
static int g_dynamic_content_index = 0;
static CDCPair g_dynamic_contents[_MAX_DYNAMIC_CONTENTS] = {{false, NULL,
    {0, 0, NULL}, {0, NULL}, {0, 0, NULL}}};

static int remallocSection(IniSection *pSection, IniItem **pItem);
static int iniDoLoadFromFile(const char *szFilename, \
		IniContext *pContext);
static int iniLoadItemsFromBuffer(char *content, \
		IniContext *pContext);
static DynamicAnnotations *iniAllocAnnotations(IniContext *pContext,
        const int annotation_count);
static AnnotationEntry *iniGetAnnotations(IniContext *pContext);
static SetDirectiveVars *iniGetVars(IniContext *pContext);

#define STR_TRIM(pStr) \
    do { \
        trim_right(pStr); \
        trim_left(pStr);  \
    } while (0)

static void iniDoSetAnnotations(AnnotationEntry *src, const int src_count,
        AnnotationEntry *dest, int *dest_count)
{
    AnnotationEntry *pSrc;
    AnnotationEntry *pSrcEnd;
    AnnotationEntry *pDest;
    AnnotationEntry *pDestEnd;

    pSrcEnd = src + src_count;
    pDestEnd = dest + *dest_count;
    for (pSrc=src; pSrc<pSrcEnd; pSrc++)
    {
        for (pDest=dest; pDest<pDestEnd; pDest++)
        {
            if (strcmp(pSrc->func_name, pDest->func_name) == 0)
            {
                break;
            }
        }

        pDest->func_name = pSrc->func_name;
        pDest->arg = pSrc->arg;
        pDest->func_init = pSrc->func_init;
        pDest->func_destroy = pSrc->func_destroy;
        pDest->func_get = pSrc->func_get;
        pDest->func_free = pSrc->func_free;
        pDest->dlhandle = pSrc->dlhandle;
        pDest->inited = false;
        if (pDest == pDestEnd)  //insert
        {
            ++(*dest_count);
            pDestEnd = dest + *dest_count;
        }
    }
}


static AnnotationEntry *iniFindAnnotation(AnnotationEntry *annotatios,
        const char *func_name)
{
    AnnotationEntry *pAnnoEntry;

    if (annotatios == NULL)
    {
        return NULL;
    }

    pAnnoEntry = annotatios;
    while (pAnnoEntry->func_name != NULL)
    {
        if (strcmp(func_name, pAnnoEntry->func_name) == 0)
        {
            return pAnnoEntry;
        }
        pAnnoEntry++;
    }

    return NULL;
}

static int iniAnnotationFuncLocalIpGet(IniContext *context,
        struct ini_annotation_entry *annotation,
        const IniItem *item, char **pOutValue, int max_values)
{
    bool need_private_ip;
    int count;
    int index;
    char param[FAST_INI_ITEM_VALUE_SIZE];
    const char *next_ip;
    char *square_start;
    char name_part[16];

    strcpy(param, item->value);
    memset(name_part, 0, sizeof(name_part));
    square_start = strchr(param, '[');
    if (square_start != NULL && param[strlen(param) - 1] == ']') {
        snprintf(name_part, sizeof(name_part) - 1, "%.*s",
                (int)(square_start - param), param);
        index = atoi(square_start + 1);
    } else {
        snprintf(name_part, sizeof(name_part) - 1, "%s", param);
        index = -2;
    }

    need_private_ip = strcasecmp(name_part, "inner") == 0 ||
        strcasecmp(name_part, "private") == 0;
    next_ip = NULL;
    count = 0;
    while ((next_ip=get_next_local_ip(next_ip)) != NULL) {
        if (count >= max_values) {
            break;
        }
        if (is_private_ip(next_ip)) {
            if (need_private_ip) {
                pOutValue[count++] = (char *)next_ip;
            }
        } else {
            if (!need_private_ip) {
                pOutValue[count++] = (char *)next_ip;
            }
        }
    }

    if (count == 0) {
        pOutValue[count++] = "";
    } else if (index > -2) {
        if (index == -1) {  //get the last one
            if (count > 1) {
                pOutValue[0] = pOutValue[count - 1];
            }
        } else if (index >= count) { //index overflow
            logWarning("file: "__FILE__", line: %d, "
                    "index: %d >= count: %d, set value to empty",
                    __LINE__, index, count);
            pOutValue[0] = "";
        } else if (index > 0) {
            pOutValue[0] = pOutValue[index];
        }
        count = 1;
    }
    return count;
}

static int iniAnnotationFuncShellExec(IniContext *context,
        struct ini_annotation_entry *annotation,
        const IniItem *item, char **pOutValue, int max_values)
{
    int count;
    int result;
    char *output;

    count = 0;
    output = (char *)malloc(FAST_INI_ITEM_VALUE_SIZE);
    if (output == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, FAST_INI_ITEM_VALUE_LEN + 1);
        return count;
    }

    if ((result=getExecResult(item->value, output, FAST_INI_ITEM_VALUE_SIZE)) != 0)
    {
        logWarning("file: "__FILE__", line: %d, "
                "exec %s fail, errno: %d, error info: %s",
                __LINE__, item->value, result, STRERROR(result));
        free(output);
        return count;
    }
    if (*output == '\0')
    {
        logWarning("file: "__FILE__", line: %d, "
                "empty reply when exec: %s", __LINE__, item->value);
    }
    pOutValue[count++] = fc_trim(output);
    return count;
}

static int iniCopyBuffer(char *dest, const int size, const char *src, int len)
{
    if (len == 0) {
        return 0;
    }

    if (len >= size) {
        logWarning("file: "__FILE__", line: %d, "
                "length: %d exceeds: %d",
                __LINE__, len, size);
        len = size - 1;
        if (len < 0) {
            len = 0;
        }
    }

    if (len > 0) {
        memcpy(dest, src, len);
    }
    return len;
}

static char *doReplaceVars(IniContext *pContext, const char *param,
        const int max_size)
{
#define VARIABLE_TAG_MIN_LENGTH  4   //%{v}

    SetDirectiveVars *set;
    const char *p;
    const char *e;
    char name[64];
    const char *start;
    const char *value;
    const char *pLoopEnd;
    const char *pEnd;
    char *pDest;
    char *output;
    int name_len;
    int len;

    output = (char *)malloc(max_size);
    if (output == NULL) {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail",
                __LINE__, FAST_INI_ITEM_VALUE_SIZE);
        return NULL;
    }

    set = iniGetVars(pContext);
    if (set == NULL || set->vars == NULL) {
        logWarning("file: "__FILE__", line: %d, "
                "NO set directives before, set value to %s",
                __LINE__, param);
        snprintf(output, FAST_INI_ITEM_VALUE_SIZE, "%s", param);
        return output;
    }

    pEnd = param + strlen(param);
    pLoopEnd = pEnd - (VARIABLE_TAG_MIN_LENGTH - 1);
    p = param;
    pDest = output;
    while (p < pLoopEnd) {
        if (*p == '%' && *(p+1) == '{') {
            start = e = p + 2;
            while (e < pEnd && *e != '}') {
                e++;
            }
            if (e == pEnd) {
                break;
            }
            name_len = e - start;
            p = e + 1;

            if (name_len >= sizeof(name)) {
                logWarning("file: "__FILE__", line: %d, "
                        "name: %.*s is too long, truncate to length: %d",
                        __LINE__, name_len, start, (int)(sizeof(name) - 1));
                name_len = sizeof(name) - 1;
            }
            if (name_len > 0) {
                memcpy(name, start, name_len);
            }
            *(name + name_len) = '\0';
            trim(name);
            name_len = strlen(name);
            if (name_len > 0) {
                value = (char *)hash_find(set->vars, name, name_len);
            } else {
                value = NULL;
            }
            if (value != NULL) {
                len = strlen(value);
            }
            else {
                logWarning("file: "__FILE__", line: %d, "
                        "name: %s NOT found, keep the origin",
                        __LINE__, name);
                value = start - 2;
                len = p - value;
            }
            pDest += iniCopyBuffer(pDest, FAST_INI_ITEM_VALUE_SIZE -
                    (pDest - output), value, len);
        }
        else {
            if (pDest - output < FAST_INI_ITEM_VALUE_LEN) {
                *pDest++ = *p++;
            }
            else {
                logWarning("file: "__FILE__", line: %d, "
                        "value too long, exceeds: %d",
                        __LINE__, (int)sizeof(output));
                break;
            }
        }
    }

    len = pEnd - p;
    pDest += iniCopyBuffer(pDest, FAST_INI_ITEM_VALUE_SIZE - (pDest - output), p, len);
    *pDest = '\0';
    return output;
}

static int iniAnnotationReplaceVars(IniContext *pContext,
        struct ini_annotation_entry *annotation,
        const IniItem *item, char **pOutValue, int max_values)
{
    char *output;
    output = doReplaceVars(pContext, item->value, FAST_INI_ITEM_VALUE_SIZE);
    if (output == NULL) {
        return 0;
    }
    else {
        pOutValue[0] = output;
        return 1;
    }
}

void iniAnnotationFreeValues(struct ini_annotation_entry *annotation,
        char **values, const int count)
{
    int i;
    for (i=0; i<count; i++) {
        free(values[i]);
        values[i] = NULL;
    }
}

static void iniSetBuiltinAnnotations(IniContext *pContext,
        AnnotationEntry *dest, int *dest_count)
{
    AnnotationEntry builtins[_BUILTIN_ANNOTATION_COUNT];
    AnnotationEntry *pAnnotation;

    memset(builtins, 0, sizeof(builtins));
    pAnnotation = builtins;
    pAnnotation->func_name = "LOCAL_IP_GET";
    pAnnotation->func_get = iniAnnotationFuncLocalIpGet;
    pAnnotation++;

    pAnnotation->func_name = "REPLACE_VARS";
    pAnnotation->func_get = iniAnnotationReplaceVars;
    pAnnotation->func_free = iniAnnotationFreeValues;
    pAnnotation++;

    if ((pContext->flags & FAST_INI_FLAGS_SHELL_EXECUTE) != 0)
    {
        pAnnotation->func_name = "SHELL_EXEC";
        pAnnotation->func_get = iniAnnotationFuncShellExec;
        pAnnotation->func_free = iniAnnotationFreeValues;
        pAnnotation++;
    }

    iniDoSetAnnotations(builtins, pAnnotation - builtins, dest, dest_count);
}

static int iniSetAnnotations(IniContext *pContext, const char annotation_type,
        AnnotationEntry *annotations, const int count)
{
    DynamicAnnotations *pDynamicAnnotations;

    pContext->annotation_type = annotation_type;
    if (pContext->annotation_type == FAST_INI_ANNOTATION_DISABLE)
    {
        return 0;
    }
    if (pContext->annotation_type == FAST_INI_ANNOTATION_WITHOUT_BUILTIN &&
            annotations == NULL)
    {
        return 0;
    }

    if ((pDynamicAnnotations=iniAllocAnnotations(pContext,
                    _BUILTIN_ANNOTATION_COUNT + count)) == NULL)
    {
        return ENOMEM;
    }
    if (pContext->annotation_type == FAST_INI_ANNOTATION_WITH_BUILTIN)
    {
        iniSetBuiltinAnnotations(pContext, pDynamicAnnotations->annotations,
                &pDynamicAnnotations->count);
    }

    if (annotations != NULL)
    {
        iniDoSetAnnotations(annotations, count, pDynamicAnnotations->annotations,
                &pDynamicAnnotations->count);
    }
    return 0;
}

int iniSetAnnotationCallBack(AnnotationEntry *annotations, int count)
{
    int bytes;

    if (count <= 0)
    {
		logWarning("file: "__FILE__", line: %d, "
			"iniSetAnnotationCallBack fail, count(%d) is invalid.",
			__LINE__, count);
        return EINVAL;
    }

    bytes = sizeof(AnnotationEntry) * (g_annotation_count + count + 1);
    g_annotations = (AnnotationEntry *)realloc(g_annotations, bytes);
    if (g_annotations == NULL)
    {
		logError("file: "__FILE__", line: %d, "
			"realloc %d fail, errno: %d, error info: %s",
			__LINE__, bytes, errno, STRERROR(errno));
        return ENOMEM;
    }

    memset(g_annotations + g_annotation_count, 0,
            sizeof(AnnotationEntry) * (count + 1));
    iniDoSetAnnotations(annotations, count, g_annotations, &g_annotation_count);
    return 0;
}

void iniDestroyAnnotationCallBack()
{
    AnnotationEntry *pAnnoEntry;

    if (g_annotations == NULL)
    {
        return;
    }

    pAnnoEntry = g_annotations;
    while (pAnnoEntry->func_name)
    {
        if (pAnnoEntry->func_destroy != NULL)
        {
            pAnnoEntry->func_destroy(pAnnoEntry);
        }
        if (pAnnoEntry->dlhandle != NULL)
        {
            dlclose(pAnnoEntry->dlhandle);
        }
        pAnnoEntry++;
    }

    free(g_annotations);
    g_annotations = NULL;
    g_annotation_count = 0;

}

static int iniCompareByItemName(const void *p1, const void *p2)
{
	return strcmp(((IniItem *)p1)->name, ((IniItem *)p2)->name);
}

static int iniInitContext(IniContext *pContext, const char annotation_type,
        AnnotationEntry *annotations, const int count,
        const char flags)
{
	int result;

	memset(pContext, 0, sizeof(IniContext));
	pContext->current_section = &pContext->global;
	if ((result=hash_init(&pContext->sections, Time33Hash, 32, 0.75)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"hash_init fail, errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	pContext->flags = flags;
    return iniSetAnnotations(pContext, annotation_type, annotations, count);
}

static int iniSortHashData(const int index, const HashData *data, void *args)
{
	IniSection *pSection;

	pSection = (IniSection *)data->value;
	if (pSection->count > 1)
	{
		qsort(pSection->items, pSection->count, \
			sizeof(IniItem), iniCompareByItemName);
	}

	return 0;
}

static void iniSortItems(IniContext *pContext)
{
	if (pContext->global.count > 1)
	{
		qsort(pContext->global.items, pContext->global.count, \
			sizeof(IniItem), iniCompareByItemName);
	}

	hash_walk(&pContext->sections, iniSortHashData, NULL);
}

int iniLoadFromFile(const char *szFilename, IniContext *pContext)
{
    return iniLoadFromFileEx(szFilename, pContext,
            FAST_INI_ANNOTATION_WITH_BUILTIN,
            NULL, 0, FAST_INI_FLAGS_NONE);
}

static void iniDestroyAnnotations(const int old_annotation_count)
{
    AnnotationEntry *pAnnoEntry;

    if (g_annotations == NULL)
    {
        return;
    }

    logDebug("iniDestroyAnnotations, old_annotation_count: %d, "
            "g_annotation_count: %d",
            old_annotation_count, g_annotation_count);
    if (old_annotation_count == 0)
    {
        iniDestroyAnnotationCallBack();
        return;
    }

    pAnnoEntry = g_annotations + old_annotation_count;
    while (pAnnoEntry->func_name)
    {
        if (pAnnoEntry->func_destroy != NULL)
        {
            pAnnoEntry->func_destroy(pAnnoEntry);
        }
        if (pAnnoEntry->dlhandle != NULL)
        {
            dlclose(pAnnoEntry->dlhandle);
        }
        pAnnoEntry++;
    }

    memset(g_annotations + old_annotation_count, 0,
            sizeof(AnnotationEntry) * (g_annotation_count - old_annotation_count));
    g_annotation_count = old_annotation_count;
}

int iniLoadFromFileEx(const char *szFilename, IniContext *pContext,
    const char annotation_type, AnnotationEntry *annotations, const int count,
    const char flags)
{
	int result;
	int len;
	char *pLast;
	char full_filename[MAX_PATH_SIZE];
    int old_annotation_count;

	if ((result=iniInitContext(pContext, annotation_type,
                    annotations, count, flags)) != 0)
	{
		return result;
	}

	if (strncasecmp(szFilename, "http://", 7) == 0)
	{
		*pContext->config_path = '\0';
		snprintf(full_filename, sizeof(full_filename),"%s",szFilename);
	}
	else
	{
		if (*szFilename == '/')
		{
			pLast = strrchr(szFilename, '/');
			len = pLast - szFilename;
			if (len >= sizeof(pContext->config_path))
			{
				logError("file: "__FILE__", line: %d, "\
					"the path of the config file: %s is " \
					"too long!", __LINE__, szFilename);
				return ENOSPC;
			}

			memcpy(pContext->config_path, szFilename, len);
			*(pContext->config_path + len) = '\0';
			snprintf(full_filename, sizeof(full_filename), \
				"%s", szFilename);
		}
		else
		{
			memset(pContext->config_path, 0, \
				sizeof(pContext->config_path));
			if (getcwd(pContext->config_path, sizeof( \
				pContext->config_path)) == NULL)
			{
				logError("file: "__FILE__", line: %d, " \
					"getcwd fail, errno: %d, " \
					"error info: %s", \
					__LINE__, errno, STRERROR(errno));
				return errno != 0 ? errno : EPERM;
			}

			len = strlen(pContext->config_path);
			if (len > 0 && pContext->config_path[len - 1] == '/')
			{
				len--;
				*(pContext->config_path + len) = '\0';
			}

			snprintf(full_filename, sizeof(full_filename), \
				"%s/%s", pContext->config_path, szFilename);

			pLast = strrchr(szFilename, '/');
			if (pLast != NULL)
			{
				int tail_len;

				tail_len = pLast - szFilename;
				if (len + 1 + tail_len >= sizeof( \
						pContext->config_path))
				{
					logError("file: "__FILE__", line: %d, "\
						"the path of the config " \
						"file: %s is too long!", \
						__LINE__, szFilename);
					return ENOSPC;
				}

                *(pContext->config_path + len++) = '/';
				memcpy(pContext->config_path + len, \
					szFilename, tail_len);
				len += tail_len;
				*(pContext->config_path + len) = '\0';
			}
		}
	}

    old_annotation_count = g_annotation_count;
	result = iniDoLoadFromFile(full_filename, pContext);
    if (g_annotation_count > old_annotation_count)
    {
        iniDestroyAnnotations(old_annotation_count);
    }

	if (result == 0)
	{
		iniSortItems(pContext);
	}
	else
	{
		iniFreeContext(pContext);
	}

	return result;
}

static int iniDoLoadFromFile(const char *szFilename, \
		IniContext *pContext)
{
	char *content;
	int result;
	int http_status;
	int content_len;
	int64_t file_size;
	char error_info[512];

	if (strncasecmp(szFilename, "http://", 7) == 0)
	{
		if ((result=get_url_content(szFilename, 10, 60, &http_status, \
				&content, &content_len, error_info)) != 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"get_url_content fail, " \
				"url: %s, error info: %s", \
				__LINE__, szFilename, error_info);
			return result;
		}

		if (http_status != 200)
		{
			free(content);
			logError("file: "__FILE__", line: %d, " \
				"HTTP status code: %d != 200, url: %s", \
				__LINE__, http_status, szFilename);
			return EINVAL;
		}
	}
	else
	{
		if ((result=getFileContent(szFilename, &content, \
				&file_size)) != 0)
		{
			return result;
		}
	}

	result = iniLoadItemsFromBuffer(content, pContext);
	free(content);

	return result;
}

int iniLoadFromBufferEx(char *content, IniContext *pContext,
    const char annotation_type, AnnotationEntry *annotations, const int count,
    const char flags)
{
	int result;
    int old_annotation_count;

	if ((result=iniInitContext(pContext, annotation_type,
                    annotations, count, flags)) != 0)
	{
		return result;
	}

    old_annotation_count = g_annotation_count;
	result = iniLoadItemsFromBuffer(content, pContext);
    if (g_annotation_count > old_annotation_count)
    {
        iniDestroyAnnotations(old_annotation_count);
    }

	if (result == 0)
	{
		iniSortItems(pContext);
	}
	else
	{
		iniFreeContext(pContext);
	}

	return result;
}

int iniLoadFromBuffer(char *content, IniContext *pContext)
{
    return iniLoadFromBufferEx(content, pContext,
            FAST_INI_ANNOTATION_WITH_BUILTIN,
            NULL, 0, FAST_INI_FLAGS_NONE);
}


typedef int (*init_annotation_func0)(AnnotationEntry *annotation);
typedef int (*init_annotation_func1)(AnnotationEntry *annotation,
        const char *arg1);
typedef int (*init_annotation_func2)(AnnotationEntry *annotation,
        const char *arg1, const char *arg2);
typedef int (*init_annotation_func3)(AnnotationEntry *annotation,
        const char *arg1, const char *arg2, const char *arg3);

static int iniAddAnnotation(char *params)
{
#define MAX_PARAMS   5
    char *cols[MAX_PARAMS];
    char *func_name;
    char *library;
    AnnotationEntry annotation;
    void *dlhandle;
    void *init_func;
    char symbol[64];
    int argc;
    int count;
    int result;

    trim(params);
    count = fc_split_string(params, " \t", cols, MAX_PARAMS);
    if (count < 2)
    {
        logError("file: "__FILE__", line: %d, "
                "invalid format, correct format: "
                "#@add_annotation FUNC_NAME library ...", __LINE__);
        return EINVAL;
    }

    func_name = fc_trim(cols[0]);
    library = fc_trim(cols[1]);
    if (*func_name == '\0')
    {
        logError("file: "__FILE__", line: %d, "
                "empty func name, correct format: "
                "#@add_annotation FUNC_NAME library ...", __LINE__);
        return EINVAL;
    }
    if (*library == '\0')
    {
        logError("file: "__FILE__", line: %d, "
                "empty library, correct format: "
                "#@add_annotation FUNC_NAME library ...", __LINE__);
        return EINVAL;
    }

    if (iniFindAnnotation(g_annotations, func_name) != NULL)
    {
        logWarning("file: "__FILE__", line: %d, "
                "function %s already exist", __LINE__, func_name);
        return EEXIST;
    }

    if (strcmp(library, "-") == 0)
    {
        library = NULL;
    }
    else if (!fileExists(library))
    {
        logError("file: "__FILE__", line: %d, "
                "library %s not exist", __LINE__, library);
        return ENOENT;
    }

    dlhandle = dlopen(library, RTLD_LAZY);
    if (dlhandle == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "dlopen %s fail, error info: %s",
                __LINE__, library != NULL ? library : "",
                dlerror());
        return EFAULT;
    }

    snprintf(symbol, sizeof(symbol), "%s_init_annotation", func_name);
    init_func = dlsym(dlhandle, symbol);
    if (init_func == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "dlsym function %s fail, error info: %s",
                __LINE__, symbol, dlerror());
        dlclose(dlhandle);
        return ENOENT;
    }

    memset(&annotation, 0, sizeof(annotation));
    argc = count - 2;
    switch (argc)
    {
        case 0:
            result = ((init_annotation_func0)init_func)(&annotation);
            break;
        case 1:
            result = ((init_annotation_func1)init_func)(&annotation, cols[2]);
            break;
        case 2:
            result = ((init_annotation_func2)init_func)(&annotation,
                    cols[2], cols[3]);
            break;
        case 3:
            result = ((init_annotation_func3)init_func)(&annotation,
                    cols[2], cols[3], cols[4]);
            break;
        default:
            result = 0;
            break;
    }

    if (result != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call function %s fail, ret: %d",
                __LINE__, symbol, result);
        dlclose(dlhandle);
        return EFAULT;
    }

    annotation.dlhandle = dlhandle;
    return iniSetAnnotationCallBack(&annotation, 1);
}

static int iniDoLoadItemsFromBuffer(char *content, IniContext *pContext)
{
	IniSection *pSection;
	IniItem *pItem;
	char *pLine;
	char *pLastEnd;
	char *pEqualChar;
    char pItemName[FAST_INI_ITEM_NAME_LEN + 1];
    char *pAnnoItemLine;
	char *pIncludeFilename;
    char *pItemValues[100];
    char pFuncName[FAST_INI_ITEM_NAME_LEN + 1];
	char full_filename[MAX_PATH_SIZE];
    int i;
	int nLineLen;
	int nNameLen;
    int nItemCnt;
	int nValueLen;
	int result;
    int isAnnotation;

	result = 0;
    pAnnoItemLine = NULL;
    isAnnotation = 0;
    *pFuncName = '\0';
	pLastEnd = content - 1;
	pSection = pContext->current_section;
    pItem = pSection->items + pSection->count;

	while (pLastEnd != NULL)
	{
		pLine = pLastEnd + 1;
		pLastEnd = strchr(pLine, '\n');
		if (pLastEnd != NULL)
		{
			*pLastEnd = '\0';
		}

        if (isAnnotation && pLine != pAnnoItemLine)
        {
            logWarning("file: "__FILE__", line: %d, " \
                "the @function annotation line " \
                "must follow by key=value line!", __LINE__);
            isAnnotation = 0;
        }

		STR_TRIM(pLine);
		if (*pLine == '#' && \
			strncasecmp(pLine+1, "include", 7) == 0 && \
			(*(pLine+8) == ' ' || *(pLine+8) == '\t'))
		{
			pIncludeFilename = strdup(pLine + 9);
			if (pIncludeFilename == NULL)
			{
				logError("file: "__FILE__", line: %d, " \
					"strdup %d bytes fail", __LINE__, \
					(int)strlen(pLine + 9) + 1);
				result = errno != 0 ? errno : ENOMEM;
				break;
			}

			STR_TRIM(pIncludeFilename);
			if (strncasecmp(pIncludeFilename, "http://", 7) == 0)
			{
				snprintf(full_filename, sizeof(full_filename),\
					"%s", pIncludeFilename);
			}
			else
			{
				if (*pIncludeFilename == '/')
				{
				snprintf(full_filename, sizeof(full_filename), \
					"%s", pIncludeFilename);
				}
				else
				{
				snprintf(full_filename, sizeof(full_filename), \
					"%s/%s", pContext->config_path, \
					 pIncludeFilename);
				}

				if (!fileExists(full_filename))
				{
				logError("file: "__FILE__", line: %d, " \
					"include file \"%s\" not exists, " \
					"line: \"%s\"", __LINE__, \
					pIncludeFilename, pLine);
				free(pIncludeFilename);
				result = ENOENT;
				break;
				}
			}

            pContext->current_section = &pContext->global;
			result = iniDoLoadFromFile(full_filename, pContext);
			if (result != 0)
			{
				free(pIncludeFilename);
				break;
			}

            pContext->current_section = &pContext->global;
			pSection = pContext->current_section;
            pItem = pSection->items + pSection->count;  //must re-asign

			free(pIncludeFilename);
			continue;
		}
        else if (*pLine == '#')
        {
            if (pContext->annotation_type == FAST_INI_ANNOTATION_DISABLE)
            {
                continue;
            }

            if (strncasecmp(pLine+1, "@function", 9) == 0 &&
                    (*(pLine+10) == ' ' || *(pLine+10) == '\t'))
            {
                nNameLen = strlen(pLine + 11);
                if (nNameLen > FAST_INI_ITEM_NAME_LEN)
                {
                    nNameLen = FAST_INI_ITEM_NAME_LEN;
                }
                memcpy(pFuncName, pLine + 11, nNameLen);
                pFuncName[nNameLen] = '\0';
                STR_TRIM(pFuncName);
                if ((int)strlen(pFuncName) > 0)
                {
                    isAnnotation = 1;
                    pAnnoItemLine = pLastEnd + 1;
                }
                else
                {
                    logWarning("file: "__FILE__", line: %d, " \
                            "the function name of annotation line is empty", \
                            __LINE__);
                }
            }
            else if (strncasecmp(pLine+1, "@add_annotation", 15) == 0 &&
                    (*(pLine+16) == ' ' || *(pLine+16) == '\t'))
            {
                result = iniAddAnnotation(pLine + 17);
                if (!(result == 0 || result == EEXIST))
                {
                    break;
                }
            }

            continue;
        }

		if (*pLine == '\0')
		{
			continue;
		}

		nLineLen = strlen(pLine);
		if (*pLine == '[' && *(pLine + (nLineLen - 1)) == ']') //section
		{
			char *section_name;
			int section_len;

			*(pLine + (nLineLen - 1)) = '\0';
			section_name = pLine + 1; //skip [

			STR_TRIM(section_name);
			if (*section_name == '\0') //global section
			{
				pContext->current_section = &pContext->global;
				pSection = pContext->current_section;
                pItem = pSection->items + pSection->count;
				continue;
			}

			section_len = strlen(section_name);
			pSection = (IniSection *)hash_find(&pContext->sections,\
					section_name, section_len);
			if (pSection == NULL)
			{
				pSection = (IniSection *)malloc(sizeof(IniSection));
				if (pSection == NULL)
				{
					result = errno != 0 ? errno : ENOMEM;
					logError("file: "__FILE__", line: %d, "\
						"malloc %d bytes fail, " \
						"errno: %d, error info: %s", \
						__LINE__, \
						(int)sizeof(IniSection), \
						result, STRERROR(result));

					break;
				}

				memset(pSection, 0, sizeof(IniSection));
				result = hash_insert(&pContext->sections, \
					  section_name, section_len, pSection);
				if (result < 0)
				{
					result *= -1;
					logError("file: "__FILE__", line: %d, "\
						"insert into hash table fail, "\
						"errno: %d, error info: %s", \
						__LINE__, result, \
						STRERROR(result));
					break;
				}
				else
				{
					result = 0;
				}
			}

			pContext->current_section = pSection;
            pItem = pSection->items + pSection->count;
			continue;
		}

		pEqualChar = strchr(pLine, '=');
		if (pEqualChar == NULL)
		{
			continue;
		}

		nNameLen = pEqualChar - pLine;
		nValueLen = strlen(pLine) - (nNameLen + 1);
		if (nNameLen > FAST_INI_ITEM_NAME_LEN)
		{
            logWarning("file: "__FILE__", line: %d, "
                    "name length: %d exceeds %d, "
                    "truncate it to \"%.*s\"", __LINE__,
                    nNameLen, FAST_INI_ITEM_NAME_LEN,
                    FAST_INI_ITEM_NAME_LEN, pLine);
			nNameLen = FAST_INI_ITEM_NAME_LEN;
		}

		if (nValueLen > FAST_INI_ITEM_VALUE_LEN)
		{
            logWarning("file: "__FILE__", line: %d, "
                    "value length: %d exceeds %d, "
                    "truncate it to \"%.*s\"", __LINE__,
                    nValueLen, FAST_INI_ITEM_VALUE_LEN,
                    FAST_INI_ITEM_VALUE_LEN, pEqualChar + 1);
			nValueLen = FAST_INI_ITEM_VALUE_LEN;
		}

		if (pSection->count >= pSection->alloc_count)
        {
            result = remallocSection(pSection, &pItem);
            if (result != 0)
            {
                break;
            }
		}

		memcpy(pItem->name, pLine, nNameLen);
		memcpy(pItem->value, pEqualChar + 1, nValueLen);

		STR_TRIM(pItem->name);
		STR_TRIM(pItem->value);

        if (isAnnotation)
        {
            AnnotationEntry *pAnnoEntryBase;
            AnnotationEntry *pAnnoEntry = NULL;

            isAnnotation = 0;
            if ((pAnnoEntryBase=iniGetAnnotations(pContext)) == NULL)
            {
                pAnnoEntryBase = g_annotations;
            }
            if (pAnnoEntryBase == NULL)
            {
                logWarning("file: "__FILE__", line: %d, " \
                    "not set annotationMap and (%s) will use " \
                    "the item value (%s)", __LINE__, pItem->name,
                    pItem->value);
                pSection->count++;
                pItem++;
                continue;
            }

            nItemCnt = -1;
            for (i=0; i<2; i++)
            {
                pAnnoEntry = iniFindAnnotation(pAnnoEntryBase, pFuncName);
                if (pAnnoEntry != NULL)
                {
                    if (pAnnoEntry->func_init != NULL && !pAnnoEntry->inited)
                    {
                        pAnnoEntry->inited = true;
                        pAnnoEntry->func_init(pAnnoEntry);
                    }

                    if (pAnnoEntry->func_get != NULL)
                    {
                        nItemCnt = pAnnoEntry->func_get(pContext,
                                pAnnoEntry, pItem, pItemValues, 100);
                    }
                    break;
                }

                if (g_annotations != NULL && pAnnoEntryBase != g_annotations)
                {
                    pAnnoEntryBase = g_annotations;
                }
                else
                {
                    break;
                }
            }

            if (nItemCnt == -1)
            {
                logWarning("file: "__FILE__", line: %d, " \
                    "not found corresponding annotation function: %s, " \
                    "\"%s\" will use the item value \"%s\"", __LINE__,
                    pFuncName, pItem->name, pItem->value);
                pSection->count++;
                pItem++;
                continue;
            }
            else if (nItemCnt == 0)
            {
                logWarning("file: "__FILE__", line: %d, " \
                    "annotation function %s execute fail, " \
                    "\"%s\" will use the item value \"%s\"", __LINE__,
                    pFuncName, pItem->name, pItem->value);
                pSection->count++;
                pItem++;
                continue;
            }

            strcpy(pItemName, pItem->name);
            nNameLen = strlen(pItemName);
            for (i = 0; i < nItemCnt; i++)
            {
                nValueLen = strlen(pItemValues[i]);
                if (nValueLen > FAST_INI_ITEM_VALUE_LEN)
                {
                    logWarning("file: "__FILE__", line: %d, "
                            "value length: %d exceeds %d, "
                            "truncate it to \"%.*s\"", __LINE__,
                            nValueLen, FAST_INI_ITEM_VALUE_LEN,
                            FAST_INI_ITEM_VALUE_LEN, pItemValues[i]);
                    nValueLen = FAST_INI_ITEM_VALUE_LEN;
                }
                strcpy(pItem->name, pItemName);
                memcpy(pItem->value, pItemValues[i], nValueLen);
                pItem->value[nValueLen] = '\0';
                pSection->count++;
                pItem++;
                if (pSection->count >= pSection->alloc_count)
                {
                    result = remallocSection(pSection, &pItem);
                    if (result != 0)
                    {
                        break;
                    }
                }
            }

            if (pAnnoEntry != NULL && pAnnoEntry->func_free != NULL)
            {
                pAnnoEntry->func_free(pAnnoEntry, pItemValues, nItemCnt);
            }
            continue;
        }

		pSection->count++;
		pItem++;
	}

    if (result == 0 && isAnnotation)
    {
        logWarning("file: "__FILE__", line: %d, " \
            "the @function annotation line " \
            "must follow by key=value line!", __LINE__);
    }

	return result;
}

static CDCPair *iniGetCDCPair(IniContext *pContext)
{
    int i;
    if (g_dynamic_contents[g_dynamic_content_index].context == pContext)
    {
        return g_dynamic_contents + g_dynamic_content_index;
    }

    if (g_dynamic_content_count > 0)
    {
        for (i=0; i<_MAX_DYNAMIC_CONTENTS; i++)
        {
            if (g_dynamic_contents[i].context == pContext)
            {
                g_dynamic_content_index = i;
                return g_dynamic_contents + g_dynamic_content_index;
            }
        }
    }

    return NULL;
}

static CDCPair *iniAllocCDCPair(IniContext *pContext)
{
    int i;
    CDCPair *pair;
    if ((pair=iniGetCDCPair(pContext)) != NULL)
    {
        return pair;
    }

    if (g_dynamic_content_count == _MAX_DYNAMIC_CONTENTS)
    {
        return NULL;
    }

    for (i=0; i<_MAX_DYNAMIC_CONTENTS; i++)
    {
        if (!g_dynamic_contents[i].used)
        {
            g_dynamic_contents[i].used = true;
            g_dynamic_contents[i].context = pContext;
            g_dynamic_content_index = i;
            g_dynamic_content_count++;
            return g_dynamic_contents + g_dynamic_content_index;
        }
    }

    return NULL;
}

static DynamicContents *iniAllocDynamicContent(IniContext *pContext)
{
    static CDCPair *pair;

    pair = iniAllocCDCPair(pContext);
    if (pair == NULL)
    {
        return NULL;
    }
    return &pair->dynamicContents;
}

static SetDirectiveVars *iniGetVars(IniContext *pContext)
{
    static CDCPair *pair;

    pair = iniGetCDCPair(pContext);
    if (pair == NULL)
    {
        return NULL;
    }
    return &pair->set;
}

static DynamicAnnotations *iniAllocDynamicAnnotation(IniContext *pContext)
{
    static CDCPair *pair;

    pair = iniAllocCDCPair(pContext);
    if (pair == NULL)
    {
        return NULL;
    }
    return &pair->dynamicAnnotations;
}

static AnnotationEntry *iniGetAnnotations(IniContext *pContext)
{
    static CDCPair *pair;

    pair = iniGetCDCPair(pContext);
    if (pair == NULL)
    {
        return NULL;
    }
    return pair->dynamicAnnotations.annotations;
}

static SetDirectiveVars *iniAllocVars(IniContext *pContext, const bool initVars)
{
    static CDCPair *pair;
    SetDirectiveVars *set;

    set = iniGetVars(pContext);
    if (set == NULL)
    {
        pair = iniAllocCDCPair(pContext);
        if (pair == NULL)
        {
            return NULL;
        }
        set = &pair->set;
    }

    if (initVars && set->vars == NULL)
    {
        set->vars = (HashArray *)malloc(sizeof(HashArray));
        if (set->vars == NULL)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail",
                    __LINE__, (int)sizeof(HashArray));
            return NULL;
        }
        if (hash_init_ex(set->vars, simple_hash, 17, 0.75, 0, true) != 0)
        {
            free(set->vars);
            set->vars = NULL;
            return NULL;
        }
    }

    return set;
}

static void iniFreeDynamicContent(IniContext *pContext)
{
    CDCPair *pCDCPair;
    DynamicContents *pDynamicContents;
    DynamicAnnotations *pDynamicAnnotations;
    int i;

    if (g_dynamic_content_count == 0)
    {
        return;
    }

    if (g_dynamic_contents[g_dynamic_content_index].context == pContext)
    {
        pCDCPair = g_dynamic_contents + g_dynamic_content_index;
    }
    else
    {
        pCDCPair = NULL;
        for (i=0; i<_MAX_DYNAMIC_CONTENTS; i++)
        {
            if (g_dynamic_contents[i].context == pContext)
            {
                pCDCPair = g_dynamic_contents + i;
                break;
            }
        }
        if (pCDCPair == NULL)
        {
            return;
        }
    }

    pDynamicContents = &pCDCPair->dynamicContents;
    if (pDynamicContents->contents != NULL)
    {
        for (i=0; i<pDynamicContents->count; i++)
        {
            if (pDynamicContents->contents[i] != NULL)
            {
                free(pDynamicContents->contents[i]);
            }
        }
        free(pDynamicContents->contents);
        pDynamicContents->contents = NULL;
        pDynamicContents->alloc_count = 0;
        pDynamicContents->count = 0;
    }

    pDynamicAnnotations = &pCDCPair->dynamicAnnotations;
    if (pDynamicAnnotations->annotations != NULL)
    {
        free(pDynamicAnnotations->annotations);
        pDynamicAnnotations->annotations = NULL;
        pDynamicAnnotations->alloc_count = 0;
        pDynamicAnnotations->count = 0;
    }

    pCDCPair->used = false;
    pCDCPair->context = NULL;
    g_dynamic_content_count--;
}

static char *iniAllocContent(IniContext *pContext, const int content_len)
{
    char *buff;
    DynamicContents *pDynamicContents;
    pDynamicContents = iniAllocDynamicContent(pContext);
    if (pDynamicContents == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc dynamic contents fail", __LINE__);
        return NULL;
    }
    if (pDynamicContents->count >= pDynamicContents->alloc_count)
    {
        int alloc_count;
        int bytes;
        char **contents;
        if (pDynamicContents->alloc_count == 0)
        {
            alloc_count = 8;
        }
        else
        {
            alloc_count = pDynamicContents->alloc_count * 2;
        }
        bytes = sizeof(char *) * alloc_count;
        contents = (char **)malloc(bytes);
        if (contents == NULL)
        {
            logError("file: "__FILE__", line: %d, "
                    "malloc %d bytes fail", __LINE__, bytes);
            return NULL;
        }
        memset(contents, 0, bytes);
        if (pDynamicContents->count > 0)
        {
            memcpy(contents, pDynamicContents->contents,
                    sizeof(char *) * pDynamicContents->count);
            free(pDynamicContents->contents);
        }
        pDynamicContents->contents = contents;
        pDynamicContents->alloc_count = alloc_count;
    }

    buff = malloc(content_len);
    if (buff == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, content_len);
        return NULL;
    }
    pDynamicContents->contents[pDynamicContents->count++] = buff;
    return buff;
}

static int iniCheckAllocAnnotations(DynamicAnnotations *pDynamicAnnotations,
        const int annotation_count)
{
    int alloc_count;
    int bytes;
    AnnotationEntry *annotations;

    if (pDynamicAnnotations->count + annotation_count <
            pDynamicAnnotations->alloc_count)
    {
        return 0;
    }

    if (pDynamicAnnotations->alloc_count == 0)
    {
        alloc_count = 8;
    }
    else
    {
        alloc_count = pDynamicAnnotations->alloc_count * 2;
    }
    while (alloc_count <= pDynamicAnnotations->count + annotation_count)
    {
        alloc_count *= 2;
    }
    bytes = sizeof(AnnotationEntry) * alloc_count;
    annotations = (AnnotationEntry *)malloc(bytes);
    if (annotations == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }
    memset(annotations, 0, bytes);
    if (pDynamicAnnotations->count > 0)
    {
        memcpy(annotations, pDynamicAnnotations->annotations,
                sizeof(AnnotationEntry) * pDynamicAnnotations->count);
        free(pDynamicAnnotations->annotations);
    }
    pDynamicAnnotations->annotations = annotations;
    pDynamicAnnotations->alloc_count = alloc_count;
    return 0;
}

static DynamicAnnotations *iniAllocAnnotations(IniContext *pContext,
        const int annotation_count)
{
    DynamicAnnotations *pDynamicAnnotations;
    pDynamicAnnotations = iniAllocDynamicAnnotation(pContext);
    if (pDynamicAnnotations == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc dynamic annotations fail", __LINE__);
        return NULL;
    }
    if (iniCheckAllocAnnotations(pDynamicAnnotations, annotation_count) == 0)
    {
        return pDynamicAnnotations;
    }
    else
    {
        return NULL;
    }
}

static bool iniMatchValue(const char *target, char **values, const int count)
{
    int i;
    for (i=0; i<count; i++)
    {
        if (strcmp(target, values[i]) == 0)
        {
            return true;
        }
    }

    return false;
}


static bool iniMatchCIDR(const char *target, const char *ip_addr,
        const char *pSlash)
{
	char *pReservedEnd;
	char ip_part[IP_ADDRESS_SIZE];
	int ip_len;
	int network_bits;
	struct in_addr addr;
	uint32_t network_hip;
	uint32_t target_hip;
    uint32_t network_mask;

	ip_len = pSlash - ip_addr;
	if (ip_len == 0 || ip_len >= IP_ADDRESS_SIZE)
	{
		logWarning("file: "__FILE__", line: %d, "
			"invalid ip address: %s", __LINE__, ip_addr);
		return false;
	}
	memcpy(ip_part, ip_addr, ip_len);
	*(ip_part + ip_len) = '\0';
	
	pReservedEnd = NULL;
	network_bits = strtol(pSlash + 1, &pReservedEnd, 10);
	if (!(pReservedEnd == NULL || *pReservedEnd == '\0'))
	{
		logError("file: "__FILE__", line: %d, " \
			"ip address: %s, invalid network bits: %s",
			__LINE__, ip_addr, pSlash + 1);
		return false;
	}

	if (network_bits < 8 || network_bits > 30)
	{
		logError("file: "__FILE__", line: %d, " \
			"ip address: %s, invalid network bits: %d, " \
			"it should >= 8 and <= 30", \
			__LINE__, ip_addr, network_bits);
		return false;
	}

	if (inet_pton(AF_INET, ip_part, &addr) != 1)
	{
		logError("file: "__FILE__", line: %d, " \
			"ip address: %s, invalid ip part: %s", \
			__LINE__, ip_addr, ip_part);
		return false;
	}
	network_hip = ntohl(addr.s_addr);

	if (inet_pton(AF_INET, target, &addr) != 1)
	{
		logError("file: "__FILE__", line: %d, "
			"invalid ip: %s", __LINE__, target);
		return false;
	}
	target_hip = ntohl(addr.s_addr);

    network_mask = ((1 << network_bits) - 1) << (32 - network_bits);
    return (target_hip & network_mask) == (network_hip & network_mask);
}

static bool iniMatchIP(const char *target, char **values, const int count)
{
    int i;
	char *pSlash;

    for (i=0; i<count; i++)
    {
        pSlash = strchr(values[i], '/');
        if (pSlash == NULL)
        {
            if (strcmp(target, values[i]) == 0)
            {
                return true;
            }
        }
        else
        {
            if (iniMatchCIDR(target, values[i], pSlash))
            {
                return true;
            }
        }
    }

    return false;
}

static bool iniCalcCondition(char *condition, const int condition_len,
         IniContext *pContext)
{
    /*
     * current only support %{VARIABLE} in [x,y,..]
     * support variables are: LOCAL_IP, LOCAL_HOST and
     * variables by #@set directive.
     * such as: %{LOCAL_IP} in [10.0.11.89,10.0.11.99]
     * local ip support CIDR addresses such as 172.16.12.0/22
     **/
#define _PREPROCESS_VARIABLE_TYPE_LOCAL_IP   1
#define _PREPROCESS_VARIABLE_TYPE_LOCAL_HOST 2
#define _PREPROCESS_VARIABLE_TYPE_SET        3
#define _PREPROCESS_MAX_LIST_VALUE_COUNT    32
    char *p;
    char *pEnd;
    char *pBraceEnd;
    char *pSquareEnd;
    char *values[_PREPROCESS_MAX_LIST_VALUE_COUNT];
    char *varStr = NULL;
    int varLen = 0;
    int varType;
    int count;
    int len;
    int i;

    pEnd = condition + condition_len;
    p = pEnd - 1;
    while (p > condition && (*p == ' ' || *p == '\t'))
    {
        p--;
    }
    if (*p != ']')
    {
		logWarning("file: "__FILE__", line: %d, "
                "expect \"]\", condition: %.*s", __LINE__,
                condition_len, condition);
        return false;
    }
    pSquareEnd = p;

    p = condition;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }

    len = pEnd - p;
    if (len < 8 || !(*p == '%' && *(p+1) == '{'))
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid condition: %.*s, "
                "correct format: %%{variable} in [...]",
                __LINE__, condition_len, condition);
        return false;
    }

    if ((len > _PREPROCESS_VARIABLE_LEN_LOCAL_IP) &&
            (memcmp(p, _PREPROCESS_VARIABLE_STR_LOCAL_IP,
                _PREPROCESS_VARIABLE_LEN_LOCAL_IP) == 0))
    {
        varType = _PREPROCESS_VARIABLE_TYPE_LOCAL_IP;
        p += _PREPROCESS_VARIABLE_LEN_LOCAL_IP;
    }
    else if ((len > _PREPROCESS_VARIABLE_LEN_LOCAL_HOST) &&
            memcmp(p, _PREPROCESS_VARIABLE_STR_LOCAL_HOST,
                _PREPROCESS_VARIABLE_LEN_LOCAL_HOST) == 0)
    {
        varType = _PREPROCESS_VARIABLE_TYPE_LOCAL_HOST;
        p += _PREPROCESS_VARIABLE_LEN_LOCAL_HOST;
    }
    else
    {
        varType = _PREPROCESS_VARIABLE_TYPE_SET;
        pBraceEnd = (char *)memchr(p + 2, '}', len - 2);
        if (pBraceEnd == NULL)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid condition: %.*s, expect }",
                    __LINE__, condition_len, condition);
            return false;
        }

        varStr = p + 2;
        varLen = pBraceEnd - varStr;
        if (varLen == 0)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid condition: %.*s, "
                    "expect variable name", __LINE__,
                    condition_len, condition);
            return false;
        }
        p = pBraceEnd + 1;
    }

    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (pEnd - p < 4 || memcmp(p, "in", 2) != 0)
    {
		logWarning("file: "__FILE__", line: %d, "
                "expect \"in\", condition: %.*s", __LINE__,
                condition_len, condition);
        return false;
    }
    p += 2;  //skip in

    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (*p != '[')
    {
		logWarning("file: "__FILE__", line: %d, "
                "expect \"[\", condition: %.*s", __LINE__,
                condition_len, condition);
        return false;
    }

    *pSquareEnd = '\0';
    count = splitEx(p + 1, ',', values,
            _PREPROCESS_MAX_LIST_VALUE_COUNT);
    for (i=0; i<count; i++)
    {
        values[i] = fc_trim(values[i]);
    }
    if (varType == _PREPROCESS_VARIABLE_TYPE_LOCAL_HOST)
    {
        char host[128];
        if (gethostname(host, sizeof(host)) != 0)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "call gethostname fail, "
                    "errno: %d, error info: %s", __LINE__,
                    errno, STRERROR(errno));
            return false;
        }
        return iniMatchValue(host, values, count);
    }
    else if (varType == _PREPROCESS_VARIABLE_TYPE_LOCAL_IP)
    {
        const char *local_ip;
        local_ip = get_first_local_ip();
        while (local_ip != NULL)
        {
            if (iniMatchIP(local_ip, values, count))
            {
                return true;
            }
            local_ip = get_next_local_ip(local_ip);
        }
    }
    else
    {
        char *value;
        SetDirectiveVars *set;

        set = iniGetVars(pContext);
        if (set != NULL && set->vars != NULL)
        {
            value = (char *)hash_find(set->vars, varStr, varLen);
            if (value == NULL)
            {
                logWarning("file: "__FILE__", line: %d, "
                        "variable \"%.*s\" not exist", __LINE__,
                        varLen, varStr);
            }
            else
            {
                return iniMatchValue(value, values, count);
            }
        }
        else
        {
            logWarning("file: "__FILE__", line: %d, "
                    "variable \"%.*s\" not exist", __LINE__,
                    varLen, varStr);
            return false;
        }
    }

    return false;
}

static char *iniFindTag(char *content, char *pStart,
        const char *tagStr, const int tagLen)
{
    char *p;

    while (1)
    {
        p = strstr(pStart, tagStr);
        if (p == NULL)
        {
            return NULL;
        }
        if (isLeadingSpacesLine(content, p))
        {
            return p;
        }
        pStart = p + tagLen;
    }
}

static char *iniFindAloneTag(char *content, const int content_len,
        char *pStart, const char *tagStr, const int tagLen)
{
    char *p;

    while ((p=iniFindTag(content, pStart, tagStr, tagLen)) != NULL)
    {
        if (isTrailingSpacesLine(p + tagLen, content + content_len))
        {
            return p;
        }
    }

    return NULL;
}

static int iniDoProccessSet(char *pSet, char **ppSetEnd,
        IniContext *pContext)
{
    char *pStart;
    char buff[FAST_INI_ITEM_NAME_LEN + FAST_INI_ITEM_VALUE_LEN + 1];
    char output[256];
    int result;
    int len;
    bool is_exec;
    char *parts[2];
    char *key;
    char *value;
    int value_len;
    char *new_value;
    SetDirectiveVars *set;

    pStart = pSet + _PREPROCESS_TAG_LEN_SET;
    *ppSetEnd = strchr(pStart, '\n');
    if (*ppSetEnd == NULL) {
        return EINVAL;
    }

    len = *ppSetEnd - pStart;
    if (len <= 1 || len >= (int)sizeof(buff)) {
        return EINVAL;
    }

    memcpy(buff, pStart, len);
    *(buff + len) = '\0';
    if (splitEx(buff, '=', parts, 2) != 2) {
        logWarning("file: "__FILE__", line: %d, "
                "invalid set format: %s%s",
                __LINE__, _PREPROCESS_TAG_STR_SET, buff);
        return EFAULT;
    }

    if ((set=iniAllocVars(pContext, true)) == NULL) {
        return ENOMEM;
    }

    key = fc_trim(parts[0]);
    value = fc_trim(parts[1]);
    value_len = strlen(value);
    is_exec = (value_len > 3 && (*value == '$' && *(value + 1) == '(')
            &&  *(value + value_len - 1) == ')');

    pStart = strstr(value, "%{");
    if (pStart != NULL && strchr(pStart + 2, '}') != NULL) {
        new_value = doReplaceVars(pContext, value, _LINE_BUFFER_SIZE);
        if (new_value != NULL) {
            value_len = strlen(new_value);
        }
        else {
            new_value = value;  //rollback
        }
    }
    else {
        new_value = value;
    }

    if (is_exec) {
        char *cmd;
        cmd = new_value + 2;
        *(new_value + value_len - 1) = '\0'; //remove ')'
        logDebug("file: "__FILE__", line: %d, cmd: %s", __LINE__, cmd);

        if ((pContext->flags & FAST_INI_FLAGS_SHELL_EXECUTE) != 0) {
            if ((result=getExecResult(cmd, output, sizeof(output))) != 0) {
                logWarning("file: "__FILE__", line: %d, "
                        "exec %s fail, errno: %d, error info: %s",
                        __LINE__, cmd, result, STRERROR(result));
                return result;
            }
            if (*output == '\0') {
                logWarning("file: "__FILE__", line: %d, "
                        "empty reply when exec: %s", __LINE__, cmd);
            }

            fc_trim(output);
            value_len = strlen(output);
            if (new_value != value) {
                free(new_value);
            }
            new_value = strdup(output);
            if (new_value == NULL) {
                logWarning("file: "__FILE__", line: %d, "
                        "malloc %d bytes fail", __LINE__, value_len + 1);
                new_value = value;
                value_len = 0;
            }
        }
        else {
            logWarning("file: "__FILE__", line: %d, "
                    "shell execute disabled, cmd: %s", __LINE__, cmd);
            *new_value = '\0';
            value_len = 0;
        }
    }

    result = hash_insert_ex(set->vars, key, strlen(key),
            new_value, value_len + 1, false);
    if (new_value != value) {
        free(new_value);
    }
    return result >= 0 ? 0 : -1 * result;
}

static int iniProccessSet(char *content, char *pEnd,
        IniContext *pContext)
{
    int result;
    SetDirectiveVars *set;
    char *pStart;
    char *pSet;
    char *pSetEnd;

    if ((set=iniAllocVars(pContext, false)) == NULL)
    {
        return ENOMEM;
    }

    pStart = content + set->offset;
    while (pStart < pEnd)
    {
        pSet = iniFindTag(content, pStart, _PREPROCESS_TAG_STR_SET,
                _PREPROCESS_TAG_LEN_SET);
        if (pSet == NULL || pSet >= pEnd)
        {
            break;
        }

        if ((result=iniDoProccessSet(pSet, &pSetEnd, pContext)) == 0)
        {
            pStart = pSetEnd;
        }
        else
        {
            if (result == EINVAL)
            {
                char *pNewLine;;
                pNewLine = pSet + _PREPROCESS_TAG_LEN_SET;
                while (pNewLine < pEnd && *pNewLine != '\n')
                {
                    ++pNewLine;
                }
                logWarning("file: "__FILE__", line: %d, "
                        "invalid set format: %.*s", __LINE__,
                        (int)(pNewLine - pSet), pSet);
            }
            pStart = pSet + _PREPROCESS_TAG_LEN_SET;
        }
    }

    set->offset = pEnd - content;
    return 0;
}

static char *iniProccessIf(char *content, const int content_len,
        int *offset, IniContext *pContext, int *new_content_len)
{
    char *pStart;
    char *pEnd;
    char *pCondition;
    char *pElse;
    char *pIfPart;
    char *pElsePart;
    int conditionLen;
    int ifPartLen;
    int elsePartLen;
    int copyLen;
    char *newContent;
    char *pDest;

    *new_content_len = content_len;
    pStart = iniFindTag(content, content + (*offset),
            _PREPROCESS_TAG_STR_IF, _PREPROCESS_TAG_LEN_IF);
    if (pStart == NULL)
    {
        *offset = *new_content_len;
        iniProccessSet(content, content + content_len, pContext);
        return content;
    }

    iniProccessSet(content, pStart, pContext);

    pCondition = pStart + _PREPROCESS_TAG_LEN_IF;
    pIfPart = strchr(pCondition, '\n');
    if (pIfPart == NULL)
    {
        logWarning("file: "__FILE__", line: %d, "
                "expect new line (\\n) for %s",
                __LINE__, pStart);
        *offset = *new_content_len;
        return content;
    }
    conditionLen = pIfPart - pCondition;

    pEnd = iniFindAloneTag(content, content_len, pIfPart,
            _PREPROCESS_TAG_STR_ENDIF, _PREPROCESS_TAG_LEN_ENDIF);
    if (pEnd == NULL)
    {
        logWarning("file: "__FILE__", line: %d, "
                "expect %s for %.*s",
                __LINE__, _PREPROCESS_TAG_STR_ENDIF,
                (int)(pIfPart - pStart), pStart);
        *offset = *new_content_len;
        return content;
    }

    pElse = iniFindAloneTag(content, content_len, pIfPart,
            _PREPROCESS_TAG_STR_ELSE, _PREPROCESS_TAG_LEN_ELSE);
    if (pElse == NULL || pElse > pEnd)
    {
        ifPartLen = pEnd - pIfPart;
        pElsePart = NULL;
        elsePartLen = 0;
    }
    else
    {
        ifPartLen = pElse - pIfPart;
        pElsePart = strchr(pElse + _PREPROCESS_TAG_LEN_ELSE, '\n');
        if (pElsePart == NULL)
        {
            *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDIF) - content;
            return content;
        }

        elsePartLen = pEnd - pElsePart;
    }

    newContent = iniAllocContent(pContext, content_len);
    if (newContent == NULL)
    {
        *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDIF) - content;
        return NULL;
    }

    pDest = newContent;
    copyLen = pStart - content;
    if (copyLen > 0)
    {
        memcpy(pDest, content, copyLen);
        pDest += copyLen;
    }
    *offset = copyLen;

    if (iniCalcCondition(pCondition, conditionLen, pContext))
    {
        if (ifPartLen > 0)
        {
            memcpy(pDest, pIfPart, ifPartLen);
            pDest += ifPartLen;
        }
    }
    else
    {
        if (elsePartLen > 0)
        {
            memcpy(pDest, pElsePart, elsePartLen);
            pDest += elsePartLen;
        }
    }

    copyLen = (content + content_len) - (pEnd + _PREPROCESS_TAG_LEN_ENDIF);
    if (copyLen > 0)
    {
        memcpy(pDest, pEnd + _PREPROCESS_TAG_LEN_ENDIF, copyLen);
        pDest += copyLen;
    }

    *pDest = '\0';
    *new_content_len = pDest - newContent;
    return newContent;
}

static char *iniGetInteger(char *str, char *pEnd, int *nlen)
{
    char *p;
    char *pNumber;

    p = str;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }

    pNumber = p;
    while (p < pEnd && (*p >= '0' && *p <= '9'))
    {
        p++;
    }

    *nlen = p - pNumber;
    return pNumber;
}

static int iniParseForRange(char *range, const int range_len,
        char **id, int *idLen, int *start, int *end, int *step)
{
    /**
     *
     * #@for i from 0 to 15 step 1
     */


    char *p;
    char *pEnd;
    char *pNumber;
    int nlen;

    pEnd = range + range_len;
    p = range;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }

    if (pEnd - p < 10)
    {
		logWarning("file: "__FILE__", line: %d, "
                "unkown for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }

    *id = p;
    while (p < pEnd && !(*p == ' ' || *p == '\t'))
    {
        p++;
    }
    *idLen = p - *id;
    if (*idLen == 0 || *idLen > 64)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }

    if (pEnd - p < 8)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }

    p++;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (!(memcmp(p, _PREPROCESS_TAG_STR_FOR_FROM,
                    _PREPROCESS_TAG_LEN_FOR_FROM) == 0 &&
                (*(p+_PREPROCESS_TAG_LEN_FOR_FROM) == ' ' ||
                 *(p+_PREPROCESS_TAG_LEN_FOR_FROM) == '\t')))
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    p += _PREPROCESS_TAG_LEN_FOR_FROM + 1;
    pNumber = iniGetInteger(p, pEnd, &nlen);
    if (nlen == 0)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    *start = atoi(pNumber);
    p = pNumber + nlen;

    if (pEnd - p < 4 || !(*p == ' ' || *p == '\t'))
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    p++;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (!(memcmp(p, _PREPROCESS_TAG_STR_FOR_TO,
                    _PREPROCESS_TAG_LEN_FOR_TO) == 0 &&
                (*(p+_PREPROCESS_TAG_LEN_FOR_TO) == ' ' ||
                 *(p+_PREPROCESS_TAG_LEN_FOR_TO) == '\t')))
    {
		logWarning("file: "__FILE__", line: %d, "
                "unkown for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    p += _PREPROCESS_TAG_LEN_FOR_TO + 1;
    pNumber = iniGetInteger(p, pEnd, &nlen);
    if (nlen == 0)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    *end = atoi(pNumber);
    p = pNumber + nlen;

    if (p == pEnd)
    {
        *step = 1;
        return 0;
    }

    if (!(*p == ' ' || *p == '\t'))
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (!(memcmp(p, _PREPROCESS_TAG_STR_FOR_STEP,
                    _PREPROCESS_TAG_LEN_FOR_STEP) == 0 &&
                (*(p+_PREPROCESS_TAG_LEN_FOR_STEP) == ' ' ||
                 *(p+_PREPROCESS_TAG_LEN_FOR_STEP) == '\t')))
    {
		logWarning("file: "__FILE__", line: %d, "
                "unkown for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    p += _PREPROCESS_TAG_LEN_FOR_STEP + 1;
    pNumber = iniGetInteger(p, pEnd, &nlen);
    if (nlen == 0)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }
    *step = atoi(pNumber);
    p = pNumber + nlen;
    while (p < pEnd && (*p == ' ' || *p == '\t'))
    {
        p++;
    }
    if (p != pEnd)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid for range: %.*s", __LINE__,
                range_len, range);
        return EINVAL;
    }

    return 0;
}

static char *iniProccessFor(char *content, const int content_len,
        int *offset, IniContext *pContext, int *new_content_len)
{
    char *pStart;
    char *pEnd;
    char *pForRange;
    char *pForBlock;
    char *id;
    char tag[80];
    char value[16];
    int idLen;
    int rangeLen;
    int forBlockLen;
    int start;
    int end;
    int step;
    int count;
    int i;
    int copyLen;
    int tagLen;
    int valueLen;
    char *newContent;
    char *pDest;

    *new_content_len = content_len;
    pStart = iniFindTag(content, content + (*offset),
            _PREPROCESS_TAG_STR_FOR, _PREPROCESS_TAG_LEN_FOR);
    if (pStart == NULL)
    {
        *offset = *new_content_len;
        return content;
    }
    pForRange = pStart + _PREPROCESS_TAG_LEN_FOR;
    pForBlock = strchr(pForRange, '\n');
    if (pForBlock == NULL)
    {
        logWarning("file: "__FILE__", line: %d, "
                "expect new line (\\n) for %s",
                __LINE__, pStart);
        *offset = *new_content_len;
        return content;
    }
    rangeLen = pForBlock - pForRange;

    pEnd = iniFindAloneTag(content, content_len, pForBlock,
            _PREPROCESS_TAG_STR_ENDFOR, _PREPROCESS_TAG_LEN_ENDFOR);
    if (pEnd == NULL)
    {
        logWarning("file: "__FILE__", line: %d, "
                "expect %s for %s", __LINE__,
                _PREPROCESS_TAG_STR_ENDFOR, pStart);
        *offset = *new_content_len;
        return content;
    }
    forBlockLen = pEnd - pForBlock;

    if (iniParseForRange(pForRange, rangeLen, &id, &idLen,
                &start, &end, &step) != 0)
    {
        logWarning("file: "__FILE__", line: %d, "
                "invalid statement: %.*s",
                __LINE__, (int)(pForBlock - pStart), pStart);
        *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDFOR) - content;
        return content;
    }
    if (step == 0)
    {
		logWarning("file: "__FILE__", line: %d, "
                "invalid step: %d for range: %.*s, set step to 1",
                __LINE__, step, rangeLen, pForRange);
        *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDFOR) - content;
        return content;
    }
    else
    {
        count = (end - start) / step;
        if (count < 0)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "invalid step: %d for range: %.*s", __LINE__,
                    step, rangeLen, pForRange);
            *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDFOR) - content;
            return content;
        }
    }

    newContent = iniAllocContent(pContext, content_len +
            (forBlockLen + 16) * count);
    if (newContent == NULL)
    {
        *offset = (pEnd + _PREPROCESS_TAG_LEN_ENDFOR) - content;
        return NULL;
    }

    pDest = newContent;
    copyLen = pStart - content;
    if (copyLen > 0)
    {
        memcpy(pDest, content, copyLen);
        pDest += copyLen;
    }
    *offset = copyLen;

    tagLen = sprintf(tag, "{$%.*s}", idLen, id);
    for (i=start; i<=end; i+=step)
    {
        char *p;
        char *pRemain;
        int remainLen;

        valueLen = sprintf(value, "%d", i);

        pRemain = pForBlock;
        remainLen = forBlockLen;
        while (remainLen >= tagLen)
        {
            p = (char *)memmem(pRemain, remainLen, tag, tagLen);
            if (p == NULL)
            {
                memcpy(pDest, pRemain, remainLen);
                pDest += remainLen;
                break;
            }

            copyLen = p - pRemain;
            if (copyLen > 0)
            {
                memcpy(pDest, pRemain, copyLen);
                pDest += copyLen;
            }
            memcpy(pDest, value, valueLen);
            pDest += valueLen;

            pRemain = p + tagLen;
            remainLen -= copyLen + tagLen;
        }
    }

    copyLen = (content + content_len) - (pEnd + _PREPROCESS_TAG_LEN_ENDFOR);
    if (copyLen > 0)
    {
        memcpy(pDest, pEnd + _PREPROCESS_TAG_LEN_ENDFOR, copyLen);
        pDest += copyLen;
    }

    *pDest = '\0';
    *new_content_len = pDest - newContent;
    return newContent;
}

static int iniLoadItemsFromBuffer(char *content, IniContext *pContext)
{
    char *pContent;
    char *new_content;
    int content_len;
    int new_content_len;
    int offset;

    new_content = content;
    new_content_len = strlen(content);

    do
    {
        offset = 0;
        pContent = new_content;
        content_len = new_content_len;
        if ((new_content=iniProccessIf(pContent, content_len,
                        &offset, pContext, &new_content_len)) == NULL)
        {
            return ENOMEM;
        }
    } while (offset < new_content_len);

    do
    {
        offset = 0;
        pContent = new_content;
        content_len = new_content_len;
        if ((new_content=iniProccessFor(pContent, content_len,
                        &offset, pContext, &new_content_len)) == NULL)
        {
            return ENOMEM;
        }
    } while (offset < new_content_len);

    return iniDoLoadItemsFromBuffer(new_content, pContext);
}

static int remallocSection(IniSection *pSection, IniItem **pItem)
{
    int bytes;
    int result;
    int alloc_count;
    IniItem *pNew;

    if (pSection->alloc_count == 0)
    {
        alloc_count = _INIT_ALLOC_ITEM_COUNT;
    }
    else
    {
        alloc_count = pSection->alloc_count * 2;
    }
    bytes = sizeof(IniItem) * alloc_count;
    pNew = (IniItem *)malloc(bytes);
    if (pNew == NULL)
    {
        logError("file: "__FILE__", line: %d, " \
            "malloc %d bytes fail", __LINE__, bytes);
        result = errno != 0 ? errno : ENOMEM;
        return result;
    }

    if (pSection->count > 0)
    {
        memcpy(pNew, pSection->items,
                sizeof(IniItem) * pSection->count);
        free(pSection->items);
    }

    pSection->alloc_count = alloc_count;
    pSection->items = pNew;
    *pItem = pSection->items + pSection->count;
    memset(*pItem, 0, sizeof(IniItem) *
        (pSection->alloc_count - pSection->count));

    return 0;
}

static int iniFreeHashData(const int index, const HashData *data, void *args)
{
	IniSection *pSection;

	pSection = (IniSection *)data->value;
	if (pSection == NULL)
	{
		return 0;
	}

	if (pSection->items != NULL)
	{
		free(pSection->items);
		memset(pSection, 0, sizeof(IniSection));
	}

	free(pSection);
	((HashData *)data)->value = NULL;
	return 0;
}

void iniFreeContext(IniContext *pContext)
{
    SetDirectiveVars *set;
	if (pContext == NULL)
	{
		return;
	}

	if (pContext->global.items != NULL)
	{
		free(pContext->global.items);
		memset(&pContext->global, 0, sizeof(IniSection));
	}

	hash_walk(&pContext->sections, iniFreeHashData, NULL);
	hash_destroy(&pContext->sections);

    set = iniGetVars(pContext);
    if (set != NULL && set->vars != NULL)
    {
        hash_destroy(set->vars);
        free(set->vars);
        set->vars = NULL;
        set->offset = 0;
    }
    iniFreeDynamicContent(pContext);
}

#define INI_FIND_ITEM(szSectionName, szItemName, pContext, pSection, \
        targetItem, pItem, return_val) \
do { \
    if (szSectionName == NULL || *szSectionName == '\0') \
    { \
        pSection = &pContext->global; \
    } \
    else \
    { \
        pSection = (IniSection *)hash_find(&pContext->sections, \
                szSectionName, strlen(szSectionName)); \
        if (pSection == NULL) \
        { \
            return return_val; \
        } \
    } \
    \
    if (pSection->count <= 0) \
    { \
        return return_val; \
    } \
    \
    snprintf(targetItem.name, sizeof(targetItem.name), "%s", szItemName); \
    pItem = (IniItem *)bsearch(&targetItem, pSection->items, \
            pSection->count, sizeof(IniItem), iniCompareByItemName); \
} while (0)


char *iniGetStrValue(const char *szSectionName, const char *szItemName, \
		IniContext *pContext)
{
	IniItem targetItem;
	IniSection *pSection;
	IniItem *pFound;
	IniItem *pItem;
	IniItem *pItemEnd;

	INI_FIND_ITEM(szSectionName, szItemName, pContext, pSection, \
			targetItem, pFound, NULL);
	if (pFound == NULL)
	{
		return NULL;
	}

	pItemEnd = pSection->items + pSection->count;
	for (pItem=pFound+1; pItem<pItemEnd; pItem++)
	{
		if (strcmp(pItem->name, szItemName) != 0)
		{
			break;
		}

        pFound = pItem;
	}

    return pFound->value;
}

int64_t iniGetInt64Value(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, const int64_t nDefaultValue)
{
	char *pValue;

	pValue = iniGetStrValue(szSectionName, szItemName, pContext);
	if (pValue == NULL)
	{
		return nDefaultValue;
	}
	else
	{
		return strtoll(pValue, NULL, 10);
	}
}

int iniGetIntValue(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, const int nDefaultValue)
{
	char *pValue;

	pValue = iniGetStrValue(szSectionName, szItemName, pContext);
	if (pValue == NULL)
	{
		return nDefaultValue;
	}
	else
	{
		return atoi(pValue);
	}
}

double iniGetDoubleValue(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, const double dbDefaultValue)
{
	char *pValue;

	pValue = iniGetStrValue(szSectionName, szItemName, pContext);
	if (pValue == NULL)
	{
		return dbDefaultValue;
	}
	else
	{
		return strtod(pValue, NULL);
	}
}

bool iniGetBoolValue(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, const bool bDefaultValue)
{
	char *pValue;

	pValue = iniGetStrValue(szSectionName, szItemName, pContext);
	if (pValue == NULL)
	{
		return bDefaultValue;
	}
	else
	{
		return FAST_INI_STRING_IS_TRUE(pValue);
	}
}

int iniGetValues(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, char **szValues, const int max_values)
{
	IniItem *pItem;
	IniItem *pItemEnd;
	char **ppValues;
	int count;

	if (max_values <= 0)
	{
		return 0;
	}

	pItem = iniGetValuesEx(szSectionName, szItemName,
			pContext, &count);
	if (count == 0)
	{
		return 0;
	}
	if (count > max_values)
	{
		count = max_values;
	}

	ppValues = szValues;
	pItemEnd = pItem + count;
	for (; pItem<pItemEnd; pItem++)
	{
		*ppValues++ = pItem->value;
	}

	return count;
}

IniItem *iniGetValuesEx(const char *szSectionName, const char *szItemName, \
		IniContext *pContext, int *nTargetCount)
{
	IniItem targetItem;
	IniSection *pSection;
	IniItem *pFound;
	IniItem *pItem;
	IniItem *pItemEnd;
	IniItem *pItemStart;

	*nTargetCount = 0;
	INI_FIND_ITEM(szSectionName, szItemName, pContext, pSection, \
			targetItem, pFound, NULL);
	if (pFound == NULL)
	{
		return NULL;
	}

	*nTargetCount = 1;
	for (pItem=pFound-1; pItem>=pSection->items; pItem--)
	{
		if (strcmp(pItem->name, szItemName) != 0)
		{
			break;
		}

		(*nTargetCount)++;
	}
	pItemStart = pFound - (*nTargetCount) + 1;

	pItemEnd = pSection->items + pSection->count;
	for (pItem=pFound+1; pItem<pItemEnd; pItem++)
	{
		if (strcmp(pItem->name, szItemName) != 0)
		{
			break;
		}

		(*nTargetCount)++;
	}

	return pItemStart;
}

static int iniPrintHashData(const int index, const HashData *data, void *args)
{
	IniSection *pSection;
	IniItem *pItem;
	IniItem *pItemEnd;
	char section_name[256];
	int section_len;
	int i;

	pSection = (IniSection *)data->value;
	if (pSection == NULL)
	{
		return 0;
	}

	section_len = data->key_len;
	if (section_len >= sizeof(section_name))
	{
		section_len = sizeof(section_name) - 1;
	}

	memcpy(section_name, data->key, section_len);
	*(section_name + section_len) = '\0';

	printf("section: %s, item count: %d\n", section_name, pSection->count);
	if (pSection->count > 0)
	{
		i = 0;
		pItemEnd = pSection->items + pSection->count;
		for (pItem=pSection->items; pItem<pItemEnd; pItem++)
		{
			printf("%d. %s=%s\n", ++i, pItem->name, pItem->value);
		}
	}
	printf("\n");

	return 0;
}

void iniPrintItems(IniContext *pContext)
{
	IniItem *pItem;
	IniItem *pItemEnd;
	int i;

	printf("global section, item count: %d\n", pContext->global.count);
	if (pContext->global.count > 0)
	{
		i = 0;
		pItemEnd = pContext->global.items + pContext->global.count;
		for (pItem=pContext->global.items; pItem<pItemEnd; pItem++)
		{
			printf("%d. %s=%s\n", ++i, pItem->name, pItem->value);
		}
	}
	printf("\n");

	hash_walk(&pContext->sections, iniPrintHashData, NULL);
}

struct section_walk_arg {
    IniSectionInfo *sections;
    int count;
    int size;
};

static int iniSectionWalkCallback(const int index, const HashData *data,
        void *args)
{
    struct section_walk_arg *walk_arg;
	IniSection *pSection;
    char *section_name;
	int section_len;

	pSection = (IniSection *)data->value;
	if (pSection == NULL)
	{
		return 0;
	}

    walk_arg = (struct section_walk_arg *)args;
    if (walk_arg->count >= walk_arg->size)
    {
        return ENOSPC;
    }

	section_len = data->key_len;
	if (section_len > FAST_INI_ITEM_NAME_LEN)
	{
        section_len = FAST_INI_ITEM_NAME_LEN;
	}

    section_name = walk_arg->sections[walk_arg->count].section_name;
	memcpy(section_name, data->key, section_len);
	*(section_name + section_len) = '\0';

    walk_arg->sections[walk_arg->count].pSection = pSection;
    walk_arg->count++;
    return 0;
}

int iniGetSectionNames(IniContext *pContext, IniSectionInfo *sections,
        const int max_size, int *nCount)
{
    struct section_walk_arg walk_arg;
    int result;

    walk_arg.sections = sections;
    walk_arg.count = 0;
    walk_arg.size = max_size;
	result = hash_walk(&pContext->sections, iniSectionWalkCallback, &walk_arg);
    *nCount = walk_arg.count;
    return result;
}

IniItem *iniGetSectionItems(const char *szSectionName, IniContext *pContext,
        int *nCount)
{
	IniSection *pSection;

	if (szSectionName == NULL || *szSectionName == '\0')
	{
		pSection = &pContext->global;
	}
	else
	{
		pSection = (IniSection *)hash_find(&pContext->sections,
				szSectionName, strlen(szSectionName));
		if (pSection == NULL)
		{
            *nCount = 0;
			return NULL;
		}
	}

    *nCount = pSection->count;
    return pSection->items;
}

char *iniGetRequiredStrValueEx(const char *szSectionName, const char *szItemName,
		IniContext *pContext, const int nMinLength)
{
    char *value;
    value = iniGetStrValue(szSectionName, szItemName, pContext);
    if (value == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "item: %s not exist", __LINE__, szItemName);
        return NULL;
    }

    if (nMinLength > 0)
    {
        if (nMinLength == 1 && *value == '\0')
        {
            logError("file: "__FILE__", line: %d, "
                    "item: %s, value is empty", __LINE__, szItemName);
            return NULL;
        }
        else
        {
            int len;
            len = strlen(value);
            if (len < nMinLength)
            {
                logError("file: "__FILE__", line: %d, "
                        "item: %s, value length: %d < min length: %d",
                        __LINE__, szItemName, len, nMinLength);
                return NULL;
            }
        }
    }
    return value;
}

