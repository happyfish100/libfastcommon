/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

//ini_file_reader.c

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
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

static AnnotationMap *g_annotataionMap = NULL;

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
    bool used;
    IniContext *context;
    DynamicContents dynamicContents;
    SetDirectiveVars set;
} CDCPair;

static int g_dynamic_content_count = 0;
static int g_dynamic_content_index = 0;
static CDCPair g_dynamic_contents[_MAX_DYNAMIC_CONTENTS] = {{false, NULL, {0, 0, NULL}, {0, NULL}}};

//dynamic alloced contents which will be freed when destroy

static int remallocSection(IniSection *pSection, IniItem **pItem);
static int iniDoLoadFromFile(const char *szFilename, \
		IniContext *pContext);
static int iniLoadItemsFromBuffer(char *content, \
		IniContext *pContext);

int iniSetAnnotationCallBack(AnnotationMap *map, int count)
{
    int bytes;
    AnnotationMap *p;

    if (count <= 0)
    {
		logWarning("file: "__FILE__", line: %d, " \
			"iniSetAnnotationCallBack fail count(%d) is incorrectly.", \
			__LINE__, count);
        return EINVAL;
    }

    bytes = sizeof(AnnotationMap) * (count + 1);
    g_annotataionMap = (AnnotationMap *) malloc(bytes);
    if (g_annotataionMap == NULL)
    {
		logError("file: "__FILE__", line: %d, " \
			"malloc (%d) fail, errno: %d, error info: %s", \
			__LINE__, bytes, errno, STRERROR(errno));
        return ENOMEM;
    }

    memcpy(g_annotataionMap, map, sizeof(AnnotationMap) * count);

    p = g_annotataionMap + count;
    p->func_name = NULL;
    p->func_init = NULL;
    p->func_destroy = NULL;
    p->func_get = NULL;

    return 0;
}

void iniDestroyAnnotationCallBack()
{
    AnnotationMap *pAnnoMap;

    pAnnoMap = g_annotataionMap;

    if (pAnnoMap == NULL)
    {
        return;
    }

    while (pAnnoMap->func_name)
    {
        if (pAnnoMap->func_destroy)
        {
            pAnnoMap->func_destroy();
        }
        pAnnoMap++;
    }
    g_annotataionMap = NULL;
}

static int iniCompareByItemName(const void *p1, const void *p2)
{
	return strcmp(((IniItem *)p1)->name, ((IniItem *)p2)->name);
}

static int iniInitContext(IniContext *pContext)
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

	return result;
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
    return iniLoadFromFileEx(szFilename, pContext, false);
}

int iniLoadFromFileEx(const char *szFilename, IniContext *pContext,
    bool ignore_annotation)
{
	int result;
	int len;
	char *pLast;
	char full_filename[MAX_PATH_SIZE];

	if ((result=iniInitContext(pContext)) != 0)
	{
		return result;
	}

    pContext->ignore_annotation = ignore_annotation;

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

	result = iniDoLoadFromFile(full_filename, pContext);
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

int iniLoadFromBuffer(char *content, IniContext *pContext)
{
	int result;

	if ((result=iniInitContext(pContext)) != 0)
	{
		return result;
	}

	result = iniLoadItemsFromBuffer(content, pContext);
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

static int iniDoLoadItemsFromBuffer(char *content, IniContext *pContext)
{
    AnnotationMap *pAnnoMap;
	IniSection *pSection;
	IniItem *pItem;
	char *pLine;
	char *pLastEnd;
	char *pEqualChar;
    char *pItemName;
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

			trim(pIncludeFilename);
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
        else if ((*pLine == '#' && \
            strncasecmp(pLine+1, "@function", 9) == 0 && \
            (*(pLine+10) == ' ' || *(pLine+10) == '\t')))
        {
            if (!pContext->ignore_annotation) {
                nNameLen = strlen(pLine + 11);
                if (nNameLen > FAST_INI_ITEM_NAME_LEN)
                {
                    nNameLen = FAST_INI_ITEM_NAME_LEN;
                }
                memcpy(pFuncName, pLine + 11, nNameLen);
                pFuncName[nNameLen] = '\0';
                trim(pFuncName);
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
            continue;
        }

		trim(pLine);
		if (*pLine == '#' || *pLine == '\0')
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

			trim(section_name);
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
			nNameLen = FAST_INI_ITEM_NAME_LEN;
		}

		if (nValueLen > FAST_INI_ITEM_VALUE_LEN)
		{
			nValueLen = FAST_INI_ITEM_VALUE_LEN;
		}

		if (pSection->count >= pSection->alloc_count)
        {
            result = remallocSection(pSection, &pItem);
            if (result)
            {
                break;
            }
		}

		memcpy(pItem->name, pLine, nNameLen);
		memcpy(pItem->value, pEqualChar + 1, nValueLen);

		trim(pItem->name);
		trim(pItem->value);

        if (isAnnotation)
        {
            isAnnotation = 0;

            if (g_annotataionMap == NULL)
            {
                logWarning("file: "__FILE__", line: %d, " \
                    "not set annotataionMap and (%s) will use " \
                    "the item value (%s)", __LINE__, pItem->name,
                    pItem->value);
                pSection->count++;
                pItem++;
                continue;
            }

            nItemCnt = -1;
            pAnnoMap = g_annotataionMap;
            while (pAnnoMap->func_name)
            {
                if (strcmp(pFuncName, pAnnoMap->func_name) == 0)
                {
                    if (pAnnoMap->func_init)
                    {
                        pAnnoMap->func_init();
                    }

                    if (pAnnoMap->func_get)
                    {
                        nItemCnt = pAnnoMap->func_get(pItem->value, pItemValues, 100);
                    }
                    break;
                }
                pAnnoMap++;
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

            pItemName = pItem->name;
            nNameLen = strlen(pItemName);
            for (i = 0; i < nItemCnt; i++)
            {
                nValueLen = strlen(pItemValues[i]);
                if (nValueLen > FAST_INI_ITEM_VALUE_LEN)
                {
                    nValueLen = FAST_INI_ITEM_VALUE_LEN;
                }
                memcpy(pItem->name, pItemName, nNameLen);
                memcpy(pItem->value, pItemValues[i], nValueLen);
                pItem->value[nValueLen] = '\0';
                pSection->count++;
                pItem++;
                if (pSection->count >= pSection->alloc_count)
                {
                    result = remallocSection(pSection, &pItem);
                    if (result)
                    {
                        break;
                    }
                }
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

    pCDCPair->used = false;
    pCDCPair->context = NULL;
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
    }
    pDynamicContents->alloc_count = 0;
    pDynamicContents->count = 0;
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
        values[i] = trim(values[i]);
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
    char buff[FAST_INI_ITEM_NAME_LEN + FAST_INI_ITEM_VALUE_LEN];
    char output[256];
    int result;
    int len;
    char *parts[2];
    char *key;
    char *value;
    int value_len;
    SetDirectiveVars *set;

    pStart = pSet + _PREPROCESS_TAG_LEN_SET;
    *ppSetEnd = strchr(pStart, '\n');
    if (*ppSetEnd == NULL)
    {
        return EINVAL;
    }

    len = *ppSetEnd - pStart;
    if (len <= 1 || len >= (int)sizeof(buff))
    {
        return EINVAL;
    }

    memcpy(buff, pStart, len);
    *(buff + len) = '\0';

    if (splitEx(buff, '=', parts, 2) != 2)
    {
        logWarning("file: "__FILE__", line: %d, "
                "invalid set format: %s%s",
                __LINE__, _PREPROCESS_TAG_STR_SET, buff);
        return EFAULT;
    }

    if ((set=iniAllocVars(pContext, true)) == NULL)
    {
        return ENOMEM;
    }

    key = trim(parts[0]);
    value = trim(parts[1]);
    value_len = strlen(value);
    if (value_len > 3 && (*value == '$' && *(value + 1) == '(')
            &&  *(value + value_len - 1) == ')')
    {
        char *cmd;
        cmd = value + 2;
        *(value + value_len - 1) = '\0'; //remove '}'
        if ((result=getExecResult(cmd, output, sizeof(output))) != 0)
        {
            logWarning("file: "__FILE__", line: %d, "
                    "exec %s fail, errno: %d, error info: %s",
                    __LINE__, cmd, result, STRERROR(result));
            return result;
        }
        if (*output == '\0')
        {
            logWarning("file: "__FILE__", line: %d, "
                    "empty reply when exec: %s", __LINE__, cmd);
        }
        value = trim(output);
        value_len = strlen(value);
    }

    return hash_insert_ex(set->vars, key, strlen(key),
            value, value_len + 1, false);
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
    int bytes, result;
    IniItem *pNew;

    if (pSection->alloc_count == 0)
    {
        pSection->alloc_count = _INIT_ALLOC_ITEM_COUNT;
    }
    else
    {
        pSection->alloc_count *= 2;
    }
    bytes = sizeof(IniItem) * pSection->alloc_count;
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

    pSection->items = pNew;
    *pItem = pSection->items + pSection->count;
    memset(*pItem, 0, sizeof(IniItem) * \
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
		return INI_STRING_IS_TRUE(pValue);
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

