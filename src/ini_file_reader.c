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
#include "ini_file_reader.h"

#define _LINE_BUFFER_SIZE	   512
#define _INIT_ALLOC_ITEM_COUNT	32

static AnnotationMap *g_annotataionMap = NULL;

static int remallocSection(IniSection *pSection, IniItem **pItem);
static int iniDoLoadFromFile(const char *szFilename, \
		IniContext *pContext);
static int iniDoLoadItemsFromBuffer(char *content, \
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

	result = iniDoLoadItemsFromBuffer(content, pContext);
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

	result = iniDoLoadItemsFromBuffer(content, pContext);
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
}


#define INI_FIND_ITEM(szSectionName, szItemName, pContext, pSection, \
			targetItem, pItem, return_val) \
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
			pSection->count, sizeof(IniItem), iniCompareByItemName);


char *iniGetStrValue(const char *szSectionName, const char *szItemName, \
		IniContext *pContext)
{
	IniItem targetItem;
	IniSection *pSection;
	IniItem *pItem;

	INI_FIND_ITEM(szSectionName, szItemName, pContext, pSection, \
			targetItem, pItem, NULL)

	if (pItem == NULL)
	{
		return NULL;
	}
	else
	{
		return pItem->value;
	}
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
		return  strcasecmp(pValue, "true") == 0 ||
			strcasecmp(pValue, "yes") == 0 ||
			strcasecmp(pValue, "on") == 0 ||
			strcmp(pValue, "1") == 0;
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
			targetItem, pFound, NULL)
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

