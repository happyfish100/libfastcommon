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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <math.h>

#include "logger.h"
#include "sockopt.h"
#include "fc_memory.h"
#include "http_func.h"
#include "shared_func.h"

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#else
#ifdef OS_FREEBSD
#include <sys/sysctl.h>
#endif
#endif

char *formatDatetime(const time_t nTime, \
	const char *szDateFormat, \
	char *buff, const int buff_size)
{
	static char szDateBuff[128];
	struct tm tmTime;
	int size;

	localtime_r(&nTime, &tmTime);
	if (buff == NULL)
	{
		buff = szDateBuff;
		size = sizeof(szDateBuff);
	}
	else
	{
		size = buff_size;
	}

	*buff = '\0';
	strftime(buff, size, szDateFormat, &tmTime);
	
	return buff;
}

int getCharLen(const char *s)
{
	unsigned char *p;
	int count = 0;
	
	p = (unsigned char *)s;
	while (*p != '\0')
	{
		if (*p > 127)
		{
			if (*(++p) != '\0')
			{
				p++;
			}
		}
		else
		{
			p++;
		}
		
		count++;
	}
	
	return count;
}

char *replaceCRLF2Space(char *s)
{
	char *p = s;
	
	while (*p != '\0')
	{
		if (*p == '\r' || *p == '\n')
		{
			*p = ' ';
		}
		
		p++;
	}
	
	return s;
}

char *getAbsolutePath(const char *filename, char *szAbsPath, \
		const int pathSize)
{
	char *p;
	int nPathLen;
	char szPath[1024];
	char cwd[256];
	
	p = strrchr(filename, '/');
	if (p == NULL)
	{
		szPath[0] = '\0';
	}
	else
	{
		nPathLen = p - filename;
		if (nPathLen >= sizeof(szPath))
		{
			logError("file: "__FILE__", line: %d, " \
				"filename length: %d is too long, exceeds %d",\
				__LINE__, nPathLen, (int)sizeof(szPath));
			return NULL;
		}
	
		memcpy(szPath, filename, nPathLen);
		szPath[nPathLen] = '\0';
	}
	
	if (szPath[0] == '/')
	{
		snprintf(szAbsPath, pathSize, "%s", szPath);
	}
	else
	{
		if (getcwd(cwd, sizeof(cwd)) == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"call getcwd fail, errno: %d, error info: %s", \
				__LINE__, errno, STRERROR(errno));
			return NULL;
		}
		
		nPathLen = strlen(cwd);
		if (cwd[nPathLen - 1] == '/')
		{
			cwd[nPathLen - 1] = '\0';
		}
		
		if (szPath[0] != '\0')
		{
			snprintf(szAbsPath, pathSize, "%s/%s", cwd, szPath);
		}
		else
		{
			snprintf(szAbsPath, pathSize, "%s", cwd);
		}
	}
	
	return szAbsPath;
}

char *getExeAbsoluteFilename(const char *exeFilename, char *szAbsFilename, \
		const int maxSize)
{
	const char *filename;
	const char *p;
	int nFileLen;
	int nPathLen;
	char cwd[256];
	char szPath[1024];
	
	nFileLen = strlen(exeFilename);
	if (nFileLen >= sizeof(szPath))
	{
		logError("file: "__FILE__", line: %d, " \
			"filename length: %d is too long, exceeds %d!", \
			__LINE__, nFileLen, (int)sizeof(szPath));
		return NULL;
	}
	
	p = strrchr(exeFilename, '/');
	if (p == NULL)
	{
		int i;
		char *search_paths[] = {"/bin", "/usr/bin", "/usr/local/bin"};

		*szPath = '\0';
		filename = exeFilename;
		for (i=0; i<3; i++)
		{
			snprintf(cwd, sizeof(cwd), "%s/%s", \
				search_paths[i], filename);
			if (fileExists(cwd))
			{
				strcpy(szPath, search_paths[i]);
				break;
			}
		}

		if (*szPath == '\0')
		{
			if (!fileExists(filename))
			{
				logError("file: "__FILE__", line: %d, " \
					"can't find exe file %s!", __LINE__, \
					filename);
				return NULL;
			}
		}
		else
		{
			snprintf(szAbsFilename, maxSize, "%s/%s", \
				szPath, filename);
			return szAbsFilename;
		}
	}
	else
	{
		filename = p + 1;
		nPathLen = p - exeFilename;
		memcpy(szPath, exeFilename, nPathLen);
		szPath[nPathLen] = '\0';
	}
	
	if (*szPath == '/')
	{
		snprintf(szAbsFilename, maxSize, "%s/%s", szPath, filename);
	}
	else
	{
		if (getcwd(cwd, sizeof(cwd)) == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"call getcwd fail, errno: %d, error info: %s", \
				__LINE__, errno, STRERROR(errno));
			return NULL;
		}
		
		nPathLen = strlen(cwd);
		if (cwd[nPathLen - 1] == '/')
		{
			cwd[nPathLen - 1] = '\0';
		}
		
		if (*szPath != '\0')
		{
			snprintf(szAbsFilename, maxSize, "%s/%s/%s", \
				cwd, szPath, filename);
		}
		else
		{
			snprintf(szAbsFilename, maxSize, "%s/%s", \
				cwd, filename);
		}
	}
	
	return szAbsFilename;
}

#ifndef WIN32
int getProccessCount(const char *progName, const bool bAllOwners)
{
	int *pids = NULL;
	return getUserProcIds(progName, bAllOwners, pids, 0);
}

int getUserProcIds(const char *progName, const bool bAllOwners, \
		int pids[], const int arrSize)
{
	char path[128]="/proc";
	char fullpath[128];
	struct stat statbuf;
	struct dirent *dirp;
	DIR  *dp;
	int  myuid=getuid();
	int  fd;
	char filepath[128];
	char buf[256];
	char *ptr;
	int  nbytes;
	char procname[64];
	int  cnt=0;
	char *pTargetProg;
	
	if ((dp = opendir(path)) == NULL)
	{
		return -1;
	}
	
	pTargetProg = (char *)fc_malloc(strlen(progName) + 1);
	if (pTargetProg == NULL)
	{
		return -1;
	}

	ptr = strrchr(progName, '/');
	if (ptr == NULL)
	{
		strcpy(pTargetProg, progName);
	}
	else
	{
		strcpy(pTargetProg, ptr + 1);
	}
	
	while ((dirp=readdir(dp)) != NULL)
	{
		if (strcmp(dirp->d_name, ".")==0 || strcmp(dirp->d_name, "..")==0)
		{
			continue;
		}
		
		sprintf(fullpath, "%s/%s", path, dirp->d_name);
		memset(&statbuf, 0, sizeof(statbuf));
		if (lstat(fullpath, &statbuf) < 0)
		{
			continue;
		}
		
		if ((bAllOwners || (statbuf.st_uid == myuid)) && S_ISDIR(statbuf.st_mode))
		{
			sprintf(filepath, "%s/cmdline", fullpath);
			if ((fd = open(filepath, O_RDONLY))<0)
			{
				continue;
			}
			
			memset(buf, 0, 256);
			if ((nbytes = read(fd, buf, 255)) < 0){
				close(fd);
				continue;
			}
			close(fd);
			
			if (*buf == '\0')
			{
				continue;
			}
			
			ptr = strrchr(buf, '/');
			if (ptr == NULL)
			{
				snprintf(procname, 64, "%s", buf);
			}
			else
			{
				snprintf(procname, 64, "%s", ptr + 1);
			}
			
			if (strcmp(procname, pTargetProg) == 0)
			{				
				if (pids != NULL)
				{
					if (cnt >= arrSize)
					{
						break;
					}
					pids[cnt] = atoi(dirp->d_name);
				}
				
				cnt++;
			}
		}
	}
	free(pTargetProg);
	
	closedir(dp);
	return cnt;
}

int getExecResult(const char *command, char *output, const int buff_size)
{
	FILE *fp;
	char *pCurrent;
	int bytes_read;
	int remain_bytes;

	if((fp=popen(command, "r")) == NULL)
	{
        *output = '\0';
		return errno != 0 ? errno : EMFILE;
	}

	pCurrent = output;
	remain_bytes = buff_size - 1;
	while (remain_bytes > 0 && \
		(bytes_read=fread(pCurrent, 1, remain_bytes, fp)) > 0)
	{
		pCurrent += bytes_read;
		remain_bytes -= bytes_read;
	}
	pclose(fp);

	*pCurrent = '\0';
	return remain_bytes > 0 ? 0 : ENOSPC;
}

#endif

int fc_get_path_child_count(const char *path)
{
    int count;
    struct dirent *ent;
    DIR *dir;

	if ((dir=opendir(path)) == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "open dir %s fail, errno: %d, error info: %s",
                __LINE__, path, errno, STRERROR(errno));
        return -1;
    }

    count = 0;
	while ((ent=readdir(dir)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }
        ++count;
    }

	closedir(dir);
	return count;
}

char *toLowercase(char *src)
{
	char *p;
	
	p = src;
	while (*p != '\0')
	{
		if (*p >= 'A' && *p <= 'Z')
		{
			*p += 32;
		}
		p++;
	}
	
	return src;
}

char *toUppercase(char *src)
{
	char *p;
	
	p = src;
	while (*p != '\0')
	{
		if (*p >= 'a' && *p <= 'z')
		{
			*p -= 32;
		}
		p++;
	}
	
	return src;	
}

void daemon_init(bool bCloseFiles)
{
#ifndef WIN32
	pid_t pid;
	int i;
	
	if((pid=fork()) != 0)
	{
		exit(0);
	}
	
	setsid();
	
	if((pid=fork()) != 0)
	{
		exit(0);
	}

#ifdef DEBUG_FLAG
	#define MAX_CORE_FILE_SIZE  (256 * 1024 * 1024)
	if (set_rlimit(RLIMIT_CORE, MAX_CORE_FILE_SIZE) != 0)
	{
		logWarning("file: "__FILE__", line: %d, " \
			"set max core dump file size to %d MB fail, " \
			"errno: %d, error info: %s", \
			__LINE__, MAX_CORE_FILE_SIZE / (1024 * 1024), \
			errno, STRERROR(errno));
	}
#else
	if (chdir("/") != 0)
	{
		logWarning("file: "__FILE__", line: %d, " \
			"change directory to / fail, " \
			"errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
	}
#endif

	if (bCloseFiles)
	{
		for(i=0; i<=2; i++)
		{
			close(i);
		}
	}
#endif

	return;
}

char *bin2hex(const char *s, const int len, char *szHexBuff)
{
	unsigned char *p;
	unsigned char *pEnd;
	int nLen;
	
	nLen = 0;
	pEnd = (unsigned char *)s + len;
	for (p=(unsigned char *)s; p<pEnd; p++)
	{
		nLen += sprintf(szHexBuff + nLen, "%02x", *p);
	}
	
	szHexBuff[nLen] = '\0';
	return szHexBuff;
}

char *hex2bin(const char *s, char *szBinBuff, int *nDestLen)
{
    char buff[3];
    char *pSrc;
    int nSrcLen;
    char *pDest;
    char *pDestEnd;

    nSrcLen = strlen(s);
    if (nSrcLen == 0)
    {
        *nDestLen = 0;
        szBinBuff[0] = '\0';
        return szBinBuff;
    }

    *nDestLen = nSrcLen / 2;
    pSrc = (char *)s;
    buff[2] = '\0';

    pDestEnd = szBinBuff + (*nDestLen);
    for (pDest=szBinBuff; pDest<pDestEnd; pDest++)
    {
        buff[0] = *pSrc++;
        buff[1] = *pSrc++;
        *pDest = (char)strtol(buff, NULL, 16);
    }

    *pDest = '\0';
    return szBinBuff;
}

void printBuffHex(const char *s, const int len)
{
	unsigned char *p;
	int i;
	
	p = (unsigned char *)s;
	for (i=0; i<len; i++)
	{
		printf("%02X", *p);
		p++;
	}
	printf("\n");
}

char *trim_left(char *pStr)
{
	char *p;
	char *pEnd;
	int nDestLen;

	pEnd = pStr + strlen(pStr);
	for (p=pStr; p<pEnd; p++)
	{
		if (!(' ' == *p|| '\n' == *p || '\r' == *p || '\t' == *p))
		{
			break;
		}
	}
	
	if ( p == pStr)
	{
		return pStr;
	}
	
	nDestLen = (pEnd - p) + 1; //including \0
	memmove(pStr, p, nDestLen);

	return pStr;
}

char *trim_right(char *pStr)
{
	int len;
	char *p;
	char *pEnd;

	len = strlen(pStr);
	if (len == 0)
	{
		return pStr;
	}

	pEnd = pStr + len - 1;
	for (p = pEnd;  p>=pStr; p--)
	{
		if (!(' ' == *p || '\n' == *p || '\r' == *p || '\t' == *p))
		{
			break;
		}
	}

	if (p != pEnd)
	{
		*(p+1) = '\0';
	}

	return pStr;
}

void string_ltrim(string_t *s)
{
	char *p;
	char *end;

	end = s->str + s->len;
	for (p=s->str; p<end; p++)
	{
		if (!(' ' == *p|| '\n' == *p || '\r' == *p || '\t' == *p))
		{
			break;
		}
	}

	if (p != s->str)
    {
        s->str = p;
        s->len = end - p;
    }
}

void string_rtrim(string_t *s)
{
	char *p;
	char *end;

	if (s->len == 0)
	{
		return;
	}

	end = s->str + s->len - 1;
	for (p = end; p >= s->str; p--)
	{
		if (!(' ' == *p || '\n' == *p || '\r' == *p || '\t' == *p))
		{
			break;
		}
	}

	if (p != end)
	{
        s->len = (p + 1) - s->str;
	}
}

char *formatDateYYYYMMDDHHMISS(const time_t t, char *szDateBuff, const int nSize)
{
	time_t timer = t;
	struct tm tm;

	localtime_r(&timer, &tm);
	
	snprintf(szDateBuff, nSize, "%04d%02d%02d%02d%02d%02d", \
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, \
		tm.tm_hour, tm.tm_min, tm.tm_sec);

	return szDateBuff;
}

int getOccurCount(const char *src, const char seperator)
{
	int count;
	char *p;

	count = 0;
	p = strchr(src, seperator);
	while (p != NULL)
	{
		count++;
		p = strchr(p + 1, seperator);
	}

	return count;
}

int fc_get_file_line_count_ex(const char *filename,
        const int64_t until_offset, int64_t *line_count)
{
#define READ_BUFFER_SIZE  (256 * 1024)
    int fd;
    int result;
    int read_bytes;
    int64_t remain_bytes;
    char *buff;

    *line_count = 0;
    buff = (char *)fc_malloc(READ_BUFFER_SIZE);
    if (buff == NULL) {
        return ENOMEM;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, filename, result, STRERROR(result));
        free(buff);
        return result;
    }

    if (until_offset >= 0) {
        remain_bytes = until_offset;
    } else {
        remain_bytes = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
    }

    while (remain_bytes > 0) {
        read_bytes = remain_bytes >= READ_BUFFER_SIZE ?
            (READ_BUFFER_SIZE - 1) : remain_bytes;
        read_bytes = read(fd, buff, read_bytes);
        if (read_bytes == 0) {
            break;
        } else if (read_bytes < 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "read file \"%s\" fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            return result;
        }

        *(buff + read_bytes) = '\0';
        *line_count += getOccurCount(buff, '\n');
        remain_bytes -= read_bytes;
    }

    close(fd);
    free(buff);
    return 0;
}

char **split(char *src, const char seperator, const int nMaxCols, int *nColCount)
{
	char **pCols;
	char **pCurrent;
	char *p;
	int i;
	int nLastIndex;

	if (src == NULL)
	{
		*nColCount = 0;
		return NULL;
	}

	*nColCount = 1;
	p = strchr(src, seperator);
	
	while (p != NULL)
	{
		(*nColCount)++;
		p = strchr(p + 1, seperator);
	}

	if (nMaxCols > 0 && (*nColCount) > nMaxCols)
	{
		*nColCount = nMaxCols;
	}
	
	pCurrent = pCols = (char **)fc_malloc(sizeof(char *) * (*nColCount));
	if (pCols == NULL)
	{
		return NULL;
	}

	p = src;
	nLastIndex = *nColCount - 1;
	for (i=0; i<*nColCount; i++)
	{
		*pCurrent = p;
		pCurrent++;

		p = strchr(p, seperator);
		if (i != nLastIndex)
		{
			*p = '\0';
			p++;
		}
	}

	return pCols;
}

void freeSplit(char **p)
{
	if (p != NULL)
	{
		free(p);
	}
}

int splitEx(char *src, const char seperator, char **pCols, const int nMaxCols)
{
	char *p;
	char **pCurrent;
	int count = 0;

	if (nMaxCols <= 0)
	{
		return 0;
	}

	p = src;
	pCurrent = pCols;

	while (true)
	{
		*pCurrent = p;
		pCurrent++;

		count++;
		if (count >= nMaxCols)
		{
			break;
		}

		p = strchr(p, seperator);
		if (p == NULL)
		{
			break;
		}

		*p = '\0';
		p++;
	}

	return count;
}

int split_string_ex(const string_t *src, const char seperator,
        string_t *dest, const int max_count, const bool ignore_empty)
{
	const char *p;
	string_t *current;
    int len;

	p = src->str;
    len = src->len;
	current = dest;
	while (true)
	{
		if ((int)(current - dest) >= max_count)
		{
			break;
		}

		current->str = (char *)p;
		p = memchr(p, seperator, len);
		if (p == NULL)
		{
            if (len > 0 || !ignore_empty)
            {
                current->len = len;
                current++;
            }
			break;
		}

        current->len = (char *)p - current->str;
        len -= current->len + 1;
        if (current->len > 0 || !ignore_empty)
        {
            current++;
        }
		p++;
	}

	return (int)(current - dest);
}

bool fc_match_delim(const char *str, const char *delim)
{
    const char *sp;
    const char *send;
    const char *dp;
    const char *dend;

    send = str + strlen(str);
    dend = delim + strlen(delim);
    for (sp=str; sp<send; sp++)
    {
        for (dp=delim; dp<dend; dp++)
        {
            if (*sp == *dp)
            {
                break;
            }
        }

        if (dp == dend)
        {
            return false;
        }
    }

    return true;
}
 
int fc_split_string(char *src, const char *delim, char **pCols, const int nMaxCols)
{
    char *token;
    char *stringp;
    int count = 0;

    stringp = src;
    while ((token=strsep(&stringp, delim)) != NULL)
    {
        if (count >= nMaxCols)
        {
            break;
        }

        if (fc_match_delim(token, delim))
        {
            continue;
        }

        pCols[count++] = token;
    }

    return count;
}

int my_strtok(char *src, const char *delim, char **pCols, const int nMaxCols)
{
    char *p;
    char **pCurrent;
    int count;
    bool bWordEnd;
    
    if (src == NULL || pCols == NULL)
    {
        return -1;
    }

    if (nMaxCols <= 0)
    {
        return 0;
    }
    
    p = src;
    pCurrent = pCols;
    
    while (*p != '\0')
    {
        if (strchr(delim, *p) == NULL)
        {
            break;
        }
        p++;
    }
    
    if (*p == '\0')
    {
        return 0;
    }
    
    *pCurrent = p;
    bWordEnd = false;
    count = 1;
    if (count >= nMaxCols)
    {
        return count;
    }
    
    while (*p != '\0')
    {
        if (strchr(delim, *p) != NULL)
        {
            *p = '\0';
            bWordEnd = true;
        }
        else
        {
            if (bWordEnd)
            {
                pCurrent++;
                *pCurrent = p;
                
                count++;
                if (count >= nMaxCols)
                {
                    break;
                }

                bWordEnd = false;
            }
        }
        
        p++;
    }

    return count;
}

int str_replace(const string_t *src, const string_t *old_str,
        const string_t *new_str, string_t *dest, const int size)
{
	const char *ps;
	const char *pe;
	const char *p;
	char *pd;
	int len;
	int max_dest_len;
	int remain_len;
    int result;

    if (size <= 0) {
        dest->len = 0;
        return EINVAL;
    }

	max_dest_len = size - 1;
    if (old_str->len == 0) {
        if (src->len <= max_dest_len) {
            dest->len = src->len;
            result = 0;
        } else {
            dest->len = max_dest_len;
            result = EOVERFLOW;
        }
        memcpy(dest->str, src->str, dest->len);
        *(dest->str + dest->len) = '\0';
        return result;
    }

	remain_len = max_dest_len;
	pd = dest->str;
	ps = src->str;
	pe = src->str + src->len;
	while (1) {
		p = strstr(ps, old_str->str);
		if (p == NULL) {
			break;
		}

		len = p - ps;
		if (len > 0) {
			if (len < remain_len) {
				memcpy(pd, ps, len);
				pd += len;
				remain_len -= len;
			} else {
				memcpy(pd, ps, remain_len);
				pd += remain_len;
				*pd = '\0';
                dest->len = pd - dest->str;
				return EOVERFLOW;
			}
		}

		if (new_str->len < remain_len) {
			memcpy(pd, new_str->str, new_str->len);
			pd += new_str->len;
			remain_len -= new_str->len;
        } else {
            memcpy(pd, new_str->str, remain_len);
            pd += remain_len;
            *pd = '\0';
            dest->len = pd - dest->str;
            return EOVERFLOW;
        }

		ps = p + old_str->len;
	}

	len = pe - ps;
    if (len > 0) {
        if (len <= remain_len) {
            result = 0;
        } else {
            len = remain_len;
            result = EOVERFLOW;
        }
        memcpy(pd, ps, len);
        pd += len;
    } else {
        result = 0;
    }
	*pd = '\0';
    dest->len = pd - dest->str;
	return result;
}

bool fileExists(const char *filename)
{
	return access(filename, 0) == 0;
}

bool isDir(const char *filename)
{
	struct stat buf;
	if (stat(filename, &buf) != 0)
	{
		return false;
	}

	return S_ISDIR(buf.st_mode);
}

bool isFile(const char *filename)
{
	struct stat buf;
	if (stat(filename, &buf) != 0)
	{
		return false;
	}

	return S_ISREG(buf.st_mode);
}

void chopPath(char *filePath)
{
	int lastIndex;

	lastIndex = strlen(filePath) - 1;
	while (lastIndex >= 0 && filePath[lastIndex] == '/')
    {
        filePath[lastIndex--] = '\0';
    }
}

int fc_remove_redundant_slashes(const string_t *src,
        string_t *dest, const int size)
{
#define MAX_SUBDIR_COUNT   128
    const bool ignore_empty = true;
    string_t input;
    string_t subdirs[MAX_SUBDIR_COUNT];
    char full_filename[PATH_MAX];
    string_t *sub;
    string_t *end;
    char *p;
    int count;

    if (src->len == 0)
    {
        logError("file: "__FILE__", line: %d, "
                "input path is empty!", __LINE__);
        return EINVAL;
    }

    if (src->str[0] == '/')
    {
        input = *src;
    }
    else
    {
        input.str = full_filename;
        input.len = normalize_path(NULL, src->str,
                full_filename, sizeof(full_filename));
    }

    if (size <= input.len)
    {
        logError("file: "__FILE__", line: %d, "
                "dest buffer is too small! buffer size: %d <= "
                "expected: %d", __LINE__, size, input.len);
        return EOVERFLOW;
    }

    p = dest->str;
    count = split_string_ex(&input, '/', subdirs,
            MAX_SUBDIR_COUNT, ignore_empty);
    if (count == 0)
    {
        *p++ = '/';
    }
    else
    {
        end = subdirs + count;
        for (sub=subdirs; sub<end; sub++)
        {
            *p++ = '/';
            memcpy(p, sub->str, sub->len);
            p += sub->len;
        }
    }

    *p = '\0';
    dest->len = p - dest->str;
    return 0;
}

int getFileContent1(int fd, const char *filename,
        char **buff, int64_t *file_size)
{
    int result;

	if ((*file_size=lseek(fd, 0, SEEK_END)) < 0) {
        *buff = NULL;
        *file_size = 0;
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "lseek file %s fail, "
                "errno: %d, error info: %s", __LINE__,
                filename, result, STRERROR(result));
        return result;
    }

	*buff = (char *)fc_malloc(*file_size + 1);
	if (*buff == NULL) {
		*file_size = 0;
		return ENOMEM;
	}

    result = 0;
    do {
        if (lseek(fd, 0, SEEK_SET) < 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "lseek file %s fail, "
                    "errno: %d, error info: %s", __LINE__,
                    filename, result, STRERROR(result));
            break;
        }
        if (read(fd, *buff, *file_size) != *file_size) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "read from file %s fail, size: %"PRId64", "
                    "errno: %d, error info: %s", __LINE__,
                    filename, *file_size, result, STRERROR(result));
            break;
        }
    } while (0);

    if (result == 0) {
        (*buff)[*file_size] = '\0';
    } else {
        free(*buff);
        *buff = NULL;
        *file_size = 0;
    }
    return result;
}

int getFileContent(const char *filename, char **buff, int64_t *file_size)
{
	int fd;
    int result;

    errno = 0;
    if (!isFile(filename))
    {
		*buff = NULL;
		*file_size = 0;
        if (errno != 0)
        {
            result = errno;
            if (result == ENOENT)
            {
                logError("file: "__FILE__", line: %d, "
                        "file %s not exist", __LINE__, filename);
            }
            else
            {
                logError("file: "__FILE__", line: %d, "
                        "stat %s fail, errno: %d, error info: %s",
                        __LINE__, filename, result, STRERROR(result));
            }
            return result;
        }
        else
        {
            logError("file: "__FILE__", line: %d, "
                    "%s is not a regular file", __LINE__, filename);
            return EINVAL;
        }
    }

	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		*buff = NULL;
		*file_size = 0;
        result = errno != 0 ? errno : ENOENT;
		logError("file: "__FILE__", line: %d, "
			"open file %s fail, "
			"errno: %d, error info: %s", __LINE__,
			filename, result, STRERROR(result));
        return result;
	}

    result = getFileContent1(fd, filename, buff, file_size);
	close(fd);

	return result;
}

int getFileContentEx1(int fd, const char *filename, char *buff,
		int64_t offset, int64_t *size)
{
    int result;
    int read_bytes;

    if ((read_bytes=pread(fd, buff, *size - 1, offset)) < 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "read from file %s fail, offset: %"PRId64", "
                "length: %"PRId64", errno: %d, error info: %s",
                __LINE__, filename, offset, *size - 1,
                result, STRERROR(result));
        *size = 0;
        return result;
    }

    *size = read_bytes;
    *(buff + (*size)) = '\0';
    return 0;
}

int getFileContentEx(const char *filename, char *buff,
		int64_t offset, int64_t *size)
{
	int fd;
    int result;

	if (*size <= 0)
	{
		logError("file: "__FILE__", line: %d, "
			"invalid size: %"PRId64, __LINE__, *size);
		return EINVAL;
	}
	
	fd = open(filename, O_RDONLY);
	if (fd < 0)
	{
		*size = 0;
        result = errno != 0 ? errno : ENOENT;
		logError("file: "__FILE__", line: %d, "
			"open file %s fail, "
			"errno: %d, error info: %s", __LINE__,
			filename, result, STRERROR(result));
		return result;
	}

    result = getFileContentEx1(fd, filename, buff, offset, size);
	close(fd);
	return result;
}

int getFileSize(const char *filename, int64_t *file_size)
{
	struct stat buf;
	if (stat(filename, &buf) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"stat file %s fail, "
			"errno: %d, error info: %s", __LINE__,
			filename, errno, STRERROR(errno));
		return errno != 0 ? errno : EIO;
	}

    *file_size = buf.st_size;
    return 0;
}

int writeToFile(const char *filename, const char *buff, const int file_size)
{
	int fd;
	int result;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
	{
		result = errno != 0 ? errno : EIO;
		logError("file: "__FILE__", line: %d, " \
			"open file %s fail, " \
			"errno: %d, error info: %s", \
			__LINE__, filename, \
			result, STRERROR(result));
		return result;
	}

	if (fc_safe_write(fd, buff, file_size) != file_size)
	{
		result = errno != 0 ? errno : EIO;
		logError("file: "__FILE__", line: %d, " \
			"write file %s fail, " \
			"errno: %d, error info: %s", \
			__LINE__, filename, \
			result, STRERROR(result));
		close(fd);
		return result;
	}

	if (fsync(fd) != 0)
	{
		result = errno != 0 ? errno : EIO;
		logError("file: "__FILE__", line: %d, " \
			"fsync file \"%s\" fail, " \
			"errno: %d, error info: %s", \
			__LINE__, filename, \
			result, STRERROR(result));
		close(fd);
		return result;
	}

	close(fd);
	return 0;
}

int safeWriteToFile(const char *filename, const char *buff, \
		const int file_size)
{
	char tmpFilename[PATH_MAX];
	int result;

	snprintf(tmpFilename, sizeof(tmpFilename), "%s.tmp", filename);
	if ((result=writeToFile(tmpFilename, buff, file_size)) != 0)
	{
		return result;
	}

	if (rename(tmpFilename, filename) != 0)
	{
		result = errno != 0 ? errno : EIO;
		logError("file: "__FILE__", line: %d, "
			"rename file \"%s\" to \"%s\" fail, "
			"errno: %d, error info: %s",
			__LINE__, tmpFilename, filename,
			result, STRERROR(result));
		return result;
	}

	return 0;
}

int fc_copy_file(const char *src_filename, const char *dest_filename)
{
	int result;
	int src_fd;
	int dest_fd;
    int bytes;
    char buff[16 * 1024];

	src_fd = open(src_filename, O_RDONLY);
	if (src_fd < 0)
    {
        result = errno != 0 ? errno : ENOENT;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, errno: %d, error info: %s",
                __LINE__, src_filename, result, STRERROR(result));
        return result;
    }

	dest_fd = open(dest_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dest_fd < 0)
    {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, errno: %d, error info: %s",
                __LINE__, dest_filename, result, STRERROR(result));
        close(src_fd);
        return result;
    }

    result = 0;
    while (1) {
        bytes = fc_safe_read(src_fd, buff, sizeof(buff));
        if (bytes < 0)
        {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "read file %s fail, errno: %d, error info: %s",
                    __LINE__, src_filename, result, STRERROR(result));
            break;
        }
        else if (bytes == 0)
        {
            break;
        }

        if (fc_safe_write(dest_fd, buff, bytes) != bytes)
        {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write file %s fail, errno: %d, error info: %s",
                    __LINE__, dest_filename, result, STRERROR(result));
            break;
        }
    }

    if (result == 0 && fsync(dest_fd) != 0)
    {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "fsync file %s fail, errno: %d, error info: %s",
                __LINE__, dest_filename, result, STRERROR(result));
    }

    close(src_fd);
    close(dest_fd);
    return result;
}

int fc_copy_to_path(const char *src_filename, const char *dest_path)
{
    char dest_filename[PATH_MAX];
    const char *fname;

    fname = strrchr(src_filename, '/');
    if (fname == NULL)
    {
        snprintf(dest_filename, sizeof(dest_filename),
                "%s/%s", dest_path, src_filename);
    }
    else
    {
        snprintf(dest_filename, sizeof(dest_filename),
                "%s%s", dest_path, fname);
    }

    return fc_copy_file(src_filename, dest_filename);
}

void short2buff(const short n, char *buff)
{
	unsigned char *p;
	p = (unsigned char *)buff;
	*p++ = (n >> 8) & 0xFF;
	*p++ = n & 0xFF;
}

short buff2short(const char *buff)
{
	return  (short)((((unsigned char)(*(buff))) << 8) | \
		((unsigned char)(*(buff+1))));
}

void int2buff(const int n, char *buff)
{
	unsigned char *p;
	p = (unsigned char *)buff;
	*p++ = (n >> 24) & 0xFF;
	*p++ = (n >> 16) & 0xFF;
	*p++ = (n >> 8) & 0xFF;
	*p++ = n & 0xFF;
}

int buff2int(const char *buff)
{
	return  (((unsigned char)(*buff)) << 24) | \
		(((unsigned char)(*(buff+1))) << 16) |  \
		(((unsigned char)(*(buff+2))) << 8) | \
		((unsigned char)(*(buff+3)));
}

void long2buff(int64_t n, char *buff)
{
	unsigned char *p;
	p = (unsigned char *)buff;
	*p++ = (n >> 56) & 0xFF;
	*p++ = (n >> 48) & 0xFF;
	*p++ = (n >> 40) & 0xFF;
	*p++ = (n >> 32) & 0xFF;
	*p++ = (n >> 24) & 0xFF;
	*p++ = (n >> 16) & 0xFF;
	*p++ = (n >> 8) & 0xFF;
	*p++ = n & 0xFF;
}

int64_t buff2long(const char *buff)
{
	unsigned char *p;
	p = (unsigned char *)buff;
	return  (((int64_t)(*p)) << 56) | \
		(((int64_t)(*(p+1))) << 48) |  \
		(((int64_t)(*(p+2))) << 40) |  \
		(((int64_t)(*(p+3))) << 32) |  \
		(((int64_t)(*(p+4))) << 24) |  \
		(((int64_t)(*(p+5))) << 16) |  \
		(((int64_t)(*(p+6))) << 8) | \
		((int64_t)(*(p+7)));
}

int fd_gets(int fd, char *buff, const int size, int once_bytes)
{
	char *pDest;
	char *p;
	char *pEnd;
	int read_bytes;
	int remain_bytes;
	int rewind_bytes;

	if (once_bytes <= 0)
	{
		once_bytes = 1;
	}

	pDest = buff;
	remain_bytes = size - 1;
	while (remain_bytes > 0)
	{
		if (once_bytes > remain_bytes)
		{
			once_bytes = remain_bytes;
		}

		read_bytes = read(fd, pDest, once_bytes);
		if (read_bytes < 0)
		{
			return -1;
		}
		if (read_bytes == 0)
		{
			break;
		}

		pEnd = pDest + read_bytes;
		for (p=pDest; p<pEnd; p++)
		{
			if (*p == '\n')
			{
				break;
			}
		}

		if (p < pEnd)
		{
			pDest = p + 1;  //find \n, skip \n
			rewind_bytes = pEnd - pDest;
			if (lseek(fd, -1 * rewind_bytes, SEEK_CUR) < 0)
			{
				return -1;
			}

			break;
		}

		pDest = pEnd;
		remain_bytes -= read_bytes;
	}

	*pDest = '\0';
	return pDest - buff;
}

ssize_t fc_read_lines(int fd, char *buf, const size_t size)
{
    ssize_t count;
    ssize_t old;
    int remain;
    char *last;

    if ((count=fc_safe_read(fd, buf, size)) <= 0)
    {
        return count;
    }

    if ((last=(char *)fc_memrchr(buf, '\n', count)) == NULL)
    {
        last = buf;
    }
    else
    {
        last++;   //skip \n
    }

    old = count;
    count = last - buf;
    remain = old - count;
    if (remain > 0)
    {
        if (lseek(fd, -1 * remain, SEEK_CUR) < 0)
        {
            return -1;
        }
    }

    return count;
}

int set_rlimit(int resource, const rlim_t value)
{
	struct rlimit limit;
    int64_t old_value;

	if (getrlimit(resource, &limit) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"call getrlimit fail, resource=%d, "
			"errno: %d, error info: %s",
			__LINE__, resource, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

	if ((limit.rlim_cur == RLIM_INFINITY) ||
            (value != RLIM_INFINITY && limit.rlim_cur >= value))
	{
		return 0;
	}

    old_value = limit.rlim_cur;
	limit.rlim_cur = value;
    if (!((limit.rlim_max == RLIM_INFINITY) ||
            (value != RLIM_INFINITY && limit.rlim_max >= value)))
    {
        limit.rlim_max = value;
    }
	if (setrlimit(resource, &limit) != 0)
	{
        const char *label;
        switch (resource)
        {
            case RLIMIT_CPU:
                label = "CPU time in sec";
                break;
            case RLIMIT_STACK:
                label = "max stack size";
                break;
            case RLIMIT_DATA:
                label = "max data size";
                break;
            case RLIMIT_FSIZE:
                label = "max file size";
                break;
            case RLIMIT_RSS:
                label = "max RSS";
                break;
            case RLIMIT_CORE:
                label = "max core file size";
                break;
            case RLIMIT_NPROC:
                label = "max processes";
                break;
            case RLIMIT_NOFILE:
                label = "max open files";
                break;
#ifdef RLIMIT_MSGQUEUE
            case RLIMIT_MSGQUEUE:
                label = "max bytes in msg queues";
                break;
#endif
            case RLIMIT_MEMLOCK:
                label = "max locked-in-memory address space";
                break;
            default:
                label = "unkown";
                break;
        }

		logError("file: "__FILE__", line: %d, "
			"call setrlimit fail, resource=%d (%s), "
            "old value=%"PRId64", new value=%"PRId64", "
			"errno: %d, error info: %s", __LINE__, resource, label,
            old_value, (int64_t)value, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

	return 0;
}

bool is_filename_secure(const char *filename, const int len)
{
	if (len < 3)
	{
		return true;
	}

	if (memcmp(filename, "../", 3) == 0)
	{
		return false;
	}

	return (strstr(filename, "/../") == NULL);
}

void load_log_level(IniContext *pIniContext)
{
	set_log_level(iniGetStrValue(NULL, "log_level", pIniContext));
}

int load_log_level_ex(const char *conf_filename)
{
	int result;
	IniContext iniContext;

	if ((result=iniLoadFromFileEx(conf_filename, &iniContext,
                    FAST_INI_ANNOTATION_DISABLE, NULL, 0,
                    FAST_INI_FLAGS_NONE)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"load conf file \"%s\" fail, ret code: %d", \
			__LINE__, conf_filename, result);
		return result;
	}

	load_log_level(&iniContext);
	iniFreeContext(&iniContext);
	return 0;
}

void set_log_level(char *pLogLevel)
{
	if (pLogLevel != NULL)
	{
		toUppercase(pLogLevel);
		if ( strncmp(pLogLevel, "DEBUG", 5) == 0 || \
		     strcmp(pLogLevel, "LOG_DEBUG") == 0)
		{
			g_log_context.log_level = LOG_DEBUG;
		}
		else if ( strncmp(pLogLevel, "INFO", 4) == 0 || \
		     strcmp(pLogLevel, "LOG_INFO") == 0)
		{
			g_log_context.log_level = LOG_INFO;
		}
		else if ( strncmp(pLogLevel, "NOTICE", 6) == 0 || \
		     strcmp(pLogLevel, "LOG_NOTICE") == 0)
		{
			g_log_context.log_level = LOG_NOTICE;
		}
		else if ( strncmp(pLogLevel, "WARN", 4) == 0 || \
		     strcmp(pLogLevel, "LOG_WARNING") == 0)
		{
			g_log_context.log_level = LOG_WARNING;
		}
		else if ( strncmp(pLogLevel, "ERR", 3) == 0 || \
		     strcmp(pLogLevel, "LOG_ERR") == 0)
		{
			g_log_context.log_level = LOG_ERR;
		}
		else if ( strncmp(pLogLevel, "CRIT", 4) == 0 || \
		     strcmp(pLogLevel, "LOG_CRIT") == 0)
		{
			g_log_context.log_level = LOG_CRIT;
		}
		else if ( strncmp(pLogLevel, "ALERT", 5) == 0 || \
		     strcmp(pLogLevel, "LOG_ALERT") == 0)
		{
			g_log_context.log_level = LOG_ALERT;
		}
		else if ( strncmp(pLogLevel, "EMERG", 5) == 0 || \
		     strcmp(pLogLevel, "LOG_EMERG") == 0)
		{
			g_log_context.log_level = LOG_EMERG;
		}
	}
}

int fcntl_add_flags(int fd, int get_cmd, int set_cmd, int adding_flags)
{
	int flags;

	flags = fcntl(fd, get_cmd, 0);
	if (flags < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"fcntl fail, errno: %d, error info: %s.", \
			__LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EACCES;
	}

	if (fcntl(fd, set_cmd, flags | adding_flags) == -1)
	{
		logError("file: "__FILE__", line: %d, " \
			"fcntl fail, errno: %d, error info: %s.", \
			__LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EACCES;
	}

	return 0;
}

int fd_add_flags(int fd, int adding_flags)
{
    return fcntl_add_flags(fd, F_GETFL, F_SETFL, adding_flags);
}

int fd_set_cloexec(int fd)
{
    return fcntl_add_flags(fd, F_GETFD, F_SETFD, FD_CLOEXEC);
}

int set_run_by(const char *group_name, const char *username)
{
#ifndef WIN32
	struct group *pGroup;
	struct passwd *pUser;
	int nErrNo;
	if (group_name != NULL && *group_name != '\0')
	{
     		pGroup = getgrnam(group_name);
		if (pGroup == NULL)
		{
			nErrNo = errno != 0 ? errno : ENOENT;
			logError("file: "__FILE__", line: %d, " \
				"getgrnam %s fail, errno: %d, error info: %s.", \
				__LINE__, group_name, nErrNo, STRERROR(nErrNo));
			return nErrNo;
		}

		if (setegid(pGroup->gr_gid) != 0)
		{
			nErrNo = errno != 0 ? errno : EPERM;
			logError("file: "__FILE__", line: %d, " \
				"setegid fail, errno: %d, error info: %s.", \
				__LINE__, nErrNo, STRERROR(nErrNo));
			return nErrNo;
		}
	}

	if (username != NULL && *username != '\0')
	{
     		pUser = getpwnam(username);
		if (pUser == NULL)
		{
			nErrNo = errno != 0 ? errno : ENOENT;
			logError("file: "__FILE__", line: %d, " \
				"getpwnam %s fail, errno: %d, error info: %s.", \
				__LINE__, username, nErrNo, STRERROR(nErrNo));
			return nErrNo;
		}

		if (seteuid(pUser->pw_uid) != 0)
		{
			nErrNo = errno != 0 ? errno : EPERM;
			logError("file: "__FILE__", line: %d, " \
				"seteuid fail, errno: %d, error info: %s.", \
				__LINE__, nErrNo, STRERROR(nErrNo));
			return nErrNo;
		}
	}
#endif

	return 0;
}

static int check_realloc_allow_ips(in_addr_t **allow_ip_addrs,
	int *alloc_count, const int target_ip_count)
{
	int bytes;
	if (*alloc_count < target_ip_count)
	{
		*alloc_count = target_ip_count;
		bytes = sizeof(in_addr_t) * (*alloc_count);
		*allow_ip_addrs = (in_addr_t *)fc_realloc(*allow_ip_addrs, bytes);
		if (*allow_ip_addrs == NULL)
		{
			return ENOMEM;
		}
	}

	return 0;
}

static int parse_cidr_ips(const char *ip_addr, in_addr_t **allow_ip_addrs,
	int *alloc_count, int *allow_ip_count, const int remain_items)
{
	char *pSlash;
	char *pReservedEnd;
	char ip_part[IP_ADDRESS_SIZE];
	int ip_len;
	int network_bits;
	int host_bits;
	int bits;
	uint32_t hip;
	in_addr_t nip;
	int h;
	int count;
	int result;
	struct in_addr addr;

	pSlash = strchr(ip_addr, '/');
	if (pSlash == NULL)
	{
		return EINVAL;
	}

	ip_len = pSlash - ip_addr;
	if (ip_len == 0 || ip_len >= IP_ADDRESS_SIZE)
	{
		logError("file: "__FILE__", line: %d, " \
			"invalid ip address: %s", \
			__LINE__, ip_addr);
		return EINVAL;
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
		return EINVAL;
	}

	if (network_bits < 10 || network_bits >= 32)
	{
		logError("file: "__FILE__", line: %d, " \
			"ip address: %s, invalid network bits: %d, " \
			"it should >= 10 and < 32", \
			__LINE__, ip_addr, network_bits);
		return EINVAL;
	}

	if (inet_pton(AF_INET, ip_part, &addr) != 1)
	{
		logError("file: "__FILE__", line: %d, " \
			"ip address: %s, invalid ip part: %s", \
			__LINE__, ip_addr, ip_part);
		return EINVAL;
	}

	host_bits = 32 - network_bits;
	count = 2;
	bits = host_bits;
	while (--bits)
	{
		count *= 2;
	}

	if ((result=check_realloc_allow_ips(allow_ip_addrs,
		alloc_count, (*allow_ip_count) + count + remain_items)) != 0)
	{
		return result;
	}

	logDebug("CIDR ip: %s, ip count: %d", ip_addr, count);

	hip = ntohl(addr.s_addr);
	for (h=0; h<count; h++)
	{
		struct sockaddr_in a;

		nip = htonl(hip | h);
		(*allow_ip_addrs)[*allow_ip_count] = nip;
		(*allow_ip_count)++;

		a.sin_addr.s_addr = nip;
		if (inet_ntop(AF_INET, &a.sin_addr, ip_part, IP_ADDRESS_SIZE) != NULL)
		{
			logDebug("%d. %s", h + 1, ip_part);
		}
	}

	return 0;
}

static int parse_range_hosts(const char *value, char *pStart, char *pEnd,
	char *hostname, const int nHeadLen, in_addr_t **allow_ip_addrs,
	int *alloc_count, int *allow_ip_count, const int remain_items)
{
	char *pTail;
	char *p;
	int result;
	int i;
	in_addr_t addr;

	pTail = pEnd + 1;
	p = pStart + 1;  //skip [
	while (p <= pEnd)
	{
		char *pNumStart1;
		char *pNumStart2;
		int nStart;
		int nEnd;
		int nNumLen1;
		int nNumLen2;
		char end_ch1;
		char end_ch2;
		char szFormat[16];

		while (*p == ' ' || *p == '\t') //trim prior spaces
		{
			p++;
		}

		pNumStart1 = p;
		while (*p >='0' && *p <= '9')
		{
			p++;
		}

		nNumLen1 = p - pNumStart1;
		while (*p == ' ' || *p == '\t') //trim tail spaces
		{
			p++;
		}

		if (!(*p == ',' || *p == '-' || *p == ']'))
		{
			logError("file: "__FILE__", line: %d, " \
				"invalid char \"%c\" in host name: %s",\
				__LINE__, *p, value);
			return EINVAL;
		}

		end_ch1 = *p;
		*(pNumStart1 + nNumLen1) = '\0';

		if (nNumLen1 == 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"invalid host name: %s, " \
				"empty entry before \"%c\"", \
				__LINE__, value, end_ch1);
			return EINVAL;
		}

		nStart = atoi(pNumStart1);
		if (end_ch1 == '-')
		{
			p++;   //skip -

			/* trim prior spaces */
			while (*p == ' ' || *p == '\t')
			{
				p++;
			}

			pNumStart2 = p;
			while (*p >='0' && *p <= '9')
			{
				p++;
			}

			nNumLen2 = p - pNumStart2;
			/* trim tail spaces */
			while (*p == ' ' || *p == '\t')
			{
				p++;
			}

			if (!(*p == ',' || *p == ']'))
			{
				logError("file: "__FILE__", line: %d, " \
					"invalid char \"%c\" in host name: %s",\
					__LINE__, *p, value);
				return EINVAL;
			}

			end_ch2 = *p;
			*(pNumStart2 + nNumLen2) = '\0';

			if (nNumLen2 == 0)
			{
				logError("file: "__FILE__", line: %d, " \
					"invalid host name: %s, " \
					"empty entry before \"%c\"", \
					__LINE__, value, end_ch2);
				return EINVAL;
			}

			nEnd = atoi(pNumStart2);
		}
		else
		{
			nEnd = nStart;
		}


		if ((result=check_realloc_allow_ips(allow_ip_addrs,
			alloc_count, (*allow_ip_count) + remain_items +
			(nEnd - nStart + 1))) != 0)
		{
			return result;
		}

		sprintf(szFormat, "%%0%dd%%s",  nNumLen1);
		for (i=nStart; i<=nEnd; i++)
		{
			sprintf(hostname + nHeadLen, szFormat, \
				i, pTail);

			addr = getIpaddrByName(hostname, NULL, 0);
			if (addr == INADDR_NONE)
			{
				logWarning("file: "__FILE__", line: %d, " \
					"invalid host name: %s", \
					__LINE__, hostname);
			}
			else
			{
				(*allow_ip_addrs)[*allow_ip_count] = addr;
				(*allow_ip_count)++;
			}

		}

		p++;
	}

	return 0;
}

int load_allow_hosts(IniContext *pIniContext, \
		in_addr_t **allow_ip_addrs, int *allow_ip_count)
{
	int result;
	int count;
	IniItem *pItem;
	IniItem *pItemStart;
	IniItem *pItemEnd;
	char item_value[256];
	char *pStart;
	char *pEnd;
	int alloc_count;
	int nHeadLen;
	int nValueLen;
	int i;
	in_addr_t addr;
	char hostname[256];

	if ((pItemStart=iniGetValuesEx(NULL, "allow_hosts", \
		pIniContext, &count)) == NULL)
	{
		*allow_ip_count = -1; /* -1 means match any ip address */
		*allow_ip_addrs = NULL;
		return 0;
	}

	pItemEnd = pItemStart + count;
	for (pItem=pItemStart; pItem<pItemEnd; pItem++)
	{
		if (strcmp(pItem->value, "*") == 0)
		{
			*allow_ip_count = -1; /* -1 means match any ip address*/
			*allow_ip_addrs = NULL;
			return 0;
		}
	}

	alloc_count = count;
	*allow_ip_count = 0;
	*allow_ip_addrs = (in_addr_t *)fc_malloc(sizeof(in_addr_t) * alloc_count);
	if (*allow_ip_addrs == NULL)
	{
		return ENOMEM;
	}

	for (pItem=pItemStart; pItem<pItemEnd; pItem++)
	{
		if (*(pItem->value) == '\0')
		{
			continue;
		}

		pStart = strchr(pItem->value, '[');
		if (pStart == NULL)
		{
			if (strchr(pItem->value, '/') != NULL) //CIDR addresses
			{
				if ((result=parse_cidr_ips(pItem->value,
					allow_ip_addrs, &alloc_count,
					allow_ip_count, pItemEnd - pItem)) != 0)
				{
					return result;
				}
				continue;
			}

			addr = getIpaddrByName(pItem->value, NULL, 0);
			if (addr == INADDR_NONE)
			{
				logWarning("file: "__FILE__", line: %d, " \
					"invalid host name: %s", \
					__LINE__, pItem->value);
			}
			else
			{
				if ((result=check_realloc_allow_ips(allow_ip_addrs,
					&alloc_count, (*allow_ip_count) + (pItemEnd - pItem))) != 0)
				{
					return result;
				}

				(*allow_ip_addrs)[*allow_ip_count] = addr;
				(*allow_ip_count)++;
			}

			continue;
		}

		
		pEnd = strchr(pStart, ']');
		if (pEnd == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"invalid host name: %s, expect \"]\"", \
				__LINE__, pItem->value);
			return EINVAL;
		}

		nValueLen = strlen(pItem->value);
		if (nValueLen >= (int)sizeof(item_value))
		{
			logError("file: "__FILE__", line: %d, " \
				"hostname too long, exceeds %d bytes", \
				__LINE__, (int)sizeof(item_value));
			return EINVAL;
		}
		memcpy(item_value, pItem->value, nValueLen + 1);
		nHeadLen = pStart - pItem->value;
		memcpy(hostname, pItem->value, nHeadLen);

		result = parse_range_hosts(pItem->value, item_value + nHeadLen,
				item_value + (pEnd - pItem->value),
				hostname, nHeadLen, allow_ip_addrs,
				&alloc_count, allow_ip_count, pItemEnd - pItem);
		if (result != 0)
		{
			return result;
		}
	}

	if (*allow_ip_count == 0)
	{
		logWarning("file: "__FILE__", line: %d, " \
			"allow ip count: 0", __LINE__);
	}

	if (*allow_ip_count > 0)
	{
		qsort(*allow_ip_addrs,  *allow_ip_count, sizeof(in_addr_t), \
			cmp_by_ip_addr_t);
	}

	logDebug("allow_ip_count=%d", *allow_ip_count);
	for (i=0; i<*allow_ip_count; i++)
	{
		struct in_addr address;
        char buff[INET_ADDRSTRLEN];
		address.s_addr = (*allow_ip_addrs)[i];
		logDebug("%d. %s", i + 1, inet_ntop(AF_INET, &address,
                    buff, sizeof(buff)));
	}

	return 0;
}

int cmp_by_ip_addr_t(const void *p1, const void *p2)
{
        return memcmp((in_addr_t *)p1, (in_addr_t *)p2, sizeof(in_addr_t));
}

int parse_bytes(const char *pStr, const int default_unit_bytes, int64_t *bytes)
{
	char *pReservedEnd;
    int result;

	pReservedEnd = NULL;
	*bytes = strtol(pStr, &pReservedEnd, 10);
	if (*bytes < 0)
    {
        logError("file: "__FILE__", line: %d, " \
                "bytes: %"PRId64" < 0, input string: %s",
                __LINE__, *bytes, pStr);
        return EINVAL;
    }

	if (pReservedEnd == NULL || *pReservedEnd == '\0')
	{
		*bytes *= default_unit_bytes;
        return 0;
	}

	if (*pReservedEnd == 'T' || *pReservedEnd == 't')
	{
		*bytes *= 1024 * 1024 * 1024 * 1024LL;
        result = 0;
	}
	else if (*pReservedEnd == 'G' || *pReservedEnd == 'g')
	{
		*bytes *= 1024 * 1024 * 1024;
        result = 0;
	}
	else if (*pReservedEnd == 'M' || *pReservedEnd == 'm')
	{
		*bytes *= 1024 * 1024;
        result = 0;
	}
	else if (*pReservedEnd == 'K' || *pReservedEnd == 'k')
    {
        *bytes *= 1024;
        result = 0;
    }
    else
    {
        result = EINVAL;
    }

    if (result == 0)
    {
        if (*(pReservedEnd + 1) == '\0')
        {
            return 0;
        }
        if ((*(pReservedEnd + 1) == 'B' || *(pReservedEnd + 1) == 'b') &&
                (*(pReservedEnd + 2) == '\0'))
        {
            return 0;
        }
        result = EINVAL;
    }

    logError("file: "__FILE__", line: %d, "
            "unkown byte unit: %s, input string: %s",
            __LINE__, pReservedEnd, pStr);
    return result;
}

int set_rand_seed()
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			 "call gettimeofday fail, " \
			 "errno=%d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

	srand(tv.tv_sec ^ tv.tv_usec);
	return 0;
}

int get_time_item_from_conf_ex(IniFullContext *ini_ctx,
		const char *item_name, TimeInfo *pTimeInfo,
		const byte default_hour, const byte default_minute,
        const bool bRetryGlobal)
{
    char *pValue;
    pValue = iniGetStrValueEx(ini_ctx->section_name, item_name,
            ini_ctx->context, bRetryGlobal);
    return get_time_item_from_str(pValue, item_name, pTimeInfo,
            default_hour, default_minute);
}

int get_time_item_from_conf(IniContext *pIniContext,
		const char *item_name, TimeInfo *pTimeInfo,
		const byte default_hour, const byte default_minute)
{
	char *pValue;
	pValue = iniGetStrValue(NULL, item_name, pIniContext);
    return get_time_item_from_str(pValue, item_name, pTimeInfo,
		default_hour, default_minute);
}

int get_time_item_from_str(const char *pValue, const char *item_name,
        TimeInfo *pTimeInfo, const byte default_hour,
        const byte default_minute)
{
	int hour;
	int minute;
	int second;
    int count;

	if (pValue == NULL)
	{
		pTimeInfo->hour = default_hour;
		pTimeInfo->minute = default_minute;
		pTimeInfo->second = 0;
		return 0;
	}

    second = 0;
    count = sscanf(pValue, "%d:%d:%d", &hour, &minute, &second);
	if (count != 2 && count != 3)
	{
		logError("file: "__FILE__", line: %d, "
			"item \"%s\" 's value \"%s\" is not an valid time",
			__LINE__, item_name, pValue);
		return EINVAL;
	}

	if ((hour < 0 || hour > 23) || (minute < 0 || minute > 59)
             || (second < 0 || second > 59))
	{
		logError("file: "__FILE__", line: %d, "
			"item \"%s\" 's value \"%s\" is not an valid time",
			__LINE__, item_name, pValue);
		return EINVAL;
	}

	pTimeInfo->hour = (byte)hour;
	pTimeInfo->minute = (byte)minute;
	pTimeInfo->second = (byte)second;

	return 0;
}

char *urlencode(const char *src, const int src_len, char *dest, int *dest_len)
{
	static unsigned char hex_chars[] = "0123456789ABCDEF";
	const unsigned char *pSrc;
	const unsigned char *pEnd;
	char *pDest;

	pDest = dest;
	pEnd = (unsigned char *)src + src_len;
	for (pSrc=(unsigned char *)src; pSrc<pEnd; pSrc++)
	{
		if ((*pSrc >= '0' && *pSrc <= '9') || 
	 	    (*pSrc >= 'a' && *pSrc <= 'z') ||
	 	    (*pSrc >= 'A' && *pSrc <= 'Z') ||
		    (*pSrc == '_' || *pSrc == '-' || *pSrc == '.'))
		{
			*pDest++ = *pSrc;
		}
		else if (*pSrc == ' ')
		{
			*pDest++ = '+';
		}
		else
		{
			*pDest++ = '%';
			*pDest++ = hex_chars[(*pSrc) >> 4];
			*pDest++ = hex_chars[(*pSrc) & 0x0F];
		}
	}

	*pDest = '\0';
	*dest_len = pDest - dest;

	return dest;
}

char *urldecode(const char *src, const int src_len, char *dest, int *dest_len)
{
    (void)urldecode_ex(src, src_len, dest, dest_len);
    *(dest + *dest_len) = '\0';
    return dest;
}

char *urldecode_ex(const char *src, const int src_len, char *dest, int *dest_len)
{
#define HEX_VALUE(ch, value) \
	if (ch >= '0' && ch <= '9') \
	{ \
		value = ch - '0'; \
	} \
	else if (ch >= 'a' && ch <= 'f') \
	{ \
		value = ch - 'a' + 10; \
	} \
	else \
	{ \
		value = ch - 'A' + 10; \
	}

	const unsigned char *pSrc;
	const unsigned char *pEnd;
	char *pDest;
	unsigned char cHigh;
	unsigned char cLow;
	int valHigh;
	int valLow;

	pDest = dest;
	pSrc = (unsigned char *)src;
	pEnd = (unsigned char *)src + src_len;
	while (pSrc < pEnd)
	{
		if (*pSrc == '%' && pSrc + 2 < pEnd)
		{
			cHigh = *(pSrc + 1);
			cLow = *(pSrc + 2);

			if (IS_HEX_CHAR(cHigh) && IS_HEX_CHAR(cLow))
			{
				HEX_VALUE(cHigh, valHigh)
				HEX_VALUE(cLow, valLow)
				*pDest++ = (valHigh << 4) | valLow;
				pSrc += 3;
			}
			else
			{
				*pDest++ = *pSrc;
				pSrc++;
			}
		}
		else if (*pSrc == '+')
		{
			*pDest++ = ' ';
			pSrc++;
		}
		else
		{
			*pDest++ = *pSrc;
			pSrc++;
		}
	}

	*dest_len = pDest - dest;
	return dest;
}

int buffer_strcpy(BufferInfo *pBuff, const char *str)
{
	pBuff->length = strlen(str);
	if (pBuff->alloc_size <= pBuff->length)
	{
		if (pBuff->buff != NULL)
		{
			free(pBuff->buff);
		}

		pBuff->alloc_size = pBuff->length + 1;
		pBuff->buff = (char *)fc_malloc(pBuff->alloc_size);
		if (pBuff->buff == NULL)
		{
			pBuff->alloc_size = 0;
			return ENOMEM;
		}
	}

	memcpy(pBuff->buff, str, pBuff->length + 1);
	return 0;
}

int buffer_memcpy(BufferInfo *pBuff, const char *buff, const int len)
{
	pBuff->length = len;
	if (pBuff->alloc_size <= pBuff->length)
	{
		if (pBuff->buff != NULL)
		{
			free(pBuff->buff);
		}

		pBuff->alloc_size = pBuff->length;
		pBuff->buff = (char *)fc_malloc(pBuff->alloc_size);
		if (pBuff->buff == NULL)
		{
			pBuff->alloc_size = 0;
			return ENOMEM;
		}
	}

	memcpy(pBuff->buff, buff, pBuff->length);
	return 0;
}

int set_timer(const int first_remain_seconds, const int interval, \
		void (*sighandler)(int))
{
	struct itimerval value;
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_handler = sighandler;
	if(sigaction(SIGALRM, &act, NULL) < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call sigaction fail, errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EINVAL;
	}

	memset(&value, 0, sizeof(value));
	value.it_interval.tv_sec = interval;
	value.it_value.tv_sec = first_remain_seconds;
	if (setitimer(ITIMER_REAL, &value, NULL) < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call setitimer fail, errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EINVAL;
	}

	return 0;
}

int set_file_utimes(const char *filename, const time_t new_time)
{
	struct timeval tvs[2];

	tvs[0].tv_sec = new_time;
	tvs[0].tv_usec = 0;
	tvs[1].tv_sec = new_time;
	tvs[1].tv_usec = 0;
	if (utimes(filename, tvs) != 0)
	{
		logWarning("file: "__FILE__", line: %d, " \
			"call utimes file: %s fail" \
			", errno: %d, error info: %s", \
			__LINE__, filename, errno, STRERROR(errno));
		return errno != 0 ? errno : ENOENT;
	}

	return 0;
}

int ignore_signal_pipe()
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, &act, NULL) < 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call sigaction fail, errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
		return errno;
	}

	return 0;
}

double get_line_distance_km(const double lat1, const double lon1,
        const double lat2, const double lon2)
{
#define FAST_ABS(v) ((v) >= 0 ? (v) : -1 * (v))
#define DISTANCE_PER_LATITUDE 111.111

    double lat_value;
    double lng_distance;
    double lat_distance;

    lat_value = FAST_ABS(lat1) < FAST_ABS(lat2) ? lat1 : lat2;
    lat_distance = FAST_ABS(lat1 - lat2) * DISTANCE_PER_LATITUDE;
    lng_distance = FAST_ABS(lon1 - lon2) * DISTANCE_PER_LATITUDE *
        cos(lat_value * 3.1415926 / 180.0);

    return sqrt(lat_distance * lat_distance + lng_distance * lng_distance);
}

bool is_private_ip(const char* ip)
{
    if (ip == NULL || (int)strlen(ip) < 8)
    {
        return false;
    }

    if (memcmp(ip, "10.", 3) == 0 || memcmp(ip, "192.168.", 8) == 0)
    {
        return true;
    }
    if (memcmp(ip, "172.", 4) == 0)
    {
        int b;
        b = atoi(ip + 4);
        if (b >= 16 && b < 32)
        {
            return true;
        }
    }

    return false;
}

int64_t get_current_time_ns()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call clock_gettime fail, "
                "errno: %d, error info: %s",
                __LINE__, errno, STRERROR(errno));
        return errno != 0 ? errno : EPERM;
    }

	return ((int64_t)ts.tv_sec * 1000 * 1000 * 1000LL + (int64_t)ts.tv_nsec);
}

int64_t get_current_time_us()
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			 "call gettimeofday fail, "
			 "errno: %d, error info: %s",
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
	}

	return ((int64_t)tv.tv_sec * 1000 * 1000 + (int64_t)tv.tv_usec);
}

static inline int do_lock_file(int fd, int cmd, int type)
{
    struct flock lock;
    int result;

    memset(&lock, 0, sizeof(lock));
    lock.l_type = type;
    lock.l_whence = SEEK_SET;
    do
    {
        if ((result=fcntl(fd, cmd, &lock)) != 0)
        {
            result = errno != 0 ? errno : ENOMEM;
            fprintf(stderr, "file: "__FILE__", line: %d, "
                    "call fcntl fail, errno: %d, error info: %s\n",
                    __LINE__, result, STRERROR(result));
        }
    } while (result == EINTR);

    return result;
}

int file_read_lock(int fd)
{
    return do_lock_file(fd, F_SETLKW, F_RDLCK);
}

int file_write_lock(int fd)
{
    return do_lock_file(fd, F_SETLKW, F_WRLCK);
}

int file_unlock(int fd)
{
    return do_lock_file(fd, F_SETLKW, F_UNLCK);
}

int file_try_read_lock(int fd)
{
    return do_lock_file(fd, F_SETLK, F_RDLCK);
}

int file_try_write_lock(int fd)
{
    return do_lock_file(fd, F_SETLK, F_WRLCK);
}

int file_try_unlock(int fd)
{
    return do_lock_file(fd, F_SETLK, F_UNLCK);
}

bool isLeadingSpacesLine(const char *content, const char *current)
{
    const char *p;
    p = current - 1;
    while (p >= content)
    {
        if (!(*p == ' ' || *p == '\t'))
        {
            break;
        }
        --p;
    }
    return (p < content || *p == '\n');
}

bool isTrailingSpacesLine(const char *tail, const char *end)
{
    const char *p;
    p = tail;
    while (p < end)
    {
        if (!(*p == ' ' || *p == '\t'))
        {
            break;
        }
        ++p;
    }
    return (p == end || *p == '\n');
}

ssize_t fc_safe_write(int fd, const char *buf, const size_t nbyte)
{
    ssize_t n;
    ssize_t remain;
    const char *p;

    n = write(fd, buf, nbyte);
    if (n < 0)
    {
        if (errno != EINTR)
        {
            return -1;
        }
        n = 0;
    }
    else if (n == nbyte)
    {
        return nbyte;
    }

    p = buf + n;
    remain = nbyte - n;
    while (remain > 0)
    {
        n = write(fd, p, remain);
        if (n < 0)
        {
            ssize_t written;
            if (errno == EINTR)
            {
                continue;
            }

            written = nbyte - remain;
            return written > 0 ? written : -1;
        }

        p += n;
        remain -= n;
    }

    return nbyte;
}

ssize_t fc_lock_write(int fd, const char *buf, const size_t nbyte)
{
    int lock_result;
    ssize_t result;

    lock_result = file_write_lock(fd);
    result = fc_safe_write(fd, buf, nbyte);
    if (lock_result == 0)
    {
        file_unlock(fd);
    }

    return result;
}

ssize_t fc_safe_read(int fd, char *buf, const size_t count)
{
    ssize_t n;
    ssize_t remain;
    char *p;

    n = read(fd, buf, count);
    if (n < 0)
    {
        if (errno != EINTR)
        {
            return -1;
        }
        n = 0;
    }
    else
    {
        if (n == 0 || n == count)
        {
            return n;
        }
    }

    p = buf + n;
    remain = count - n;
    while (remain > 0)
    {
        n = read(fd, p, remain);
        if (n < 0)
        {
            ssize_t done;
            if (errno == EINTR)
            {
                continue;
            }

            done = count - remain;
            return done > 0 ? done : -1;
        }
        else if (n == 0)
        {
            break;
        }

        p += n;
        remain -= n;
    }

    return count - remain;
}

key_t fc_ftok(const char *path, const int proj_id)
{
    int hash_code;
    hash_code = fc_simple_hash(path, strlen(path));
    return (((proj_id & 0xFF) << 24) | (hash_code & 0xFFFFFF));
}

static void add_thousands_separator(char *str, const int len)
{
    int new_len;
    int addings;
    int sub;
    int chars;
    int add_count;
    char *src;
    char *dest;
    char *first;

    if (len <= 3)
    {
        return;
    }

    if (*str == '-')
    {
        first = str + 1;
        sub = 2;
    }
    else
    {
        first = str;
        sub = 1;
    }

    addings = (len - sub) / 3;
    new_len = len + addings;

    src = str + (len - 1);
    dest = str + new_len;
    *dest-- = '\0';
    chars = 0;
    add_count = 0;
    while (src >= first)
    {
        *dest-- = *src--;
        if (++chars % 3 == 0)
        {
            if (add_count == addings)
            {
                break;
            }

            *dest-- = ',';
            add_count++;
        }
    }
}

const char *int2str(const int n, char *buff, const bool thousands_separator)
{
    int len;
    len = sprintf(buff, "%d", n);
    if (thousands_separator)
    {
        add_thousands_separator(buff, len);
    }
    return buff;
}

const char *long2str(const int64_t n, char *buff, const bool thousands_separator)
{
    int len;
    len = sprintf(buff, "%"PRId64, n);
    if (thousands_separator)
    {
        add_thousands_separator(buff, len);
    }
    return buff;
}

bool starts_with(const char *str, const char *needle)
{
    int str_len;
    int needle_len;

    str_len = strlen(str);
    needle_len = strlen(needle);
    if (needle_len > str_len) {
        return false;
    }

    return memcmp(str, needle, needle_len) == 0;
}

bool ends_with(const char *str, const char *needle)
{
    int str_len;
    int needle_len;
    int start_offset;

    str_len = strlen(str);
    needle_len = strlen(needle);
    start_offset = str_len - needle_len;
    if (start_offset < 0) {
        return false;
    }

    return memcmp(str + start_offset, needle, needle_len) == 0;
}

char *fc_strdup1(const char *str, const int len)
{
    char *output;

    output = (char *)fc_malloc(len + 1);
    if (output == NULL) {
        return NULL;
    }

    if (len > 0) {
        memcpy(output, str, len);
    }
    *(output + len) = '\0';
    return output;
}

const char *fc_memmem(const string_t *str, const string_t *needle)
{
    const char *ps;
    const char *last;
    const char *pn;
    const char *nend;
    int loop;
    int i;

    loop = str->len - needle->len;
    if (loop < 0) {
        return NULL;
    }

    last = str->str + loop;
    nend = needle->str + needle->len;
    for (ps=str->str; ps<=last; ps++) {
        for (pn=needle->str,i=0; pn<nend; pn++,i++) {
            if (*pn != *(ps + i)) {
                break;
            }
        }
        if (pn == nend) {
            return ps;
        }
    }

    return NULL;
}

const char *fc_memrchr(const char *str, const int ch, const int len)
{
    const char *p;

    p = str + len - 1;
    while (p >= str)
    {
        if (*p == ch)
        {
            return p;
        }
        --p;
    }

    return NULL;
}

char *format_http_date(time_t t, BufferInfo *buffer)
{
    struct tm tm_info;

    gmtime_r(&t, &tm_info);
    buffer->length = strftime(buffer->buff, buffer->alloc_size,
            "%a, %d %b %Y %H:%M:%S GMT", &tm_info);
    return buffer->buff;
}

int normalize_path(const char *from, const char *filename,
        char *full_filename, const int size)
{
    const char *start;
    const char *last;
    const char *end;
	char cwd[PATH_MAX];
    int up_count;
    int path_len;
    int i;

    if (IS_FILE_RESOURCE(filename)) {
        filename = filename + FILE_RESOURCE_TAG_LEN;
    }

    if (*filename == '/') {
        return snprintf(full_filename, size, "%s", filename);
    }

    if (from == NULL) {
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            logError("file: "__FILE__", line: %d, "
                    "call getcwd fail, errno: %d, error info: %s",
                    __LINE__, errno, STRERROR(errno));
            *full_filename = '\0';
            return 0;
        }

        path_len = strlen(cwd);
        if (cwd[path_len - 1] != '/') {
            if ((path_len + 1) >= sizeof(cwd)) {
                logError("file: "__FILE__", line: %d, "
                        "cwd length is too long, exceeds %d",
                        __LINE__, (int)sizeof(cwd));
                *full_filename = '\0';
                return 0;
            }

            cwd[path_len] = '/';
            cwd[path_len + 1] = '\0';
        }
        from = cwd;
    } else if (IS_FILE_RESOURCE(from)) {
        from = from + FILE_RESOURCE_TAG_LEN;
    }

    last = strrchr(from, '/');
    if (last != NULL) {
        end = filename + strlen(filename);
        if (memcmp(filename, "./", 2) == 0) {
            start = filename + 2;
        } else {
            start = filename;
        }
        up_count = 0;
        while (start + 3 < end) {
            if (memcmp(start, "../", 3) != 0) {
                break;
            }

            ++up_count;
            start += 3;
        }

        path_len = last - from;
        for (i=0; i<up_count; i++) {
            last = fc_memrchr(from, '/', path_len);
            if (last == NULL) {
                logWarning("file: "__FILE__", line: %d, "
                        "too many ../ in the path resolve filename: %s, "
                        "from filename: %s", __LINE__, filename, from);
                break;
            }
            path_len = last - from;
        }
        return snprintf(full_filename, size, "%.*s/%s",
                path_len, from, start);
    } else {
        logWarning("file: "__FILE__", line: %d, "
                "no \"/\" in the from filename: %s",
                __LINE__, from);
        return snprintf(full_filename, size, "%s", filename);
    }
}

int normalize_uri(const string_t *from, const char *uri,
        char *dest, const int size)
{
#define MAX_UP_PATH_COUNT  8
    const char *start;
    const char *end;
    const char *last;
    string_t fpath;
    string_t parts[MAX_UP_PATH_COUNT];
    int up_count;
    int path_count;
    int keep_count;
    int len;
    int i;

    if (*uri == '/') {
        return snprintf(dest, size, "%s", uri);
    }

    end = uri + strlen(uri);
    if (memcmp(uri, "./", 2) == 0) {
        start = uri + 2;
    } else {
        start = uri;
    }
    up_count = 0;
    while (start + 3 < end) {
        if (memcmp(start, "../", 3) != 0) {
            break;
        }

        ++up_count;
        start += 3;
    }

    last = fc_memrchr(from->str, '/', from->len);
    if (last == NULL) {
        logWarning("file: "__FILE__", line: %d, "
                "no \"/\" in the from uri: %s",
                __LINE__, from->str);
        return snprintf(dest, size, "/%s", start);
    }

    if (up_count == 0) {
        return snprintf(dest, size, "%.*s/%s",
                (int)(last - from->str), from->str, start);
    } else {
        fpath.str = (char *)from->str;
        fpath.len = last - from->str;
        path_count = split_string_ex(&fpath, '/',
                parts, MAX_UP_PATH_COUNT, true);
        keep_count = path_count - up_count;
        if (keep_count < 0) {
            logWarning("file: "__FILE__", line: %d, "
                    "uri: %s, contails too many \"../\"",
                    __LINE__, uri);
        }

        len = 0;
        for (i=0; i<keep_count; i++) {
            len += snprintf(dest + len, size - len,
                    "/%.*s", parts[i].len, parts[i].str);
        }

        len += snprintf(dest + len, size - len, "/%s", start);
        return len;
    }
}

int normalize_path_ex(const char *from, const char *filename,
        char *full_filename, const int size, const int flags)
{
    bool is_url_from;
    bool is_url_filename;
    const char *base_end;
    const char *from_ask;
    const char *dest_ask;
    string_t from_uri;
    int base_len;
    int full_len;

    if ((flags & NORMALIZE_FLAGS_URL_ENABLED) == 0) {
        return normalize_path(from, filename, full_filename, size);
    }

    is_url_from = IS_URL_RESOURCE(from);
    is_url_filename = IS_URL_RESOURCE(filename);
    if (!(is_url_from || is_url_filename)) {
        return normalize_path(from, filename, full_filename, size);
    }

    if (IS_FILE_RESOURCE(filename)) {
        return snprintf(full_filename, size, "%s",
                filename + FILE_RESOURCE_TAG_LEN);
    }

    if (!is_url_from) {
        return snprintf(full_filename, size, "%s", filename);
    }

    if (is_url_filename) {
        full_len = snprintf(full_filename, size, "%s", filename);
        if ((flags & NORMALIZE_FLAGS_URL_APPEND_PARAMS) == 0) {
            return full_len;
        }
        from_ask = strchr(from + 8, '?');
    } else {
        base_end = strchr(from + 8, '/');
        if (base_end == NULL) {
            return snprintf(full_filename, size, "%s%s%s",
                    from, (*filename == '/' ? "" : "/"), filename);
        }

        base_len = base_end - from;
        from_ask = strchr(base_end + 1, '?');
        from_uri.str = (char *)base_end;
        if (from_ask == NULL) {
            from_uri.len = strlen(from_uri.str);
        } else {
            from_uri.len = from_ask - from_uri.str;
        }

        full_len = snprintf(full_filename, size, "%.*s", base_len, from);
        full_len = normalize_uri(&from_uri, filename,
                full_filename + full_len, size - full_len);
    }

    if ((flags & NORMALIZE_FLAGS_URL_APPEND_PARAMS) != 0) {
        if (from_ask != NULL) {
            dest_ask = strchr(filename, '?');
            full_len += snprintf(full_filename + full_len,
                    size - full_len, "%c%s", (dest_ask == NULL ?
                        '?' : '&'), from_ask + 1);
        }
    }

    return full_len;
}

const char *get_gzip_command_filename()
{
    if (access("/usr/bin/gzip", F_OK) == 0)
    {
        return "/usr/bin/gzip";
    }
    else if (access("/bin/gzip", F_OK) == 0)
    {
        return "/bin/gzip";
    }
    else if (access("/usr/local/bin/gzip", F_OK) == 0)
    {
        return "/usr/local/bin/gzip";
    }
    else
    {
        return "gzip";
    }
}

int fc_delete_file_ex(const char *filename, const char *caption)
{
    int result;

    if (unlink(filename) == 0)
    {
        return 0;
    }

    result = errno != 0 ? errno : ENOENT;
    if (result == ENOENT)
    {
        result = 0;
    }
    else
    {
        logError("file: "__FILE__", line: %d, "
                "unlink %s file: %s fail, "
                "errno: %d, error info: %s",
                __LINE__, caption, filename,
                result, STRERROR(result));
    }

    return result;
}

bool fc_is_prime(const int64_t n)
{
    int64_t loop;
    int64_t i;

    if (n <= 0)
    {
        return false;
    }

    loop = llround(sqrt((double)n));
    for (i=2; i<=loop; i++)
    {
        if (n % i == 0)
        {
            return false;
        }
    }

    return true;
}

int64_t fc_floor_prime(const int64_t n)
{
    int64_t start;
    int64_t i;

    start =  (n % 2 == 0 ? n - 1 : n);
    for (i = start; i > 0; i -= 2)
    {
      if (fc_is_prime(i))
      {
          return i;
      }
    }

    return 1;
}

int64_t fc_ceil_prime(const int64_t n)
{
    int64_t i;

    if (n <= 0)
    {
        return 1;
    }

    i = (n % 2 == 0 ? n + 1 : n);
    while (!fc_is_prime(i))
    {
        i += 2;
    }

    return i;
}

int fc_init_buffer(BufferInfo *buffer, const int buffer_size)
{
    buffer->buff = (char *)fc_malloc(buffer_size);
    if (buffer->buff == NULL)
    {
        return ENOMEM;
    }
    buffer->alloc_size = buffer_size;
    buffer->length = 0;
    return 0;
}

void fc_free_buffer(BufferInfo *buffer)
{
    if (buffer->buff != NULL)
    {
        free(buffer->buff);
        buffer->buff = NULL;
        buffer->alloc_size = buffer->length = 0;
    }
}

int fc_check_mkdir_ex(const char *path, const mode_t mode, bool *created)
{
    int result;

    *created = false;
    if (access(path, F_OK) == 0) {
        return 0;
    }

    result = errno != 0 ? errno : EPERM;
    if (result != ENOENT) {
        logError("file: "__FILE__", line: %d, "
                "access %s fail, errno: %d, error info: %s",
                __LINE__, path, result, STRERROR(result));
        return result;
    }

    if (mkdir(path, mode) != 0) {
        result = errno != 0 ? errno : EPERM;
        if (result == EEXIST) {
            return 0;
        }

        logError("file: "__FILE__", line: %d, "
                "mkdir %s fail, errno: %d, error info: %s",
                __LINE__, path, result, STRERROR(result));
        return result;
    }

    *created = true;
    return 0;
}

int fc_mkdirs_ex(const char *path, const mode_t mode, int *create_count)
{
#define MAX_SUBDIR_COUNT 128
    int result;
    int path_len;
    int dir_count;
    int i;
    bool created;
    char new_path[PATH_MAX];
    char buff[PATH_MAX];
    string_t fp;
    char *subdirs[MAX_SUBDIR_COUNT];

    *create_count = 0;
    if (access(path, F_OK) == 0) {
        return 0;
    }

    path_len = strlen(path);
    if (path_len >= sizeof(new_path)) {
        logError("file: "__FILE__", line: %d, "
                "path length: %d is too large, exceeds %d",
                __LINE__, path_len, (int)sizeof(new_path));
        return ENAMETOOLONG;
    }

    FC_SET_STRING_EX(fp, buff, 0);
    memcpy(new_path, path, path_len + 1);
    dir_count = splitEx(new_path, '/', subdirs, MAX_SUBDIR_COUNT);
    for (i=0; i<dir_count; i++) {
        fp.len += sprintf(fp.str + fp.len, "%s/", subdirs[i]);
        if ((result=fc_check_mkdir_ex(fp.str, mode, &created)) != 0) {
            return result;
        }
        if (created) {
            (*create_count)++;
        }
    }

    return 0;
}

int fc_check_rename_ex(const char *oldpath, const char *newpath,
        const bool overwritten)
{
    int result;

    if (access(oldpath, F_OK) != 0) {
        result = errno != 0 ? errno : EPERM;
        if (result != ENOENT) {
            logError("file: "__FILE__", line: %d, "
                    "access %s fail, errno: %d, error info: %s",
                    __LINE__, oldpath, result, STRERROR(result));
            return result;
        }
        return 0;
    }

    if (!overwritten) {
        if (access(newpath, F_OK) == 0) {
            logError("file: "__FILE__", line: %d, "
                    "dest path: %s already exist",
                    __LINE__, newpath);
            return EEXIST;
        } else {
            result = errno != 0 ? errno : EPERM;
            if (result != ENOENT) {
                logError("file: "__FILE__", line: %d, "
                        "access %s fail, errno: %d, error info: %s",
                        __LINE__, newpath, result, STRERROR(result));
                return result;
            }
        }
    }

    if (rename(oldpath, newpath) != 0) {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, "
                "rename file \"%s\" to \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, oldpath, newpath,
                result, STRERROR(result));
        return result;
    }

    return 0;
}

int fc_get_first_line(const char *filename, char *buff,
        const int buff_size, string_t *line)
{
    int result;
    int64_t read_bytes;
    char *line_end;

    read_bytes = buff_size - 1;
    if ((result=getFileContentEx(filename, buff, 0, &read_bytes)) != 0) {
        return result;
    }
    if (read_bytes == 0) {
        return ENOENT;
    }

    line_end = (char *)memchr(buff, '\n', read_bytes);
    if (line_end == NULL) {
        logError("file: "__FILE__", line: %d, "
                "file: %s, line no: 1, "
                "expect new line char \"\\n\"",
                __LINE__, filename);
        return EINVAL;
    }
    line->str = buff;
    line->len = line_end - buff + 1;
    return 0;
}

int fc_get_last_line(const char *filename, char *buff,
        const int buff_size, int64_t *file_size, string_t *line)
{
    int64_t offset;
    int64_t read_bytes;
    int result;

    if ((result=getFileSize(filename, file_size)) != 0) {
        return result;
    }

    if (*file_size == 0) {
        return ENOENT;
    }

    if (*file_size >= buff_size) {
        offset = (*file_size - buff_size) + 1;
    } else {
        offset = 0;
    }
    read_bytes = (*file_size - offset) + 1;
    if ((result=getFileContentEx(filename, buff,
                    offset, &read_bytes)) != 0)
    {
        return result;
    }
    if (read_bytes == 0) {
        return ENOENT;
    }

    line->str = (char *)fc_memrchr(buff, '\n', read_bytes - 1);
    if (line->str == NULL) {
        line->str = buff;
    } else {
        line->str += 1;  //skip \n
    }
    line->len = (buff + read_bytes) - line->str;
    return 0;
}

int fc_get_last_lines(const char *filename, char *buff,
        const int buff_size, string_t *lines, int *count)
{
    int64_t file_size;
    int64_t offset;
    int64_t read_bytes;
    int remain_len;
    int i;
    int result;

    if (*count <= 0) {
        return EINVAL;
    }

    if ((result=getFileSize(filename, &file_size)) != 0) {
        *count = 0;
        return result;
    }

    if (file_size == 0) {
        *count = 0;
        return ENOENT;
    }

    if (file_size >= buff_size) {
        offset = (file_size - buff_size) + 1;
    } else {
        offset = 0;
    }
    read_bytes = (file_size - offset) + 1;
    if ((result=getFileContentEx(filename, buff,
                    offset, &read_bytes)) != 0)
    {
        return result;
    }
    if (read_bytes == 0) {
        *count = 0;
        return ENOENT;
    }

    remain_len = read_bytes - 1;
    for (i=0; i<*count; i++) {
        lines->str = (char *)fc_memrchr(buff, '\n', remain_len);
        if (lines->str == NULL) {
            lines->str = buff;
            break;
        }

        remain_len = lines->str - buff;
    }

    if (i < *count) {
        *count = i + 1;
    } else {
        lines->str += 1;  //skip \n
    }
    lines->len = (buff + read_bytes) - lines->str;
    return 0;
}

static bool path_contains_special(const string_t *pts, const int count)
{
    const string_t *ps;
    const string_t *end;

    end = pts + count;
    for (ps=pts; ps<end; ps++) {
        if ((ps->len == 1 && *ps->str == '.') ||
                fc_string_equal2(ps, "..", 2))
        {
            return true;
        }
    }

    return false;
}

bool fc_path_contains(const string_t *path, const string_t *needle,
        int *result)
{
#define MAX_PATH_SECTION_COUNT   128

    string_t pts[MAX_PATH_SECTION_COUNT];
    string_t nds[MAX_PATH_SECTION_COUNT];
    string_t *ps;
    string_t *ns;
    string_t *end;
    int pc;
    int nc;

    if ((path->len == 0 || *path->str != '/') ||
            (needle->len == 0 || *needle->str != '/'))
    {
        *result = EINVAL;
        return false;
    }

    pc = split_string_ex(path, '/', pts, MAX_PATH_SECTION_COUNT, true);
    if (pc == MAX_PATH_SECTION_COUNT) {
        *result = ENAMETOOLONG;
        return false;
    }
    if (path_contains_special(pts, pc)) {
        *result = EINVAL;
        return false;
    }

    nc = split_string_ex(needle, '/', nds, MAX_PATH_SECTION_COUNT, true);
    if (nc == MAX_PATH_SECTION_COUNT) {
        *result = ENAMETOOLONG;
        return false;
    }
    if (path_contains_special(nds, nc)) {
        *result = EINVAL;
        return false;
    }

    *result = 0;
    if (nc > pc) {
        return false;
    }

    end = nds + nc;
    for (ns=nds, ps=pts; ns<end; ns++, ps++) {
        if (!fc_string_equal(ns, ps)) {
            return false;
        }
    }

    return true;
}

int fc_check_filename_ex(const string_t *filename, const char *caption,
        char *error_info, int *error_len, const int error_size)
{
    if (filename->len <= 0) {
        *error_len = snprintf(error_info, error_size,
                "invalid %s, length: %d <= 0",
                caption, filename->len);
        return EINVAL;
    }

    if (fc_string_equal2(filename, ".", 1) ||
            fc_string_equal2(filename, "..", 2))
    {
        *error_len = snprintf(error_info, error_size,
                "invalid %s: %.*s", caption,
                filename->len, filename->str);
        return EINVAL;
    }

    if (memchr(filename->str, '/', filename->len) != NULL) {
        *error_len = snprintf(error_info, error_size,
                "%s is invalid because contains /", caption);
        return EINVAL;
    }

    if (memchr(filename->str, '\0', filename->len) != NULL) {
        *error_len = snprintf(error_info, error_size,
                "%s is invalid because contains 0x0", caption);
        return EINVAL;
    }

    return 0;
}

int fc_check_filename(const string_t *filename, const char *caption)
{
    char error_info[256];
    int error_len;
    int result;

    if ((result=fc_check_filename_ex(filename, caption, error_info,
                    &error_len, sizeof(error_info))) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "%s", __LINE__, error_info);
    }
    return result;
}

bool is_digital_string(const char *str)
{
    const char *p;
    const char *end;
    int len;

    len = strlen(str);
    if (len == 0)
    {
        return false;
    }

    end = str + len;
    for (p=str; p<end; p++)
    {
        if (!FC_IS_DIGITAL(*p))
        {
            return false;
        }
    }

    return true;
}

int fc_safe_write_file_init(SafeWriteFileInfo *fi,
        const char *file_path, const char *redo_filename,
        const char *tmp_filename)
{
    char full_filename[PATH_MAX];

    snprintf(full_filename, sizeof(full_filename), "%s/%s",
            file_path, redo_filename);
    if ((fi->filename=fc_strdup(full_filename)) == NULL)
    {
        return ENOMEM;
    }

    snprintf(full_filename, sizeof(full_filename), "%s/%s",
            file_path, tmp_filename);
    if ((fi->tmp_filename=fc_strdup(full_filename)) == NULL)
    {
        return ENOMEM;
    }

    fi->fd = -1;
    return 0;
}
