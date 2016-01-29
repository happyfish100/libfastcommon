/**
* Copyright (C) 2008 Seapeak.Xu / xvhfeng@gmail.com
*
* FastLib may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastLib source kit.
* Please visit the FastLib Home Page http://www.csource.org/ for more detail.
**/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "io_opt.h"

int mkdir_by_cascading(const char *path,mode_t mode)
{
	int length,pointer_postion = 0;
	char *postion;
	// some compiler reports warning without(char *)
	char *path_temp = (char *)path;
	char cwd[MAX_PATH_SIZE];
	char *subfolder;
	int result = 0;
	if(NULL == getcwd(cwd,sizeof(cwd)))
	{
		return -1;
	}

	if(*path_temp == '/')
	{
		if(-1 == chdir("/"))
		{
			return -2;
		}
		pointer_postion ++;
	}

	while(pointer_postion != strlen(path_temp))
	{
		postion = strchr(path_temp+pointer_postion,'/');
		if(NULL == postion)
		{
			length = strlen(path_temp) - pointer_postion;
		}
		else
		{
			length = postion - path_temp - pointer_postion;
		}

		do
		{
			subfolder = (char *)calloc(length,sizeof(char));
			if(NULL == subfolder)
			{
				result = -3;
				break;
			}
			memcpy(subfolder,path_temp+pointer_postion,length);
			if(is_dir(subfolder))
			{
				// if subfolder exists, do not create, just chdir to it
				if(-1 == chdir(subfolder))
				{
					result = -2;
					break;
				}
			}
			else
			{
				// if subfolder not exists, creates it
				if(-1 == mkdir(subfolder,mode))
				{
					result = -4;
					break;
				}
				if(-1 == chdir(subfolder))
				{
					result = -2;
					break;
				}
			}

		}while(0);

		if(NULL != subfolder)
		{
			free(subfolder);
			subfolder = NULL;
		}

		pointer_postion += 0 == postion ? length :  length + 1;
	}

	return result;
}

int is_dir(const char *dir_path) {
	struct stat buf;
	if (0 != stat(dir_path, &buf)) {
		return 0;
	}

	return S_ISDIR(buf.st_mode);
}

