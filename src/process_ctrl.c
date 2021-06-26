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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "shared_func.h"
#include "logger.h"
#include "process_ctrl.h"

int get_pid_from_file(const char *pidFilename, pid_t *pid)
{
  char buff[32];
  int64_t file_size;
  int result;

  if (access(pidFilename, F_OK) != 0) {
    return errno != 0 ? errno : EPERM;
  }

  file_size = sizeof(buff);
  if ((result=getFileContentEx(pidFilename, buff, 0, &file_size)) != 0) {
    return result;
  }

  *pid = strtol(buff, NULL, 10);
  if (*pid == 0) {
    return EINVAL;
  }

  return 0;
}

int write_to_pid_file(const char *pidFilename)
{
  char buff[32];
  int len;

  len = sprintf(buff, "%d", (int)getpid());
  return writeToFile(pidFilename, buff, len);
}

int delete_pid_file(const char *pidFilename)
{
  int result;
  pid_t pid;

  if ((result=get_pid_from_file(pidFilename, &pid)) != 0) {
    return result;
  }

  if (pid != getpid()) {
    fprintf(stderr, "pid file: %s not mine, pid: %d != mine: %d",
        pidFilename, (int)pid, (int)getpid());
    return ESRCH;
  }

  if (unlink(pidFilename) == 0) {
    return 0;
  }
  else {
    fprintf(stderr, "unlink file: %s fail, "
        "errno: %d, error info: %s!\n",
        pidFilename, errno, strerror(errno));
    return errno != 0 ? errno : ENOENT;
  }
}

static int do_stop(const char *pidFilename, const bool bShowError, pid_t *pid)
{
  int result;

  if ((result=get_pid_from_file(pidFilename, pid)) != 0) {
    if (bShowError) {
      if (result == ENOENT) {
        fprintf(stderr, "pid file: %s not exist!\n", pidFilename);
      }
      else {
        fprintf(stderr, "get pid from file: %s fail, " \
            "errno: %d, error info: %s\n",
            pidFilename, result, strerror(result));
      }
    }

    return result;
  }

  if (kill(*pid, SIGTERM) == 0) {
    return 0;
  }
  else {
    result = errno != 0 ? errno : EPERM;
    if (bShowError || result != ESRCH) {
      fprintf(stderr, "kill pid: %d fail, errno: %d, error info: %s\n",
          (int)*pid, result, strerror(result));
    }
    return result;
  }
}

int process_stop_ex(const char *pidFilename, const bool bShowError)
{
#define MAX_WAIT_COUNT  300
  pid_t pid;
  int result;
  int sig;
  int i;

  if ((result=do_stop(pidFilename, bShowError, &pid)) != 0) {
    return result;
  }

  fprintf(stderr, "waiting for pid [%d] exit ...\n", (int)pid);
  for (i=0; i<MAX_WAIT_COUNT; i++) {
    sig = (i % 10 == 0) ? SIGTERM : 0;
    if (kill(pid, sig) != 0) {
      break;
    }

    usleep(100 * 1000);
  }

  if (i == MAX_WAIT_COUNT) {
    if (kill(pid, SIGKILL) == 0) {
      fprintf(stderr, "waiting for pid [%d] exit timeout, "
              "force kill!\n", (int)pid);
      usleep(100 * 1000);
    }
  }

  fprintf(stderr, "pid [%d] exit.\n\n", (int)pid);
  return 0;
}

int process_restart(const char *pidFilename)
{
  const bool bShowError = false;
  int result;

  result = process_stop_ex(pidFilename, bShowError);
  if (result == ENOENT || result == ESRCH) {
    result = 0;
  } else if (result == 0) {
    fprintf(stderr, "starting ...\n");
  }

  return result;
}

static const char *process_get_exename(const char* program)
{
    const char *exename;
    exename = strrchr(program, '/');
    if (exename != NULL) {
        return exename + 1;
    }
    else {
        return program;
    }
}

static const char *get_exename_by_pid(const pid_t pid, char *buff,
        const int buff_size, int *result)
{
    char cmdfile[MAX_PATH_SIZE];
    int64_t cmdsz;

    cmdsz = buff_size;
    sprintf(cmdfile, "/proc/%d/cmdline", pid);
    if ((*result=getFileContentEx(cmdfile, buff, 0, &cmdsz)) != 0) {
        fprintf(stderr, "read file %s fail, errno: %d, error info: %s\n",
                cmdfile, *result, strerror(*result));
        return NULL;
    }

    return process_get_exename(buff);
}

int process_start(const char* pidFilename)
{
    pid_t pid;
    int result;

    if ((result=get_pid_from_file(pidFilename, &pid)) != 0) {
        if (result == ENOENT) {
            return 0;
        }
        else {
            fprintf(stderr, "get pid from file: %s fail, " \
                "errno: %d, error info: %s\n",
                pidFilename, result, strerror(result));
            return result;
        }
    }

    if (kill(pid, 0) == 0) {
        if (access("/proc", F_OK) == 0) {
            char cmdline[MAX_PATH_SIZE];
            char argv0[MAX_PATH_SIZE];
            const char *exename1, *exename2;

            exename1 = get_exename_by_pid(pid, cmdline, sizeof(cmdline), &result);
            if (exename1 == NULL) {
                return result;
            }
            exename2 = get_exename_by_pid(getpid(), argv0, sizeof(argv0), &result);
            if (exename2 == NULL) {
                return result;
            }
            if (strcmp(exename1, exename2) == 0) {
                fprintf(stderr, "process %s already running, pid: %d\n",
                        argv0, (int)pid);
                return EEXIST;
            }
            return 0;
        }
        else {
            fprintf(stderr, "process already running, pid: %d\n", (int)pid);
            return EEXIST;
        }
    }
    else if (errno == ENOENT || errno == ESRCH) {
        return 0;
    }
    else {
        result = errno != 0 ? errno : EPERM;
        fprintf(stderr, "kill pid: %d fail, errno: %d, error info: %s\n",
            (int)pid, errno, strerror(errno));
        return result;
    }
}

int process_exist(const char *pidFilename, pid_t *pid)
{
  int result;

  if ((result=get_pid_from_file(pidFilename, pid)) != 0) {
    if (result == ENOENT) {
      return result;
    }
    else {
      fprintf(stderr, "get pid from file: %s fail, " \
          "errno: %d, error info: %s\n",
          pidFilename, result, strerror(result));
      return result;
    }
  }

  if (kill(*pid, 0) == 0) {
    return 0;
  }
  else if (errno == ENOENT || errno == ESRCH) {
    return ENOENT;
  }
  else {
    result = errno != 0 ? errno : EPERM;
    fprintf(stderr, "kill pid: %d fail, errno: %d, error info: %s\n",
        (int)*pid, result, strerror(result));
    return result;
  }
}

int get_base_path_from_conf_file(const char *filename, char *base_path,
	const int path_size) 
{
	char *pBasePath;
	IniContext iniContext;
	int result;

	if ((result=iniLoadFromFileEx(filename, &iniContext,
                    FAST_INI_ANNOTATION_DISABLE, NULL, 0,
                    FAST_INI_FLAGS_NONE)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"load conf file \"%s\" fail, ret code: %d", \
			__LINE__, filename, result);
		return result;
	}

	do
	{
		pBasePath = iniGetStrValue(NULL, "base_path", &iniContext);
		if (pBasePath == NULL)
		{
			logError("file: "__FILE__", line: %d, " \
				"conf file \"%s\" must have item " \
				"\"base_path\"!", __LINE__, filename);
			result = ENOENT;
			break;
		}

		snprintf(base_path, path_size, "%s", pBasePath);
		chopPath(base_path);
		if (!fileExists(base_path))
		{
			logError("file: "__FILE__", line: %d, " \
				"\"%s\" can't be accessed, error info: %s", \
				__LINE__, base_path, STRERROR(errno));
			result = errno != 0 ? errno : ENOENT;
			break;
		}
		if (!isDir(base_path))
		{
			logError("file: "__FILE__", line: %d, " \
				"\"%s\" is not a directory!", \
				__LINE__, base_path);
			result = ENOTDIR;
			break;
		}
	} while (0);

	iniFreeContext(&iniContext);
	return result;
}

int process_action(const char *pidFilename, const char *action, bool *stop)
{
    const bool bShowError = true;
    int result;
    pid_t pid;

	*stop = false;
	if (action == NULL)
	{
		return 0;
	}

	if (strcmp(action, "stop") == 0)
	{
		*stop = true;
		return process_stop_ex(pidFilename, bShowError);
	}
    else if (strcmp(action, "status") == 0)
	{
		*stop = true;
		result = process_exist(pidFilename, &pid);
        switch (result) {
            case 0:
                printf("Running, pid: %d\n", (int)pid);
                break;
            case ENOENT:
                printf("NOT running\n");
                break;
            default:
                printf("Unkown status\n");
                break;
        }
        return result;
	}
	else if (strcmp(action, "restart") == 0)
	{
		return process_restart(pidFilename);
	}
	else if (strcmp(action, "start") == 0)
	{
		return process_start(pidFilename);
	}
	else
	{
		fprintf(stderr, "invalid action: %s\n", action);
		return EINVAL;
	}
}

