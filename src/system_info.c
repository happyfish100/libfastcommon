/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include "logger.h"
#include "system_info.h"

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#else
#ifdef OS_FREEBSD
#include <sys/sysctl.h>
#endif
#endif

int get_sys_total_mem_size(int64_t *mem_size)
{
#ifdef OS_LINUX
    struct sysinfo si;
    if (sysinfo(&si) != 0)
    {
		logError("file: "__FILE__", line: %d, " \
			 "call sysinfo fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
    *mem_size = si.totalram;
    return 0;
#else
#ifdef OS_FREEBSD
   int mib[2];
   size_t len;

   mib[0] = CTL_HW;
   mib[1] = HW_MEMSIZE;
   len = sizeof(*mem_size);
   if (sysctl(mib, 2, mem_size, &len, NULL, 0) != 0)
   {
		logError("file: "__FILE__", line: %d, " \
			 "call sysctl  fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
   }
   return 0;
#else
#error port me!
#endif
#endif
}

int get_sys_cpu_count()
{
#if defined(OS_LINUX) || defined(OS_FREEBSD)
    return sysconf(_SC_NPROCESSORS_ONLN);
#else
#error port me!
#endif
}

int get_uptime(time_t *uptime)
{
#ifdef OS_LINUX
    struct sysinfo si;
    if (sysinfo(&si) != 0)
    {
		logError("file: "__FILE__", line: %d, " \
			 "call sysinfo fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
    *uptime = si.uptime;
    return 0;
#else
#ifdef OS_FREEBSD
    struct timeval boottime;
    size_t size;
    int mib[2];

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    size = sizeof(boottime);
    if (sysctl(mib, 2, &boottime, &size, NULL, 0) == 0 &&
            boottime.tv_sec != 0)
    {
        *uptime = time(NULL) - boottime.tv_sec;
        return 0;
    }
    else
    {
        *uptime = 0;
		logError("file: "__FILE__", line: %d, " \
			 "call sysctl  fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
#else
#error port me!
#endif
#endif
}

