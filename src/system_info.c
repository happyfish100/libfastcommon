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
#include <dirent.h>
#include "logger.h"
#include "shared_func.h"
#include "system_info.h"

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#else
#ifdef OS_FREEBSD
#include <sys/sysctl.h>
#include <sys/ucred.h>
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
#elif defined(OS_FREEBSD)
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
   *mem_size = 0;
   logError("file: "__FILE__", line: %d, "
           "please port me!", __LINE__);
   return EOPNOTSUPP;
#endif
}

int get_sys_cpu_count()
{
#if defined(OS_LINUX) || defined(OS_FREEBSD)
    return sysconf(_SC_NPROCESSORS_ONLN);
#else
    logError("file: "__FILE__", line: %d, "
            "please port me!", __LINE__);
    return 0;
#endif
}

int get_uptime(time_t *uptime)
{
#ifdef OS_LINUX
    struct sysinfo si;
    if (sysinfo(&si) != 0)
    {
		logError("file: "__FILE__", line: %d, "
			 "call sysinfo fail, "
			 "errno: %d, error info: %s",
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
    *uptime = si.uptime;
    return 0;
#elif defined(OS_FREEBSD)
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
		logError("file: "__FILE__", line: %d, "
			 "call sysctl  fail, "
			 "errno: %d, error info: %s",
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
#else
    *uptime = 0;
    logError("file: "__FILE__", line: %d, "
            "please port me!", __LINE__);
    return EOPNOTSUPP;
#endif
}

#define SET_STATFS_FIELDS(left, right) \
    do { \
        left.f_type = right.f_type;     \
        left.f_bsize = right.f_bsize;   \
        left.f_blocks = right.f_blocks; \
        left.f_bfree = right.f_bfree;   \
        left.f_bavail = right.f_bavail; \
        left.f_files = right.f_files;   \
        left.f_ffree = right.f_ffree;   \
    } while (0)

#define SET_MNT_FIELDS(left, fstypename, mntfromname, mntonname) \
    do { \
        snprintf(left.f_fstypename, sizeof(left.f_fstypename), "%s", fstypename); \
        snprintf(left.f_mntfromname, sizeof(left.f_mntfromname), "%s", mntfromname); \
        snprintf(left.f_mntonname, sizeof(left.f_mntonname), "%s", mntonname); \
    } while (0)

int get_mounted_filesystems(struct fast_statfs *stats, const int size, int *count)
{
#ifdef OS_LINUX
    const char *filename = "/proc/mounts";
    FILE *fp;
    char *p;
    char *mntfromname;
    char *mntonname;
    char *fstypename;
    struct statfs buf;
    char line[1024];
    int result;
    int i;

    *count = 0;
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        result = errno != 0 ? errno : ENOENT;
		logError("file: "__FILE__", line: %d, "
			 "call fopen %s fail, "
			 "errno: %d, error info: %s",
			 __LINE__, filename, errno, STRERROR(errno));
		return result;
    }

    memset(stats, 0, sizeof(struct fast_statfs) * size);
    result = 0;
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (*count >= size)
        {
            result = ENOSPC;
            break;
        }

        p = line;
        mntfromname = strsep(&p, " \t");
        mntonname = strsep(&p, " \t");
        fstypename = strsep(&p, " \t");

        snprintf(stats[*count].f_mntfromname,
                sizeof(stats[*count].f_mntfromname), "%s", mntfromname);
        snprintf(stats[*count].f_mntonname,
                sizeof(stats[*count].f_mntonname), "%s", mntonname);
        snprintf(stats[*count].f_fstypename,
                sizeof(stats[*count].f_fstypename), "%s", fstypename);

        (*count)++;
    }
    fclose(fp);

    for (i=0; i<*count; i++)
    {
        if (statfs(stats[i].f_mntonname, &buf) == 0)
        {
            SET_STATFS_FIELDS(stats[i], buf);
#ifdef HAVE_FILE_SYSTEM_ID
            stats[i].f_fsid = buf.f_fsid;
#endif
        }
        else
        {
            logWarning("file: "__FILE__", line: %d, "
                    "call statfs fail, "
                    "errno: %d, error info: %s",
                    __LINE__, errno, STRERROR(errno));
        }
    }

    return result;

#elif defined(OS_FREEBSD)

    struct statfs *mnts;
    int result;
    int i;

    mnts = NULL;
    *count = getmntinfo(&mnts, 0);
    if (*count == 0)
    {
        result = errno != 0 ? errno : EPERM;
		logError("file: "__FILE__", line: %d, "
			 "call getmntinfo fail, "
			 "errno: %d, error info: %s",
			 __LINE__, errno, STRERROR(errno));
		return result;
    }

    if (*count <= size)
    {
        result = 0;
    }
    else
    {
        *count = size;
        result = ENOSPC;
    }

    for (i=0; i<*count; i++)
    {
        SET_STATFS_FIELDS(stats[i], mnts[i]);
#ifdef HAVE_FILE_SYSTEM_ID
        stats[i].f_fsid = mnts[i].f_fsid;
#endif
        SET_MNT_FIELDS(stats[i], mnts[i].f_fstypename,
                mnts[i].f_mntfromname, mnts[i].f_mntonname);
    }
    return result;
#else
    *count = 0;
    logError("file: "__FILE__", line: %d, "
            "please port me!", __LINE__);
    return EOPNOTSUPP;
#endif
}

#if defined(OS_LINUX) || defined(OS_FREEBSD)

typedef struct fast_process_array {
    struct fast_process_info *procs;
    int alloc_size;
    int count;
} FastProcessArray;

#if defined(OS_LINUX)
static int check_process_capacity(FastProcessArray *proc_array)
{
    struct fast_process_info *procs;
    int alloc_size;
    int bytes;

    if (proc_array->alloc_size > proc_array->count)
    {
        return 0;
    }

    alloc_size = proc_array->alloc_size > 0 ?
        proc_array->alloc_size * 2 : 128;
    bytes = sizeof(struct fast_process_info) * alloc_size;
    procs = (struct fast_process_info *)malloc(bytes);
    if (procs == NULL)
    {
		logError("file: "__FILE__", line: %d, "
			 "malloc %d bytes fail", __LINE__, bytes);
        return ENOMEM;
    }

    memset(procs, 0, bytes);
    if (proc_array->count > 0)
    {
        memcpy(procs, proc_array->procs, sizeof(struct fast_process_info) *
                proc_array->count);
        free(proc_array->procs);
    }

    proc_array->alloc_size = alloc_size;
    proc_array->procs = procs;
    return 0;
}

static void parse_proc_stat(char *buff, const int len, struct fast_process_info *process)
{
    char *p;
    char *end;
    char *start;
    int cmd_len;

    if (len == 0)
    {
        process->field_count = 0;
        return;
    }

    end = buff + len;
    process->pid = strtol(buff, &p, 10);
    p++;  //skip space
    start = p;
    while (p < end)
    {
        if (*p == ' ' || *p == '\t')
        {
            if (*start == '(')
            {
                if (*(p - 1) == ')')
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }

        p++;
    }
    if (p == end)
    {
        process->field_count = 1;
        return;
    }

    if (*start == '(')
    {
        start++;
        cmd_len = p - start - 1;
    }
    else
    {
        cmd_len = p - start;
    }
    if (cmd_len >= sizeof(process->comm))
    {
        cmd_len = sizeof(process->comm) - 1;
    }

    memcpy(process->comm, start, cmd_len);

    p++;  //skip space
    process->field_count = 2 +
        sscanf(p, "%c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld "
                "%ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu "
                "%lu %lu %d %d %u %u %llu %lu %ld",
       &process->state,
       &process->ppid,
       &process->pgrp,
       &process->session,
       &process->tty_nr,
       &process->tpgid,
       &process->flags,
       &process->minflt,
       &process->cminflt,
       &process->majflt,
       &process->cmajflt,
       &process->utime,
       &process->stime,
       &process->cutime,
       &process->cstime,
       &process->priority,
       &process->nice,
       &process->num_threads,
       &process->itrealvalue,
       &process->starttime,
       &process->vsize,
       &process->rss,
       &process->rsslim,
       &process->startcode,
       &process->endcode,
       &process->startstack,
       &process->kstkesp,
       &process->kstkeip,
       &process->signal,
       &process->blocked,
       &process->sigignore,
       &process->sigcatch,
       &process->wchan,
       &process->nswap,
       &process->cnswap,
       &process->exit_signal,
       &process->processor,
       &process->rt_priority,
       &process->policy,
       &process->delayacct_blkio_ticks,
       &process->guest_time,
       &process->cguest_time);
}

int get_processes(struct fast_process_info **processes, int *count)
{
    const char *dirname = "/proc";
    char filename[128];
    char buff[4096];
    DIR *dir;
    struct dirent *ent;
    FastProcessArray proc_array;
    int64_t bytes;
    int result;
    int len;
    int i;

    dir = opendir(dirname);
    if (dir == NULL)
    {
        *count = 0;
        *processes = NULL;
		logError("file: "__FILE__", line: %d, "
			 "call opendir %s fail, "
			 "errno: %d, error info: %s",
			 __LINE__, dirname, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }

    result = 0;
    proc_array.procs = NULL;
    proc_array.alloc_size = 0;
    proc_array.count = 0;
    while ((ent=readdir(dir)) != NULL)
    {
        len = strlen(ent->d_name);
        for (i=0; i<len; i++)
        {
            if (!(ent->d_name[i] >= '0' && ent->d_name[i] <= '9'))
            {
                break;
            }
        }
        if (i < len)  //not digital string
        {
            continue;
        }

        sprintf(filename, "%s/%s/stat", dirname, ent->d_name);
        bytes = sizeof(buff);
        if (getFileContentEx(filename, buff, 0, &bytes) != 0)
        {
            continue;
        }

        if ((result=check_process_capacity(&proc_array)) != 0)
        {
            break;
        }

        parse_proc_stat(buff, bytes, proc_array.procs + proc_array.count);
        proc_array.count++;
    }
    closedir(dir);

    *count = proc_array.count;
    *processes = proc_array.procs;
    return result;
}

#elif  defined(OS_FREEBSD)

int get_processes(struct fast_process_info **processes, int *count)
{
    struct kinfo_proc *procs;
    struct fast_process_info *process;
    int mib[4];
    size_t size;
    int bytes;
    int nproc;
    int i;
    bool success;

    *count = 0;
    *processes = NULL;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    mib[3] =  0;
    size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
    {
		logError("file: "__FILE__", line: %d, " \
			 "call sysctl  fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }

    nproc = size / sizeof(struct kinfo_proc);
    if (nproc == 0) {
        return ENOENT;
    }

    success = false;
    procs = NULL;
    for (i=0; i<10; i++)
    {
        nproc += 32;
        if (procs != NULL)
        {
            free(procs);
        }

        size = sizeof(struct kinfo_proc) * nproc;
        procs = (struct kinfo_proc *)malloc(size);
        if (procs == NULL)
        {
            logError("file: "__FILE__", line: %d, " \
                    "malloc %d bytes fail, " \
                    "errno: %d, error info: %s", \
                    __LINE__, (int)size, errno, STRERROR(errno));
            return errno != 0 ? errno : ENOMEM;
        }

        if (sysctl(mib, 4, procs, &size, NULL, 0) == 0)
        {
            success = true;
            break;
        }

        if (errno != ENOMEM)
        {
            logError("file: "__FILE__", line: %d, " \
                    "call sysctl  fail, " \
                    "errno: %d, error info: %s", \
                    __LINE__, errno, STRERROR(errno));
            free(procs);
            return errno != 0 ? errno : EPERM;
        }
    }

    if (!success)
    {
        free(procs);
        return ENOSPC;
    }

    nproc = size / sizeof(struct kinfo_proc);

    bytes = sizeof(struct fast_process_info) * nproc;
    *processes = (struct fast_process_info *)malloc(bytes);
    if (*processes == NULL)
    {
		logError("file: "__FILE__", line: %d, "
			 "malloc %d bytes fail", __LINE__, bytes);
        free(procs);
        return ENOMEM;
    }
    memset(*processes, 0, bytes);
    process = *processes;
    for (i=0; i<nproc; i++)
    {
        process->field_count = 9;
        snprintf(process->comm, sizeof(process->comm),
                "%s", procs[i].kp_proc.p_comm);
        process->pid = procs[i].kp_proc.p_pid;
        process->ppid = procs[i].kp_eproc.e_ppid;
        process->starttime = procs[i].kp_proc.p_starttime.tv_sec;
        process->flags = procs[i].kp_proc.p_flag;
        process->state = procs[i].kp_proc.p_stat;

        process->sigignore = procs[i].kp_proc.p_sigignore;
        process->sigcatch = procs[i].kp_proc.p_sigcatch;
        process->priority = procs[i].kp_proc.p_priority;

        //process->uid = procs[i].kp_eproc.e_pcred.p_ruid;
        //process->gid = procs[i].kp_eproc.e_pcred.p_rgid;

        process++;
    }

    free(procs);
    *count = nproc;
    return 0;
}
#endif
#endif

