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
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include "logger.h"
#include "shared_func.h"
#include "fc_memory.h"
#include "system_info.h"

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#else
#ifdef OS_FREEBSD
#include <sys/sysctl.h>
#include <sys/ucred.h>

#if HAVE_USER_H == 1
#include <sys/user.h>
#endif

#if HAVE_VMMETER_H == 1
#include <sys/vmmeter.h>
#endif

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
#ifdef DARWIN
   mib[1] = HW_MEMSIZE;
#else
   mib[1] = HW_PHYSMEM;
#endif
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

#define TIMEVAL_TO_SECONDS(tv) \
    ((double)tv.tv_sec + (double)tv.tv_usec / 1000000.00)

#define SECONDS_TO_TIMEVAL(secs, tv) \
    do { \
        (tv).tv_sec = (time_t)secs; \
        (tv).tv_usec = (secs - (tv).tv_sec) * 1000000; \
    } while (0)

int get_boot_time(struct timeval *boot_time)
{
#ifdef OS_LINUX
    char buff[256];
    int64_t bytes;
    struct sysinfo si;

    bytes = sizeof(buff);
    if (getFileContentEx("/proc/uptime", buff, 0, &bytes) == 0)
    {
        double uptime;
        double btime;
        struct timeval current_time;

        if (sscanf(buff, "%lf", &uptime) == 1)
        {
            gettimeofday(&current_time, NULL);
            btime = TIMEVAL_TO_SECONDS(current_time) - uptime;
            SECONDS_TO_TIMEVAL(btime, *boot_time);
            boot_time->tv_usec = 0;
            return 0;
        }
    }

    if (sysinfo(&si) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call sysinfo fail, "
                "errno: %d, error info: %s",
                __LINE__, errno, STRERROR(errno));
        return errno != 0 ? errno : EPERM;
    }

    boot_time->tv_sec = time(NULL) - si.uptime;
    boot_time->tv_usec = 0;
    return 0;
#elif defined(OS_FREEBSD)
    size_t size;
    int mib[2];

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    size = sizeof(struct timeval);
    if (sysctl(mib, 2, boot_time, &size, NULL, 0) == 0)
    {
        return 0;
    }
    else
    {
        boot_time->tv_sec = 0;
        boot_time->tv_usec = 0;
		logError("file: "__FILE__", line: %d, "
			 "call sysctl  fail, "
			 "errno: %d, error info: %s",
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }
#else
    boot_time->tv_sec = 0;
    boot_time->tv_usec = 0;
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
        fc_safe_strcpy(left.f_fstypename, fstypename);   \
        fc_safe_strcpy(left.f_mntfromname, mntfromname); \
        fc_safe_strcpy(left.f_mntonname, mntonname); \
    } while (0)

#ifdef OS_LINUX
static int get_device_type(const char *type_name, FastDeviceType *device_type)
{
    int i;
    const char *disk_ftypes[] = {"ext2", "ext3", "ext4", "xfs",
        "btrfs", "f2fs", "jfs", "reiserfs", "nilfs", "zfs",
        "ufs", "ntfs", "vfat", "udf", "romfs", "squashfs"};
    const int disk_ftype_count = sizeof(disk_ftypes) / sizeof(char *);

    for (i=0; i<disk_ftype_count; i++)
    {
        if (strcmp(type_name, disk_ftypes[i]) == 0)
        {
            *device_type = fast_device_type_disk;
            return 0;
        }
    }

    if (strcmp(type_name, "tmpfs") == 0 || strcmp(type_name, "devtmpfs") == 0
            || strcmp(type_name, "ramfs") == 0)
    {
        *device_type = fast_device_type_memory;
        return 0;
    }

    if (strcmp(type_name, "nfs") == 0 || strcmp(type_name, "smb") == 0 ||
            strcmp(type_name, "cifs") == 0 || strcmp(type_name, "afp") == 0)
    {
        *device_type = fast_device_type_network;
        return 0;
    }

    if (strcmp(type_name, "fuse") == 0)
    {
        *device_type = fast_device_type_fuse;
        return 0;
    }

    *device_type = fast_device_type_unkown;
    return ENOENT;
}
#endif

int get_mounted_filesystems(struct fast_statfs *stats,
        const int size, int *count)
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
        toLowercase(fstypename);
        if (get_device_type(fstypename, &stats[*count].device_type) == 0)
        {
            fc_safe_strcpy(stats[*count].f_mntfromname, mntfromname);
            fc_safe_strcpy(stats[*count].f_mntonname, mntonname);
            fc_safe_strcpy(stats[*count].f_fstypename, fstypename);
            (*count)++;
        }
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
    *count = getmntinfo(&mnts, MNT_NOWAIT);
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
        stats[i].device_type = fast_device_type_unkown;
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

int get_statfs_by_path(const char *path, FastStatFS *statfs)
{
#define MAX_STATFS_COUNT  256
    int result;
    int count;
    int path_len;
    int mnt_len;
    int matched_len;
    char resolved_path[PATH_MAX];
    struct fast_statfs stats[MAX_STATFS_COUNT];
    struct fast_statfs *entry;
    struct fast_statfs *end;

    if ((result=get_mounted_filesystems(stats, MAX_STATFS_COUNT,
                    &count)) != 0)
    {
        return result;
    }

    if (realpath(path, resolved_path) == NULL)
    {
        return errno != 0 ? errno : ENOENT;
    }
    path_len = strlen(resolved_path);
    matched_len = 0;
    end = stats + count;
    for (entry=stats; entry<end; entry++)
    {
        mnt_len = strlen(entry->f_mntonname);
        if (mnt_len <= path_len && memcmp(resolved_path, entry->
                    f_mntonname, mnt_len) == 0)
        {
            if ((mnt_len > 1 && mnt_len < path_len) &&
                    *(resolved_path + mnt_len) != '/')
            {
                continue;
            }

            if (mnt_len > matched_len)
            {
                matched_len = mnt_len;
                *statfs = *entry;
            }
        }
    }

    return (matched_len > 0 ? 0 : ENOENT);
}

bool is_rotational_device_by_path(const char *path)
{
#if defined(OS_LINUX)
#define DEV_PATH_PREFIX_STR  "/dev/"
#define DEV_PATH_PREFIX_LEN  (sizeof(DEV_PATH_PREFIX_STR) - 1)

    int result;
    int fd;
    int len;
    FastStatFS statfs;
    char resolved_path[PATH_MAX];
    char filename[PATH_MAX];
    char buff[8];
    char *device_name;

    if ((result=get_statfs_by_path(path, &statfs)) != 0) {
        return true;
    }

    if (statfs.device_type == fast_device_type_memory) {
        return false;
    }

    if (!(statfs.device_type == fast_device_type_disk &&
                strncmp(statfs.f_mntfromname, DEV_PATH_PREFIX_STR,
                    DEV_PATH_PREFIX_LEN) == 0))
    {
        return true;
    }

    if (realpath(statfs.f_mntfromname, resolved_path) == NULL) {
        return true;
    }
    if (strncmp(resolved_path, DEV_PATH_PREFIX_STR,
                DEV_PATH_PREFIX_LEN) != 0)
    {
        return true;
    }
    device_name = resolved_path + DEV_PATH_PREFIX_LEN;
    sprintf(filename, "/sys/class/block/%s/queue/rotational", device_name);
    if ((fd=open(filename, O_RDONLY)) < 0) {
        sprintf(filename, "/sys/class/block/%s/../queue/rotational", device_name);
        if ((fd=open(filename, O_RDONLY)) < 0) {
            return true;
        }
    }

    len = read(fd, buff, sizeof(buff));
    close(fd);
    if (len == 1 || len == 2) {
        return (buff[0] != '0');
    } else {
        return true;
    }
#else
    return true;
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
    procs = (struct fast_process_info *)fc_malloc(bytes);
    if (procs == NULL)
    {
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

static void parse_proc_stat(char *buff, const int len,
        struct fast_process_info *process, unsigned long long *starttime)
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
       starttime,
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
    struct timeval boot_time;
    struct dirent *ent;
    FastProcessArray proc_array;
    int64_t bytes;
    unsigned long long starttime;
    int tickets;
    int result;
    int len;
    int i;

    tickets = sysconf(_SC_CLK_TCK);
    if (tickets == 0)
    {
        tickets = 100;
    }

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

        if ((result=check_process_capacity(&proc_array)) != 0)
        {
            break;
        }

        sprintf(filename, "%s/%s/stat", dirname, ent->d_name);
        bytes = sizeof(buff);
        if (getFileContentEx(filename, buff, 0, &bytes) != 0)
        {
            continue;
        }

        get_boot_time(&boot_time);

        parse_proc_stat(buff, bytes, proc_array.procs + proc_array.count,
                &starttime);

        SECONDS_TO_TIMEVAL(TIMEVAL_TO_SECONDS(boot_time) +
                (double)starttime / (double)tickets,
                proc_array.procs[proc_array.count].starttime);
	proc_array.procs[proc_array.count].starttime.tv_usec = 0;

        proc_array.count++;
    }
    closedir(dir);

    *count = proc_array.count;
    *processes = proc_array.procs;
    return result;
}

int get_sysinfo(struct fast_sysinfo *info)
{
    struct sysinfo si;

    get_boot_time(&info->boot_time);
    if (sysinfo(&si) != 0)
    {
		logError("file: "__FILE__", line: %d, " \
			 "call sysinfo fail, " \
			 "errno: %d, error info: %s", \
			 __LINE__, errno, STRERROR(errno));
		return errno != 0 ? errno : EPERM;
    }

    info->loads[0] = si.loads[0] / (double)(1 << SI_LOAD_SHIFT);
    info->loads[1] =  si.loads[1] / (double)(1 << SI_LOAD_SHIFT),
    info->loads[2] = si.loads[2] / (double)(1 << SI_LOAD_SHIFT);
    info->totalram = si.totalram;
    info->freeram = si.freeram;
    info->sharedram = si.sharedram;
    info->bufferram = si.bufferram;
    info->totalswap = si.totalswap;
    info->freeswap = si.freeswap;
    info->procs = si.procs;
    return 0;
}

#elif  defined(OS_FREEBSD)

#ifdef DARWIN
#define ki_pid  kp_proc.p_pid
#define ki_comm kp_proc.p_comm
#define ki_ppid kp_eproc.e_ppid
#define ki_start kp_proc.p_starttime
#define ki_flag kp_proc.p_flag
#define ki_stat kp_proc.p_stat
#define ki_sigignore kp_proc.p_sigignore
#define ki_sigcatch kp_proc.p_sigcatch
#define ki_priority kp_proc.p_priority
#define ki_ruid kp_eproc.e_pcred.p_ruid
#define ki_rgid kp_eproc.e_pcred.p_rgid
#define GET_SIGNAL(sig) sig

#else
#define ki_priority ki_pri.pri_level
#define GET_SIGNAL(sig) *((int *)&sig)
#endif

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
    mib[3] = 0;
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
        procs = (struct kinfo_proc *)fc_malloc(size);
        if (procs == NULL)
        {
            return ENOMEM;
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
    *processes = (struct fast_process_info *)fc_malloc(bytes);
    if (*processes == NULL)
    {
        free(procs);
        return ENOMEM;
    }
    memset(*processes, 0, bytes);
    process = *processes;
    for (i=0; i<nproc; i++)
    {
        process->field_count = 9;
        fc_safe_strcpy(process->comm, procs[i].ki_comm);
        process->pid = procs[i].ki_pid;
        process->ppid = procs[i].ki_ppid;
        process->starttime = procs[i].ki_start;
        process->flags = procs[i].ki_flag;
        process->state = procs[i].ki_stat;

        process->sigignore = GET_SIGNAL(procs[i].ki_sigignore);
        process->sigcatch = GET_SIGNAL(procs[i].ki_sigcatch);
        process->priority = procs[i].ki_priority;

        //process->uid = procs[i].ki_ruid;
        //process->gid = procs[i].ki_rgid;

        process++;
    }

    free(procs);
    *count = nproc;
    return 0;
}

int get_sysinfo(struct fast_sysinfo *info)
{
        int mib[4];
        size_t size;
	struct loadavg loads;
#if HAVE_VMMETER_H == 1
	struct vmtotal vm;
#endif

#ifdef VM_SWAPUSAGE
	struct xsw_usage sw_usage;
#endif

	memset(info, 0, sizeof(struct fast_sysinfo));
	get_boot_time(&info->boot_time);

	mib[0] = CTL_VM;
	mib[1] = VM_LOADAVG;
	size = sizeof(loads);
	if (sysctl(mib, 2, &loads, &size, NULL, 0) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
				"call sysctl  fail, " \
				"errno: %d, error info: %s", \
				__LINE__, errno, STRERROR(errno));
	}
	else if (loads.fscale > 0)
	{
		info->loads[0] = (double)loads.ldavg[0] / loads.fscale;
		info->loads[1] = (double)loads.ldavg[1] / loads.fscale;
		info->loads[2] = (double)loads.ldavg[2] / loads.fscale;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_ALL;
	mib[3] =  0;
	size = 0;
	if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call sysctl  fail, " \
			"errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
	}
	else
	{
		info->procs = size / sizeof(struct kinfo_proc);
	}

	get_sys_total_mem_size((int64_t *)&info->totalram);

#if HAVE_VMMETER_H == 1
	mib[0] = CTL_VM;
	mib[1] = VM_METER;
	size = sizeof(vm);
	if (sysctl(mib, 2, &vm, &size, NULL, 0) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call sysctl  fail, " \
			"errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
	}
	else
	{
		int page_size;

		page_size = sysconf(_SC_PAGESIZE);
		info->freeram = vm.t_free * page_size;
		info->sharedram = vm.t_rmshr * page_size;
	}
#endif

#ifdef VM_SWAPUSAGE
	mib[0] = CTL_VM;
	mib[1] = VM_SWAPUSAGE;
	size = sizeof(sw_usage);
	if (sysctl(mib, 2, &sw_usage, &size, NULL, 0) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call sysctl fail, " \
			"errno: %d, error info: %s", \
			__LINE__, errno, STRERROR(errno));
	}
	else
	{
		info->totalswap = sw_usage.xsu_total;
		info->freeswap = sw_usage.xsu_avail;
	}
#endif

	return 0;
}

#endif
#endif

int get_kernel_version(Version *version)
{
    struct utsname name;
    char *p;
    int numbers[2];
    int i;

    if (uname(&name) < 0)
    {
		logError("file: "__FILE__", line: %d, "
			"call uname fail, errno: %d, error info: %s",
			__LINE__, errno, STRERROR(errno));
        return errno != 0 ? errno : EFAULT;
    }

    numbers[0] = numbers[1] = 0;
    p = name.release;
    for (i=0; i<2; i++) {
        p = strchr(p, '.');
        if (p == NULL) {
            break;
        }

        p++;
        numbers[i] = strtol(p, NULL, 10);
    }

    version->major = strtol(name.release, NULL, 10);
    version->minor = numbers[0];
    version->patch = numbers[1];
    return 0;
}

#ifdef OS_LINUX
int get_device_block_size(const char *device, int *block_size)
{
    int result;
    int fd;
    size_t bs;

    if ((fd=open(device, O_RDONLY | O_CLOEXEC)) < 0) {
        result = errno != 0 ? errno : ENOENT;
        logError("file: "__FILE__", line: %d, "
                "open device %s fail, errno: %d, error info: %s",
                __LINE__, device, result, strerror(result));
        return result;
    }

    if (ioctl(fd, BLKSSZGET, &bs) == 0) {
        *block_size = bs;
        result = 0;
    } else {
        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, "
                "ioctl device %s fail, errno: %d, error info: %s",
                __LINE__, device, result, strerror(result));
    }

    close(fd);
    return result;
}

static int get_block_size_by_write(const char *path, int *block_size)
{
#define MAX_BLK_SIZE  (128 * 1024)
    char tmp_filename[PATH_MAX];
    char *buff;
    int result;
    int fd;

    if ((result=posix_memalign((void **)&buff,
                    MAX_BLK_SIZE, MAX_BLK_SIZE)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "posix_memalign %d bytes fail, "
                "errno: %d, error info: %s", __LINE__,
                MAX_BLK_SIZE, result, STRERROR(result));
        return result;
    }

    fc_combine_full_filename(path, ".blksize-test.tmp", tmp_filename);
    if ((fd=open(tmp_filename, O_WRONLY | O_CREAT |
                    O_DIRECT | O_CLOEXEC, 0755)) < 0)
    {
        result = errno != 0 ? errno : ENOENT;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, errno: %d, error info: %s",
                __LINE__, tmp_filename, result, strerror(result));
        free(buff);
        return result;
    }

    result = EINVAL;
    *block_size = 512;
    while (*block_size <= MAX_BLK_SIZE) {
        if (write(fd, buff, *block_size) == *block_size) {
            result = 0;
            break;
        }
        result = errno != 0 ? errno : EINTR;
        if (result == EINTR) {
            continue;
        }

        if (result != EINVAL) {
            logError("file: "__FILE__", line: %d, "
                    "write to file %s fail, errno: %d, error info: %s",
                    __LINE__, tmp_filename, result, strerror(result));
            break;
        }

        *block_size *= 2;
    }

    free(buff);
    close(fd);
    unlink(tmp_filename);
    return result;
}

int get_path_block_size(const char *path, int *block_size)
{
    char dev_path[64];
    struct stat statbuf;
    int result;

    if (stat(path, &statbuf) != 0) {
        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, "
                "stat %s fail, errno: %d, error info: %s",
                __LINE__, path, result, strerror(result));
        return result;
    }

    if (S_ISBLK(statbuf.st_mode)) {
        return get_device_block_size(path, block_size);
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        logError("file: "__FILE__", line: %d, "
                "%s is NOT a directory!", __LINE__, path);
        return ENOTDIR;
    }

    sprintf(dev_path, "/dev/block/%d:%d", (int)major(statbuf.st_dev),
            (int)minor(statbuf.st_dev));
    if (access(dev_path, R_OK) == 0) {
        if ((result=get_device_block_size(dev_path, block_size)) == 0) {
            return 0;
        }
    }

    return get_block_size_by_write(path, block_size);
}

int get_groups(const pid_t pid, const gid_t gid, const int size, gid_t *list)
{
#define GROUPS_TAG_STR   "\nGroups:"
#define GROUPS_TAG_LEN   (sizeof(GROUPS_TAG_STR) - 1)

    char filename[64];
    char buff[1024];
    char *p;
    char *end;
    int fd;
    int len;
    gid_t val;
    int count;

    sprintf(filename, "/proc/%d/status", pid);
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    len = read(fd, buff, sizeof(buff));
    close(fd);
    if (len <= 0) {
        return 0;
    }

    buff[len - 1] = '\0';
    if ((p=strstr(buff, GROUPS_TAG_STR)) == NULL) {
        return 0;
    }

    p += GROUPS_TAG_LEN;
    count = 0;
    while (count < size) {
        val = strtoul(p, &end, 10);
        if (end == p) {
            break;
        }

        if (val != gid) {
            list[count++] = val;
        }
        p = end;
    }

    return count;
}

#elif defined(OS_FREEBSD)

int get_groups(const pid_t pid, const gid_t gid, const int size, gid_t *list)
{
    int mibpath[4];
    struct kinfo_proc kp;
    size_t kplen;
    int count;
    int i;

#if defined(CTL_KERN) && defined(KERN_PROC) && defined(KERN_PROC_PID)
    mibpath[0] = CTL_KERN;
    mibpath[1] = KERN_PROC;
    mibpath[2] = KERN_PROC_PID;
#else
    kplen = 4;
    sysctlnametomib("kern.proc.pid", mibpath, &kplen);
#endif
    mibpath[3] = pid;

    kplen = sizeof(kp);
    memset(&kp,0,sizeof(kp));
    if (sysctl(mibpath, 4, &kp, &kplen, NULL, 0) != 0) {
        return 0;
    }

#if defined(DARWIN)
#define ki_ngroups kp_eproc.e_ucred.cr_ngroups
#define ki_groups  kp_eproc.e_ucred.cr_groups
#endif

    count = 0;
    for (i=0; i<kp.ki_ngroups && count<size; i++) {
        if (kp.ki_groups[i] != gid) {
            list[count++] = kp.ki_groups[i];
        }
    }

    return count;
}

#endif
