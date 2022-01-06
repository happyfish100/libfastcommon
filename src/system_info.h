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

#ifndef SYSTEM_INFO_H
#define SYSTEM_INFO_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/mount.h>
#include "common_define.h"

#ifdef OS_LINUX
#include <sys/sysinfo.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MFSNAMELEN
#define MFSNAMELEN 16
#endif

#ifndef MNAMELEN 
#define MNAMELEN 128
#endif

   typedef struct fast_statfs {
        long    f_type;     /* type of file system (see below) */
        long    f_bsize;    /* optimal transfer block size */
        long    f_blocks;   /* total data blocks in file system */
        long    f_bfree;    /* free blocks in fs */
        long    f_bavail;   /* free blocks avail to non-superuser */
        long    f_files;    /* total file nodes in file system */
        long    f_ffree;    /* free file nodes in fs */
#ifdef HAVE_FILE_SYSTEM_ID
        fsid_t  f_fsid;     /* file system id */
#endif
        char    f_fstypename[MFSNAMELEN]; /* fs type name */
        char    f_mntfromname[MNAMELEN];  /* mounted file system */
        char    f_mntonname[MNAMELEN];    /* directory on which mounted */
    } FastStatFS;

#if defined(OS_LINUX) || defined(OS_FREEBSD)
   struct fast_sysinfo {
       struct timeval boot_time;   /* system boot times */
       double loads[3];  /* 1, 5, and 15 minute load averages */
       unsigned long totalram;  /* Total usable main memory size */
       unsigned long freeram;   /* Available memory size */
       unsigned long sharedram; /* Amount of shared memory */
       unsigned long bufferram; /* Memory used by buffers */
       unsigned long totalswap; /* Total swap space size */
       unsigned long freeswap;  /* swap space still available */
       unsigned short procs;    /* Number of current processes */
   };

   typedef struct fast_process_info {
       int field_count;  //field count in /proc/$pid/stat
       int pid;
       char comm[128];
       char state;
       int ppid;
       int pgrp;
       int session;
       int tty_nr;
       int tpgid;
       unsigned int flags;
       unsigned long minflt;
       unsigned long cminflt;
       unsigned long majflt;
       unsigned long cmajflt;
       unsigned long utime;
       unsigned long stime;
       long cutime;
       long cstime;
       long priority;
       long nice;
       long num_threads;
       long itrealvalue;
       struct timeval starttime;
       unsigned long vsize;
       long rss;
       unsigned long rsslim;
       unsigned long startcode;
       unsigned long endcode;
       unsigned long startstack;
       unsigned long kstkesp;
       unsigned long kstkeip;
       unsigned long signal;
       unsigned long blocked;
       unsigned long sigignore;
       unsigned long sigcatch;
       unsigned long wchan;
       unsigned long nswap;
       unsigned long cnswap;
       int exit_signal;
       int processor;
       unsigned int rt_priority;
       unsigned int policy;
       unsigned long long delayacct_blkio_ticks;
       unsigned long guest_time;
       long cguest_time;
   } FastProcessInfo;
#endif

/** get system total memory size
 *  parameters:
 *  	mem_size: return the total memory size
 *  return: error no, 0 success, != 0 fail
*/
int get_sys_total_mem_size(int64_t *mem_size);


/** get system CPU count
 *  parameters:
 *  return: error no, 0 success, != 0 fail
*/
int get_sys_cpu_count();

/** get system boot time
 *  parameters:
 *      uptime: store the up time
 *  return: error no, 0 success, != 0 fail
*/
int get_boot_time(struct timeval *boot_time);

/** get mounted file systems
 *  parameters:
 *      stats: the stat array
 *      size:  max size of the array
 *      count: return the count of the array
 *  return: error no, 0 success, != 0 fail
*/
int get_mounted_filesystems(struct fast_statfs *stats,
        const int size, int *count);

#if defined(OS_LINUX) || defined(OS_FREEBSD)
/** get processes
 *  parameters:
 *      processes: return the processes
 *      count: return the count of the processes
 *  return: error no, 0 success, != 0 fail
*/
int get_processes(struct fast_process_info **processes, int *count);

int get_sysinfo(struct fast_sysinfo *info);

int get_kernel_version(Version *version);

#ifdef OS_LINUX
int get_device_block_size(const char *device, int *block_size);
int get_path_block_size(const char *path, int *block_size);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif

