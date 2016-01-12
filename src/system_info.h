/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

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
        fsid_t  f_fsid;     /* file system id */

        char    f_fstypename[MFSNAMELEN]; /* fs type name */
        char    f_mntfromname[MNAMELEN];  /* mounted file system */
        char    f_mntonname[MNAMELEN];    /* directory on which mounted */
    } FastStatFS;

/** get system total memory size
 *  parameters:
 *  	mem_size: return the total memory size
 *  return: error no , 0 success, != 0 fail
*/
int get_sys_total_mem_size(int64_t *mem_size);


/** get system CPU count
 *  parameters:
 *  return: error no , 0 success, != 0 fail
*/
int get_sys_cpu_count();

/** get system up time
 *  parameters:
 *      uptime: store the up time
 *  return: error no , 0 success, != 0 fail
*/
int get_uptime(time_t *uptime);

/** get mounted file systems
 *  parameters:
 *      stats: the stat array
 *      size:  max size of the array
 *      count: return the count of the array
 *  return: error no , 0 success, != 0 fail
*/
int get_mounted_filesystems(struct fast_statfs *stats, const int size, int *count);

#ifdef __cplusplus
}
#endif

#endif

