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
#include "common_define.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif

