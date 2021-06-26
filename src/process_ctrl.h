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


#ifndef PROCESS_CTRL_H
#define PROCESS_CTRL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifdef __cplusplus
extern "C" {
#endif

int get_base_path_from_conf_file(const char *filename, char *base_path,
	const int path_size);

int get_pid_from_file(const char *pidFilename, pid_t *pid);

int write_to_pid_file(const char *pidFilename);

int delete_pid_file(const char *pidFilename);

int process_stop_ex(const char *pidFilename, const bool bShowError);

#define process_stop(pidFilename) process_stop_ex(pidFilename, true)

int process_restart(const char *pidFilename);

int process_exist(const char *pidFilename, pid_t *pid);

int process_action(const char *pidFilename, const char *action, bool *stop);

#ifdef __cplusplus
}
#endif

#endif

