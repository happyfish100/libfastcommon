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

//local_ip_func.h

#ifndef _LOCAL_IP_FUNC_H
#define _LOCAL_IP_FUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"

#define FAST_IF_ALIAS_PREFIX_MAX_SIZE 32
#define FAST_MAX_LOCAL_IP_ADDRS	  16

#define LOCAL_LOOPBACK_IP  "127.0.0.1"

#ifdef __cplusplus
extern "C" {
#endif

extern int g_local_host_ip_count;
extern char g_local_host_ip_addrs[FAST_MAX_LOCAL_IP_ADDRS * \
				IP_ADDRESS_SIZE];
extern char g_if_alias_prefix[FAST_IF_ALIAS_PREFIX_MAX_SIZE];

void load_local_host_ip_addrs();
bool is_local_host_ip(const char *client_ip);

const char *get_first_local_ip();
const char *get_next_local_ip(const char *previous_ip);

const char *get_first_local_private_ip();

int insert_into_local_host_ip(const char *client_ip);
void log_local_host_ip_addrs();
void print_local_host_ip_addrs();
const char *local_host_ip_addrs_to_string(char *buff, const int size);

#ifdef __cplusplus
}
#endif

#endif

