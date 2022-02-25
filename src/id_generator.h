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

/**
  64 bits id generator for multi processes, the generated id format:
  32 bits timestamp + X bits machine id  + Y bits of extra data + Z bits serial number
  such as 12 bits machine id, 0 bits extra data and 20 bits serial number
*/

#ifndef ID_GENERATOR_H
#define ID_GENERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <fcntl.h>
#include "common_define.h"

#define ID_GENERATOR_DEFAULT_FILE_MODE  0666

#ifdef __cplusplus
extern "C" {
#endif

struct idg_context {
    int fd;
    int machine_id;
    int mid_bits;   //bits of machine id
    int extra_bits; //extra bits
    int sn_bits;    //bits of serial number
    int mes_bits_sum;  //mid_bits + extra_bits + sn_bits
    int64_t masked_mid;
    int64_t extra_mask;
    int64_t sn_mask;
};

/**
* init function
* parameter:
*   context: the id generator context
*   filename: the filename to store id
*   machine_id: the machine id, 0 for auto generate by local ip address
*   mid_bits:  the bits of machine id, such as 16
*   extra_bits: the extra bits, such as 0
*   sn_bits:  the bits of serial no, such as 16, mid_bits + sn_bits must <= 32
*   mode:     the mode for file open
* return error no, 0 for success, none zero for fail
*/
int id_generator_init_extra_ex(struct idg_context *context, const char *filename,
    const int machine_id, const int mid_bits, const int extra_bits,
    const int sn_bits, const mode_t mode);

/**
* init function
* parameter:
*   context: the id generator context
*   filename: the filename to store id
*   machine_id: the machine id, 0 for auto generate by local ip address
*   mid_bits:  the bits of machine id, such as 16
*   extra_bits: the extra bits, such as 0
*   sn_bits:  the bits of serial no, such as 16, mid_bits + sn_bits must <= 32
* return error no, 0 for success, none zero for fail
*/
int id_generator_init_extra(struct idg_context *context, const char *filename,
    const int machine_id, const int mid_bits, const int extra_bits,
    const int sn_bits);

/**
* init function
* parameter:
*   context: the id generator context
*   filename: the filename to store id
*   machine_id: the machine id, 0 for auto generate by local ip address
*   mid_bits:  the bits of machine id, such as 16
*   sn_bits:  the bits of serial no, such as 16, mid_bits + sn_bits must <= 32
* return error no, 0 for success, none zero for fail
*/
static inline int id_generator_init_ex(struct idg_context *context,
        const char *filename, const int machine_id, const int mid_bits,
        const int sn_bits)
{
    const int extra_bits = 0;
	return id_generator_init_extra(context, filename, machine_id, mid_bits,
            extra_bits, sn_bits);
}

/**
* init function
    set machine_id to 2 bytes of local ip address
    set mid_bits to 16
    set extra_bits to 0
    set sn_bits to 16
* parameter:
*   context: the id generator context
*   filename: the filename to store id
* return error no, 0 for success, none zero for fail
*/
static inline int id_generator_init(struct idg_context *context, const char *filename)
{
	const int machine_id = 0;
	const int mid_bits = 16;
    const int extra_bits = 0;
	const int sn_bits = 16;
	return id_generator_init_extra(context, filename, machine_id, mid_bits,
            extra_bits, sn_bits);
}

/**
* destroy function
* parameter:
*   context: the id generator context
* return none
*/
void id_generator_destroy(struct idg_context *context);

/**
* generate next id with extra pointer
* parameter:
*   context: the id generator context
*   extra: the extra data pointer, NULL for set extra data to sn % (1 << extra_bits)
*   id: store the id
* return error no, 0 for success, none zero for fail
*/
int id_generator_next_extra_ptr(struct idg_context *context,
        const int *extra, int64_t *id);

/**
* generate next id with extra data
* parameter:
*   context: the id generator context
*   extra: the extra data
*   id: store the id
* return error no, 0 for success, none zero for fail
*/
static inline int id_generator_next_extra(struct idg_context *context,
        const int extra, int64_t *id)
{
    return id_generator_next_extra_ptr(context, &extra, id);
}

/**
* generate next id, set extra data to sn % (1 << extra_bits)
* parameter:
*   context: the id generator context
*   id: store the id
* return error no, 0 for success, none zero for fail
*/
static inline int id_generator_next_extra_by_mod(struct idg_context *context,
        int64_t *id)
{
    return id_generator_next_extra_ptr(context, NULL, id);
}

/**
* generate next id
* parameter:
*   context: the id generator context
*   id: store the id
* return error no, 0 for success, none zero for fail
*/
static inline int id_generator_next(struct idg_context *context, int64_t *id)
{
    const int extra = 0;
    return id_generator_next_extra_ptr(context, &extra, id);
}

/**
* get extra data from id
* parameter:
*   context: the id generator context
*   id: the id
* return the extra data
*/
static inline int id_generator_get_extra(struct idg_context *context,
        const int64_t id)
{
    return (int)((id & context->extra_mask) >> context->sn_bits);
}

/**
* get timestamp from id
* parameter:
*   context: the id generator context
*   id: the id
* return the timestamp
*/
static inline long id_generator_get_timestamp(struct idg_context *context,
        const int64_t id)
{
    return (long)(id >> context->mes_bits_sum);
}

#ifdef __cplusplus
}
#endif

#endif

