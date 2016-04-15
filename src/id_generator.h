/**
* Copyright (C) 2016 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

/**
  64 bits id generator for multi processes, the generated id format:
  32 bits timestamp + X bits machine id  + Y bits serial number
  such as 12 bits machine id and 20 bits serial number
*/

#ifndef ID_GENERATOR_H
#define ID_GENERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>
#include "common_define.h"

#ifdef __cplusplus
extern "C" {
#endif

struct idg_context {
    int fd;
    int machine_id;
    int mid_bits;   //bits of machine id
    int sn_bits;    //bits of serial number
    int mid_sn_bits;  //mid_bits + sn_bits
    int64_t masked_mid;
    int64_t sn_mask;
};

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
int id_generator_init_ex(struct idg_context *context, const char *filename,
    const int machine_id, const int mid_bits, const int sn_bits);

/**
* init function
    set machine_id to 2 bytes of local ip address
    set mid_bits to 16
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
	const int sn_bits = 16;
	return id_generator_init_ex(context, filename, machine_id, mid_bits, sn_bits);
}

/**
* destroy function
* parameter:
*   context: the id generator context
* return none
*/
void id_generator_destroy(struct idg_context *context);

/**
* generate next id
* parameter:
*   context: the id generator context
*   id: store the id
* return error no, 0 for success, none zero for fail
*/
int id_generator_next(struct idg_context *context, int64_t *id);

#ifdef __cplusplus
}
#endif

#endif

