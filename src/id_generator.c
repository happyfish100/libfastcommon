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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "logger.h"
#include "shared_func.h"
#include "local_ip_func.h"
#include "id_generator.h"

int id_generator_init_ex(struct idg_context *context, const char *filename,
    const int machine_id, const int mid_bits)
{
	int result;
	int mid;
	if (mid_bits < 2 || mid_bits > 20)
	{
		logError("file: "__FILE__", line: %d, "
			"invalid bits of machine id: %d",
			__LINE__, mid_bits);
		context->fd = -1;
		return EINVAL;
	}
	if (machine_id < 0 || machine_id >= (1 << mid_bits))
	{
		logError("file: "__FILE__", line: %d, "
			"invalid machine id: %d",
			__LINE__, machine_id);
		context->fd = -1;
		return EINVAL;
	}
	if (machine_id != 0)
	{
		mid = machine_id;
	}
	else
	{
		const char *local_ip;
		struct in_addr ip_addr;

		local_ip = get_first_local_ip();
		if (local_ip == NULL)
		{
			logError("file: "__FILE__", line: %d, "
				"can't get local ip address", __LINE__);
			context->fd = -1;
			return ENOENT;
		}

		if (inet_pton(AF_INET, local_ip, &ip_addr) != 1)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid local ip address: %s",
				__LINE__, local_ip);
			context->fd = -1;
			return EINVAL;
		}

		printf("ip_addr: %s, s_addr: %08X\n", local_ip, ip_addr.s_addr);
		printf("mask number: %08X\n", (1 << mid_bits));

		mid = (ip_addr.s_addr >> (32 - mid_bits))  & ((1 << mid_bits) - 1);
	}

	if ((context->fd = open(filename, O_RDWR | O_CREAT, 0644)) < 0)
	{
		result = errno != 0 ? errno : EACCES;
		logError("file: "__FILE__", line: %d, "
			"open file \"%s\" fail, "
			"errno: %d, error info: %s", __LINE__,
			filename, result, STRERROR(result));
		return result;
	}

	context->machine_id = mid;
	context->mid_bits = mid_bits;
	context->sn_bits = 32 - mid_bits;
	context->masked_mid = ((int64_t)mid) << context->sn_bits;
	context->sn_mask = ((int64_t)1 << context->sn_bits) - 1;

	printf("mid: %08X, masked_mid: %016llX, sn_mask: %08llX\n", mid, context->masked_mid, context->sn_mask);

	return 0;
}

void id_generator_destroy(struct idg_context *context)
{
	if (context->fd >= 0)
	{
		close(context->fd);
		context->fd = -1;
	}
}

int id_generator_next(struct idg_context *context, int64_t *id)
{
	int result;
	int len;
	int bytes;
	int64_t sn;
	char buff[32];
	char *endptr;

	if ((result=file_write_lock(context->fd)) != 0)
	{
		return result;
	}

	do
	{
		if (lseek(context->fd, 0L, SEEK_SET) == -1)
		{
			result = errno != 0 ? errno : EACCES;
			logError("file: "__FILE__", line: %d, "
				"file lseek fail, "
				"errno: %d, error info: %s", __LINE__,
				result, STRERROR(result));
			sn = 0;
			break;
		}

		if ((bytes=read(context->fd, buff, sizeof(buff) - 1)) < 0)
		{
			result = errno != 0 ? errno : EACCES;
			logError("file: "__FILE__", line: %d, "
				"file read fail, "
				"errno: %d, error info: %s", __LINE__,
				result, STRERROR(result));
			sn = 0;
			break;
		}
		*(buff + bytes) = '\0';

		sn = strtoll(buff, &endptr, 10);
		++sn;

		if (lseek(context->fd, 0L, SEEK_SET) == -1)
		{
			result = errno != 0 ? errno : EACCES;
			logError("file: "__FILE__", line: %d, "
				"cal lseek fail, "
				"errno: %d, error info: %s", __LINE__,
				result, STRERROR(result));
			break;
		}

		len = sprintf(buff, "%019"PRId64, sn);
		if ((bytes=write(context->fd, buff, len)) != len)
		{
			result = errno != 0 ? errno : EACCES;
			logError("file: "__FILE__", line: %d, "
				"file write %d bytes fail, written: %d bytes, "
				"errno: %d, error info: %s", __LINE__,
				len, bytes, result, STRERROR(result));
			break;
		}
	} while (0);

	file_unlock(context->fd);

	*id = (time(NULL) << 32) | context->masked_mid | (sn & context->sn_mask);
	return result;
}

