//fast_allocator.c

#include <errno.h>
#include <pthread.h>
#include "logger.h"
#include "shared_func.h"
#include "fast_allocator.h"

static int region_init(struct fast_allocator_context *acontext,
	struct fast_region_info *region)
{
	int result;
	int bytes;
	int element_size;
	int allocator_count;
	struct fast_mblock_man *mblock;

	allocator_count = (region->end - region->start) / region->step;
	bytes = sizeof(struct fast_mblock_man) * allocator_count;
	region->allocators = (struct fast_mblock_man *)malloc(bytes);
	if (region->allocators == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, "
				"malloc %d bytes fail, errno: %d, error info: %s",
				__LINE__, bytes, result, STRERROR(result));
		return result;
	}
	memset(region->allocators, 0, bytes);

	result = 0;
	mblock = region->allocators;
	for (element_size=region->start+region->step; element_size<=region->end;
		element_size+=region->step,mblock++)
	{
		result = fast_mblock_init_ex(mblock, element_size,
			region->alloc_elements_once, NULL, acontext->need_lock);
		if (result != 0)
		{
			break;
		}
	}

	return result;
}

static void region_destroy(struct fast_allocator_context *acontext,
	struct fast_region_info *region)
{
	int element_size;
	int allocator_count;
	struct fast_mblock_man *mblock;

	allocator_count = (region->end - region->start) / region->step;
	mblock = region->allocators;
	for (element_size=region->start+region->step; element_size<=region->end;
		element_size+=region->step,mblock++)
	{
		fast_mblock_destroy(mblock);
	}

	free(region->allocators);
	region->allocators = NULL;
}

int fast_allocator_init_ex(struct fast_allocator_context *acontext,
        struct fast_region_info *regions, const int region_count,
        const bool need_lock)
{
	int result;
	int bytes;
	int previous_end;
	struct fast_region_info *pRegion;
	struct fast_region_info *region_end;

	memset(acontext, 0, sizeof(*acontext));
	if (region_count <= 0)
	{
		return EINVAL;
	}

	bytes = sizeof(struct fast_region_info) * region_count;
	acontext->regions = (struct fast_region_info *)malloc(bytes);
	if (acontext->regions == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, "
				"malloc %d bytes fail, errno: %d, error info: %s",
				__LINE__, bytes, result, STRERROR(result));
		return result;
	}
	memcpy(acontext->regions, regions, bytes);
	acontext->region_count = region_count;
	acontext->need_lock = need_lock;
	result = 0;
	previous_end = 0;
	region_end = acontext->regions + acontext->region_count;
	for (pRegion=acontext->regions; pRegion<region_end; pRegion++)
	{
		if (pRegion->start != previous_end)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid start: %d != last end: %d",
				__LINE__, pRegion->start, previous_end);
			result = EINVAL;
			break;
		}
		if (pRegion->start >= pRegion->end)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid start: %d >= end: %d",
				__LINE__, pRegion->start, pRegion->end);
			result = EINVAL;
			break;
		}
		if (pRegion->step <= 0)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid step: %d",
				__LINE__, pRegion->step);
			result = EINVAL;
			break;
		}
		if (pRegion->start % pRegion->step != 0)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid start: %d, must multiple of step: %d",
				__LINE__, pRegion->start, pRegion->step);
			result = EINVAL;
			break;
		}
		if (pRegion->end % pRegion->step != 0)
		{
			logError("file: "__FILE__", line: %d, "
				"invalid end: %d, must multiple of step: %d",
				__LINE__, pRegion->end, pRegion->step);
			result = EINVAL;
			break;
		}
		previous_end = pRegion->end;

		if ((result=region_init(acontext, pRegion)) != 0)
		{
			break;
		}
	}

	return result;
}

#define INIT_REGION(region, _start, _end, _step, _alloc_once) \
	do { \
		region.start = _start; \
		region.end = _end;     \
		region.step = _step;   \
		region.alloc_elements_once = _alloc_once;   \
	} while(0)

int fast_allocator_init(struct fast_allocator_context *acontext,
        const bool need_lock)
{
#define DEFAULT_REGION_COUNT 6

        struct fast_region_info regions[DEFAULT_REGION_COUNT]; 

	INIT_REGION(regions[0],     0,   256,    8,  4096);
	INIT_REGION(regions[1],   256,  1024,   16,  1024);
	INIT_REGION(regions[2],  1024,  4096,   64,   256);
	INIT_REGION(regions[3],  4096, 16384,  256,    64);
	INIT_REGION(regions[4], 16384, 65536, 1024,    16);

	return fast_allocator_init_ex(acontext, regions,
		DEFAULT_REGION_COUNT, need_lock);
}

void fast_allocator_destroy(struct fast_allocator_context *acontext)
{
	struct fast_region_info *pRegion;
	struct fast_region_info *region_end;

	region_end = acontext->regions + acontext->region_count;
	for (pRegion=acontext->regions; pRegion<region_end; pRegion++)
	{
		region_destroy(acontext, pRegion);
	}

	free(acontext->regions);
	acontext->regions = NULL;
}

void* fast_allocator_alloc(struct fast_allocator_context *acontext,
	const int bytes)
{
	return NULL;
}

void fast_allocator_free(struct fast_allocator_context *acontext, void *ptr)
{
}

