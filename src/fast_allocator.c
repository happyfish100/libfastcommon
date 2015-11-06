//fast_allocator.c

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include "logger.h"
#include "shared_func.h"
#include "fast_allocator.h"

#define BYTES_ALIGN(x, pad_mask)  (((x) + pad_mask) & (~pad_mask))

struct allocator_wrapper {
	int alloc_bytes;
	short allocator_index;
	short magic_number;
};

static struct fast_allocator_info malloc_allocator;

#define ADD_ALLOCATOR_TO_ARRAY(acontext, allocator, _pooled) \
	do { \
		(allocator)->index = acontext->allocator_array.count; \
		(allocator)->magic_number = rand();   \
		(allocator)->pooled = _pooled;        \
		acontext->allocator_array.allocators[ \
			acontext->allocator_array.count++] = allocator; \
		/* logInfo("count: %d, magic_number: %d", acontext->allocator_array.count, (allocator)->magic_number); */\
	} while (0)


static int allocator_array_check_capacity(struct fast_allocator_context *acontext,
	const int allocator_count)
{
	int result;
	int bytes;
	struct fast_allocator_info  **new_allocators;

	if (acontext->allocator_array.alloc >= acontext->allocator_array.count +
		allocator_count)
	{
		return 0;
	}
	if (acontext->allocator_array.alloc == 0)
	{
		acontext->allocator_array.alloc = 2 * allocator_count;
	}
	else
	{
		do
		{
			acontext->allocator_array.alloc *= 2;
		} while (acontext->allocator_array.alloc < allocator_count);
	}

	bytes = sizeof(struct fast_allocator_info*) * acontext->allocator_array.alloc;
	new_allocators = (struct fast_allocator_info **)malloc(bytes);
	if (new_allocators == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, "
				"malloc %d bytes fail, errno: %d, error info: %s",
				__LINE__, bytes, result, STRERROR(result));
		return result;
	}

	if (acontext->allocator_array.allocators != NULL)
	{
		memcpy(new_allocators, acontext->allocator_array.allocators,
			sizeof(struct fast_allocator_info *) *
			acontext->allocator_array.count);
		free(acontext->allocator_array.allocators);
	}
	acontext->allocator_array.allocators = new_allocators;
	return 0;
}

static int region_init(struct fast_allocator_context *acontext,
	struct fast_region_info *region)
{
	int result;
	int bytes;
	int element_size;
	int allocator_count;
	struct fast_allocator_info *allocator;

	region->pad_mask = region->step - 1;
	allocator_count = (region->end - region->start) / region->step;
	bytes = sizeof(struct fast_allocator_info) * allocator_count;
	region->allocators = (struct fast_allocator_info *)malloc(bytes);
	if (region->allocators == NULL)
	{
		result = errno != 0 ? errno : ENOMEM;
		logError("file: "__FILE__", line: %d, "
				"malloc %d bytes fail, errno: %d, error info: %s",
				__LINE__, bytes, result, STRERROR(result));
		return result;
	}
	memset(region->allocators, 0, bytes);


	if ((result=allocator_array_check_capacity(acontext, allocator_count)) != 0)
	{
		return result;
	}

	result = 0;
 	allocator = region->allocators;
	for (element_size=region->start+region->step; element_size<=region->end;
		element_size+=region->step,allocator++)
	{
		result = fast_mblock_init_ex(&allocator->mblock, element_size,
			region->alloc_elements_once, NULL, acontext->need_lock);
		if (result != 0)
		{
			break;
		}

		ADD_ALLOCATOR_TO_ARRAY(acontext, allocator, true);
	}

	return result;
}

static void region_destroy(struct fast_allocator_context *acontext,
	struct fast_region_info *region)
{
	int element_size;
	int allocator_count;
	struct fast_allocator_info *allocator;

	allocator_count = (region->end - region->start) / region->step;
	allocator = region->allocators;
	for (element_size=region->start+region->step; element_size<=region->end;
		element_size+=region->step,allocator++)
	{
		fast_mblock_destroy(&allocator->mblock);
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

	srand(time(NULL));
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
		if (pRegion->step <= 0 || !is_power2(pRegion->step))
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

	if (result != 0)
	{
		return result;
	}

	if ((result=allocator_array_check_capacity(acontext, 1)) != 0)
	{
		return result;
	}

	ADD_ALLOCATOR_TO_ARRAY(acontext, &malloc_allocator, false);
	/*
	logInfo("sizeof(struct allocator_wrapper): %d, allocator_array count: %d",
		(int)sizeof(struct allocator_wrapper), acontext->allocator_array.count);
	*/
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
#define DEFAULT_REGION_COUNT 5

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

	if (acontext->regions != NULL)
	{
		region_end = acontext->regions + acontext->region_count;
		for (pRegion=acontext->regions; pRegion<region_end; pRegion++)
		{
			region_destroy(acontext, pRegion);
		}
		free(acontext->regions);
	}

	if (acontext->allocator_array.allocators != NULL)
	{
		free(acontext->allocator_array.allocators);
	}
	memset(acontext, 0, sizeof(*acontext));
}

static struct fast_allocator_info *get_allocator(struct fast_allocator_context *acontext,
	int *alloc_bytes)
{
	struct fast_region_info *pRegion;
	struct fast_region_info *region_end;

	region_end = acontext->regions + acontext->region_count;
	for (pRegion=acontext->regions; pRegion<region_end; pRegion++)
	{
		if (*alloc_bytes <= pRegion->end)
		{
			*alloc_bytes = BYTES_ALIGN(*alloc_bytes, pRegion->pad_mask);
			return pRegion->allocators + ((*alloc_bytes -
				pRegion->start) / pRegion->step) - 1;
		}
	}

	return &malloc_allocator;
}

void *fast_allocator_alloc(struct fast_allocator_context *acontext,
	const int bytes)
{
	int alloc_bytes;
	struct fast_allocator_info *allocator_info;
	void *ptr;

	if (bytes < 0)
	{
		return NULL;
	}

	alloc_bytes = sizeof(struct allocator_wrapper) + bytes;
	allocator_info = get_allocator(acontext, &alloc_bytes);
	if (allocator_info->pooled)
	{
		ptr = fast_mblock_alloc_object(&allocator_info->mblock);
	}
	else
	{
		ptr = malloc(alloc_bytes);
	}
	if (ptr == NULL)
	{
		return NULL;
	}

	((struct allocator_wrapper *)ptr)->allocator_index = allocator_info->index;
	((struct allocator_wrapper *)ptr)->magic_number = allocator_info->magic_number;
	((struct allocator_wrapper *)ptr)->alloc_bytes = alloc_bytes;

	__sync_add_and_fetch(&acontext->alloc_bytes, alloc_bytes);
	return (char *)ptr + sizeof(struct allocator_wrapper);
}

void fast_allocator_free(struct fast_allocator_context *acontext, void *ptr)
{
	struct allocator_wrapper *pWrapper;
	struct fast_allocator_info *allocator_info;
	void *obj;
	if (ptr == NULL)
	{
		return;
	}

	obj = (char *)ptr - sizeof(struct allocator_wrapper);
	pWrapper = (struct allocator_wrapper *)obj;
	if (pWrapper->allocator_index < 0 || pWrapper->allocator_index >=
		acontext->allocator_array.count)
	{
		logError("file: "__FILE__", line: %d, "
				"invalid allocator index: %d",
				__LINE__, pWrapper->allocator_index);
		return;
	}

	allocator_info = acontext->allocator_array.allocators[pWrapper->allocator_index];
	if (pWrapper->magic_number != allocator_info->magic_number)
	{
		logError("file: "__FILE__", line: %d, "
				"invalid magic number: %d != %d",
				__LINE__, pWrapper->magic_number,
				allocator_info->magic_number);
		return;
	}

	__sync_sub_and_fetch(&acontext->alloc_bytes, pWrapper->alloc_bytes);
	pWrapper->allocator_index = -1;
	pWrapper->magic_number = 0;
	if (allocator_info->pooled)
	{
		fast_mblock_free_object(&allocator_info->mblock, obj);
	}
	else
	{
		free(obj);
	}
}

