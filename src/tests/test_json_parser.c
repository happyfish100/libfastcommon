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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/json_parser.h"

int main(int argc, char *argv[])
{
    int result;
    int json_type;
    fc_json_context_t json_ctx;
    char error_info[256];
    string_t input;
    BufferInfo output;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <json_string | json_array | json_map>\n",
                argv[0]);
        return EINVAL;
    }
	
	log_init();

    if ((result=fc_init_json_context_ex(&json_ctx, 1024,
                    error_info, sizeof(error_info))) != 0)
    {
        return result;
    }
    memset(&output, 0, sizeof(output));

    input.str = argv[1];
    input.len = strlen(input.str);
    json_type = fc_detect_json_type(&input);
    if (json_type == FC_JSON_TYPE_ARRAY) {
        const fc_json_array_t *array;

        if ((array=fc_decode_json_array(&json_ctx, &input)) == NULL) {
            fprintf(stderr, "decode json array fail, %s\n", error_info);
            return fc_json_parser_get_error_no(&json_ctx);
        }

        if ((result=fc_encode_json_array_ex(&json_ctx, array->elements,
                        array->count, &output)) != 0)
        {
            fprintf(stderr, "encode json array fail, %s\n", error_info);
            return result;
        }

        printf("%.*s\n", output.length, output.buff);
    } else if (json_type == FC_JSON_TYPE_MAP) {
        const fc_json_map_t *map;

        if ((map=fc_decode_json_map(&json_ctx, &input)) == NULL) {
            fprintf(stderr, "decode json map fail, %s\n", error_info);
            return fc_json_parser_get_error_no(&json_ctx);
        }

        if ((result=fc_encode_json_map_ex(&json_ctx, map->elements,
                        map->count, &output)) != 0)
        {
            fprintf(stderr, "encode json map fail, %s\n", error_info);
            return result;
        }

        printf("%.*s\n", output.length, output.buff);
    } else {
        fprintf(stderr, "string\n");
    }
 
    fc_destroy_json_context(&json_ctx);
	return 0;
}
