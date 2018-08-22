//json_parser.h

#ifndef _JSON_PARSER_H
#define _JSON_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common_define.h"

#define FC_JSON_TYPE_STRING   1
#define FC_JSON_TYPE_ARRAY    2
#define FC_JSON_TYPE_MAP      3

typedef struct
{
	string_t *elements;
	int count;

	int alloc;   //for internal use
    char *buff;  //for internal use
} string_array_t;

#ifdef __cplusplus
extern "C" {
#endif

    int detect_json_type(const string_t *input);

    int decode_json_array(const string_t *input, string_array_t *array,
            char *error_info, const int error_size);

    int encode_json_array(string_array_t *array, string_t *output,
            char *error_info, const int error_size);

    void free_json_array(string_array_t *array);

    static inline void free_json_string(string_t *buffer)
    {
        if (buffer->str != NULL) {
            free(buffer->str);
            buffer->str = NULL;
            buffer->len = 0;
        }
    }

#ifdef __cplusplus
}
#endif

#endif

