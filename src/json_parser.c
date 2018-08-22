#include <unistd.h>
#include <errno.h>
#include "shared_func.h"
#include "json_parser.h"

#define JSON_SPACE(ch) \
    (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')

int detect_json_type(const string_t *input)
{
    if (input->len < 2) {
        return FC_JSON_TYPE_STRING;
    }

    if (input->str[0] == '[' && input->str[input->len - 1] == ']') {
        return FC_JSON_TYPE_ARRAY;
    }
    if (input->str[0] == '{' && input->str[input->len - 1] == '}') {
        return FC_JSON_TYPE_MAP;
    }

    return FC_JSON_TYPE_STRING;
}

typedef struct {
    const char *p;
    const char *end;
    string_t element;
    char *error_info;
    int error_size;
} ParseContext;

static int next_json_element(ParseContext *context, const char delim)
{
    char *dest;
    char quote_ch;

    dest = context->element.str;
    quote_ch = *context->p;
    if (quote_ch == '\"' || quote_ch == '\'') {
        context->p++;
        while (context->p < context->end && *context->p != quote_ch) {
            if (*context->p == '\\') {
                if (++context->p == context->end) {
                    snprintf(context->error_info, context->error_size,
                            "expect a character after \\");
                    return EINVAL;
                }
                switch (*context->p) {
                    case '\\':
                        *dest++ = '\\';
                        break;
                    case '/':
                        *dest++ = '/';
                        break;
                    case 't':
                        *dest++ = '\t';
                        break;
                    case 'r':
                        *dest++ = '\r';
                        break;
                    case 'n':
                        *dest++ = '\n';
                        break;
                    case 'b':
                        *dest++ = '\f';
                        break;
                    case '"':
                        *dest++ = '\"';
                        break;
                    case '\'':
                        *dest++ = '\'';
                        break;
                    default:
                        snprintf(context->error_info, context->error_size,
                                "invalid escaped character: %c(0x%x)",
                                *context->p, (unsigned char)*context->p);
                        return EINVAL;
                }
                context->p++;
            } else {
                *dest++ = *context->p++;
            }
        }

        if (context->p == context->end) {
            snprintf(context->error_info, context->error_size,
                    "expect closed character: %c", quote_ch);
            return EINVAL;
        }
        context->p++; //skip quote char
    } else {
        while (context->p < context->end && *context->p != delim) {
            *dest++ = *context->p++;
        }
    }

    *dest = '\0';
    context->element.len = dest - context->element.str;
    return 0;
}

static int check_alloc_json_array(string_array_t *array,
        char *error_info, const int error_size)
{
    int bytes;
    if (array->count < array->alloc) {
        return 0;
    }

    if (array->alloc == 0) {
        array->alloc = 32;
    } else {
        array->alloc *= 2;
    }

    bytes = sizeof(string_t) * array->alloc;
    array->elements = (string_t *)realloc(array->elements, bytes);
    if (array->elements == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", bytes);
        return ENOMEM;
    }

    return 0;
}

int decode_json_array(const string_t *input, string_array_t *array,
        char *error_info, const int error_size)
{
    ParseContext context;
    int buff_len;
    int result;

    array->elements = NULL;
    array->count = array->alloc = 0;
    array->buff = NULL;

    if (input->len < 2) {
        snprintf(error_info, error_size, "invalid json array, "
                "correct format: [e1, e2, ...]");
        return EINVAL;
    }

    if (input->str[0] != '[') {
        snprintf(error_info, error_size, "json array must start with [");
        return EINVAL;
    }
    if (input->str[input->len - 1] != ']') {
        snprintf(error_info, error_size, "json array must end with ]");
        return EINVAL;
    }

    buff_len = input->len - 2;
    array->buff = (char *)malloc(buff_len + 1);
    if (array->buff == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", buff_len + 1);
        return ENOMEM;
    }

    context.error_info = error_info;
    context.error_size = error_size;
    context.element.str = array->buff;
    context.element.len = 0;
    context.p = input->str + 1;
    context.end = input->str + input->len - 1;
    result = 0;
    while (context.p < context.end) {
        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }

        if (context.p == context.end) {
            break;
        }

        fprintf(stderr, "start: %s\n", context.p);

        if (*context.p == ',') {
            context.p++;
            while (context.p < context.end && JSON_SPACE(*context.p)) {
                context.p++;
            }
            if (context.p < context.end) { //ignore last comma
                snprintf(error_info, error_size, "unexpect comma");
                result = EINVAL;
            }
            break;
        }

        if ((result=next_json_element(&context, ',')) != 0) {
            break;
        }

        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }
        if (context.p < context.end && *context.p == ',') {
            context.p++;   //skip comma
        }
        fprintf(stderr, "end: %s\n", context.p);

        if ((result=check_alloc_json_array(array, error_info, error_size)) != 0) {
            array->count = 0;
            break;
        }

        array->elements[array->count++] = context.element;
        context.element.str += context.element.len + 1;
    }

    if (result != 0) {
        free_json_array(array);
    }
    return result;
}

void free_json_array(string_array_t *array)
{
    if (array->elements != NULL) {
        free(array->elements);
        array->elements = NULL;
        array->count = 0;
    }

    if (array->buff != NULL) {
        free(array->buff);
        array->buff = NULL;
    }
}

int encode_json_array(string_array_t *array, string_t *output,
        char *error_info, const int error_size)
{
    string_t *el;
    string_t *end;
    char *p;
    int size;

    end = array->elements + array->count;
    size = 3;
    for (el=array->elements; el<end; el++) {
        size += el->len + 3;
    }

    output->str = (char *)malloc(size);
    if (output->str == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", size);
        return ENOMEM;
    }

    p = output->str;
    *p++ = '[';
    output->len = 1;
    for (el=array->elements; el<end; el++) {
        if (el > array->elements) {
            *p++ = ',';
            output->len++;
        }

        *p++ = '"';
        memcpy(p, el->str, el->len);
        p += el->len;
        *p++ = '"';
        output->len += el->len + 2;
    }

    *p++ = ']';
    *p = '\0';
    return 0;
}
