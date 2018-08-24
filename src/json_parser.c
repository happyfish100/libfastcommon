#include <unistd.h>
#include <errno.h>
#include "shared_func.h"
#include "json_parser.h"

#define EXPECT_STR_LEN   80

#define JSON_SPACE(ch) \
    (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')

#define JSON_TOKEN(ch) \
    ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || \
     (ch >= '0' && ch <= '9') || (ch == '_' || ch == '-'  || \
         ch == '.'))

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
    const char *str;  //input string
    const char *p;    //current
    const char *end;
    string_t element;
    char *error_info;
    int error_size;
} ParseContext;

static void set_parse_error(const char *str, const char *current,
        const int expect_len, const char *front,
        char *error_info, const int error_size)
{
    const char *show_str;
    int show_len;

    show_len = current - str;
    if (show_len > expect_len) {
        show_len = expect_len;
    }
    show_str = current - show_len;
    snprintf(error_info, error_size, "%s, input: %.*s",
            front, show_len, show_str);
}

static int json_escape_string(const string_t *input, string_t *output,
        char *error_info, const int error_size)
{
    const char *src;
    const char *end;
    char *dest;
    int size;

    size = 2 * input->len + 1;
    output->str = (char *)malloc(size);
    if (output->str == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", size);
        return ENOMEM;
    }

    dest = output->str;
    end = input->str + input->len;
    for (src=input->str; src<end; src++) {
        switch (*src) {
            case '\\':
                *dest++ = '\\';
                *dest++ = '\\';
                break;
            case '\t':
                *dest++ = '\\';
                *dest++ = 't';
                break;
            case '\r':
                *dest++ = '\\';
                *dest++ = 'r';
                break;
            case '\n':
                *dest++ = '\\';
                *dest++ = 'n';
                break;
            case '\b':
                *dest++ = '\\';
                *dest++ = 'b';
                break;
            case '\"':
                *dest++ = '\\';
                *dest++ = '\"';
                break;
            case '\'':
                *dest++ = '\\';
                *dest++ = '\'';
                break;
            default:
                *dest++ = *src;
                break;
        }
    }

    *dest = '\0';
    output->len = dest - output->str;
    return 0;
}

static int next_json_element(ParseContext *context)
{
    char *dest;
    char buff[128];
    char quote_ch;

    dest = context->element.str;
    quote_ch = *context->p;
    if (quote_ch == '\"' || quote_ch == '\'') {
        context->p++;
        while (context->p < context->end && *context->p != quote_ch) {
            if (*context->p == '\\') {
                if (++context->p == context->end) {
                    set_parse_error(context->str, context->p,
                            EXPECT_STR_LEN, "expect a character after \\",
                            context->error_info, context->error_size);
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
                        sprintf(buff, "invalid escaped character: %c(0x%x)",
                                *context->p, (unsigned char)*context->p);
                        set_parse_error(context->str, context->p + 1, EXPECT_STR_LEN,
                                buff, context->error_info, context->error_size);
                        return EINVAL;
                }
                context->p++;
            } else {
                *dest++ = *context->p++;
            }
        }

        if (context->p == context->end) {
            sprintf(buff, "expect closed character: %c", quote_ch);
            set_parse_error(context->str, context->p, EXPECT_STR_LEN,
                    buff, context->error_info, context->error_size);
            return EINVAL;
        }
        context->p++; //skip quote char
    } else {
        while (context->p < context->end && JSON_TOKEN(*context->p)) {
            *dest++ = *context->p++;
        }
    }

    *dest = '\0';
    context->element.len = dest - context->element.str;
    return 0;
}

static int check_alloc_array(common_array_t *array,
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

    bytes = array->element_size * array->alloc;
    array->elements = realloc(array->elements, bytes);
    if (array->elements == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", bytes);
        return ENOMEM;
    }

    return 0;
}

static inline int check_alloc_json_array(json_array_t *array,
                char *error_info, const int error_size)
{
    return check_alloc_array((common_array_t *)array, error_info, error_size);
}

static inline int check_alloc_json_map(json_map_t *array,
                char *error_info, const int error_size)
{
    return check_alloc_array((common_array_t *)array, error_info, error_size);
}

static int prepare_json_parse(const string_t *input, common_array_t *array,
        char *error_info, const int error_size,
        const char lquote, const char rquote, ParseContext *context)
{
    int buff_len;

    array->elements = NULL;
    array->count = array->alloc = 0;
    array->buff = NULL;

    if (input->len < 2) {
        snprintf(error_info, error_size, "json string is too short");
        return EINVAL;
    }

    if (input->str[0] != lquote) {
        snprintf(error_info, error_size,
                "json array must start with \"%c\"", lquote);
        return EINVAL;
    }
    if (input->str[input->len - 1] != rquote) {
        snprintf(error_info, error_size,
                "json array must end with \"%c\"", rquote);
        return EINVAL;
    }

    buff_len = input->len - 2;
    array->buff = (char *)malloc(buff_len + 1);
    if (array->buff == NULL) {
        snprintf(error_info, error_size,
                "malloc %d bytes fail", buff_len + 1);
        return ENOMEM;
    }

    context->error_info = error_info;
    context->error_size = error_size;
    context->element.str = array->buff;
    context->element.len = 0;
    context->str = input->str;
    context->p = input->str + 1;
    context->end = input->str + input->len - 1;
    return 0;
}

int decode_json_array(const string_t *input, json_array_t *array,
        char *error_info, const int error_size)
{
    ParseContext context;
    int result;

    array->element_size = sizeof(string_t);
    if ((result=prepare_json_parse(input, (common_array_t *)array,
                    error_info, error_size, '[', ']', &context)) != 0)
    {
        return result;
    }

    result = 0;
    while (context.p < context.end) {
        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }

        if (context.p == context.end) {
            break;
        }

        if (*context.p == ',') {
            set_parse_error(input->str, context.p + 1,
                    EXPECT_STR_LEN, "unexpect comma \",\"",
                    error_info, error_size);
            result = EINVAL;
            break;
        }

        if ((result=next_json_element(&context)) != 0) {
            break;
        }

        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }
        if (context.p < context.end) {
            if (*context.p == ',') {
                context.p++;   //skip comma
            } else {
                set_parse_error(input->str, context.p,
                        EXPECT_STR_LEN, "expect comma \",\"",
                        error_info, error_size);
                result = EINVAL;
                break;
            }
        }

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

void free_common_array(common_array_t *array)
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

static int json_quote_string(const string_t *input, char **buff,
        char *error_info, const int error_size)
{
    int result;
    string_t escaped;
    char *p;

    if ((result=json_escape_string(input, &escaped,
                    error_info, error_size)) != 0)
    {
        return result;
    }

    p = *buff;
    *p++ = '"';
    memcpy(p, escaped.str, escaped.len);
    p += escaped.len;
    *p++ = '"';

    *buff = p;
    free(escaped.str);
    return 0;
}

int encode_json_array(json_array_t *array, string_t *output,
        char *error_info, const int error_size)
{
    string_t *el;
    string_t *end;
    char *p;
    int result;
    int size;

    end = array->elements + array->count;
    size = 3;
    for (el=array->elements; el<end; el++) {
        size += 2 * el->len + 3;
    }

    output->str = (char *)malloc(size);
    if (output->str == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", size);
        return ENOMEM;
    }

    p = output->str;
    *p++ = '[';
    for (el=array->elements; el<end; el++) {
        if (el > array->elements) {
            *p++ = ',';
        }

        if ((result=json_quote_string(el, &p, error_info, error_size)) != 0) {
            free_json_string(output);
            return result;
        }
    }

    *p++ = ']';
    *p = '\0';
    output->len = p - output->str;
    return 0;
}

int decode_json_map(const string_t *input, json_map_t *map,
        char *error_info, const int error_size)
{
    ParseContext context;
    key_value_pair_t kv_pair;
    int result;

    map->element_size = sizeof(key_value_pair_t);
    if ((result=prepare_json_parse(input, (common_array_t *)map,
                    error_info, error_size, '{', '}', &context)) != 0)
    {
        return result;
    }

    result = 0;
    while (context.p < context.end) {
        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }

        if (context.p == context.end) {
            break;
        }

        if (*context.p == ',') {
            set_parse_error(input->str, context.p + 1,
                    EXPECT_STR_LEN, "unexpect comma \",\"",
                    error_info, error_size);
            result = EINVAL;
            break;
        }

        if ((result=next_json_element(&context)) != 0) {
            break;
        }
        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }
        if (!(context.p < context.end && *context.p == ':')) {
            set_parse_error(input->str, context.p,
                    EXPECT_STR_LEN, "expect colon \":\"",
                    error_info, error_size);
            result = EINVAL;
            break;
        }
        context.p++;   //skip colon

        kv_pair.key = context.element;
        context.element.str += context.element.len + 1;

        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }
        if ((result=next_json_element(&context)) != 0) {
            break;
        }
        while (context.p < context.end && JSON_SPACE(*context.p)) {
            context.p++;
        }
        if (context.p < context.end) {
            if (*context.p == ',') {
                context.p++;  //skip comma
            } else {
                set_parse_error(input->str, context.p,
                        EXPECT_STR_LEN, "expect comma \",\"",
                        error_info, error_size);
                result = EINVAL;
                break;
            }
        }

        kv_pair.value = context.element;
        context.element.str += context.element.len + 1;

        if ((result=check_alloc_json_map(map, error_info, error_size)) != 0) {
            map->count = 0;
            break;
        }
        map->elements[map->count++] = kv_pair;
    }

    if (result != 0) {
        free_json_map(map);
    }
    return result;
}

int encode_json_map(json_map_t *map, string_t *output,
        char *error_info, const int error_size)
{
    key_value_pair_t *pair;
    key_value_pair_t *end;
    char *p;
    int result;
    int size;

    end = map->elements + map->count;
    size = 3;
    for (pair=map->elements; pair<end; pair++) {
        size += 2 * (pair->key.len + pair->value.len + 2) + 1;
    }

    output->str = (char *)malloc(size);
    if (output->str == NULL) {
        snprintf(error_info, error_size, "malloc %d bytes fail", size);
        return ENOMEM;
    }

    p = output->str;
    *p++ = '{';
    for (pair=map->elements; pair<end; pair++) {
        if (pair > map->elements) {
            *p++ = ',';
        }

        if ((result=json_quote_string(&pair->key, &p,
                        error_info, error_size)) != 0)
        {
            free_json_string(output);
            return result;
        }
        *p++ = ':';
        if ((result=json_quote_string(&pair->value, &p,
                        error_info, error_size)) != 0)
        {
            free_json_string(output);
            return result;
        }
    }

    *p++ = '}';
    *p = '\0';
    output->len = p - output->str;
    return 0;
}
