/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include "logger.h"
#include "shared_func.h"
#include "char_convert_loader.h"

int char_convert_loader_init(FastCharConverter *pCharConverter,
        const IniItem *items, const int count)
{
    char_converter_init(pCharConverter, NULL, 0);
    return char_convert_loader_add(pCharConverter, items, count);
}

int char_convert_loader_add(FastCharConverter *pCharConverter,
        const IniItem *items, const int count)
{
    const IniItem *pItem;
    const IniItem *pEnd;
    int result;

    pEnd = items + count;
    for (pItem=items; pItem<pEnd; pItem++) {
        result = char_convert_loader_set_pair(pCharConverter,
                pItem->name, pItem->value);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

static int char_convert_loader_parse(const char *s, unsigned char *out_char)
{
    int len;
    len = strlen(s);
    if (len == 1) {
        *out_char = *s;
        return 0;
    }

    if (*s != '\\') {
        logError("file: "__FILE__", line: %d, "
                "invalid char string: %s", __LINE__, s);
        return EINVAL;
    }

    if (len == 2) {
        switch (s[1]) {
            case '0':
                *out_char = '\0';
                break;
            case 'a':
                *out_char = '\a';
                break;
            case 'b':
                *out_char = '\b';
                break;
            case 't':
                *out_char = '\t';
                break;
            case 'n':
                *out_char = '\n';
                break;
            case 'v':
                *out_char = '\v';
                break;
            case 'f':
                *out_char = '\f';
                break;
            case 'r':
                *out_char = '\r';
                break;
            case 's':
                *out_char = ' ';
                break;
            case '\\':
                *out_char = '\\';
                break;
            default:
                logError("file: "__FILE__", line: %d, "
                        "invalid char string: %s", __LINE__, s);
                return EINVAL;
        }
        return 0;
    }

    if (len != 4 || s[1] != 'x' || !isxdigit(s[2]) || !isxdigit(s[3])) {
        logError("file: "__FILE__", line: %d, "
                "invalid char string: %s, correct format: \\x##, "
                "## for hex digital. eg. \\x20 for the SPACE char",
                __LINE__, s);
        return EINVAL;
    }

    *out_char = (unsigned char)strtol(s+2, NULL, 16);
    return 0;
}

int char_convert_loader_set_pair(FastCharConverter *pCharConverter,
        const char *src, const char *dest)
{
    unsigned char src_char;
    unsigned char dest_char;
    int result;

    if (src == NULL || *src == '\0') {
        logError("file: "__FILE__", line: %d, "
                "empty src string", __LINE__);
        return EINVAL;
    }
    if (dest == NULL || *dest == '\0') {
        logError("file: "__FILE__", line: %d, "
                "empty dest string, src string: %s",
                __LINE__, src);
        return EINVAL;
    }

    if ((result=char_convert_loader_parse(src, &src_char)) != 0) {
        return result;
    }

    if (*dest == '"') {
        if (strlen(dest) != 4 || dest[1] != '\\' || dest[3] != '"') {
            logError("file: "__FILE__", line: %d, "
                    "invalid dest string: %s, correct format: \"\\c\", "
                    "eg. \"\\t\"", __LINE__, src);
            return EINVAL;
        }
        dest_char = dest[2];
        char_converter_set_pair_ex(pCharConverter,
                src_char, FAST_CHAR_OP_ADD_BACKSLASH, dest_char);
        return 0;
    }

    if ((result=char_convert_loader_parse(dest, &dest_char)) != 0) {
        return result;
    }
    char_converter_set_pair_ex(pCharConverter,
            src_char, FAST_CHAR_OP_NO_BACKSLASH, dest_char);
    return 0;
}

