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
#include "fastcommon/ini_file_reader.h"

static int iniAnnotationFuncExpressCalc(IniContext *context,
        struct ini_annotation_entry *annotation, const IniItem *item,
        char **pOutValue, int max_values)
{
    int count;
    int result;
    char cmd[512];
    static char output[256];

    count = 0;
    sprintf(cmd, "echo \'%s\' | bc -l", item->value);
    if ((result=getExecResult(cmd, output, sizeof(output))) != 0)
    {
        logWarning("file: "__FILE__", line: %d, "
                "exec %s fail, errno: %d, error info: %s",
                __LINE__, cmd, result, STRERROR(result));
        return count;
    }
    if (*output == '\0')
    {
        logWarning("file: "__FILE__", line: %d, "
                "empty reply when exec: %s", __LINE__, item->value);
    }
    pOutValue[count++] = fc_trim(output);
    return count;
}

int main(int argc, char *argv[])
{
	int result;
    IniContext context;
    const char *szFilename = "test.ini";
    AnnotationEntry annotations[1];

    if (argc > 1) {
        szFilename = argv[1];
    }
	
	log_init();

    memset(annotations, 0, sizeof(annotations));
    annotations[0].func_name = "EXPRESS_CALC";
    annotations[0].func_get = iniAnnotationFuncExpressCalc;

    //printf("sizeof(IniContext): %d\n", (int)sizeof(IniContext));
    result = iniLoadFromFileEx(szFilename, &context,
            FAST_INI_ANNOTATION_WITH_BUILTIN, annotations, 1,
            FAST_INI_FLAGS_SHELL_EXECUTE);
    if (result != 0)
    {
        return result;
    }

    iniPrintItems(&context);
    iniDestroyAnnotationCallBack();
    iniFreeContext(&context);
	return 0;
}
