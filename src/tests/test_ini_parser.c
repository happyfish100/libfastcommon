#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "logger.h"
#include "ini_file_reader.h"

int main(int argc, char *argv[])
{
	int result;
    IniContext context;
    const char *szFilename = "/home/yuqing/watchd-config/order.conf";

    if (argc > 1) {
        szFilename = argv[1];
    }
	
	log_init();
    if ((result=iniLoadFromFile(szFilename, &context)) != 0)
    {
        return result;
    }

    iniPrintItems(&context);

    iniFreeContext(&context);
	return 0;
}

