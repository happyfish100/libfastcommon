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
#include "fastcommon/server_id_func.h"

int main(int argc, char *argv[])
{
	int result;
    const char *config_filename = "servers.conf";
    FCServerContext ctx;
    const int default_port = 1111;
    const bool share_between_groups = false;

    if (argc > 1) {
        config_filename = argv[1];
    }
	
	log_init();

    if ((result=fc_server_load_from_file_ex(&ctx, config_filename,
                    default_port, share_between_groups)) != 0)
    {
        return result;
    }

    fc_server_to_log(&ctx);

    fc_server_destroy(&ctx);
	return 0;
}
