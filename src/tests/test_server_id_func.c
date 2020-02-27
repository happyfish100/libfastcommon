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
    FCServerConfig ctx;
    const int default_port = 1111;
    const int min_hosts_each_group = 1;
    const bool share_between_groups = true;
    FastBuffer buffer;

    if (argc > 1) {
        config_filename = argv[1];
    }
	
	log_init();
    if ((result=fc_server_load_from_file_ex(&ctx, config_filename,
                    default_port, min_hosts_each_group,
                    share_between_groups)) != 0)
    {
        return result;
    }

    if ((result=fast_buffer_init_ex(&buffer, 1024)) != 0) {
        return result;
    }
    fc_server_to_config_string(&ctx, &buffer);
    printf("%.*s", buffer.length, buffer.data);
    //printf("%.*s\n(%d)", buffer.length, buffer.data, buffer.length);

    fast_buffer_destroy(&buffer);

    //fc_server_to_log(&ctx);
    fc_server_destroy(&ctx);
	return 0;
}
