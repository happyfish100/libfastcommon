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
#include "shared_func.h"
#include "sched_thread.h"
#include "ini_file_reader.h"
#include "fast_mblock.h"
#include "sockopt.h"
#include "system_info.h"
#include "local_ip_func.h"

struct my_struct {
    struct fast_mblock_man *mblock;
    void *obj;
};

static int test_delay(void *args)
{
    struct my_struct *my;
    my = (struct my_struct *)args;
    fast_mblock_free_object(my->mblock, my->obj);
    return 0;
}

int main(int argc, char *argv[])
{
    int result;
    int64_t start_time;
    int64_t end_time;
    char *filename;
    IniContext iniContext;
    int64_t mem_size;
    struct fast_mblock_man mblock1;
    struct fast_mblock_man mblock2;
    struct my_struct *objs;
    void *obj1;
    void *obj2;
    int reclaim_target;
    int reclaim_count;
    int i;
    int count;
    pthread_t schedule_tid;
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntries[1];
    volatile bool continue_flag = true;
    FastIFConfig if_configs[32];
    struct fast_statfs stats[32];

    if (argc > 1) {
        filename  = argv[1];
    } else {
        filename = "/etc/mc/worker.conf";
    }

    start_time = get_current_time_ms();
    srand(time(NULL));
    log_init();
    g_log_context.log_level = LOG_DEBUG;

    load_local_host_ip_addrs();
    print_local_host_ip_addrs();
    printf("first_local_ip: %s\n", get_first_local_ip());

    getifconfigs(if_configs, sizeof(if_configs) / sizeof(if_configs[0]), &count);
    printf("ifconfig count: %d\n", count);
    for (i=0; i<count; i++) {
        printf("%s ipv4: %s, ipv6: %s, mac: %s\n",
                if_configs[i].name, if_configs[i].ipv4,
                if_configs[i].ipv6, if_configs[i].mac); 
    }

    get_mounted_filesystems(stats, sizeof(stats) / sizeof(stats[0]), &count);
    printf("mounted fs count: %d\n", count);
    for (i=0; i<count; i++) {
        printf("%s => %s %s %ld %ld %ld %ld %ld %ld %ld\n",
                stats[i].f_mntfromname, stats[i].f_mntonname, stats[i].f_fstypename,
                stats[i].f_type, stats[i].f_bsize, stats[i].f_blocks,
                stats[i].f_bfree, stats[i].f_bavail, stats[i].f_files,
                stats[i].f_ffree);
    }

#if defined(OS_LINUX) || defined(OS_FREEBSD)
    {
        FastProcessInfo *processes;
        struct fast_sysinfo info;
        struct stat st;

        get_processes(&processes, &count);
        printf("process count: %d\n", count);
        for (i=0; i<count; i++)
        {
            printf("%d %d %d %d %s %d.%d\n", processes[i].field_count,
                    processes[i].pid, processes[i].ppid, processes[i].state,
                    processes[i].comm, (int)processes[i].starttime.tv_sec,
                    (int)processes[i].starttime.tv_usec);
        }
        if (processes != NULL)
        {
            free(processes);
        }

	if (get_sysinfo(&info) == 0)
	{
		printf("boot time: %d sec, %d usec\n",
                (int)info.boot_time.tv_sec,
                (int)info.boot_time.tv_usec);
		printf("loads: %.2f, %.2f, %.2f\n",
                info.loads[0], info.loads[1], info.loads[2]);
		printf("totalram: %ld\n", info.totalram);
		printf("freeram: %ld\n", info.freeram);
		printf("sharedram: %ld\n", info.sharedram);
		printf("bufferram: %ld\n", info.bufferram);
		printf("totalswap: %ld\n", info.totalswap);
		printf("freeswap: %ld\n", info.freeswap);
		printf("procs: %d\n", info.procs);
	}

    stat("/dev/zero", &st);
    printf("file inode: %ld\n", (long)st.st_ino);
    printf("file device: %ld\n", (long)st.st_dev);
    printf("file access time: %d.%ld\n", (int)st.st_atime, st.st_atimensec);
    printf("file modify time: %d.%ld\n", (int)st.st_mtime, st.st_mtimensec);
    printf("file change time: %d.%ld\n", (int)st.st_ctime, st.st_ctimensec);

    }

#endif

    if ((result=iniLoadFromFile(filename, &iniContext)) != 0) {
        logError("file: "__FILE__", line: %d, "
                "load conf file \"%s\" fail, ret code: %d",
                __LINE__, filename, result);
        return result;
    }


    //iniPrintItems(&iniContext);
    iniFreeContext(&iniContext);

    sched_enable_delay_task();
    scheduleArray.entries = scheduleEntries;
    scheduleArray.count = 0;
    sched_start(&scheduleArray, &schedule_tid,
            64 * 1024, (bool * volatile)&continue_flag);

    if (get_sys_total_mem_size(&mem_size) == 0) {
        printf("total memory size: %"PRId64" MB\n", mem_size / (1024 * 1024));
    }
    printf("cpu count: %d\n", get_sys_cpu_count());

    end_time = get_current_time_ms();
    logInfo("time used: %d ms", (int)(end_time - start_time));

    fast_mblock_manager_init();

    fast_mblock_init_ex2(&mblock1, "mblock1", 1024, 128, NULL, false, NULL, NULL, NULL);
    fast_mblock_init_ex2(&mblock2, "mblock2", 1024, 100, NULL, false, NULL, NULL, NULL);
   
    count = 2048;
    objs = (struct my_struct *)malloc(sizeof(struct my_struct) * count);
    for (i=0; i<count; i++)
    {
        int delay;

        delay = (30L * rand()) / RAND_MAX;

        objs[i].mblock = &mblock1;
        objs[i].obj = fast_mblock_alloc_object(&mblock1);
        sched_add_delay_task(test_delay, objs + i, delay, false);
    }

    /*
    for (i=0; i<count; i++)
    {
        fast_mblock_free_object(&mblock1, objs[i]);
    }
    */

    obj1 = fast_mblock_alloc_object(&mblock1);
    obj2 = fast_mblock_alloc_object(&mblock1);
    fast_mblock_free_object(&mblock1, obj1);
    //fast_mblock_delay_free_object(&mblock1, obj2, 10);
    fast_mblock_free_object(&mblock1, obj2);

    obj1 = fast_mblock_alloc_object(&mblock2);
    obj2 = fast_mblock_alloc_object(&mblock2);
    fast_mblock_delay_free_object(&mblock2, obj1, 20);
    fast_mblock_free_object(&mblock2, obj2);
    fast_mblock_manager_stat_print(false);

    reclaim_target = mblock1.info.trunk_total_count - mblock1.info.trunk_used_count;
    reclaim_target -= 2;
    fast_mblock_reclaim(&mblock1, reclaim_target, &reclaim_count, NULL);
    fast_mblock_reclaim(&mblock2, reclaim_target, &reclaim_count, NULL);

    fast_mblock_manager_stat_print(false);

    sleep(31);
    obj1 = fast_mblock_alloc_object(&mblock1);
    obj2 = fast_mblock_alloc_object(&mblock1);

    reclaim_target = (mblock1.info.trunk_total_count - mblock1.info.trunk_used_count);
    //reclaim_target = 1;
    fast_mblock_reclaim(&mblock1, reclaim_target, &reclaim_count, NULL);
    fast_mblock_reclaim(&mblock2, reclaim_target, &reclaim_count, NULL);

    fast_mblock_manager_stat_print(false);

    obj1 = fast_mblock_alloc_object(&mblock1);
    obj2 = fast_mblock_alloc_object(&mblock2);

    fast_mblock_manager_stat_print(false);

    fast_mblock_destroy(&mblock1);
    fast_mblock_destroy(&mblock2);
    fast_mblock_manager_stat_print(false);

    return 0;
}

