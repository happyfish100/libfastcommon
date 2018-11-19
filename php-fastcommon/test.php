<?php

echo 'version: ' . fastcommon_version() . "\n";
var_dump(fastcommon_gethostaddrs());

$s = 'this is a test.';
echo 'simple_hash: ' . fastcommon_simple_hash($s) . "\n";
echo 'time33_hash: ' . fastcommon_time33_hash($s) . "\n";

echo 'first local ip: ' . fastcommon_get_first_local_ip() . "\n";

$next_ip = null;
while (($next_ip=fastcommon_get_next_local_ip($next_ip)))
{
    $is_private_ip = fastcommon_is_private_ip($next_ip);
    echo "local ip: $next_ip, private: $is_private_ip\n";
}

$handle = fastcommon_id_generator_init();

$id = fastcommon_id_generator_next(1);
printf("id: %d %X, extra: %d, timestamp: %d\n", $id, $id,
        fastcommon_id_generator_get_extra($id),
        fastcommon_id_generator_get_timestamp($id));
unset($handle);

/*
resource fastcommon_id_generator_init([string filename = "/tmp/fastcommon_id_generator.sn",
        int machine_id = 0, int mid_bits = 16, int extra_bits = 0, int sn_bits = 16, int flags = 0])
*/

$id = 6301319781687017475;
$handle1 = fastcommon_id_generator_init("/tmp/sn1.txt", 0, 8, 10, 14, 0666);
echo 'extra no: ' . fastcommon_id_generator_get_extra($id, $handle1) . "\n"; 

$handle2 = fastcommon_id_generator_init("/tmp/sn2.txt", 0, 8, 8, 16);

$id = fastcommon_id_generator_next(1, $handle1);
printf("id1: %d %X, extra: %d, timestamp: %d\n", $id, $id,
        fastcommon_id_generator_get_extra($id, $handle1),
        fastcommon_id_generator_get_timestamp($id, $handle1));

$id = fastcommon_id_generator_next(2, $handle2);
printf("id2: %d %X, extra: %d, timestamp: %d\n", $id, $id,
        fastcommon_id_generator_get_extra($id, $handle2),
        fastcommon_id_generator_get_timestamp($id, $handle2));

$handle = fastcommon_id_generator_init("/tmp/sn.txt", 0, 8, 10, 14);
$id = fastcommon_id_generator_next(512, $handle);
printf("%d %X, extra: %d, timestamp: %d\n", $id, $id,
        fastcommon_id_generator_get_extra($id, $handle),
        fastcommon_id_generator_get_timestamp($id, $handle));

for ($i=0; $i<10; $i++) {
	$id = fastcommon_id_generator_next($i, $handle);
    printf("%d %X, extra: %d, timestamp: %d\n", $id, $id,
            fastcommon_id_generator_get_extra($id, $handle),
            fastcommon_id_generator_get_timestamp($id, $handle));
}

fastcommon_error_log("this is a test\n", 3, "/tmp/test.log");
fastcommon_error_log("this is a test11\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
fastcommon_error_log("this is a test12\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
fastcommon_error_log("this is a test21\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
fastcommon_error_log("this is a test22\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
fastcommon_error_log("this is a test23\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
fastcommon_error_log("this is a test31\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
fastcommon_error_log("this is a test32\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
fastcommon_error_log("this is a test33\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
