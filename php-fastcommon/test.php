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

//fastcommon_id_generator_init();

$handle1 = fastcommon_id_generator_init("/tmp/sn1.txt", 0, 16, 0, 16);
$handle2 = fastcommon_id_generator_init("/tmp/sn2.txt", 0, 8, 8, 16);

$id = fastcommon_id_generator_next(1, $handle1);
printf("id1: %d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id, $handle1));

$id = fastcommon_id_generator_next(2, $handle2);
printf("id2: %d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id, $handle2));

$handle = fastcommon_id_generator_init("/tmp/sn.txt", 0, 8, 10, 14);
$id = fastcommon_id_generator_next(512, $handle);
printf("%d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id, $handle));

for ($i=0; $i<10; $i++) {
	$id = fastcommon_id_generator_next($i, $handle);
    printf("%d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id, $handle));
}

fastcommon_id_generator_destroy($handle);
fastcommon_id_generator_destroy($handle1);
fastcommon_id_generator_destroy($handle2);


