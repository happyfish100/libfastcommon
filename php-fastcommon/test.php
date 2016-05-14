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
fastcommon_id_generator_init("/tmp/sn.txt", 0, 8, 10, 14);

$id = fastcommon_id_generator_next(1024);
printf("%d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id));

for ($i=0; $i<1024; $i++) {
	$id = fastcommon_id_generator_next($i);
    printf("%d %X, extra: %d\n", $id, $id, fastcommon_id_generator_get_extra($id));
}

fastcommon_id_generator_destroy();

