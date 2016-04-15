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

fastcommon_id_generator_init();
//fastcommon_id_generator_init("/tmp/sn.txt", 0, 8, 16);

var_dump(fastcommon_id_generator_next());
for ($i=0; $i<10; $i++) {
	$id = fastcommon_id_generator_next();
    printf("%d %X\n", $id, $id);
}

fastcommon_id_generator_destroy();

