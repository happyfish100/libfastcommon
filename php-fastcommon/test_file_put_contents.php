<?php

define('TEST_FLAGS', FILE_APPEND);
define('LOOP_COUNT', 102400);
function test_fastcommon_file_put_contents()
{
    $start = microtime(true);
    for ($i=0; $i<LOOP_COUNT; $i++)
    {
        fastcommon_file_put_contents("/tmp/test.log", "this is a test\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test1.log", "this is a test11\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test1.log", "this is a test12\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test21\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test22\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test23\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test31\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test32\n", TEST_FLAGS);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test33\n", TEST_FLAGS);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "fastcommon_file_put_contents time used: $timeUsed\n";
}

function test_file_put_contents()
{
    $start = microtime(true);
    for ($i=0; $i<LOOP_COUNT; $i++)
    {
        file_put_contents("/tmp/test.log", "this is a test\n", TEST_FLAGS);
        file_put_contents("/tmp/test1.log", "this is a test11\n", TEST_FLAGS);
        file_put_contents("/tmp/test1.log", "this is a test12\n", TEST_FLAGS);
        file_put_contents("/tmp/test2.log", "this is a test21\n", TEST_FLAGS);
        file_put_contents("/tmp/test2.log", "this is a test22\n", TEST_FLAGS);
        file_put_contents("/tmp/test2.log", "this is a test23\n", TEST_FLAGS);
        file_put_contents("/tmp/test3.log", "this is a test31\n", TEST_FLAGS);
        file_put_contents("/tmp/test3.log", "this is a test32\n", TEST_FLAGS);
        file_put_contents("/tmp/test3.log", "this is a test33\n", TEST_FLAGS);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "file_put_contents time used: $timeUsed\n";
}

test_fastcommon_file_put_contents();
echo "sleep ...\n";
sleep(2);
echo "sleep done.\n";
test_file_put_contents();

