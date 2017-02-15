<?php

function test_fastcommon_file_put_contents()
{
    $start = microtime(true);
    for ($i=0; $i<102400; $i++)
    {
        fastcommon_file_put_contents("/tmp/test.log", "this is a test\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test1.log", "this is a test11\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test1.log", "this is a test12\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test21\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test22\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test2.log", "this is a test23\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test31\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test32\n", FILE_APPEND);
        fastcommon_file_put_contents("/tmp/test3.log", "this is a test33\n", FILE_APPEND);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "fastcommon_file_put_contents time used: $timeUsed\n";
}

function test_file_put_contents()
{
    $start = microtime(true);
    for ($i=0; $i<102400; $i++)
    {
        file_put_contents("/tmp/test.log", "this is a test\n", FILE_APPEND);
        file_put_contents("/tmp/test1.log", "this is a test11\n", FILE_APPEND);
        file_put_contents("/tmp/test1.log", "this is a test12\n", FILE_APPEND);
        file_put_contents("/tmp/test2.log", "this is a test21\n", FILE_APPEND);
        file_put_contents("/tmp/test2.log", "this is a test22\n", FILE_APPEND);
        file_put_contents("/tmp/test2.log", "this is a test23\n", FILE_APPEND);
        file_put_contents("/tmp/test3.log", "this is a test31\n", FILE_APPEND);
        file_put_contents("/tmp/test3.log", "this is a test32\n", FILE_APPEND);
        file_put_contents("/tmp/test3.log", "this is a test33\n", FILE_APPEND);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "file_put_contents time used: $timeUsed\n";
}

test_file_put_contents();
echo "sleep ...\n";
sleep(2);
echo "sleep done.\n";
test_fastcommon_file_put_contents();

