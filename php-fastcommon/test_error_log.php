<?php

function test_fastcommon_error_log()
{
    $start = microtime(true);
    for ($i=0; $i<102400; $i++)
    {
        fastcommon_error_log("this is a test\n", 3, "/tmp/test.log");
        fastcommon_error_log("this is a test11\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
        fastcommon_error_log("this is a test12\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
        fastcommon_error_log("this is a test21\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        fastcommon_error_log("this is a test22\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        fastcommon_error_log("this is a test23\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        fastcommon_error_log("this is a test31\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
        fastcommon_error_log("this is a test32\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
        fastcommon_error_log("this is a test33\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "fastcommon_error_log time used: $timeUsed\n";
}

function test_error_log()
{
    $start = microtime(true);
    for ($i=0; $i<102400; $i++)
    {
        error_log("this is a test\n", 3, "/tmp/test.log");
        error_log("this is a test11\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
        error_log("this is a test12\n", 3, "/tmp/test1.log", FASTCOMMON_LOG_TIME_PRECISION_MSECOND);
        error_log("this is a test21\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        error_log("this is a test22\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        error_log("this is a test23\n", 3, "/tmp/test2.log", FASTCOMMON_LOG_TIME_PRECISION_USECOND);
        error_log("this is a test31\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
        error_log("this is a test32\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
        error_log("this is a test33\n", 3, "/tmp/test3.log", FASTCOMMON_LOG_TIME_PRECISION_SECOND);
    }

    $end = microtime(true);
    $timeUsed = round($end - $start, 3);
    echo "error_log time used: $timeUsed\n";
}

test_fastcommon_error_log();
echo "sleep ...\n";
sleep(2);
echo "sleep done.\n";
test_error_log();

