# ⽇志⽂件优化PHP扩展函数

```
出于提升性能目的，基于libfastcommon封装的php扩展，提供了函数fastcommon_error_log
来替代PHP原⽣的error_log，使⽤fastcommon_file_put_contents替换PHP原⽣的file_put_contents。

原理很简单，就是⽇志⽂件打开后将其⽂件描述符（或⽂件句柄）持久化，避免每次调⽤error_log
或file_put_contents时都执⾏open和close等⽂件操作。

在短字符串的场景下，通过实测fastcommon_file_put_contents⽐file_put_contents性能提升2倍以上。
fastcommon_error_log⽐error_log性能提升50%以上。
两个扩展函数的⽤法和PHP原⽣函数⼀致。在可以优化的场景下，由fastcommon扩展接管处理，否则透传给PHP原⽣函数处理。
```

## 函数简要说明如下：
```
bool fastcommon_error_log (string $message [, int $message_type = 0, string
    $destination, string $extra_headers] )
接管（优化处理）条件： $message_type为3，且指定了$destination（即⽇志⽂件名）
在接管的情况下， $extra_headers可以为下列常量之⼀：
    FASTCOMMON_LOG_TIME_PRECISION_NONE：⽇志⾏⾸不输出⽇期时间字符串（默认值）
    FASTCOMMON_LOG_TIME_PRECISION_SECOND：⽇志⾏⾸输出的时间精度到秒
    FASTCOMMON_LOG_TIME_PRECISION_MSECOND：⽇志⾏⾸输出的时间精度到毫秒
    FASTCOMMON_LOG_TIME_PRECISION_USECOND：⽇志⾏⾸输出的时间精度到微秒
  注：如果$message最后没有换⾏符，会⾃动增加。这和error_log的⾏为不⼀致。
```

```
int fastcommon_file_put_contents (string $filename , mixed $data [, int $flags = 0,
    resource $context ])
接管（优化处理）条件，需满⾜如下3个条件：
     * $data为字符串
     * $flags 为FILE_APPEND或 (FILE_APPEND | LOCK_EX)
     * $context 为null，即没有指定$context
```
