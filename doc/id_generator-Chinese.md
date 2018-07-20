
# 64位ID⽣成器说明

```
    我们在libfastcommon中实现了64位（ 8字节整数） ID⽣成器，针对PHP这样的多进程⽅式，⽣成的64位ID也可以做到全局唯⼀。

    提供的PHP扩展php-fastcommon，封装了64位ID⽣成器。

    64位ID⽣成规则（注：⽣成的ID可以⼩于64位）
    32 位Unix时间戳 + X位机器ID + Y位extra data + Z位顺序号
    其中 X + Y + Z <= 32

    * 机器ID（ machine_id，缩写为mid）可以在初始化时指定，如果设置为0表⽰获取本地IP地址的后X位作为机器ID
    * extra data⽤来存储额外信息，例如订单分库的库号。如果不需要这个特性，将Y设置为0即可
    * 顺序号（sn）会保存在本地⽂件中，建议顺序号的位数Z⾄少为14，其对应的最⼤数值为16383（16K）
```

## php-fastcommon扩展提供的4个PHP函数

```
resource fastcommon_id_generator_init([string $filename = "/tmp/fastcommon_id_generator.sn",
     int $machine_id = 0, int $mid_bits = 16, int $extra_bits = 0, int $sn_bits = 16])
return resource handle for success, false for fail
   * 这个函数只需要在初始化的时候调⽤⼀次即可，建议不同的实例采⽤不同的⽂件来保存序列号。
   * php程序运⾏⽤户对这个⽂件必须有读写权限，⽂件不存在会⾃动创建。
   * 返回的resoure需要保存到php变量，否则该初始化⼯作会⾃动撤销
```

```
long/string fastcommon_id_generator_next([int $extra = 0, resource $handle = null])
return id for success, false for fail
return long in 64 bits OS, return string in 32 bits OS 
   * 如果不需要存储额外信息， extra传0即可。
   * 其中$handle参数为 fastcommon_id_generator_init返回值，不传递该参数表⽰使⽤最后⼀次调⽤
```

```
fastcommon_id_generator_init 返回的handle。
int fastcommon_id_generator_get_extra(long id [, resource $handle = null])
return the extra data
   * 使⽤了额外信息的情况下，可以使⽤这个函数获取ID中包含的extra data
```

```
bool fastcommon_id_generator_destroy([resource $handle = null])
return true for success
    * 这个函数通常不需要显式调⽤
```
