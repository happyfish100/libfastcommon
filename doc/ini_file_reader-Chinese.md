
## libfastcommon概述

```
libfastcommon是在github开源的⼀个C函数库。它提供了ini⽂件解析、logger、
64位唯⼀整数⽣成器、字符串处理、socket封装、对象池、skiplist、
定时任务调度器、时间轮等等。接下来主要介绍下ini⽂件解析ini_file_reader。
```

## ini_file_reader的主要特点：

### 1、⽀持section
```
    例如: [workers]
```

### 2、⼀个配置项可以出现多次
```
  通过iniGetValues或者iniGetValuesEx获取。例如：
    tracker_server = ip1
    tracker_server = ip2
```

### 3、 #include指令包含其他配置⽂件
```
    可以包含本地⽂件，也可以包含URL（目前仅⽀持HTTP）。例如：
    #include http.conf
```

### 4、 #@function指令⽀持标注

```
  配置项的取值为扩展（外部）动态库的返回值
  V1.39⽀持三个内置标注：
    I. LOCAL_IP_GET [inner | private | outer | public] 获取本机IP地址
      inner或private表示获取内网IP，outer或public表示获取外网IP
      [index]表示获取指定序号的本机IP，0表示获取第一个IP，-1表示获取最后一个IP，
      例如：[0]、inner[-1], outer[1]等等
    II. SHELL_EXEC 获取命令⾏输出，执行的command为配置项
    III. REPLACE_VARS  替换配置项中%{VARIABLE}格式的变量，变量由#@set指令设置
```

```
配置⽰例：
#@function SHELL_EXEC
  host = hostname

#@function LOCAL_IP_GET
  bind_ip = inner

#@set encoder_filename=/usr/local/etc/encoder.conf
#@set encoder_port = $(grep ^inner_port  %{encoder_filename} | awk -F '=' '{print $2;}')

#@function REPLACE_VARS
  check_alive_command = /usr/local/lib/libdfscheckalive.so %{encoder_port} 2 30
```

### 5、 #@add_annotation 扩展#@function标签

```
格式：
#@add_annotation <function标签> <动态库文件名> [参数1, 参数2, ...]
参数个数0到3个。

使用libshmcache扩展标签CONFIG_GET示例：
#@add_annotation CONFIG_GET /usr/lib/libshmcache.so /etc/libshmcache.conf

#@function CONFIG_GET
app.version = app1.key1
```

### 6、⽀持简单的流程控制，控制标签包括：

####  I. 条件判断

```
#@if %{VARIABLE} in [x,y,..]
…
#@else
…
#@endif
其中#@else指令为可选项。

#@if指令目前仅⽀持这种格式。
VARIABLE包括：
  1） LOCAL_IP：本机IP
  2） LOCAL_HOST：通过hostname获得的本机主机名
  3） #@set指令设置的变量， #@set指令格式：

#@set VAR = value
若要获取shell命令⾏输出， value部分格式为： $(command)，例如：
#@set os_name = $(uname -a | awk '{print $1;}')

注： LOCAL_IP⽀持CIDR格式的IP地址，例如： 172.16.12.0/22
例如：
#@if %{LOCAL_IP} in [10.0.11.89,10.0.11.99,172.16.12.0/22]
  min_subprocess_number = 4
#@else
  min_subprocess_number = 20
#@endif
```

####  II. 计数循环

```
#@for VARIABLE from 0 to 15 step 1
…
#@endfor

其中VARIABLE⻓度不超过64位字符，在循环体中通过
{$VARIABLE}格式获取其值。 step可以为负数，但不能为0。例如：
#@for i from 0 to 15 step 1
[section{$i}]
  subprocess_command = /usr/bin/php xxx {$i}
  subprocess_number = 1
#@endfor
```

```
另外， libfastcommon中的部分函数提供了PHP扩展。 github地址：
https://github.com/happyfish100/libfastcommon，欢迎⼤家下载使⽤。
```
