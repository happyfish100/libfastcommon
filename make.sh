tmp_src_filename=fast_check_bits.c
cat <<EOF > $tmp_src_filename
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main()
{
	printf("%d\n", (int)sizeof(void*));
	printf("%d\n", (int)sizeof(off_t));
	return 0;
}
EOF

gcc -D_FILE_OFFSET_BITS=64 -o a.out $tmp_src_filename
output=`./a.out`

if [ -f /bin/expr ]; then
  EXPR=/bin/expr
else
  EXPR=/usr/bin/expr
fi

count=0
int_bytes=4
off_bytes=8
LIB_VERSION=lib64

for col in $output; do
    if [ $count -eq 0 ]; then
        int_bytes=$col
    else
        off_bytes=$col
    fi

    count=`$EXPR $count + 1`
done

/bin/rm -f a.out $tmp_src_filename
if [ "$int_bytes" -eq 8 ]; then
 OS_BITS=64
 LIB_VERSION=lib64
else
 OS_BITS=32
 LIB_VERSION=lib
fi

if [ "$off_bytes" -eq 8 ]; then
 OFF_BITS=64
else
 OFF_BITS=32
fi

DEBUG_FLAG=0

CFLAGS='-Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE'
if [ "$DEBUG_FLAG" = "1" ]; then
  CFLAGS="$CFLAGS -g -DDEBUG_FLAG"
else
  CFLAGS="$CFLAGS -g -O3"
fi

LIBS='-lm'
uname=`uname`

HAVE_VMMETER_H=0
HAVE_USER_H=0
if [ "$uname" = "Linux" ]; then
  OS_NAME=OS_LINUX
  IOEVENT_USE=IOEVENT_USE_EPOLL
elif [ "$uname" = "FreeBSD" ] || [ "$uname" = "Darwin" ]; then
  OS_NAME=OS_FREEBSD 
  IOEVENT_USE=IOEVENT_USE_KQUEUE
  if [ "$uname" = "Darwin" ]; then
    CFLAGS="$CFLAGS -DDARWIN"
  fi

  if [ -f /usr/include/sys/vmmeter.h ]; then
     HAVE_VMMETER_H=1
  fi

  if [ -f /usr/include/sys/user.h ]; then
     HAVE_USER_H=1
  fi
elif [ "$uname" = "SunOS" ]; then
  OS_NAME=OS_SUNOS
  IOEVENT_USE=IOEVENT_USE_PORT
  CFLAGS="$CFLAGS -D_THREAD_SAFE"
  LIBS="$LIBS -lsocket -lnsl -lresolv"
  export CC=gcc
elif [ "$uname" = "AIX" ]; then
  OS_NAME=OS_AIX
  IOEVENT_USE=IOEVENT_USE_NONE
  CFLAGS="$CFLAGS -D_THREAD_SAFE"
  export CC=gcc
elif [ "$uname" = "HP-UX" ]; then
  OS_NAME=OS_HPUX
  IOEVENT_USE=IOEVENT_USE_NONE
else
  OS_NAME=OS_UNKOWN
  IOEVENT_USE=IOEVENT_USE_NONE
fi

cat <<EOF > src/_os_define.h
#ifndef _OS_DEFINE_H
#define _OS_DEFINE_H

#define OS_BITS  $OS_BITS
#define OFF_BITS $OFF_BITS

#ifndef $OS_NAME
#define $OS_NAME  1
#endif

#ifndef $IOEVENT_USE
#define $IOEVENT_USE  1
#endif

#ifndef HAVE_VMMETER_H
#define HAVE_VMMETER_H $HAVE_VMMETER_H
#endif

#ifndef HAVE_USER_H
#define HAVE_USER_H $HAVE_USER_H
#endif
#endif
EOF

if [ -f /usr/lib/libpthread.so ] || [ -f /usr/local/lib/libpthread.so ] || [ -f /usr/lib64/libpthread.so ] || [ -f /usr/lib/libpthread.a ] || [ -f /usr/local/lib/libpthread.a ] || [ -f /usr/lib64/libpthread.a ]; then
  LIBS="$LIBS -lpthread"
elif [ -f /usr/lib/libc_r.so ]; then
  line=`nm -D /usr/lib/libc_r.so | grep pthread_create | grep -w T`
  if [ -n "$line" ]; then
    LIBS="$LIBS -lc_r"
  fi
fi

sed_replace()
{
    sed_cmd=$1
    filename=$2
    if [ "$uname" = "FreeBSD" ] || [ "$uname" = "Darwin" ]; then
       sed -i "" "$sed_cmd" $filename
    else
       sed -i "$sed_cmd" $filename
    fi
}

cd src
cp Makefile.in Makefile
sed_replace "s/\\\$(CFLAGS)/$CFLAGS/g" Makefile
sed_replace "s/\\\$(LIBS)/$LIBS/g" Makefile
sed_replace "s/\\\$(LIB_VERSION)/$LIB_VERSION/g" Makefile
make $1 $2 $3

if [ "$1" = "clean" ]; then
  /bin/rm -f Makefile _os_define.h
fi

