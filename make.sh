tmp_src_filename=fast_check_bits.c
cat <<EOF > $tmp_src_filename
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
int main()
{
	printf("%d\n", (int)sizeof(long));
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
else
 OS_BITS=32
fi

if [ "$off_bytes" -eq 8 ]; then
 OFF_BITS=64
else
 OFF_BITS=32
fi

cat <<EOF > src/_os_bits.h
#ifndef _OS_BITS_H
#define _OS_BITS_H

#define OS_BITS  $OS_BITS
#define OFF_BITS $OFF_BITS

#endif
EOF

DEBUG_FLAG=1

CFLAGS='-Wall -D_FILE_OFFSET_BITS=64'
if [ "$DEBUG_FLAG" = "1" ]; then
  CFLAGS="$CFLAGS -g -DDEBUG_FLAG"
else
  CFLAGS="$CFLAGS -O3"
fi

LIBS=''
uname=`uname`
if [ "$uname" = "Linux" ]; then
  CFLAGS="$CFLAGS -DOS_LINUX -DIOEVENT_USE_EPOLL"
elif [ "$uname" = "FreeBSD" ] || [ "$uname" = "Darwin" ]; then
  CFLAGS="$CFLAGS -DOS_FREEBSD -DIOEVENT_USE_KQUEUE"
  if [ "$uname" = "Darwin" ]; then
    CFLAGS="$CFLAGS -DDARWIN"
  fi
elif [ "$uname" = "SunOS" ]; then
  CFLAGS="$CFLAGS -DOS_SUNOS -D_THREAD_SAFE -DIOEVENT_USE_PORT"
  LIBS="$LIBS -lsocket -lnsl -lresolv"
  export CC=gcc
elif [ "$uname" = "AIX" ]; then
  CFLAGS="$CFLAGS -DOS_AIX -D_THREAD_SAFE"
  export CC=gcc
elif [ "$uname" = "HP-UX" ]; then
  CFLAGS="$CFLAGS -DOS_HPUX"
fi

if [ -f /usr/lib/libpthread.so ] || [ -f /usr/local/lib/libpthread.so ] || [ -f /usr/lib64/libpthread.so ] || [ -f /usr/lib/libpthread.a ] || [ -f /usr/local/lib/libpthread.a ] || [ -f /usr/lib64/libpthread.a ]; then
  LIBS="$LIBS -lpthread"
elif [ -f /usr/lib/libc_r.so ]; then
  line=`nm -D /usr/lib/libc_r.so | grep pthread_create | grep -w T`
  if [ -n "$line" ]; then
    LIBS="$LIBS -lc_r"
  fi
fi

cd src
cp Makefile.in Makefile
perl -pi -e "s#\\\$\(CFLAGS\)#$CFLAGS#g" Makefile
perl -pi -e "s#\\\$\(LIBS\)#$LIBS#g" Makefile
make $1 $2

