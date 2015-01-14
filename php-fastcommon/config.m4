dnl config.m4 for extension fastcommon

PHP_ARG_WITH(fastcommon, wapper for libfastcommon
[  --with-fastcommon             Include fastcommon wapper for libfastcommon])

if test "$PHP_FASTCOMMON" != "no"; then
  PHP_SUBST(FASTCOMMON_SHARED_LIBADD)

  if test -z "$ROOT"; then
	ROOT=/usr
  fi

  PHP_ADD_INCLUDE($ROOT/include/fastcommon)

  PHP_ADD_LIBRARY_WITH_PATH(fastcommon, $ROOT/lib, FASTCOMMON_SHARED_LIBADD)

  PHP_NEW_EXTENSION(fastcommon, fastcommon.c, $ext_shared)

  CFLAGS="$CFLAGS -Wall"
fi
