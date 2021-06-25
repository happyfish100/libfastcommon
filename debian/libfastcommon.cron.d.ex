#
# Regular cron jobs for the libfastcommon package
#
0 4	* * *	root	[ -x /usr/bin/libfastcommon_maintenance ] && /usr/bin/libfastcommon_maintenance
