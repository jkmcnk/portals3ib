
## Process this file with automake to produce Makefile.in

EXTRA_DIST = \
./linux/list.h \
./linux/prefetch.h \
./linux/stddef.h \
./p3/debug.h \
./p3/errno.h \
./p3/handle.h \
./p3/lock.h \
./p3/nal_types.h \
./p3/obj_alloc.h \
./p3/process.h \
./p3/uid.h \
./p3api/api.h \
./p3api/debug.h \
./p3api/misc.h \
./p3api/nal.h \
./p3api/types.h \
./p3lib/acl.h \
./p3lib/debug.h \
./p3lib/eq.h \
./p3lib/id.h \
./p3lib/init.h \
./p3lib/md.h \
./p3lib/me.h \
./p3lib/move.h \
./p3lib/nal.h \
./p3lib/ni.h \
./p3lib/p3lib.h \
./p3lib/p3lib_support.h \
./p3lib/p3validate.h \
./p3lib/types.h \
./p3nal_ibng.h \
./p3nal_utcp.h \
./p3rt/dispatch.h \
./p3rt/forward.h \
./p3rt/p3rt.h \
./p3rt/types.h \
./p3utils.h \
./portals3.h

commonheaders =    \
	p3/nal_types.h \
	p3/errno.h     \
	p3api/types.h  \
	p3api/api.h    \
	p3api/misc.h   \
	p3api/debug.h  \
	portals3.h

nalheaders = p3nal_utcp.h p3nal_ibng.h
rtheaders = p3rt/p3rt.h

nobase_include_HEADERS = $(commonheaders) $(nalheaders) $(rtheaders)
