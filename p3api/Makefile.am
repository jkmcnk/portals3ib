if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

noinst_LTLIBRARIES = libp3api.la

libp3api_la_SOURCES =  \
	acl.c \
	eq.c \
	errno.c \
	id.c \
	init.c \
	md.c \
	me.c \
	move.c \
	misc.c \
	ni.c \
	init.h \
	request_lock.c \
	request_lock.h

libp3api_la_CPPFLAGS = -I@top_srcdir@/include
libp3api_la_CPPFLAGS += -I@top_srcdir@/linux/include
libp3api_la_CPPFLAGS += $(AM_CPPFLAGS)
