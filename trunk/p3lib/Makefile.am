if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

if CONFIG_P3RT
    P3RT = @top_builddir@/p3rt/libp3rt.la
endif

lib_LTLIBRARIES = libportals3.la

libportals3_la_SOURCES  = \
	p3lib_support.c \
	acl.c \
	eq.c \
	id.c \
	init.c \
	md.c \
	me.c \
	move.c \
	msg.c \
	nal.c \
	ni.c

libportals3_la_CPPFLAGS = -I@top_srcdir@/include
libportals3_la_CPPFLAGS += -I@top_srcdir@/linux/include
libportals3_la_CPPFLAGS += $(AM_CPPFLAGS)

libportals3_la_LIBADD = 							\
	@top_builddir@/p3common/libp3common.la	\
	@top_builddir@/p3api/libp3api.la		\
	$(P3RT)

if CONFIG_PTHREADS
    libportals3_la_LIBADD += -lpthread
endif

if CONFIG_UTCP_NAL
    libportals3_la_CPPFLAGS += -I@top_srcdir@/nal/tcp
    libportals3_la_LIBADD += @top_builddir@/nal/tcp/libportals3-utcp.la
endif # CONFIG_UTCP_NAL

if CONFIG_IBNG_NAL
    libportals3_la_CPPFLAGS += -I@top_srcdir@/nal/ibng
    libportals3_la_LIBADD += @top_builddir@/nal/ibng/libportals3-ibng.la
endif # CONFIG_IBNG_NAL
