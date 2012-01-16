if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

noinst_LTLIBRARIES = libp3rt.la

libp3rt_la_SOURCES = \
	    rt_api.c \
        rt_api_fw2user.c \
        rt_dispatch.c \
        rt_lib.c

libp3rt_la_CPPFLAGS = -I@top_srcdir@/include
libp3rt_la_CPPFLAGS += $(AM_CPPFLAGS)
libp3rt_la_CPPFLAGS += -I@top_srcdir@/linux/include
