if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

noinst_LTLIBRARIES = libp3common.la

libp3common_la_SOURCES  = \
    p3utils.c

libp3common_la_CPPFLAGS = -I@top_srcdir@/include $(AM_CPPFLAGS)
