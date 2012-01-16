if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

docdir = @docdir@/nal/utcp
doc_DATA = README

lib_LTLIBRARIES = libportals3-utcp.la
# bin_PROGRAMS = utcp_nid

libportals3_utcp_la_SOURCES = lib-tcpnal.c lib-tcpnal.h hash_int.h

libportals3_utcp_la_CPPFLAGS = -I@top_srcdir@/include
libportals3_utcp_la_CPPFLAGS += -I@top_srcdir@/linux/include
libportals3_utcp_la_CPPFLAGS += $(AM_CPPFLAGS)

# utcp_nid_SOURCES = tcp_nid.c
# utcp_nid_CPPFLAGS = -I@top_srcdir@/include $(AM_CPPFLAGS)
# utcp_nid_LDADD  = \
#    $(top_builddir)/libp3.la \
#    libp3utcp.la
