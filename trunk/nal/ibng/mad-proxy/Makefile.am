sbin_PROGRAMS =

if !CONFIG_IBNG_EMBEDDED_MAD
sbin_PROGRAMS += ibng-mad-proxy

ibng_mad_proxy_SOURCES = daemon.c \
	@top_srcdir@/nal/ibng/ht.c \
	@top_srcdir@/nal/ibng/ht.h \
	@top_srcdir@/p3common/p3utils.c

ibng_mad_proxy_CPPFLAGS = 			\
    -I@top_srcdir@/nal/ibng			\
    -I@top_srcdir@/include			\
    -I@top_srcdir@/linux/include	\
    $(OFED_CFLAGS)					\
    $(AM_CPPFLAGS)					\
	$(MAD_PROXY_CPPFLAGS)

ibng_mad_proxy_LDADD = libnetmap.la
endif

noinst_LTLIBRARIES = libnetmap.la

libnetmap_la_SOURCES = \
	netmap.c \
	netmap.h

libnetmap_la_CPPFLAGS = \
    -I@top_srcdir@/nal/ibng			\
    -I@top_srcdir@/include			\
    -I@top_srcdir@/linux/include	\
    $(OFED_CFLAGS)					\
    $(AM_CPPFLAGS)

libnetmap_la_LDFLAGS = \
	$(OFED_LDFLAGS)

libnetmap_la_LIBADD = \
	$(OFED_LIBS)
