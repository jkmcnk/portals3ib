if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

docdir = @docdir@/nal/ibng
doc_DATA = README

if CONFIG_IBNG_CNX_CM
SUBDIRS = mad-proxy
NETMAP_SOURCES = map.c map.h map-types.h
endif

lib_LTLIBRARIES = libportals3-ibng.la

libportals3_ibng_la_SOURCES = 	\
	ibng_nal.c			\
	ibng_nal.h			\
	buf.c				\
	buf.h				\
	srv.c				\
	srv.h				\
	cnx.c				\
	cnx.h				\
	ht.c				\
	ht.h				\
	cfg.c				\
	cfg.h				\
	msg.h				\
	iset.h              \
	dbg.h				\
	$(NETMAP_SOURCES)

libportals3_ibng_la_CPPFLAGS = 			\
    -I@top_srcdir@/nal/ibng			\
    -I@top_srcdir@/include			\
    -I@top_srcdir@/linux/include	\
    $(OFED_CFLAGS)					\
    $(AM_CPPFLAGS)

libportals3_ibng_la_LDFLAGS = \
	$(OFED_LDFLAGS)

if CONFIG_IBNG_CNX_CM
if CONFIG_IBNG_EMBEDDED_MAD
NETMAP_LIBS=@top_builddir@/nal/ibng/mad-proxy/libnetmap.la
else
NETMAP_LIBS=
endif
endif

libportals3_ibng_la_LIBADD = \
	$(OFED_LIBS) \
	$(NETMAP_LIBS)
