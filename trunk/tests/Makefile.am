## Process this file with automake to produce Makefile.in
##
## Note that we are making no attempt to support Automake's built-in
## testing support.
##
## Note also that if multiple NALs with a user-space API are configured,
## we will build the test programs for all of them simultaneously, hence
## the NAL suffix on the executable name.

if COMPILER_IS_GCC
    AM_CFLAGS = -Wsign-compare -Wall -Wno-parentheses
endif

user_includes = -I@srcdir@/../include -I@srcdir@/../user

EXTRA_DIST = handshake.h
noinst_PROGRAMS =
bin_PROGRAMS =

p3libs = $(top_builddir)/p3lib/libportals3.la
if CONFIG_PTHREADS
p3libs += -lpthread
endif

if CONFIG_UTCP_TESTS
	nallibs = $(top_builddir)/nal/ibng/libportals3-utcp.la

    noinst_PROGRAMS += get_test_utcp
    noinst_PROGRAMS += getput_test_utcp
    bin_PROGRAMS += p3_ping_pong_utcp
    bin_PROGRAMS += p3_lat_utcp
    bin_PROGRAMS += p3_bw_utcp

    get_test_utcp_SOURCES = ptl_opts.c ptl_opts.h get_test.c 
    get_test_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    get_test_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    get_test_utcp_LDADD = $(p3libs) $(nallibs)
    
    getput_test_utcp_SOURCES = ptl_opts.c ptl_opts.h getput_test.c 
    getput_test_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    getput_test_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    getput_test_utcp_LDADD = $(p3libs) $(nallibs)

    p3_lat_utcp_SOURCES = ptl_lat.c 
    p3_lat_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    p3_lat_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_lat_utcp_LDADD = $(p3libs) $(nallibs)

    p3_bw_utcp_SOURCES = ptl_bw.c 
    p3_bw_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    p3_bw_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_bw_utcp_LDADD = $(p3libs) $(nallibs)

    p3_ping_pong_utcp_SOURCES = ptl_opts.c ptl_opts.h ping_pong.c 
    p3_ping_pong_utcp_CPPFLAGS  = -DP3_NAL=\<p3nal\_utcp\.h\>
    p3_ping_pong_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_ping_pong_utcp_LDADD = $(p3libs) $(nallibs)

if CONFIG_P3RT
    noinst_PROGRAMS += put_bw_utcp
    noinst_PROGRAMS += get_bw_utcp
    noinst_PROGRAMS += put_pp_utcp
    noinst_PROGRAMS += getput_pp_utcp
    noinst_PROGRAMS += forktest_utcp
    noinst_PROGRAMS += locktest_utcp
    noinst_PROGRAMS += ringtest_utcp
    noinst_PROGRAMS += selftest_utcp

    forktest_utcp_SOURCES = forktest.c
    forktest_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    forktest_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    forktest_utcp_LDADD = $(p3libs) $(nallibs)

    locktest_utcp_SOURCES = locktest.c
    locktest_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    locktest_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    locktest_utcp_LDADD = $(p3libs) $(nallibs)

    ringtest_utcp_SOURCES = ringtest.c
    ringtest_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    ringtest_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    ringtest_utcp_LDADD = $(p3libs) $(nallibs)

    selftest_utcp_SOURCES = selftest.c
    selftest_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    selftest_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    selftest_utcp_LDADD = $(p3libs) $(nallibs)

    put_bw_utcp_SOURCES = put_bw.c
    put_bw_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    put_bw_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    put_bw_utcp_LDADD  = $(p3libs) $(nallibs)

    get_bw_utcp_SOURCES = get_bw.c
    get_bw_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    get_bw_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    get_bw_utcp_LDADD  = $(p3libs) $(nallibs)

    put_pp_utcp_SOURCES = put_pp.c
    put_pp_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    put_pp_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    put_pp_utcp_LDADD  = $(p3libs) $(nallibs)

    getput_pp_utcp_SOURCES = getput_pp.c
    getput_pp_utcp_CPPFLAGS = -DP3_NAL=\<p3nal\_utcp\.h\>
    getput_pp_utcp_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    getput_pp_utcp_LDADD  = $(p3libs) $(nallibs)
endif
endif

if CONFIG_IBNG_TESTS
	nallibs = $(top_builddir)/nal/ibng/libportals3-ibng.la

    noinst_PROGRAMS += get_test_ibng
    noinst_PROGRAMS += getput_test_ibng
    bin_PROGRAMS += p3_ping_pong_ibng
    bin_PROGRAMS += p3_lat_ibng
    bin_PROGRAMS += p3_bw_ibng

    get_test_ibng_SOURCES = ptl_opts.c get_test.c 
    get_test_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    get_test_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    get_test_ibng_LDFLAGS = $(OFED_LDFLAGS)
    get_test_ibng_LDADD = $(p3libs) $(nallibs)

    getput_test_ibng_SOURCES = ptl_opts.c getput_test.c 
    getput_test_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    getput_test_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    getput_test_ibng_LDFLAGS = $(OFED_LDFLAGS)
    getput_test_ibng_LDADD = $(p3libs) $(nallibs)

    p3_lat_ibng_SOURCES = ptl_lat.c 
    p3_lat_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    p3_lat_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_lat_ibng_LDFLAGS = $(OFED_LDFLAGS)
    p3_lat_ibng_LDADD = $(p3libs) $(nallibs)

    p3_bw_ibng_SOURCES = ptl_bw.c 
    p3_bw_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    p3_bw_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_bw_ibng_LDFLAGS = $(OFED_LDFLAGS)
    p3_bw_ibng_LDADD = $(p3libs) $(nallibs)

    p3_ping_pong_ibng_SOURCES = ptl_opts.c ping_pong.c 
    p3_ping_pong_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    p3_ping_pong_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    p3_ping_pong_ibng_LDFLAGS = $(OFED_LDFLAGS)
    p3_ping_pong_ibng_LDADD = $(p3libs) $(nallibs)

if CONFIG_P3RT
    noinst_PROGRAMS += put_bw_ibng
    noinst_PROGRAMS += get_bw_ibng
    noinst_PROGRAMS += put_pp_ibng
    noinst_PROGRAMS += getput_pp_ibng
    noinst_PROGRAMS += forktest_ibng
    noinst_PROGRAMS += ringtest_ibng
    noinst_PROGRAMS += locktest_ibng
    noinst_PROGRAMS += selftest_ibng

    forktest_ibng_SOURCES = forktest.c
    forktest_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    forktest_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    forktest_ibng_LDFLAGS = $(OFED_LDFLAGS)
    forktest_ibng_LDADD = $(p3libs) $(nallibs)

    locktest_ibng_SOURCES = locktest.c
    locktest_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    locktest_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    locktest_ibng_LDFLAGS = $(OFED_LDFLAGS)
    locktest_ibng_LDADD = $(p3libs) $(nallibs)

    ringtest_ibng_SOURCES = ringtest.c
    ringtest_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    ringtest_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    ringtest_ibng_LDFLAGS = $(OFED_LDFLAGS)
    ringtest_ibng_LDADD = $(p3libs) $(nallibs)

    selftest_ibng_SOURCES = selftest.c
    selftest_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    selftest_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    selftest_ibng_LDFLAGS = $(OFED_LDFLAGS)
    selftest_ibng_LDADD = $(p3libs) $(nallibs)

    put_bw_ibng_SOURCES = put_bw.c
    put_bw_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    put_bw_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    put_bw_ibng_LDFLAGS = $(OFED_LDFLAGS)
    put_bw_ibng_LDADD = $(p3libs) $(nallibs)

    get_bw_ibng_SOURCES = get_bw.c
    get_bw_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    get_bw_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    get_bw_ibng_LDFLAGS = $(OFED_LDFLAGS)
    get_bw_ibng_LDADD = $(p3libs) $(nallibs)

    put_pp_ibng_SOURCES = put_pp.c
    put_pp_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    put_pp_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    put_pp_ibng_LDFLAGS = $(OFED_LDFLAGS)
    put_pp_ibng_LDADD = $(p3libs) $(nallibs)

    getput_pp_ibng_SOURCES = getput_pp.c
    getput_pp_ibng_CPPFLAGS = -DP3_NAL=\<p3nal\_ibng\.h\>
    getput_pp_ibng_CPPFLAGS += $(user_includes) $(AM_CPPFLAGS)
    getput_pp_ibng_LDFLAGS = $(OFED_LDFLAGS)
    getput_pp_ibng_LDADD = $(p3libs) $(nallibs)
endif
endif

#ptl_opts.c: $(srcdir)/ptl_opts.ggo Makefile.am
#	gengetopt -F $* -S --set-package=$(PACKAGE) \
#	--set-version=$(VERSION) < $(srcdir)/ptl_opts.ggo

srcdir = @srcdir@
VPATH = @srcdir@
