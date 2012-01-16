## Process this file with automake to produce Makefile.in

pkgconfigdir = $(libdir)/pkgconfig

docdir = @docdir@
doc_DATA = AUTHORS COPYING README
doc_DATA += README.nals README.limitations

if CONFIG_TESTS
   P3TESTS = tests
endif

if CONFIG_P3RT
    P3RT = p3rt
endif

SUBDIRS = include p3common p3api $(P3RT) nal p3lib $(P3TESTS)

# Extra files/directories needed in this distribution.

EXTRA_DIST = CODING_STYLE autogen.sh portals3.spec portals3.pc.in
EXTRA_DIST += README.build README.tree TODO ChangeLog
EXTRA_DIST += README.nals README.limitations

pkgconfig_DATA = portals3.pc

# Extra distribution directories are included recursively, so use
# dist-hook to whack any CVS info when we build the distribution.

dist-hook:
	rm -rf `find $(distdir) -name CVS`

# extra distcheck configure flags: need to enable at least one NAL

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = --enable-utcp-nal --enable-ibng-nal --with-ibng-connection-method=CMA --enable-threaded-library --enable-tests --disable-lib-debug --disable-lib-profile --enable-runtime-support
