dnl
dnl   This Cplant(TM) source code is part of the Portals3 Reference
dnl   Implementation.
dnl   
dnl   This Cplant(TM) source code is the property of Sandia National
dnl   Laboratories.
dnl   
dnl   This Cplant(TM) source code is copyrighted by Sandia National
dnl   Laboratories.
dnl   
dnl   The redistribution of this Cplant(TM) source code is subject to the
dnl   terms of version 2 of the GNU General Public License.
dnl   (See COPYING, or http://www.gnu.org/licenses/lgpl.html.)
dnl   
dnl   Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
dnl   
dnl   Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
dnl   license for use of this work by or on behalf of the US Government.
dnl   Export of this program may require a license from the United States
dnl   Government.
dnl

dnl
dnl   Portals3 is free software; you can redistribute it and/or modify
dnl   it under the terms of version 2 of the GNU General Public License,
dnl   as published by the Free Software Foundation.
dnl   
dnl   Portals3 is distributed in the hope that it will be useful,
dnl   but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl   GNU General Public License for more details.
dnl   
dnl   You should have received a copy of the GNU General Public License
dnl   along with Portals3; if not, write to the Free Software
dnl   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
dnl   

dnl   Copyright 2008-2011 NEC Deutschland GmbH, NEC HPC Europe

AC_PREREQ(2.59)
AC_INIT(Portals 3 IBNG Implementation, 3.4.0, jaka@xlab.si, portals3)
AC_CONFIG_HEADERS([p3-config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_COPYRIGHT(Copyright (C) 2004-2006 Sandia Corporation.  All Rights Reserved.)
AC_COPYRIGHT(Copyright (C) 2009-2011 NEC Corporation.  All Rights Reserved.)

AC_DISABLE_STATIC

AC_PROG_LIBTOOL
AC_PROG_CC
AM_PROG_CC_C_O
AM_CONDITIONAL(COMPILER_IS_GCC, [test x"$GCC" = xyes])

AC_LANG(C)

# configure options
AC_ARG_ENABLE(
	utcp-nal,
	AC_HELP_STRING(--enable-utcp-nal, Build user-space TCP NAL.),
	[case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-utcp-nal) ;;
	esac],
	enable_utcp_nal=no
)
if test x"$enable_utcp_nal" = xyes ; then
    at_least_one_nal=yes
    bld_tests=yes
fi

AC_ARG_ENABLE(
	ibng-nal,
	AC_HELP_STRING(--enable-ibng-nal, Build user-space IB NAL.),
	[case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-ibng-nal) ;;
	esac],
	enable_ibng_nal=no
)
if test x"$enable_ibng_nal" = xyes ; then
    at_least_one_nal=yes
	ibng_cnx_method=CM
    bld_tests=yes
else
	ibng_cnx_method=none
fi

AC_ARG_ENABLE(
	runtime-support,
	AC_HELP_STRING(--enable-runtime-support,
		       Enable support for process rank and group size.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-runtime-support) ;;
	  esac
	],
	enable_runtime_support=yes
)

AC_ARG_ENABLE(
	tests,
	AC_HELP_STRING(--enable-tests,
		       Build user-space tests for applicable enabled NALs.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-tests) ;;
	  esac
	],
	enable_tests=yes
)
if test x"$enable_tests" = xyes ; then
    bld_tests=yes
else
    bld_tests=no
fi

AC_ARG_ENABLE(
	lib-debug,
	AC_HELP_STRING(--enable-lib-debug,
		       Compile extra debugging code in the Portals library.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-lib-debug) ;;
	  esac
	],
)
if test x"$enable_lib_debug" = xyes ; then
    MAD_PROXY_CPPFLAGS=
else
    MAD_PROXY_CPPFLAGS=-DDAEMONIZE
fi
AC_SUBST(MAD_PROXY_CPPFLAGS)

AC_ARG_ENABLE(
	lib-profile,
	AC_HELP_STRING(--enable-lib-profile,
		       Compile extra profiling code in the Portals library.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-lib-profile) ;;
	  esac
	],
)

AC_ARG_ENABLE(
	threaded-library,
	AC_HELP_STRING(--enable-threaded-library,
		Build threaded user-space Portals library.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-threaded-library) ;;
	  esac
	],
)
if test x"$enable_threaded_library" = xyes; then
    bld_threaded=yes
else
    bld_threaded=no
fi

AC_ARG_WITH(
	ibng-connection-method,
	AC_HELP_STRING(--with-ibng-connection-method={CM|CMA},
	               Choose connection method for IBNG NAL.),
	[case "$with_ibng_connection_method" in
	      CM) ibng_cnx_method=CM ;;
	      CMA) ibng_cnx_method=CMA ;;
	      *) AC_MSG_ERROR(Use CM or CMA with --with-ibng-connection-method) ;;
	esac],
)

AC_ARG_ENABLE(
	ibng-embedded-mad,
	AC_HELP_STRING(--enable-ibng-embedded-mad,
		Embed MAD net mapping code in the NAL as opposed to building MAD proxy daemon. This will require you to set write permissions for the MAD device so that the Portals applications will be able to access it.),
	[ case "$enableval" in
	      yes) ;;
	      no)  ;;
	      *) AC_MSG_ERROR(Use yes or no with --enable-embedded-mad) ;;
	  esac
	],
	enable_embedded_mad=no
)
if test x"$enable_ibng_embedded_mad" = xyes; then
    ibng_embedded_mad=yes
else
	ibng_embedded_mad=no
fi

AC_ARG_WITH(
    ofed,
	AC_HELP_STRING(--with-ofed=DIR,
		OFED IB software stack installed in directory DIR; headers expected
		in DIR/include and libraries in DIR/lib.),
	[if test ! -d "$with_ofed" ; then
	    AC_MSG_ERROR(OFED installation directory $with_ofed does not exist)
	 fi
	 OFED_LDFLAGS="-L$with_ofed/lib"
	 OFED_CFLAGS="-I$with_ofed/include"
	],
	[with_ofed=""
	 OFED_LDFLAGS=""
	 OFED_CFLAGS=""
    ]
)
OFED_LIBS="-libcommon -libverbs -ldl"
if test "x$ibng_cnx_method" = "xCMA"; then
    OFED_LIBS="$OFED_LIBS -lrdmacm"
elif test "x$ibng_cnx_method" = "xCM"; then
	OFED_LIBS="-libcm -libmad -libumad $OFED_LIBS"
fi
if test "x$bld_threaded" = "xyes"; then
   OFED_LIBS="$OFED_LIBS -lrt"
fi

AC_SUBST(OFED_CFLAGS)
AC_SUBST(OFED_LDFLAGS)
AC_SUBST(OFED_LIBS)

# rule out unsupported configuration combinations here

if test x"$at_least_one_nal" != xyes ; then
    AC_MSG_ERROR(Must enable at least one NAL.)
fi

# Checks for typedefs, structures, and compiler characteristics.

AH_TEMPLATE([SIZE_T_IS_UINT],
	[size_t is typedef unsigned int])
AH_TEMPLATE([SIZE_T_IS_ULONG],
	[size_t is typedef unsigned long])

AC_MSG_CHECKING([the type of size_t])

size_t_type=undefined
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[ #include <stdlib.h>
		   #include <sys/types.h>
		]] , 
		[[ size_t s;
		   unsigned long u;
		   s=&s-&u;
		   exit(0);
		]]
	)],
	AC_DEFINE(SIZE_T_IS_ULONG) [size_t_type="unsigned long"]
)
if test "$size_t_type" = undefined ; then
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[ #include <stdlib.h>
		   #include <sys/types.h>
		]] , 
		[[ size_t s;
		   unsigned u;
		   s=&s-&u;
		   exit(0);
		]]
	)],
	AC_DEFINE(SIZE_T_IS_UINT) [size_t_type="unsigned int"]
)
fi
AC_MSG_RESULT([$size_t_type])
if test "$size_t_type" = undefined ; then
    AC_MSG_FAILURE([size_t is not defined or has unexpected type.])
fi

AH_TEMPLATE([UINT64_T_IS_UINT],
	[uint64_t is typedef unsigned int])
AH_TEMPLATE([UINT64_T_IS_ULONG],
	[uint64_t is typedef unsigned long])
AH_TEMPLATE([UINT64_T_IS_ULONGLONG],
	[uint64_t is typedef unsigned long long])

AC_MSG_CHECKING([the type of uint64_t])

uint64_t_type=undefined
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[ #include <stdint.h>
		]] , 
		[[ uint64_t s;
		   unsigned long long u;
		   s=&s-&u;
		   exit(0);
		]]
	)],
	AC_DEFINE(UINT64_T_IS_ULONGLONG) [uint64_t_type="unsigned long long"]
)
if test "$uint64_t_type" = undefined ; then
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[ #include <stdint.h>
		]] , 
		[[ uint64_t s;
		   unsigned long u;
		   s=&s-&u;
		   exit(0);
		]]
	)],
	AC_DEFINE(UINT64_T_IS_ULONG) [uint64_t_type="unsigned long"]
)
elif test "$uint64_t_type" = undefined ; then
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[ #include <stdint.h>
		]] , 
		[[ uint64_t s;
		   unsigned u;
		   s=&s-&u;
		   exit(0);
		]]
	)],
	AC_DEFINE(UINT64_T_IS_UINT) [uint64_t_type="unsigned int"]
)
fi
AC_MSG_RESULT([$uint64_t_type])
if test "$uint64_t_type" = undefined ; then
    AC_MSG_FAILURE([uint64_t is not defined or has unexpected type.])
fi

AC_MSG_CHECKING([for MSG_NOSIGNAL flag])

AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <sys/socket.h>
		]] ,
		[[ unsigned int t;
		   t |= MSG_NOSIGNAL;
		   exit(0);
		   ]]
	)] ,
	AC_DEFINE([HAVE_MSG_NOSIGNAL],[1],[the MSG_NOSIGNAL send() flag])
        AC_MSG_RESULT([yes]),
	AC_MSG_RESULT([no])
)

AC_MSG_CHECKING([for SO_NOSIGPIPE flag])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <sys/socket.h>
		]] ,
		[[ unsigned int t;
		   t |= SO_NOSIGPIPE;
		   exit(0);
		   ]]
	)] ,
	AC_DEFINE([HAVE_SO_NOSIGPIPE],[1],[the SO_NOSIGPIPE socket option])
        AC_MSG_RESULT([yes]),
	AC_MSG_RESULT([no])
)

# real-time library required for asynchronous I/O library
# (defines HAVE_RT, RT_{CPPFLAGS,CFLAGS,LDFLAGS,LIBS})
AC_RT([], [AC_MSG_WARN("missing rtlib ... aio disabled")])

# configuration sanity checks
if test x"$ibng_cnx_method" != xnone && test x"$enable_ibng_nal" != xyes ; then
    AC_MSG_WARN(IBNG connection method only applies to IBNG NAL which was not selected.)
	ibng_cnx_method=none
fi
if test x"$ibng_embedded_mad" = xyes; then
    if test x"$enable_ibng_nal" != xyes; then
   	    AC_MSG_WARN(Enabling embedded MAD only applies to IBNG NAL which was not selected.)
		ibng_embedded_mad=no
	elif test x"$ibng_cnx_method" != xCM; then
    	AC_MSG_WARN(Enabling embedded MAD only applies to IBNG NAL with CM connection method. Connection method selected is $ibng_cnx_method.)
		ibng_embedded_mad=no
	fi
fi

# build tests?
AM_CONDITIONAL(CONFIG_TESTS, [test x"$bld_tests" = xyes])

# which NAL tests to build
AM_CONDITIONAL(CONFIG_UTCP_TESTS, [test x"$enable_utcp_nal" = xyes])
AM_CONDITIONAL(CONFIG_IBNG_TESTS, [test x"$enable_ibng_nal" = xyes])

# which parts of portals lib to build?
AM_CONDITIONAL(CONFIG_P3RT,       [test x"$enable_runtime_support" = xyes])
AM_CONDITIONAL(CONFIG_UTCP_NAL,   [test x"$enable_utcp_nal" = xyes])
AM_CONDITIONAL(CONFIG_IBNG_NAL,   [test x"$enable_ibng_nal" = xyes])
AM_CONDITIONAL(CONFIG_IBNG_EMBEDDED_MAD, [test x"$ibng_embedded_mad" = xyes])
AM_CONDITIONAL(CONFIG_IBNG_CNX_CM, [test x"$ibng_cnx_method" = xCM])
AM_CONDITIONAL(CONFIG_PTHREADS,   [test x"$bld_threaded" = xyes])

# collect NAL and dependency libs for pkg-config
pcnallibs=
pcdeplibs=
if test x"$enable_ibng_nal" = xyes; then
   pcdeplibs="$pcdeplibs $OFED_LIBS"
   pcnallibs="$pcnallibs -lportals3-ibng"
fi
if test x"$enable_utcp_nal" = xyes; then
   pcnallibs="$pcnallibs -lportals3-utcp"
fi
if test x"$enable_runtime_support" = xyes; then
   pcdeplibs="$pcdeplibs -lrt"
fi
if test x"$bld_threaded" = xyes; then
   pcdeplibs="$pcdeplibs -lpthread"
fi
AC_SUBST(pcnallibs)
AC_SUBST(pcdeplibs)

AH_TEMPLATE([ENABLE_P3RT_SUPPORT],
	[Enable runtime support code in the Portals library])
test x"$enable_runtime_support" = xyes && AC_DEFINE(ENABLE_P3RT_SUPPORT) 

AH_TEMPLATE([PORTALS_PROFILE],
	[Enable profiling code in the Portals library])
test x"$enable_lib_profile" = xyes && AC_DEFINE(PORTALS_PROFILE) 

AH_TEMPLATE([DEBUG_PTL_INTERNALS],
	[Enable additional debugging in the Portals library])
test x"$enable_lib_debug" = xyes && AC_DEFINE(DEBUG_PTL_INTERNALS) 

AH_TEMPLATE([PTL_UTCP_NAL_SUPPORT],
	[Enable initialization code for the UTCP NAL])
test x"$enable_utcp_nal" = xyes && AC_DEFINE(PTL_UTCP_NAL_SUPPORT) 

AH_TEMPLATE([PTL_IBNG_NAL_SUPPORT],
	[Enable initialization code for the ibng NAL])
test x"$enable_ibng_nal" = xyes && AC_DEFINE(PTL_IBNG_NAL_SUPPORT) 

AH_TEMPLATE([PTL_IBNG_EMBEDDED_MAD],
	[Enable embedded MAD code.])
test x"$ibng_embedded_mad" = xyes && AC_DEFINE(PTL_IBNG_EMBEDDED_MAD)

AH_TEMPLATE([PTL_IBNG_CMA],
	[Use CMA connection method in IBNG NAL.])
test x"$ibng_cnx_method" = xCMA && AC_DEFINE(PTL_IBNG_CMA)

AH_TEMPLATE([PTL_PROGRESS_THREAD],
	[Enable a separate progress thread using POSIX threads])
test x"$bld_threaded" = xyes && AC_DEFINE(PTL_PROGRESS_THREAD) 
test x"$bld_threaded" = xyes && AC_DEFINE(_REENTRANT, 1, [Use POSIX threading])

AH_TEMPLATE([WITH_DEBUG_LOCKING],
	[Enable debug locking for unthreaded user-space Portals library])
test x"$bld_threaded" != xyes -a x"$enable_lib_debug" = xyes && AC_DEFINE(WITH_DEBUG_LOCKING) 

AH_TEMPLATE([WITH_NO_LOCKING],
	[Enable no locking for unthreaded user-space Portals library])
test x"$bld_threaded" != xyes -a x"$enable_lib_debug" != xyes &&
	AC_DEFINE(WITH_NO_LOCKING) 

AH_TOP([/* This file contains macro definitions for compile-time options for
 * the Portals3 library as built for user space.
 *
 * Macros defined here _must_ _not_ be used in header files that code
 * using the Portals3 library must include.  This file _must_ _not_
 * be included from header files that code using the Portals3 library
 * must include.
 */])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(include/Makefile)
AC_CONFIG_FILES(tests/Makefile)
AC_CONFIG_FILES(p3common/Makefile)
AC_CONFIG_FILES(p3api/Makefile)
AC_CONFIG_FILES(p3lib/Makefile)
AC_CONFIG_FILES(p3rt/Makefile)
AC_CONFIG_FILES(nal/Makefile)
AC_CONFIG_FILES(nal/tcp/Makefile)
AC_CONFIG_FILES(nal/ibng/Makefile)
AC_CONFIG_FILES(nal/ibng/mad-proxy/Makefile)
AC_CONFIG_FILES(portals3.pc)

AC_OUTPUT

echo "
$PACKAGE_STRING configured as follows:
"
test x"$enable_static_exe" = xyes && \
	echo "  Linking executables statically."
if test x"$enable_threaded_library" = xyes; then
    echo "  Enabling threading support in Portals library."
else
    echo "  Disabling threading support in Portals library."
fi
test x"$enable_lib_profile" = xyes && \
    echo "  Enabling profiling in Portals library."
test x"$enable_lib_debug" = xyes && \
    echo "  Enabling extra debug output in Portals library."
test x"$enable_runtime_support" = xyes && \
    echo "  Enabling runtime support in Portals library."
if test x"$enable_utcp_nal" = xyes; then
    echo "  Building UTCP NAL."
	test x"$bld_threaded" = xyes && \
    echo "    Enabling UTCP NAL progress thread."
fi
if test x"$enable_ibng_nal" = xyes; then
    echo "  Building IBNG NAL."
	test x"$bld_threaded" = xyes && \
    echo "    Enabling IBNG NAL progress thread."
	if test x"$ibng_cnx_method" = xCMA; then
	  echo "    Using CMA connection method.";
    elif test x"$ibng_cnx_method" = xCM; then
      echo "    Using CM connection method.";
	  (test x"$ibng_embedded_mad" = xyes && \
	  echo "      Using embedded network mapping.") || \
	  echo "      Using MAD proxy daemon for network mapping."
    else
      echo "    Unknown connection method. Configure script BUG!";
    fi
fi
test x"$bld_tests" = xyes && \
    echo "  Building tests."

echo
