dnl @synopsis AC_LIBRT([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
dnl
dnl This macro tries to find out how to compile programs that
dnl use the realtime library and API. 
dnl
dnl On success, it defines HAVE_LIBRT and sets LIBRT_LIBS 
dnl to any libraries that are needed for linking LIBRT. 
dnl
dnl If you want to compile everything with LIBRT, you should set:
dnl
dnl     LIBS="$LIBRT_LIBS $LIBS"
dnl
dnl ACTION-IF-FOUND is a list of shell commands to run if the LIBRT
dnl library is found, and ACTION-IF-NOT-FOUND is a list of commands
dnl to run it if it is not found.  If ACTION-IF-FOUND is not specified,
dnl the default action will define HAVE_LIBRT.
dnl
dnl @version $Id: acx_mpi.m4 676 2006-05-16 20:44:08Z raoldfi $
dnl @author Ron A. Oldfield <raoldfi@sandia.gov>

AC_DEFUN([AC_RT], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
ac_rt_ok=yes
ac_rt_path=""

AM_CONDITIONAL(HAVE_RT,true)


AC_ARG_WITH(rt,
	[  --with-rt=DIR      Location of LIBRT],
	[RT_CPPFLAGS="-I$withval/include";
	 RT_LDFLAGS="-L$withval/lib"; 
	 ac_rt_path=$withval])

dnl Look for a header file
save_CPPFLAGS=${CPPFLAGS}
CPPFLAGS="${CPPFLAGS} ${RT_CPPFLAGS}"
if test x"$ac_rt_ok" = xyes; then
	dnl AC_MSG_NOTICE([searching for includes in $CPPFLAGS])
	AC_CHECK_HEADER(aio.h, 
		[], 
		[ac_rt_ok=no])
fi
CPPFLAGS=$save_CPPFLAGS;


ac_rt_flags="none -lc -lrt"

if test x"$ac_rt_ok" = xyes; then
for flag in $ac_rt_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether rt works without any additional flags])
                ;;

                -l*)
                AC_MSG_CHECKING([whether rt works with $flag])
                EXTRA_LIBS="$flag"
                ;;

                -*)
                AC_MSG_CHECKING([whether rt works with $flag])
                EXTRA_CFLAGS="$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
	save_LDFLAGS="$LDFLAGS"
        LIBS="$LIBS $RT_LIBS $EXTRA_LIBS"
        CFLAGS="$CFLAGS $RT_CFLAGS $EXTRA_FLAGS"
        LDFLAGS="$LDFLAGS $RT_LDFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK_FUNC([aio_write],
		    [ac_rt_ok=yes],
                    [ac_rt_ok=no])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
	LDFLAGS="$save_LDFLAGS"

        AC_MSG_RESULT($ac_rt_ok)
        if test "x$ac_rt_ok" = xyes; then
		RT_LIBS="$RT_LIBS $EXTRA_LIBS";
		RT_CFLAGS="$RT_CFLAGS $EXTRA_CFLAGS";
                break;
        fi

        EXTRA_LIBS=""
        EXTRA_CFLAGS=""
done
fi

if test x"$ac_rt_ok" = xyes; then
	AM_CONDITIONAL(HAVE_RT,true)
else
	AM_CONDITIONAL(HAVE_RT,false)
fi


AC_SUBST(RT_LDFLAGS)
AC_SUBST(RT_LIBS)
AC_SUBST(RT_CFLAGS)
AC_SUBST(RT_CPPFLAGS)


# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$ac_rt_ok" = xyes; then
        ifelse([$1],,[AC_DEFINE(HAVE_RT,1,[Define if you have RT.])],[$1])
        :
else
        $2
        :
fi
AC_LANG_RESTORE
])dnl AC_RT
