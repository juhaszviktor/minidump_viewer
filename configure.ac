dnl ***************************************************************************
dnl Initial setup for autoconf/automake/libtool
dnl ***************************************************************************

AC_PREREQ(2.59)
AC_INIT([minidumpe_viewer], [0.1], [jviktor@balabit.hu])
AC_CONFIG_SRCDIR([minidump_viewer.c])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])

GLIB_MIN_VERSION="2.10.1"

LT_INIT()
AC_PROG_CC

dnl ***************************************************************************
dnl Initial setup (set up defaults for CFLAGS, LDFLAGS, etc)
dnl ***************************************************************************
echo "Configuring for host: $host"

ostype=`uname -s`

case "$ostype" in
  *CYGWIN*|*MINGW*)
    IS_WINDOWS=1
  ;;
esac

AC_CHECK_HEADER(bfd.h)

GLIB_ADDONS="gmodule-2.0 gthread-2.0"
PKG_CHECK_MODULES(GLIB, glib-2.0 >= $GLIB_MIN_VERSION $GLIB_ADDONS,,)

BFD_LIBS="-lbfd"

if test $IS_WINDOWS -ne 0; then
  BFD_LIBS="$BFD_LIBS -liberty -lintl -liconv"
fi

CFLAGS="$GLIB_CFLAGS"
LDFLAGS="$LDFLAGS $GLIB_LIBS $BFD_LIBS"

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
