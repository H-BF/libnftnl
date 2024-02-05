dnl Process this file with autoconf to create configure.

AC_INIT([libnftnl], [1.2.6])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AM_INIT_AUTOMAKE([-Wall foreign tar-pax no-dist-gzip dist-xz
	1.6 subdir-objects])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Dependencies
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.4])
AC_PROG_CC
AM_PROG_CC_C_O
AC_EXEEXT
AC_DISABLE_STATIC
LT_INIT
CHECK_GCC_FVISIBILITY
case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

regular_CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_REENTRANT"

regular_CFLAGS="-Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wshadow -Wstrict-prototypes \
	-Wformat=2 -Wwrite-strings -pipe"
AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])

AC_ARG_WITH([pkgdst], [AS_HELP_STRING([--with-pkgdst=DIR],
			[Where the package will be installed. By default DIR=prefix])],
			[pkgdst=$withval], [pkgdst=/usr/local])

AC_ARG_WITH([build-deb], [AS_HELP_STRING([--with-build-deb],
            [Build deb package. Required fpm utility])],
			[with_builddeb=$withval], [with_builddeb=no])

AC_ARG_WITH([build-rpm], [AS_HELP_STRING([--with-build-rpm],
            [Build rpm package. Required fpm utility])],
			[with_buildrpm=$withval], [with_buildrpm=no])

AS_IF([test "x$with_builddeb" = "xyes"], [
	AC_CHECK_PROG(FPM, fpm, fpm, false)

	if test "$FPM" = "false"; then
		AC_MSG_ERROR([fpm not available. Required for creating packages.])
	fi

	AC_PREFIX_DEFAULT([$(pwd)/packages/content/])
	BUILD_DEB=1
], [BUILD_DEB=0])

AM_CONDITIONAL([BUILD_DEB], [test "x$with_builddeb" = "xyes"])

AS_IF([test "x$with_buildrpm" = "xyes"], [
	AC_CHECK_PROG(FPM, fpm, fpm, false)

	if test "$FPM" = "false"; then
		AC_MSG_ERROR([fpm not available. Required for creating packages.])
	fi
	BUILD_RPM=1
], [BUILD_RPM=0])

AS_IF([test "x$with_builddeb" = "xyes" -o  "x$with_buildrpm" = "xyes"], [
	PKG_NAME=swarm-libnftnl

	PKG_VERSION=$(git describe --tags --exact-match 2> /dev/null | cut -d "-" -f 2)
	if test -z "$PKG_VERSION"; then
		PKG_VERSION=${STRIPPED_VERSION}
	fi

	if test -z "$PKG_VERSION"; then
		PKG_VERSION=$(git tag |tail -n 1 |cut -d "-" -f 2)-$(git symbolic-ref -q --short HEAD || git rev-parse --short HEAD)
	fi

	AC_MSG_NOTICE([The package version is $PKG_VERSION])

	AC_SUBST(PKG_VERSION)
	AC_SUBST(PKG_NAME)
], [])

AM_CONDITIONAL([BUILD_RPM], [test "x$with_buildrpm" = "xyes"])

AM_CONDITIONAL([BUILD_DEB_OR_RPM], [test "x$with_builddeb" = "xyes" -o  "x$with_buildrpm" = "xyes"])

AC_SUBST([pkgdst])
AC_SUBST(BUILD_DEB)
AC_SUBST(BUILD_RPM)
AC_SUBST(BUILD_DEB_OR_RPM)

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile include/libnftnl/Makefile include/linux/Makefile include/linux/netfilter/Makefile examples/Makefile tests/Makefile libnftnl.pc doxygen.cfg packages/Makefile packages/deb/Makefile packages/rpm/Makefile])
AC_OUTPUT
