dnl Autoconf configuration for kadmin-remctl.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2007, 2008, 2010, 2011, 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([kadmin-remctl], [3.5], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news dist-xz foreign silent-rules subdir-objects
    -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_INSTALL
AC_PROG_RANLIB

RRA_LIB_REMCTL
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_FUNCS([krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags])
AC_CHECK_FUNCS([krb5_appdefault_string], [],
    [AC_CHECK_FUNCS([krb5_get_profile])
     AC_CHECK_HEADERS([k5profile.h profile.h])
     AC_LIBOBJ([krb5-profile])])
RRA_LIB_KRB5_RESTORE

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bitypes.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
