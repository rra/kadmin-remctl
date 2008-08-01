dnl Process this file with Autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See README for licensing terms.

AC_PREREQ([2.61])
AC_INIT([kadmin-remctl], [2.1], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_INSTALL

RRA_LIB_REMCTL
RRA_LIB_KRB5

dnl Temporary hack until we use a proper error reporting library, since we may
dnl not insist on -lcom_err if we have better error handling functions.
LIBS="-lcom_err $LIBS"
RRA_LIB_KRB5_SET

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
