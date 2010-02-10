# Automake makefile for kadmin-remctl.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008, 2010 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE docs/design ksetpass.pod passwd_change.pod \
	remctl/kadmin remctl/password

# Globally build everything against the Kerberos libraries.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS = $(KRB5_LDFLAGS)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5-extra.c \
        portable/krb5.h portable/macros.h portable/stdbool.h            \
        portable/system.h
portable_libportable_a_CPPFLAGS = $(KRB5_CPPFLAGS)
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/concat.c util/concat.h util/macros.h	\
        util/messages-krb5.c util/messages-krb5.h util/messages.c	\
        util/messages.h util/xmalloc.c util/xmalloc.h
util_libutil_a_CPPFLAGS = $(KRB5_CPPFLAGS)

bin_PROGRAMS = passwd_change ksetpass
passwd_change_CPPFLAGS = $(REMCTL_CPPFLAGS) $(AM_CPPFLAGS)
passwd_change_LDFLAGS = $(REMCTL_LDFLAGS) $(AM_LDFLAGS)
passwd_change_LDADD = util/libutil.a portable/libportable.a $(REMCTL_LIBS) \
	$(KRB5_LIBS)
ksetpass_LDADD = util/libutil.a portable/libportable.a $(KRB5_LIBS)

dist_sbin_SCRIPTS = kadmin-backend kadmin-backend-heim

dist_man_MANS = passwd_change.1 kadmin-backend.8 kadmin-backend-heim.8 \
	ksetpass.1

# Make maintainer-clean do the right thing rather than what GNU thinks it
# should do.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/depcomp \
	build-aux/install-sh build-aux/missing config.h.in config.h.in~ \
	configure passwd_change.1 kadmin-backend.8 kadmin-backend-heim.8 \
	ksetpass.1

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
        -Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
        -Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
