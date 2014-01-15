# Automake makefile for kadmin-remctl.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2007, 2008, 2010, 2011, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore LICENSE autogen docs/design ksetpass.pod	\
	passwd_change.pod remctl/kadmin remctl/password

# Globally build everything against the Kerberos libraries.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS = $(KRB5_LDFLAGS)

noinst_LIBRARIES = portable/libportable.a util/libutil.a
portable_libportable_a_SOURCES = portable/dummy.c portable/krb5-extra.c \
        portable/krb5.h portable/macros.h portable/stdbool.h            \
        portable/system.h
portable_libportable_a_CPPFLAGS = $(KRB5_CPPFLAGS)
portable_libportable_a_LIBADD = $(LIBOBJS)
util_libutil_a_SOURCES = util/macros.h util/messages-krb5.c		    \
        util/messages-krb5.h util/messages.c util/messages.h util/xmalloc.c \
        util/xmalloc.h
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

# Work around the GNU Coding Standards, which leave all the Autoconf and
# Automake stuff around after make maintainer-clean, thus making that command
# mostly worthless.  Also remove the generated man pages.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile		\
	build-aux/depcomp build-aux/install-sh build-aux/missing	\
	config.h.in config.h.in~ configure kadmin-backend.8		\
	kadmin-backend-heim.8 ksetpass.1 passwd_change.1

# A set of flags for warnings.	Add -O because gcc won't find some warnings
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion	http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.7.2 (2013-04-22).	-D_FORTIFY_SOURCE=2 enables
# warn_unused_result attribute markings on glibc functions on Linux, which
# catches a few more issues.
WARNINGS = -g -O -D_FORTIFY_SOURCE=2 -Wall -Wextra -Wendif-labels	   \
	-Wformat=2 -Winit-self -Wswitch-enum -Wuninitialized -Wfloat-equal \
	-Wdeclaration-after-statement -Wshadow -Wpointer-arith		   \
	-Wbad-function-cast -Wcast-align -Wwrite-strings		   \
	-Wjump-misses-init -Wlogical-op -Wstrict-prototypes		   \
	-Wold-style-definition -Wmissing-prototypes -Wnormalized=nfc	   \
	-Wpacked -Wredundant-decls -Wnested-externs -Winline -Wvla -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
