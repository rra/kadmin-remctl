# Makefile.am -- Automake makefile for kadmin-remctl.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
#
# See LICENSE for licensing terms.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE docs/design ksetpass.pod passwd_change.pod \
	remctl/kadmin remctl/password

# Globally build everything against the Kerberos libraries.
AM_CPPFLAGS = $(KRB5_CPPFLAGS)
AM_LDFLAGS = $(KRB5_LDFLAGS)

bin_PROGRAMS = passwd_change ksetpass
passwd_change_CPPFLAGS = $(REMCTL_CPPFLAGS) $(AM_CPPFLAGS)
passwd_change_LDFLAGS = $(REMCTL_LDFLAGS) $(AM_LDFLAGS)
passwd_change_LDADD = $(REMCTL_LIBS) $(KRB5_LIBS)
ksetpass_LDADD = $(KRB5_LIBS)

dist_sbin_SCRIPTS = kadmin-backend kadmin-backend-heimdal

dist_man_MANS = passwd_change.1 kadmin-backend.8 ksetpass.1

# Make maintainer-clean do the right thing rather than what GNU thinks it
# should do.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/depcomp \
	build-aux/install-sh build-aux/missing config.h.in config.h.in~ \
	configure passwd_change.1 kadmin-backend.8 ksetpass.1

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
        -Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
        -Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
