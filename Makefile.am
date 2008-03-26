# Makefile.am -- Automake makefile for kadmin-remctl.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007, 2008 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = docs/design ksetpass.pod passwd_change.pod remctl/kadmin \
	remctl/password

bin_PROGRAMS = passwd_change ksetpass
passwd_change_LDADD = -lremctl

dist_sbin_SCRIPTS = kadmin-backend

dist_man_MANS = passwd_change.1 kadmin-backend.8 ksetpass.1

$(srcdir)/passwd_change.1: $(srcdir)/passwd_change.pod
	pod2man --release=$(VERSION) --center="User Commands" \
	    $(srcdir)/passwd_change.pod > $@

$(srcdir)/kadmin-backend.8: $(srcdir)/kadmin-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kadmin-backend > $@

$(srcdir)/ksetpass.1: $(srcdir)/ksetpass.pod
	pod2man --release=$(VERSION) --center="User Commands" \
	    $(srcdir)/ksetpass.pod > $@

# Make maintainer-clean do the right thing rather than what GNU thinks it
# should do.
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure passwd_change.1 kadmin-backend.8 ksetpass.1

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
        -Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
        -Wmissing-prototypes -Wnested-externs -Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)
