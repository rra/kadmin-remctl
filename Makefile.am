# Makefile.am -- Automake makefile for kadmin-remctl.
# $Id$
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2007 Board of Trustees, Leland Stanford Jr. University
# See README for licensing terms.

AUTOMAKE_OPTIONS = foreign subdir-objects
EXTRA_DIST = docs/design kadmin-backend.8 passwd_change.1 passwd_change.pod \
	remctl/kadmin remctl/password

bin_PROGRAMS = passwd_change
passwd_change_LDADD = -lremctl

dist_sbin_SCRIPTS = kadmin-backend

man_MANS = passwd_change.1 kadmin-backend.8

$(srcdir)/passwd_change.1: $(srcdir)/passwd_change.pod
	pod2man --release=$(VERSION) --center="User Commands" \
	    $(srcdir)/passwd_change.pod > $@

$(srcdir)/kadmin-backend.8: $(srcdir)/kadmin-backend
	pod2man --release=$(VERSION) --center="Administrative Commands" \
	    --section=8 $(srcdir)/kadmin-backend > $@
