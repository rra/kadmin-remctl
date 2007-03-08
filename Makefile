# $Id$

VERSION = 1.0

CC	= gcc
CFLAGS	= -O2 -Wall
LIBS	= -lremctl -lkrb5 -lcom_err

all: passwd_change passwd_change.1

.c.o: $*.c
	$(CC) $(CFLAGS) -c $*.c -o $@

passwd_change.o: passwd_change.c

passwd_change: passwd_change.o
	$(CC) -o $@ passwd_change.o $(LIBS)

passwd_change.1: passwd_change.pod
	pod2man --release=$(VERSION) --center="User Commands" \
	    passwd_change.pod > $@

clean:
	rm -f *.o core passwd_change
