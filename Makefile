# $Id: Makefile,v 0.1 1998/01/14 02:53:12 eagle Exp $

CC	= gcc
CFLAGS	= -O2 -Wall
LIBS	= -lcom_err -lsunetkadm -lkadm -lkrb -ldes -lsocket -lnsl

all: passwd_change

.c.o: $*.c
	$(CC) $(CFLAGS) -c $*.c -o $@

passwd_change.o: passwd_change.c

passwd_change: passwd_change.o
	$(CC) -o $@ passwd_change.o $(LIBS)

clean:
	rm -f *.o core passwd_change
