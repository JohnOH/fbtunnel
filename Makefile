#
# Makefile for fbtunnel
#
# Copyright (C) Rick Payne, August 2003
#

HEADERS = fbtunnel.h
SRCS =    fbtunnel.c fb_mac.c fb_linux.c
OBJS =    fbtunnel.o fb_mac.o fb_linux.o

CC = gcc
CFLAGS = -g -Wall
LDLIBS = -lcrypto

.c.o:	
	${CC} ${CFLAGS} -c $*.c

fbtunnel:	${OBJS} ${HEADERS}
	${CC} -o fbtunnel ${LDFLAGS} ${OBJS} ${LDLIBS}


all:	fbtunnel

clean:	
	rm -f core *.o fbtunnel