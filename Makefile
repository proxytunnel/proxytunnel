# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC = gcc
CFLAGS = -Wall -DHAVE_GETOPT_LONG
LDFLAGS =

# Solaris needs this (According to Martin Senft <martin@illicon.de>)
# CFLAGS = -I/usr/include -Wall
# LDFLAGS = -lsocket -lnsl

PROGNAME = proxytunnel
OBJ = proxytunnel.o \
	 cmdline.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(LDFLAGS) $(OBJ)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		mkdir -p /usr/local/bin
		install -g root -m755 -o root $(PROGNAME) /usr/local/bin/$(PROGNAME)
