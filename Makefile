# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC = gcc
CFLAGS = -Wall -DHAVE_GETOPT_LONG
LDFLAGS =
INSTALLPATH = /usr/local/bin

# Solaris needs this (According to Martin Senft <martin@illicon.de>)
# CFLAGS = -I/usr/include -Wall
# LDFLAGS = -lsocket -lnsl

PROGNAME = proxytunnel
OBJ = proxytunnel.o	\
	base64.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	messages.o	\
	cmdline.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(LDFLAGS) $(OBJ)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		mkdir -p $(INSTALLPATH)
		install -g root -m755 -o root $(PROGNAME) $(INSTALLPATH)/$(PROGNAME)
