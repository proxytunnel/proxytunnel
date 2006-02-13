# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC ?= gcc
CFLAGS ?= -Wall -O2 -g
CFLAGS += -DHAVE_GETOPT_LONG -DUSE_SSL
CFLAGS += -DSETPROCTITLE -DSPT_TYPE=1
LDFLAGS += -lssl -lcrypto

PREFIX =/usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share
MANDIR = $(DATADIR)/man

DESTDIR = 

PROGNAME = proxytunnel
OBJ = proxytunnel.o	\
	base64.o	\
	setproctitle.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	messages.o	\
	cmdline.o	\
	ntlm.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(CFLAGS) $(LDFLAGS) $(OBJ)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		mkdir -p $(INSTALLPATH) $(INSTALLMANPATH)
		install -D -m755 $(PROGNAME) $(DESTDIR)$(BINDIR)/$(PROGNAME)
		install -D -m644 debian/$(PROGNAME).1 $(DESTDIR)$(MANDIR))/$(PROGNAME).1
