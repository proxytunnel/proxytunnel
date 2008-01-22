# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC ?= cc
CFLAGS ?= -Wall -O2 -ggdb

OPTFLAGS = -DREV=$(shell ./getrev.sh)

# Comment on non-gnu systems
OPTFLAGS += -DHAVE_GETOPT_LONG

# Comment if you don't have/want ssl
OPTFLAGS += -DUSE_SSL

# Most systems
OPTFLAGS += -DSETPROCTITLE -DSPT_TYPE=2

# Comment if you don't have this flag
OPTFLAGS += -DSO_REUSEPORT

# System dependant blocks... if your system is listed below, uncomment
# the relevant lines

# OpenBSD
#OPTFLAGS += -DHAVE_SYS_PSTAT_H

# DARWIN
#OPTFLAGS += -DDARWIN

# CYGWIN
#OPTFLAGS += -DCYGWIN

# SOLARIS
#LDFLAGS += -lsocket -lnsl
#LDFLAGS += -L/usr/local/ssl/lib	# Path to your SSL lib dir

# END system dependant block

SSL_LIBS := $(shell pkg-config --libs libssl 2>/dev/null)
ifeq ($(SSL_LIBS),)
SSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
endif
ifeq ($(SSL_LIBS),)
SSL_LIBS := -lssl -lcrypto
endif
LDFLAGS += $(SSL_LIBS)

PREFIX =/usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share
MANDIR = $(DATADIR)/man

PROGNAME = proxytunnel

# Remove strlcpy/strlcat on (open)bsd/darwin systems
OBJ = proxytunnel.o	\
	base64.o	\
	strlcpy.o	\
	strlcat.o	\
	strzcat.o	\
	setproctitle.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	readpassphrase.o	\
	messages.o	\
	cmdline.o	\
	ntlm.o		\
	ptstream.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(CFLAGS) $(OPTFLAGS) $(OBJ) $(LDFLAGS)

clean:
	@rm -f $(PROGNAME) $(OBJ)

install:
	install -Dp -m0755 $(PROGNAME) $(DESTDIR)$(BINDIR)/$(PROGNAME)
	install -Dp -m0644 $(PROGNAME).1 $(DESTDIR)$(MANDIR)/man1/$(PROGNAME).1

.c.o:
	$(CC) $(CFLAGS) $(OPTFLAGS) -c -o $@ $<
