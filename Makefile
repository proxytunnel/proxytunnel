# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC ?= cc
CFLAGS ?= -Wall -O2 -ggdb
CFLAGS += -DHAVE_GETOPT_LONG # Comment on non-gnu systems
CFLAGS += -DUSE_SSL # Comment if you don't have/want ssl
# Most systems
CFLAGS += -DSETPROCTITLE -DSPT_TYPE=2

# System dependant blocks... if your system is listed below, uncomment
# the relevant lines

# OpenBSD
#CFLAGS += -DHAVE_SYS_PSTAT_H
# DARWIN
#CFLAGS += -DDARWIN
# CYGWIN
#CFLAGS += -DCYGWIN
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
	setproctitle.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	readpassphrase.o \
	messages.o	\
	cmdline.o	\
	ntlm.o		\
	ptstream.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(CFLAGS) $(OBJ) $(LDFLAGS)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		install -Dp -m0755 $(PROGNAME) $(DESTDIR)$(BINDIR)/$(PROGNAME)
		install -Dp -m0644 debian/$(PROGNAME).1 $(DESTDIR)$(MANDIR)/man1/$(PROGNAME).1

