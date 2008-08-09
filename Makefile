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

name = proxytunnel
version = $(shell awk 'BEGIN { FS="\"" } /^\#define VERSION / { print $$2 }' config.h)

prefix = /usr/local
bindir = $(prefix)/bin
datadir = $(prefix)/share
mandir = $(datadir)/man

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

.PHONY: all clean docs install

all: proxytunnel docs

docs:
	$(MAKE) -C docs

proxytunnel: $(OBJ)
	$(CC) -o $(name) $(CFLAGS) $(OPTFLAGS) $(OBJ) $(LDFLAGS)

clean:
	@rm -f $(name) $(OBJ)
	$(MAKE) -C docs clean

install:
	install -Dp -m0755 $(name) $(DESTDIR)$(bindir)/$(name)
	$(MAKE) -C docs install

.c.o:
	$(CC) $(CFLAGS) $(OPTFLAGS) -c -o $@ $<

dist: clean docs
	find . ! -wholename '*/.svn*' | pax -d -w -x ustar -s ,^./,$(name)-$(version)/, | bzip2 >../$(name)-$(version).tar.bz2
