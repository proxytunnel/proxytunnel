# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

name = proxytunnel
version = $(shell awk 'BEGIN { FS="\"" } /^\#define VERSION / { print $$2 }' config.h)

prefix = /usr/local
bindir = $(prefix)/bin
datadir = $(prefix)/share
mandir = $(datadir)/man

CC ?= cc
CFLAGS ?= -Wall -O2 -ggdb

# Comment on non-gnu systems
OPTFLAGS += -DHAVE_GETOPT_LONG

# Comment if you don't have/want ssl
OPTFLAGS += -DUSE_SSL

# Most systems
OPTFLAGS += -DSETPROCTITLE -DSPT_TYPE=2

# System dependant blocks... if your system is listed below, uncomment
# the relevant lines

# OpenBSD
#OPTFLAGS += -DHAVE_SYS_PSTAT_H

# DARWIN
OPTFLAGS += -DDARWIN

# DARWIN, continued, if compiling for macOS with Homebrew
openssl_bin = $(prefix)/opt/openssl/bin/openssl
cacert_dir = $(shell "$(openssl_bin)" version -d | sed -E 's/^[^"]+"|"$$//g')
cacert_file = $(cacert_dir)/cacert.pem

CFLAGS += -I$(prefix)/opt/openssl/include
LDFLAGS += -L$(prefix)/opt/openssl/lib
OPTFLAGS += -DDEFAULT_CA_FILE='$(subst ','"'"',$(subst \,\\,$(shell gls --quoting-style=c "$(cacert_file)")))'
OPTFLAGS += -DDEFAULT_CA_DIR=NULL

# CYGWIN
#OPTFLAGS += -DCYGWIN

# SOLARIS
#LDFLAGS += -lsocket -lnsl
#LDFLAGS += -L/usr/local/ssl/lib	# Path to your SSL lib dir

# END system dependant block

SSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(SSL_LIBS),)
SSL_LIBS := $(shell pkg-config --libs libssl 2>/dev/null)
endif
ifeq ($(SSL_LIBS),)
SSL_LIBS := -lssl -lcrypto
endif
LDFLAGS += $(SSL_LIBS)

# Remove strlcpy/strlcat on (open)bsd/darwin systems
OBJ = proxytunnel.o	\
	base64.o	\
	strzcat.o	\
	setproctitle.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	readpassphrase.o	\
	messages.o	\
	cmdline.o	\
	globals.o	\
	ntlm.o		\
	ptstream.o

UNAME = $(shell uname)
ifneq ($(UNAME),Darwin)
OBJ += strlcpy.o	\
	strlcat.o
endif

.PHONY: all clean docs install

all: proxytunnel

docs:
	$(MAKE) -C docs

proxytunnel: $(OBJ)
	$(CC) -o $(name) $(CPPFLAGS) $(CFLAGS) $(OPTFLAGS) $(OBJ) $(LDFLAGS)

clean:
	@rm -f $(name) $(OBJ)
	$(MAKE) -C docs clean

install:
	install -d $(DESTDIR)$(bindir)
	install -p -m555 $(name) $(DESTDIR)$(bindir)
	$(MAKE) -C docs install

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPTFLAGS) -c -o $@ $<

dist: clean docs
	sed -i -e 's/^Version:.*$$/Version: $(version)/' contrib/proxytunnel.spec
	find . ! -wholename '*/.svn*' | pax -d -w -x ustar -s ,^./,$(name)-$(version)/, | bzip2 >../$(name)-$(version).tar.bz2

rpm: dist
	rpmbuild -tb --clean --rmsource --rmspec --define "_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" --define "_rpmdir ../" ../$(name)-$(version).tar.bz2

srpm: dist
	rpmbuild -ts --clean --rmsource --rmspec --define "_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" --define "_srcrpmdir ../" ../$(name)-$(version).tar.bz2
