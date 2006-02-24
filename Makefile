# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC ?= gcc
CFLAGS ?= -Wall -O2 -g
CFLAGS += -DHAVE_GETOPT_LONG -DUSE_SSL
CFLAGS += -DSETPROCTITLE -DSPT_TYPE=1

SSL_LIBS := $(shell pkg-config --libs libssl 2>/dev/null)
ifeq ($(SSL_LIBS),)
SSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
endif
ifeq ($(SSL_LIBS),)
SSL_LIBS := -lssl -lcrypto
endif
LDFLAGS += $(SSL_LIBS)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/man/man1

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
	$(CC) -o $(PROGNAME) $(CFLAGS) $(OBJ) $(LDFLAGS)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		install -D -m755 $(PROGNAME) $(BINDIR)/$(PROGNAME)
		install -D -m644 debian/$(PROGNAME).1 $(MANDIR)/$(PROGNAME).1
