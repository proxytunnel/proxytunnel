# Makefile for proxytunnel
#
# Please uncomment the appropriate settings

CC ?= gcc
CFLAGS += -Wall -DHAVE_GETOPT_LONG -DUSE_SSL
LDFLAGS += -lssl
BINDIR = /usr/local/bin
INSTALLPATH = $(DESTDIR)/$(BINDIR)
MANPATH = /usr/share/man/man1
INSTALLMANPATH = $(DESTDIR)/$(MANPATH)


PROGNAME = proxytunnel
OBJ = proxytunnel.o	\
	base64.o	\
	io.o		\
	http.o		\
	basicauth.o	\
	messages.o	\
	cmdline.o	\
	ntlm.o

proxytunnel: $(OBJ)
	$(CC) -o $(PROGNAME) $(LDFLAGS) $(OBJ)

clean:		
	@rm -f $(PROGNAME) $(OBJ)

install:
		mkdir -p $(INSTALLPATH) $(INSTALLMANPATH)
		install -m755 $(PROGNAME) $(INSTALLPATH)/$(PROGNAME)
		install -m644 debian/$(PROGNAME).1 $(INSTALLMANPATH)/$(PROGNAME).1
