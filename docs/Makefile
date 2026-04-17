prefix = /usr/local
datadir = $(prefix)/share
mandir = $(datadir)/man

adoctargets = $(shell echo *.adoc)
htmltargets = $(patsubst %.adoc, %.html, $(adoctargets))

version = $(shell grep ' VERSION ' ../config.h | cut -d'"' -f2)
version_date = $(shell grep ' VERSION_DATE ' ../config.h | cut -d'"' -f2)

docs: proxytunnel.1 $(htmltargets)

install: proxytunnel.1
	install -d $(DESTDIR)$(mandir)/man1
	install -p proxytunnel.1 $(DESTDIR)$(mandir)/man1

clean:
	rm -f proxytunnel.1 *.html *.xml

%.1.html: %.1.adoc
	asciidoc -d manpage -arevnumber=$(version) -arevdate=$(version_date) $<

%.1: %.1.xml
	xmlto man $<

%.html: %.adoc
	asciidoc $<

%.1.xml: %.1.adoc
	asciidoc -b docbook -d manpage -arevnumber=$(version) -arevdate=$(version_date) $<
