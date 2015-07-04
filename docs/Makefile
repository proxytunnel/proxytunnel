prefix = /usr/local
datadir = $(prefix)/share
mandir = $(datadir)/man

adoctargets = $(shell echo *.adoc)
htmltargets = $(patsubst %.adoc, %.html, $(adoctargets))

docs: proxytunnel.1 $(htmltargets)

install: proxytunnel.1
	install -Dp -m0644 proxytunnel.1 $(DESTDIR)$(mandir)/man1/proxytunnel.1

clean:
	rm -f proxytunnel.1 *.html *.xml

%.1.html: %.1.adoc
	asciidoc -d manpage $<

%.1: %.1.xml
	xmlto man $<

%.html: %.adoc
	asciidoc $<

%.1.xml: %.1.adoc
	asciidoc -b docbook -d manpage $<
