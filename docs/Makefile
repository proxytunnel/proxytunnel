prefix = /usr/local
datadir = $(prefix)/share
mandir = $(datadir)/man

txttargets = $(shell echo *.txt)
htmltargets = $(patsubst %.txt, %.html, $(txttargets))

docs: proxytunnel.1 $(htmltargets)

install: proxytunnel.1
	install -Dp -m0644 proxytunnel.1 $(DESTDIR)$(mandir)/man1/proxytunnel.1

clean:
	rm -f proxytunnel.1 *.html *.xml

%.1.html: %.1.txt
	asciidoc -d manpage $<

%.1: %.1.xml
	xmlto man $<

%.html: %.txt
	asciidoc $<

%.1.xml: %.1.txt
	asciidoc -b docbook -d manpage $<
