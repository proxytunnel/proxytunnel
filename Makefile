proxytunnel:	proxytunnel.o cmdline.o

clean:		
	@rm -f proxytunnel proxytunnel.o cmdline.o

install:
		mkdir -p /usr/local/bin
		install -g root -m755 -o root proxytunnel /usr/local/bin/proxytunnel
