/* Proxytunnel - (C) 2001 Jos Visser / Mark Janssen    */
/* Contact:             josv@osp.nl / maniac@maniac.nl */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "config.h"
#include "cmdline.h"

/* Needed for base64 encoding... */
static const char base64digits[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BAD     -1
static const char base64val[] = {
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
     52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
     15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
    BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
     41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
};
/* bounds-check input */
#define DECODE64(c) (isascii(c) ? base64val[c] : BAD)

/* 
 * Some variables
 */
int sd;				/* The tunnel's socket descriptor */
int read_fd=0;			/* The file descriptor to read from */
int write_fd=1;			/* The file destriptor to write to */

/*
 * All the command line options
 */
struct gengetopt_args_info args_info;

#define SIZE 80
char basicauth[SIZE];		/* Buffer to hold the proxy's basic authentication screen */

#define SIZE2 65536
char buf[SIZE2];		/* Data transfer buffer */

/*
 * Small MAX macro
 */
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif


/*
 * Kill the program (signal handler)
 */
void signal_handler(int signal) {
	close(0);
	close(1);

	if (sd!=0) close(sd);

	fprintf(stderr,"Tunnel closed on signal %d\n",signal);
	exit(1);
}

/* 
 * This base64 code is heavily modified from fetchmail (also GPL'd, of
 * course) by Brendan Cully <brendan@kublai.com>.
 * 
 * Original copyright notice:
 * 
 * The code in the fetchmail distribution is Copyright 1997 by Eric
 * S. Raymond.  Portions are also copyrighted by Carl Harris, 1993
 * and 1995.  Copyright retained for the purpose of protecting free
 * redistribution of source. 
 * 
 */

/* raw bytes to null-terminated base 64 string */
void base64(unsigned char *out, const unsigned char *in, int len)
{
  while (len >= 3) {
    *out++ = base64digits[in[0] >> 2];
    *out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
    *out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
    *out++ = base64digits[in[2] & 0x3f];
    len -= 3;
    in += 3;
 }

  /* clean up remainder */
  if (len > 0) {
    unsigned char fragment;

    *out++ = base64digits[in[0] >> 2];
    fragment = (in[0] << 4) & 0x30;
    if (len > 1)
      fragment |= in[1] >> 4;
    *out++ = base64digits[fragment];
    *out++ = (len < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
    *out++ = '=';
  }
  *out = '\0';
}


/*
 * Create and connect the socket that connects to the proxy. After
 * this routine the sd socket is connected to the proxy.
 */
void tunnel_connect() {
	struct sockaddr_in 	sa;
	struct hostent		*he;

	/*
	 * Create the socket
	 */
	if ((sd=socket(AF_INET,SOCK_STREAM,0))<0) {
		perror("Can not create socket");
		exit(1);
	}

	/* 
	 * Lookup the IP address of the proxy
	 */
	if (!(he=gethostbyname(args_info.proxyhost_arg))) {
		perror("Proxy host not found");
		exit(1);
	}
 
 	if (args_info.verbose_flag)
 		fprintf(stderr,"%s is %d.%d.%d.%d\n",args_info.proxyhost_arg,
			he->h_addr[0], he->h_addr[1], he->h_addr[2], he->h_addr[3]);

	/*
	 * Set up the structure to connect to the proxy port of the proxy host
	 */
	memset (&sa, '\0', sizeof(sa));
  	sa.sin_family=AF_INET;
  	memcpy(&sa.sin_addr.s_addr,he->h_addr,4);
  	sa.sin_port= htons(args_info.proxyport_arg);
  
  	/*
	 * Connect the socket
	 */
  	if (connect(sd,(struct sockaddr*) &sa,sizeof(sa))<0) {
		perror("connect() failed");
		exit(1);
	}

	fprintf(stderr,"Connected to %s:%d\n",args_info.proxyhost_arg,args_info.proxyport_arg);
}

/*
 * Create the HTTP basic authentication cookie for use by the proxy. Result
 * is stored in basicauth.
 */
void make_basicauth() {
	int len=strlen(args_info.user_arg)+strlen(args_info.pass_arg)+2;
	char *p=(char *)malloc(len);

	/*
	 * Set up the cookie in clear text
	 */
	sprintf(p,"%s:%s",args_info.user_arg,args_info.pass_arg);

	/*
	 * Base64 encode the clear text cookie to create the HTTP base64
	 * authentication cookie
	 */
	base64( basicauth, p, strlen(p));
	fprintf(stderr,"Proxy basic authentication is %s\n",basicauth);

	if (args_info.verbose_flag)
		fprintf(stderr,"Proxy basic authentication is %s\n",basicauth);

	free(p);
}

/* 
 * Read one line of data from the tunnel. Line is terminated by a
 * newline character. Result is stored in buf.
 */
void readline() {
	char *p=buf;
	char c=0;
	int i=0;

	/*
	 * Read one character at a time into buf, until a newline is
	 * encountered.
	 */
	while (c!=10 && i<SIZE2-1) {
		if (recv(sd,&c,1,0)<0) {
			perror("Socket read error");
			exit(1);
		}

		*p=c;
		p++;
		i++;
	}

	*p=0;

	if (args_info.verbose_flag)
		fprintf(stderr,buf);
}

/*
 * Analyze the proxy's HTTP response. This must be a HTTP/1.? 200 OK type
 * header
 */
void analyze_HTTP() {
	char *p=strtok(buf," ");

	if (strcmp(p,"HTTP/1.0")!=0 && strcmp(p,"HTTP/1.1")!=0) {
		fprintf(stderr,"Unsupported HTTP version number %s\n",p);
		exit(1);
	}

	p=strtok(0," ");

	if (strcmp(p,"200")!=0) {
		fprintf(stderr,"HTTP return code: '%s'\n",p);
		p+=strlen(p)+1;
		fprintf(stderr, "%s\n",p);
		exit(1);
	}
}

/*
 * Execute the basic proxy protocol of CONNECT and response, until the
 * last line of the response has been read. The tunnel is then open.
 */
void proxy_protocol()
{
	/*
	 * Create the proxy CONNECT command into buf
	 */

	if (args_info.dottedquad_flag)
	{
		static char ipbuf[64];
		struct hostent * he = gethostbyname( args_info.desthost_arg);
		if ( he )
		{
			sprintf( ipbuf, "%d.%d.%d.%d", 
				he->h_addr[0] & 255,
				he->h_addr[1] & 255,
				he->h_addr[2] & 255,
				he->h_addr[3] & 255 );

			if( args_info.verbose_flag )
			{
			   fprintf( stderr, "DEBUG: ipbuf = '%s'\n", ipbuf );
			   fprintf( stderr, "DEBUG: desthost = '%s'\n", args_info.desthost_arg );
			}

			args_info.desthost_arg = ipbuf;

			if( args_info.verbose_flag )
			   fprintf( stderr, "DEBUG: desthost = '%s'\n", args_info.desthost_arg );

		}
		else if( args_info.verbose_flag )
			fprintf( stderr,
			"Cannot lookup destination host: %s.\n", args_info.desthost_arg );

	}

	if ( args_info.user_given && args_info.pass_given )
	{
		/*
		 * Create connect string including the authorization part
		 */
		sprintf( buf,
	"CONNECT %s:%d HTTP/1.0\r\nProxy-authorization: Basic %s \r\nProxy-Connection: Keep-Alive\r\n\r\n",
	args_info.desthost_arg,args_info.destport_arg,basicauth);
	}
	else
	{
		/*
		 * Create connect string without authorization part
		 */
		sprintf( buf, "CONNECT %s:%d HTTP/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n",
			args_info.desthost_arg,args_info.destport_arg);
	}
	
	if (args_info.verbose_flag)
		fprintf(stderr,buf);
	
	/*
	 * Send the CONNECT instruction to the proxy
	 */
	if (send(sd,buf,strlen(buf),0)<0) {
		perror("Socket write error");
		exit(1);
	}

	/*
	 * Read the first line of the response and analyze it
	 */
	readline();
	analyze_HTTP();

	/*
	 * Then, repeat reading lines of the responses until a blank line
	 * (which signifies the end of the response) is encountered.
	 */
	do {
		readline();
	} while (strcmp(buf,"\r\n")!=0);
}

/*
 * Copy a block of data from one socket descriptor to another. A true
 * return code signifies EOF on the from socket descriptor.
 */
int copy(int from, int to) {
	int n;

	/* 
	 * Read a buffer from the source socket
	 */
	if ((n=read(from,buf,SIZE2))<0) {
		perror("Socket read error");
		exit(1);
	}

	/*
	 * If we have read 0 bytes, there is an EOF on src
	 */
	if (n==0) return 1;

	/*
	 * Write the buffer to the destination socket
	 */
	if (write(to,buf,n)!=n) {
		perror("Socket write error");
		exit(1);
	}

	/*
	 * We're not yet at EOF
	 */
	return 0;
}

/*
 * Move into a loop of copying data to and from the tunnel.
 * stdin (fd 0) and stdout (fd 1) are the file descriptors
 * for the connected application, sd is the file descriptor
 * of the tunnel.
 */
void cpio() {
	fd_set	readfds;
	fd_set	writefds;
	fd_set	exceptfds;
	int	max_fd;

	/*
	 * Find the biggest file descriptor for select()
	 */
	max_fd=MAX(read_fd,write_fd);
	max_fd=MAX(max_fd,sd);


	/*
	 * We're never interested in sockets being available for write.
	 */
	FD_ZERO(&writefds);

	fprintf(stderr,"Starting tunnel\n");

	/*
	 * Only diamonds are forever :-)
	 */
	while (1==1) {
		/*
		 * Clear the interesting socket sets
		 */
		FD_ZERO(&readfds);
		FD_ZERO(&exceptfds);

		/*
		 * We want to know whether stdin or sd is ready for reading
		 */
		FD_SET(read_fd,&readfds);
		FD_SET(sd,&readfds);

		/*
		 * And we want to know about exceptional conditions on either
		 * stdin, stdout or the tunnel
		 */
		FD_SET(read_fd,&exceptfds);
		FD_SET(write_fd,&exceptfds);
		FD_SET(sd,&exceptfds);

		/*
		 * Wait until something happens on one of the registered sockets/files
		 */
		if (select(max_fd+1,&readfds,&writefds,&exceptfds,0)<0) {
			perror("select error");
			exit(1);
		}

		/*
		 * Is stdin ready for read? If so, copy a block of data from stdin to the tunnel.
		 * Or else if the tunnel socket is ready for read, copy a block of data from the
		 * tunnel to stdout. Otherwise an exceptional condition is flagged and the program
		 * is terminated.
		 */
		if (FD_ISSET(read_fd,&readfds)) {
			if (copy(read_fd,sd)) break;
		} else if (FD_ISSET(sd,&readfds)) {
			if (copy(sd,write_fd)) break;
		} else {
			perror("Exceptional condition");
			break;
		}
	}

	/*
	 * Close all files we deal with
	 */
	close(read_fd);
	close(sd);

	if (read_fd!=write_fd) close(write_fd);

	if (args_info.verbose_flag) fprintf(stderr,"Tunnel closed\n");

}

/*
 * We begin at the beginning
 */
int main(int argc, char *argv[])
{
	/*
	 * New and improved option handling, using GNU getopts
	 * now, this is still a work in progress -- Maniac
	 */

	cmdline_parser( argc, argv, &args_info );

	/*
	 * This is what we do:
	 * - Set a signal for the hangup (HUP) signal
	 * - Optionally create the proxy basic authenticcation cookie
	 * - Connect the sd socket to the proxy
	 * - Execute the proxy protocol to connect it to the origin server
	 * - Enter copy in-out mode to channel data hence and forth
	 */

	signal(SIGHUP,signal_handler);
	if ( args_info.user_given && args_info.pass_given ) make_basicauth();

	/* Inetd */
	if (args_info.inetd_flag) write_fd=0;

	tunnel_connect();
	proxy_protocol();
	cpio();
	exit(0);
}
