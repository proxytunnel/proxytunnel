/* Proxytunnel - (C) 2001-2002 Jos Visser / Mark Janssen    */
/* Contact:                  josv@osp.nl / maniac@maniac.nl */

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
#include <syslog.h>
#include <stdarg.h>

#include "config.h"
#include "cmdline.h"

/* Needed for base64 encoding... */
static const char base64digits[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* 
 * Some variables
 */
int sd;				/* The tunnel's socket descriptor */
int read_fd=0;			/* The file descriptor to read from */
int write_fd=1;			/* The file destriptor to write to */
char *program_name;		/* Guess what? */
int i_am_daemon;		/* Also... */


/*
 * All the command line options
 */
struct gengetopt_args_info args_info;

#define SIZE 80
char basicauth[SIZE];	/* Buffer to hold the proxies basic authentication data */

#define SIZE2 65536
char buf[SIZE2];		/* Data transfer buffer */

/*
 * Small MAX macro
 */
#ifndef MAX
#define MAX( x, y )	( ( (x)>(y) ) ? (x) : (y) )
#endif

/*
 * Give a message to the user
 */
void message( char *s, ... )
{
	va_list	ap;
	char	buf[1024];

	va_start( ap, s );
	vsnprintf( buf, sizeof( buf ), s, ap );
	va_end( ap );

	if ( i_am_daemon )
		syslog( LOG_NOTICE, buf );
	else
		fputs( buf, stderr );
}

/*
 * My own perror function (uses the internal message)
 */
void my_perror( char *msg )
{
	char *err = strerror( errno );

	message( "Error! %s: %s\n", msg, err );
}

/*
 * Kill the program (signal handler)
 */
void signal_handler( int signal )
{
	close(0);
	close(1);

	if ( sd != 0 )
		close( sd );

	message( "Tunnel closed on signal %d\n", signal );
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
	if( ( sd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
	{
		my_perror("Can not create socket");
		exit(1);
	}

	/* 
	 * Lookup the IP address of the proxy
	 */
	if( ! ( he = gethostbyname( args_info.proxyhost_arg ) ) )
	{
		my_perror("Proxy host not found");
		exit(1);
	}
 
 	if( args_info.verbose_flag )
	{
 		message( "%s is %d.%d.%d.%d\n",
				args_info.proxyhost_arg,
				he->h_addr[0] & 255,
				he->h_addr[1] & 255,
				he->h_addr[2] & 255,
				he->h_addr[3] & 255 );
	}

	/*
	 * Set up the structure to connect to the proxy port of the proxy host
	 */
	memset( &sa, '\0', sizeof( sa ) );
  	sa.sin_family = AF_INET;
  	memcpy( &sa.sin_addr.s_addr, he->h_addr, 4);
  	sa.sin_port = htons( args_info.proxyport_arg );
  
  	/*
	 * Connect the socket
	 */
  	if( connect( sd, (struct sockaddr*) &sa, sizeof( sa ) ) < 0 )
	{
		my_perror("connect() failed");
		exit(1);
	}

	if( ! args_info.quiet_flag )
	{
		message( "Connected to %s:%d\n",
			args_info.proxyhost_arg,
			args_info.proxyport_arg );
	}

	/* Make sure we get warned when someone hangs up on us */
	signal(SIGHUP,signal_handler);
}

/*
 * Create the HTTP basic authentication cookie for use by the proxy. Result
 * is stored in basicauth.
 */
void make_basicauth()
{
	int len = strlen( args_info.user_arg ) + \
		strlen( args_info.pass_arg ) + 2;
	char *p = (char *) malloc( len );

	/*
	 * Set up the cookie in clear text
	 */
	sprintf( p, "%s:%s", args_info.user_arg, args_info.pass_arg );

	/*
	 * Base64 encode the clear text cookie to create the HTTP base64
	 * authentication cookie
	 */
	base64( basicauth, p, strlen( p ) );

	if( args_info.verbose_flag )
	{
		message( "Proxy basic auth is %s\n", basicauth );
	}

	free( p );
}

/* 
 * Read one line of data from the tunnel. Line is terminated by a
 * newline character. Result is stored in buf.
 */
void readline()
{
	char	*p = buf;
	char	c = 0;
	int	i = 0;

	/*
	 * Read one character at a time into buf, until a newline is
	 * encountered.
	 */
	while ( c != 10 && i < SIZE2 - 1 )
	{
		if( recv( sd, &c ,1 ,0 ) < 0)
		{
			my_perror( "Socket read error" );
			exit( 1 );
		}

		*p = c;
		p++;
		i++;
	}

	*p = 0;

	if( args_info.verbose_flag )
		message( "%s", buf );
}

/*
 * Analyze the proxy's HTTP response. This must be a HTTP/1.? 200 OK type
 * header
 */
void analyze_HTTP()
{
	char *p = strtok( buf, " ");

	if (strcmp( p, "HTTP/1.0" ) != 0 && strcmp( p, "HTTP/1.1" ) != 0)
	{
		message( "Unsupported HTTP version number %s\n", p );
		exit( 1 );
	}

	p = strtok( 0, " ");

	if( strcmp( p, "200" ) != 0 )
	{
		message( "HTTP return code: '%s'\n", p );
		p += strlen( p ) + 1;
		message( "%s\n", p );
		exit( 1 );
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

	if( args_info.dottedquad_flag )
	{
		static char ipbuf[16]; /* IPv4: 'xxx.xxx.xxx.xxx' + \0 = 16 */
		struct hostent * he = gethostbyname( args_info.desthost_arg );
		if ( he )
		{
			sprintf( ipbuf, "%d.%d.%d.%d", 
				he->h_addr[0] & 255,
				he->h_addr[1] & 255,
				he->h_addr[2] & 255,
				he->h_addr[3] & 255 );

			if( args_info.verbose_flag )
			{
			   message( "DEBUG: ipbuf = '%s'\n", ipbuf );
			   message( "DEBUG: desthost = '%s'\n",
					   args_info.desthost_arg );
			}

			args_info.desthost_arg = ipbuf;

			if( args_info.verbose_flag )
			   message( "DEBUG: desthost = '%s'\n",
					   args_info.desthost_arg );

		}
		else if( args_info.verbose_flag )
			message( "Can't lookup dest host: %s.\n",
					args_info.desthost_arg );

	}

	if ( args_info.user_given && args_info.pass_given )
	{
		/*
		 * Create connect string including the authorization part
		 */
		sprintf( buf,
	"CONNECT %s:%d HTTP/1.0\r\nProxy-authorization: Basic %s \r\nProxy-Connection: Keep-Alive\r\n\r\n",
			args_info.desthost_arg,
			args_info.destport_arg,basicauth );
	}
	else
	{
		/*
		 * Create connect string without authorization part
		 */
		sprintf( buf, "CONNECT %s:%d HTTP/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n",
				args_info.desthost_arg,
				args_info.destport_arg );
	}
	
	if( args_info.verbose_flag )
		message( "%s", buf);
	
	/*
	 * Send the CONNECT instruction to the proxy
	 */
	if( send( sd, buf, strlen( buf ), 0 ) < 0 )
	{
		my_perror( "Socket write error" );
		exit( 1 );
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
	} while ( strcmp( buf, "\r\n" ) != 0 );
}

/*
 * Copy a block of data from one socket descriptor to another. A true
 * return code signifies EOF on the from socket descriptor.
 */
int copy(int from, int to)
{
	int n;

	/* 
	 * Read a buffer from the source socket
	 */
	if ( ( n = read( from, buf, SIZE2 ) ) < 0 )
	{
		my_perror( "Socket read error" );
		exit( 1 );
	}

	/*
	 * If we have read 0 bytes, there is an EOF on src
	 */
	if( n==0 )
		return 1;

	/*
	 * Write the buffer to the destination socket
	 */
	if ( write( to, buf, n ) != n )
	{
		my_perror( "Socket write error" );
		exit( 1 );
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
void cpio()
{
	fd_set	readfds;
	fd_set	writefds;
	fd_set	exceptfds;
	int	max_fd;

	/*
	 * Find the biggest file descriptor for select()
	 */
	max_fd = MAX( read_fd,write_fd );
	max_fd = MAX( max_fd,sd );


	/*
	 * We're never interested in sockets being available for write.
	 */
	FD_ZERO( &writefds );

	if( ! args_info.quiet_flag )
	{
		message( "Starting tunnel\n" );
	}

	/*
	 * Only diamonds are forever :-)
	 */
	while( 1==1 )
	{
		/*
		 * Clear the interesting socket sets
		 */
		FD_ZERO( &readfds );
		FD_ZERO( &exceptfds );

		/*
		 * We want to know whether stdin or sd is ready for reading
		 */
		FD_SET( read_fd,&readfds );
		FD_SET( sd,&readfds );

		/*
		 * And we want to know about exceptional conditions on either
		 * stdin, stdout or the tunnel
		 */
		FD_SET( read_fd,&exceptfds );
		FD_SET( write_fd,&exceptfds );
		FD_SET( sd,&exceptfds );

		/*
		 * Wait until something happens on one of the registered
		 * sockets/files
		 */
		if ( select( max_fd + 1, &readfds, &writefds,
					&exceptfds, 0 ) < 0 )
		{
			perror("select error");
			exit(1);
		}

		/*
		 * Is stdin ready for read? If so, copy a block of data
		 * from stdin to the tunnel. Or else if the tunnel socket
		 * is ready for read, copy a block of data from the
		 * tunnel to stdout. Otherwise an exceptional condition
		 * is flagged and the program is terminated.
		 */
		if ( FD_ISSET( read_fd, &readfds ) )
		{
			if ( copy( read_fd, sd ) )
				break;
		}
		else if( FD_ISSET( sd, &readfds ) )
		{
			if( copy(sd,write_fd ) )
				break;
		}
		else
		{
			my_perror( "Exceptional condition" );
			break;
		}
	}

	/*
	 * Close all files we deal with
	 */
	close( read_fd );
	close( sd );

	if( read_fd != write_fd )	/* When not running from inetd */
	{
		close( write_fd );
	}

	if( args_info.verbose_flag )
	{
		message( "Tunnel closed\n" );
	}
}

/*
 * Leave a goodbye message
 */
void einde() {
        syslog(LOG_NOTICE,"Goodbye...");
        closelog();
}

/*
 * Run as a standalone daemon
 */
void do_daemon()
{
	int			listen_sd;
	struct sockaddr_in	sa_serv;
	struct sockaddr_in	sa_cli;
	size_t			client_len;
	int			pid = 0;
	int			sd_client;
	char			buf[80];
	unsigned char		addr[4];

	if ( ( listen_sd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
	{
		my_perror( "Server socket creation failed" );
		exit(1);
	}

	memset( &sa_serv, '\0', sizeof( sa_serv ) );
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons( args_info.standalone_arg );

	if ( bind( listen_sd, (struct sockaddr * )&sa_serv, sizeof( sa_serv ) ) < 0)
	{
		my_perror("Server socket bind failed");
		exit(1);
	}

	signal(SIGHUP,SIG_IGN);
	signal(SIGCHLD,SIG_IGN);

	if ( ( pid = fork( ) ) < 0 )
	{
		my_perror( "Cannot fork into the background" );
		exit( 1 );
	}
	else if ( pid > 0 )
	{
       		message( "Forked into the background with pid %d\n", pid );
       		exit(0);
	}

	openlog( program_name, LOG_CONS|LOG_PID,LOG_DAEMON );
	i_am_daemon = 1;
	atexit( einde );
	listen( listen_sd, 5 );

	while (1==1)
	{
		sd_client = accept( listen_sd,
			(struct sockaddr *)&sa_cli, &client_len );

		if ( sd_client < 0 )
		{
        		syslog( LOG_ERR, "accept() failed. Bailing out..." );
        		exit(1);
		}

		if ( ( pid = fork() ) < 0 )
		{
        		syslog( LOG_ERR, "Cannot fork worker" );
		}
		else if ( pid == 0 )
		{
        		read_fd = write_fd = sd_client;
			tunnel_connect();
			proxy_protocol();
			cpio();
			exit( 0 );
		}

		memcpy( &addr, &sa_cli.sin_addr.s_addr, 4 );
		sprintf( buf, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3] );
		syslog( LOG_NOTICE,
			"Started tunnel pid=%d for connection from %s", pid, buf );
		close( sd_client );
	}
}


/*
 * We begin at the beginning
 */
int main( int argc, char *argv[] )
{
	program_name = argv[0];

	/*
	 * New and improved option handling, using GNU getopts  -- Maniac
	 */

	cmdline_parser( argc, argv, &args_info );

	/*
	 * This is what we do:
	 * - Check if we need to run as a daemon. If so, a completely
	 *   different mainline is needed...
	 * - Set a signal for the hangup (HUP) signal
	 * - Optionally create the proxy basic authenticcation cookie
	 * - Connect the sd socket to the proxy
	 * - Execute the proxy protocol to connect it to the origin server
	 * - Enter copy in-out mode to channel data hence and forth
	 */

	signal( SIGHUP, signal_handler );

	if( args_info.user_given && args_info.pass_given )
	{
		make_basicauth();
	}

	/* Do we need to run as a standalone daemon? */
	if ( args_info.standalone_arg > 0 )
	{
		/* Do processing in the other mainline... */
		do_daemon();
	}
	else
	{
		/* Inetd trick */
		if( args_info.inetd_flag )
		{
			write_fd=0;
		}

		/* Main processing */
		tunnel_connect();
		proxy_protocol();
		cpio();
	}

	exit( 0 );
}
