/* Proxytunnel - (C) 2001-2006 Jos Visser / Mark Janssen    */
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

/* http.c */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "proxytunnel.h"
#include "io.h"
#include "basicauth.h"
#include "ntlm.h"

/*
 * Analyze the proxy's HTTP response. This must be a HTTP/1.? 200 OK type
 * header
 */
void analyze_HTTP(PTSTREAM *pts)
{
	char *p = strtok( buf, " ");

	/* 
	 * Strip html error pages for faulty proxies
	 * by: Stephane Engel <steph[at]macchiati.org>
	 */
	while (strncmp( p, "HTTP/", 5) != 0 )
	{
		if ( readline(pts) )
			p = strtok( buf, " ");
		else
		{
			message( "analyze_HTTP: readline failed: Connection closed by remote host\n" );
			exit(2);
		}
	}

	if (strcmp( p, "HTTP/1.0" ) != 0 && strcmp( p, "HTTP/1.1" ) != 0)
	{
		message( "Unsupported HTTP version number %s\n", p );
		exit( 1 );
	}

	p = strtok( NULL, " ");

	if( strcmp( p, "200" ) != 0 )
	{
		if( ! args_info.quiet_flag )
			message( "HTTP return code: %s ", p );

		p += strlen( p ) + 1;

		if( ! args_info.quiet_flag )
			message( "%s", p );

		if (!ntlm_challenge && strcmp( p, "407") != 0)
		{
			do
			{
				readline(pts);
				if (strncmp( buf, "Proxy-Authenticate: NTLM ", 25) == 0)
				{
					if (parse_type2((unsigned char *)&buf[25]) < 0)
						exit(1);
				}
			} while ( strcmp( buf, "\r\n" ) != 0 );
		}
		if (ntlm_challenge == 1)
		{
			proxy_protocol(pts);
			return;
		}
		exit( 1 );
	}
}

/*
 * Prints lines from a buffer prepended with a prefix
 */
void print_line_prefix(char *buf, char *prefix)
{
    buf = strdup(buf);
    char *cur = strtok(buf, "\r\n");
    while ( cur != NULL) {
        message( "%s%s\n", prefix, cur );
        cur = strtok(NULL, "\r\n");
    }
}

/*
 * Append an undefined number of strings together
 */
void strzcat(char *strz, ...)
{
    va_list ap;
    va_start(ap, strz);
    char *z;
    int i;
    for(i=0; i<sizeof(*ap); i++) {
        z = va_arg(ap, char *);
        strlcat(strz, z, SIZE);
//      fprintf ( stderr, "strzcat: len-strz(%d)(%s), len-z(%d)(%s), size(%d)\n", strlen(strz), strz, strlen(z), z, SIZE );
    }
    va_end(ap);
}

/*
 * Execute the basic proxy protocol of CONNECT and response, until the
 * last line of the response has been read. The tunnel is then open.
 */
void proxy_protocol(PTSTREAM *pts)
{
	/*
	 * Create the proxy CONNECT command into buf
	 */
	if (args_info.remproxy_given )
	{
		if( args_info.verbose_flag )
			message( "\nTunneling to %s (remote proxy)\n", args_info.remproxy_arg );
		sprintf( buf, "CONNECT %s HTTP/1.0\r\n", args_info.remproxy_arg );
	}
	else
	{
		if( args_info.verbose_flag )
			message( "\nTunneling to %s (destination)\n", args_info.dest_arg );
		sprintf( buf, "CONNECT %s HTTP/1.0\r\n", args_info.dest_arg );
	}
	
	if ( args_info.user_given && args_info.pass_given )
	{
		/*
		 * Create connect string including the authorization part
		 */
              if (args_info.ntlm_flag) {
                      if (ntlm_challenge == 1)
		      {
				build_type3_response();
//				strzcat( buf, "Proxy-Authorization: NTLM ", ntlm_type3_buf, "\r\n" );
				strlcat( buf, "Proxy-Authorization: NTLM ", SIZE );
				strlcat( buf, ntlm_type3_buf, SIZE );
				strlcat( buf, "\r\n", SIZE );
                      }
		      else if (ntlm_challenge == 0)
		      {
//				strzcat( buf, "Proxy-Authorization: NTLM ", ntlm_type1_buf, "\r\n" );
				strlcat( buf, "Proxy-Authorization: NTLM ", SIZE );
				strlcat( buf, ntlm_type1_buf, SIZE );
				strlcat( buf, "\r\n", SIZE );
                      }
              }
	      else
	      {
//                     strzcat( buf, "Proxy-authorization: Basic ", basicauth, "\r\n" );
			strlcat( buf, "Proxy-authorization: Basic ", SIZE );
			strlcat( buf, basicauth, SIZE);
			strlcat( buf, "\r\n", SIZE );
              }
	}

	/* Add extra header(s) */
	if ( args_info.header_given )
	{
//		strzcat( buf, args_info.header_arg, "\r\n" );
		strlcat( buf, args_info.header_arg, SIZE );
		strlcat( buf, "\r\n", SIZE );
	}

	strlcat( buf, "Proxy-Connection: Keep-Alive\r\n\r\n", SIZE);
	
	/*
	 * Print the CONNECT instruction before sending to proxy
	 */
	if( args_info.verbose_flag ) {
//		message( "Connect string sent to local proxy:\n");
		message( "Communication with local proxy:\n");
		print_line_prefix(buf, "đ-> ");
	}
	
	/*
	 * Send the CONNECT instruction to the proxy
	 */
	if( stream_write( pts, buf, strlen( buf )) < 0 )
	{
		my_perror( "Socket write error" );
		exit( 1 );
	}
	/*
	 * Read the first line of the response and analyze it
	 */
//	if( args_info.verbose_flag )
//		message( "Data received from local proxy:\n");

	analyze_HTTP(pts);

	if (args_info.remproxy_given )
	{
		/*
		 * Clean buffer for next analysis
		 */
		while ( strcmp( buf, "\r\n" ) != 0 ) readline(pts);

		if( args_info.verbose_flag )
			message( "\nTunneling to %s (destination)\n", args_info.dest_arg );
		sprintf( buf, "CONNECT %s HTTP/1.0\r\n", args_info.dest_arg);

		/*
		 * Add extra header(s)
		 */
		if ( args_info.header_given )
		{
//			strzcat( buf, args_info.header_arg, "\r\n" );
			strlcat( buf, args_info.header_arg, SIZE );
			strlcat( buf, "\r\n", SIZE );
		}

		if ( args_info.user_given && args_info.pass_given )
		{
			strlcat( buf, "Proxy-authorization: Basic ", SIZE );
			strlcat( buf, basicauth, SIZE );
			strlcat( buf, "\r\n", SIZE );
		}

		strlcat( buf, "Proxy-Connection: Keep-Alive\r\n\r\n", SIZE );
		
		/*
		 * Print the CONNECT instruction before sending to proxy
		 */
		if( args_info.verbose_flag ) {
//			message( "Connect string sent to remote proxy:\n");
			message( "Communication with remote proxy:\n");
			print_line_prefix(buf, " -> ");
		}
	
		/*
		 * Send the CONNECT instruction to the proxy
		 */
		if( stream_write( pts, buf, strlen( buf )) < 0 )
		{
			my_perror( "Socket write error" );
			exit( 1 );
		}
	
		/*
		 * Read the first line of the response and analyze it
		 */
//		if( args_info.verbose_flag )
//			message( "Received from remote proxy:\n");

		analyze_HTTP(pts);
	}

	/*
	 * Then, repeat reading lines of the responses until a blank line
	 * (which signifies the end of the response) is encountered.
	 */
	if (ntlm_challenge == 1) {
		ntlm_challenge = 2;
	} else {
		do {
			readline(pts);
		} while ( strcmp( buf, "\r\n" ) != 0 );
	}
}
