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

/* http.c */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "io.h"
#include "proxytunnel.h"
#include "basicauth.h"
#include "ntlm.h"

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

		if (!ntlm_challenge && strcmp( p, "407") != 0) {
			do {
				readline();
				if (strncmp( buf, "Proxy-Authenticate: NTLM ", 25) == 0) {
					if (parse_type2(&buf[25]) < 0)
						exit(1);
				}
			} while ( strcmp( buf, "\r\n" ) != 0 );
		}
		if (ntlm_challenge == 1) {
			return proxy_protocol();
		}
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

	sprintf( buf, "CONNECT %s:%d HTTP/1.0\r\n",
			args_info.desthost_arg, args_info.destport_arg );
	
	if ( args_info.user_given && args_info.pass_given )
	{
		/*
		 * Create connect string including the authorization part
		 */
              if (args_info.ntlm_flag) {
                      if (ntlm_challenge == 1) {
                              build_type3_response();
                              sprintf( buf, "%sProxy-Authorization: NTLM %s\r\n",
                                              buf, ntlm_type3_buf );
                      } else if (ntlm_challenge == 0){
                              sprintf( buf, "%sProxy-Authorization: NTLM %s\r\n",
                                              buf, ntlm_type1_buf );
                      }
              } else {
                      sprintf( buf, "%sProxy-authorization: Basic %s\r\n",
                                      buf, basicauth );
              }
	}
	
	if ( args_info.header_given )
	{
		/*
		 * Add extra header(s)
		 */
		sprintf( buf, "%s%s\r\n", buf, args_info.header_arg );
	}

	sprintf( buf, "%sProxy-Connection: Keep-Alive\r\n\r\n", buf );
	
	if( args_info.verbose_flag )
		message( "Connect string sent to Proxy: '%s'\n", buf);
	
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
	if (ntlm_challenge == 1) {
		ntlm_challenge = 2;
	} else {
		do {
			readline();
		} while ( strcmp( buf, "\r\n" ) != 0 );
	}
}
