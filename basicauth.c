/* Proxytunnel - (C) 2001-2008 Jos Visser / Mark Janssen    */
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
#include <string.h>

#include "base64.h"
#include "config.h"
#include "cmdline.h"
#include "proxytunnel.h"
#include "basicauth.h"

/*
 * Create the HTTP basic authentication cookie for use by the proxy. Result
 * is stored in basicauth.
 */
char *basicauth(char *user, char *pass) {
	char *b64str = malloc(80);

	int len = strlen( user ) + strlen( pass ) + 2;
	char *p = (char *) malloc( len );

	/* Set up the cookie in clear text */
	sprintf( p, "%s:%s", user, pass );

	/*
	 * Base64 encode the clear text cookie to create the HTTP base64
	 * authentication cookie
	 */
	base64( (unsigned char *)b64str, (unsigned char *)p, strlen(p) );

//	if( args_info.verbose_flag ) {
//		message( "Proxy basic auth of %s is %s\n", p, basicauth );
//	}

	free( p );

	return b64str;
}

// vim:noexpandtab:ts=4
