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
	base64( (unsigned char *)basicauth, (unsigned char *)p, strlen( p ) );

	if( args_info.verbose_flag )
	{
		message( "Proxy basic auth is %s\n", basicauth );
	}

	free( p );
}

