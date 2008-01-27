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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include "proxytunnel.h"

/*
 * Give a message to the user
 */
void message( char *s, ... ) {
	va_list ap;
	char buf[1024];

	va_start( ap, s );
	vsnprintf( (char *)buf, sizeof( buf ), s, ap );
	va_end( ap );

	if ( i_am_daemon )
		syslog( LOG_NOTICE, "%s", buf );
	else
		fputs( buf, stderr );
}

/* My own perror function (uses the internal message) */
void my_perror( char *msg ) {
	if (errno == 0) {
		message( "error: %s.\n", msg );
	} else {
		char *errstr = strerror( errno );
		message( "error: %s: [%d] %s\n", msg, errno, errstr );
	}
}

// vim:noexpandtab:ts=4
