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

/* io.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "proxytunnel.h"
#include "io.h"


/*
 * Read one line of data from the tunnel. Line is terminated by a
 * newline character. Result is stored in buf.
 */
int readline(PTSTREAM *pts) {
	char *p = buf;
	char c = 0;
	int i = 0;

	/* Read one character at a time into buf, until a newline is encountered. */
	while ( c != 10 && ( i < SIZE - 1 ) ) {
		if( stream_read( pts, &c ,1) < 0) {
			my_perror( "Socket read error" );
			exit( 1 );
		}

		*p = c;
		p++;
		i++;
	}

	*p = 0;

	if( args_info.verbose_flag ) {
		/* Copy line of data into dstr without trailing newline */
		char *dstr = malloc(sizeof(buf) + 1);
		strlcpy( dstr, buf, strlen(buf) - 1);
		if (strcmp(dstr, ""))
			message( " <- %s\n", dstr );
	}
	return strlen( buf );
}

/*
 * Bond stream1 and stream2 together; any data received in stream1 is relayed
 * to stream2, and vice-versa.
 */
void cpio(PTSTREAM *stream1, PTSTREAM *stream2) {
	fd_set readfds;
	fd_set writefds;
	fd_set exceptfds;
	int in_max_fd, out_max_fd, max_fd;

	/* Find the biggest file descriptor for select() */
	in_max_fd = MAX(stream_get_incoming_fd(stream1), stream_get_incoming_fd(stream2));
	out_max_fd = MAX(stream_get_outgoing_fd(stream1), stream_get_outgoing_fd(stream2));
	max_fd = MAX(in_max_fd, out_max_fd);

	/* We are never interested in sockets being available for write */
	FD_ZERO( &writefds );

	if( args_info.verbose_flag )
		message( "\nTunnel established.\n" );

	/* Only diamonds are forever :-) */
	while( 1==1 ) {
		/* Clear the interesting socket sets */
		FD_ZERO( &readfds );
		FD_ZERO( &exceptfds );

		/* We want to know whether stream1 or stream2 is ready for reading */
		FD_SET( stream_get_incoming_fd(stream1), &readfds );
		FD_SET( stream_get_incoming_fd(stream2), &readfds );

		/* And we want to know about exceptional conditions on either stream */
		FD_SET( stream_get_incoming_fd(stream1), &exceptfds );
		FD_SET( stream_get_outgoing_fd(stream1), &exceptfds );
		FD_SET( stream_get_incoming_fd(stream2), &exceptfds );
		FD_SET( stream_get_outgoing_fd(stream2), &exceptfds );

		/* Wait until something happens on the registered sockets/files */
		if ( select( max_fd + 1, &readfds, &writefds, &exceptfds, 0 ) < 0 ) {
			perror("select error");
			exit(1);
		}

		/*
		 * Is stream1 ready for read? If so, copy a block of data
		 * from stream1 to stream2. Or else if stream2
		 * is ready for read, copy a block of data from the
		 * stream2 to stream1. Otherwise an exceptional condition
		 * is flagged and the program is terminated.
		 */
		if ( FD_ISSET( stream_get_incoming_fd(stream1), &readfds ) ) {
			if ( stream_copy(stream1, stream2 ) )
				break;
		} else if( FD_ISSET( stream_get_incoming_fd(stream2), &readfds ) ) {
			if( stream_copy(stream2, stream1 ) )
				break;
		} else {
			my_perror( "Exceptional condition" );
			break;
		}
	}
	closeall();
}

// vim:noexpandtab:ts=4
