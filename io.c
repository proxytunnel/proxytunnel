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
void readline()
{
	char	*p = buf;
	char	c = 0;
	int	i = 0;

	/*
	 * Read one character at a time into buf, until a newline is
	 * encountered.
	 */
	while ( c != 10 && i < SIZE - 1 )
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
 * Copy a block of data from one socket descriptor to another. A true
 * return code signifies EOF on the from socket descriptor.
 */
int copy(int from, int to)
{
	int n;

	/* 
	 * Read a buffer from the source socket
	 */
	if ( ( n = read( from, buf, SIZE ) ) < 0 )
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
