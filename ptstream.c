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

/* ptstream.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "proxytunnel.h"


/* Open a stream for incoming and outgoing data with the specified fds */
PTSTREAM *stream_open(int incoming_fd, int outgoing_fd) {
	PTSTREAM *pts;

	/* Initialise the structure and store the file descriptor */
	pts = malloc(sizeof(PTSTREAM));
	pts->incoming_fd = incoming_fd;
	pts->outgoing_fd = outgoing_fd;
	pts->ssl = NULL;
	pts->ctx = NULL;

	/* Return a pointer to the structure */
	return pts;
}


/* Close a stream */
int stream_close(PTSTREAM *pts) {
#ifdef USE_SSL
	/* Destroy the SSL context */
	if (pts->ssl) {
		SSL_shutdown (pts->ssl);
		SSL_free (pts->ssl);
		SSL_CTX_free (pts->ctx);
	}
#endif /* USE_SSL */

	/* Close the incoming fd */
	close(pts->incoming_fd);

	/* Close the outgoing fd */
	close(pts->outgoing_fd);

	/* Free the structure */
	free(pts);

	return 1;
}


/* Read from a stream */
int stream_read(PTSTREAM *pts, void *buf, size_t len) {
	/* Read up to the specified number of bytes into the buffer */
	int bytes_read;	

	if (!pts->ssl) {
		/* For a non-SSL stream... */
		bytes_read = read(pts->incoming_fd, buf, len);
	} else {
#ifdef USE_SSL
		/* For an SSL stream... */
		bytes_read = SSL_read(pts->ssl, buf, len);
#else
		/* No SSL support, so must use a non-SSL stream */
		bytes_read = read(pts->incoming_fd, buf, len);
#endif /* USE_SSL */
	}

	return bytes_read;
}


/* Write to a stream */
int stream_write(PTSTREAM *pts, void *buf, size_t len) {
	/* Write the specified number of bytes from the buffer */
	int bytes_written;

	if (!pts->ssl) {
		/* For a non-SSL stream... */
		bytes_written = write(pts->outgoing_fd, buf, len);
	} else {
#ifdef USE_SSL
		/* For an SSL stream... */
		bytes_written = SSL_write(pts->ssl, buf, len);
#else
		/* No SSL support, so must use a non-SSL stream */
		bytes_written = write(pts->outgoing_fd, buf, len);
#endif /* USE_SSL */
	}

	return bytes_written;
}


/*
 * Copy a block of data from one stream to another. A true
 * return code signifies EOF on the from socket descriptor.
 */
int stream_copy(PTSTREAM *pts_from, PTSTREAM *pts_to) {
	char buf[SIZE];
	int n;

	/* Read a buffer from the source socket */
	if ( ( n = stream_read( pts_from, buf, SIZE ) ) < 0 ) {
		my_perror( "Socket read error" );
		exit( 1 );
	}

	/* If we have read 0 bytes, there is an EOF on src */
	if( n==0 )
		return 1;

	/* Write the buffer to the destination socket */
	if ( stream_write( pts_to, buf, n ) != n ) {
		my_perror( "Socket write error" );
		exit( 1 );
	}

	/* We're not yet at EOF */
	return 0;
}


/* Initiate an SSL handshake on this stream and encrypt all subsequent data */
int stream_enable_ssl(PTSTREAM *pts) {
#ifdef USE_SSL
	SSL_METHOD *meth;
	SSL *ssl;
	SSL_CTX *ctx;
	
	/* Initialise the connection */
	SSLeay_add_ssl_algorithms();
	meth = SSLv3_client_method();
	SSL_load_error_strings();

	ctx = SSL_CTX_new (meth);
	ssl = SSL_new (ctx);
	SSL_set_rfd (ssl, stream_get_incoming_fd(pts));
	SSL_set_wfd (ssl, stream_get_outgoing_fd(pts));	
	SSL_connect (ssl);

	/* Store ssl and ctx parameters */
	pts->ssl = ssl;
	pts->ctx = ctx;
#else
	message("Warning: stream_open(): SSL stream requested but no SSL support available; using unencrypted connection");
#endif /* USE_SSL */

	return 1;
}


/* Return the incoming_fd for a given stream */
int stream_get_incoming_fd(PTSTREAM *pts) {

	if (!pts->ssl)
		return pts->incoming_fd;
	else
#ifdef USE_SSL
		return SSL_get_rfd(pts->ssl);
#else
		return pts->incoming_fd;
#endif /* USE_SSL */
}

/* Return the outgoing_fd for a given stream */
int stream_get_outgoing_fd(PTSTREAM *pts) {
	if (!pts->ssl)
		return pts->outgoing_fd;
	else
#ifdef USE_SSL
		return SSL_get_wfd(pts->ssl);
#else
		return pts->outgoing_fd;
#endif /* USE_SSL */
}

// vim:noexpandtab:ts=4
