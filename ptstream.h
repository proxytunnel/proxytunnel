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

/* ptstream.h */

#ifdef USE_SSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#endif

typedef struct ptstream {
	int incoming_fd;
	int outgoing_fd;
#ifdef USE_SSL
	SSL *ssl;
	SSL_CTX *ctx;
#else
	void *ssl;
	void *ctx;
#endif
} PTSTREAM;


PTSTREAM *stream_open(int incoming_fd, int outgoing_fd);
int stream_close(PTSTREAM *pts);
int stream_read(PTSTREAM *pts, void *buf, size_t len);
int stream_write(PTSTREAM *pts, void *buf, size_t len);
int stream_copy(PTSTREAM *pts_from, PTSTREAM *pts_to);
int stream_enable_ssl(PTSTREAM *pts);
int stream_get_incoming_fd(PTSTREAM *pts);
int stream_get_outgoing_fd(PTSTREAM *pts);

// vim:noexpandtab:ts=4
