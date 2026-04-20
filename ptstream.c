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

#include <arpa/inet.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

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
	int total_bytes_written = 0;

	while (total_bytes_written < len) {
		if (!pts->ssl) {
			/* For a non-SSL stream... */
			bytes_written = write(pts->outgoing_fd,
					      buf + total_bytes_written,
					      len - total_bytes_written);
		} else {
#ifdef USE_SSL
			/* For an SSL stream... */
			bytes_written = SSL_write(pts->ssl,
						  buf + total_bytes_written,
						  len - total_bytes_written);
#else
			/* No SSL support, so must use a non-SSL stream */
			bytes_written = write(pts->outgoing_fd,
					      buf + total_bytes_written,
					      len - total_bytes_written);
#endif /* USE_SSL */
		}

		if (bytes_written <= 0) {
			break;
		}
		total_bytes_written += bytes_written;
	}

	return total_bytes_written;
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


/* Check the certificate host name against the expected host name */
/* Return 1 if peer hostname is valid, any other value indicates failure */
int check_cert_valid_host(const char *cert_host, const char *peer_host) {
	if (cert_host == NULL || peer_host == NULL) {
		return 0;
	}
	if (cert_host[0] == '*') {
		if (strncmp(cert_host, "*.", 2) != 0) {
			/* Invalid wildcard hostname */
			return 0;
		}
		/* Skip "*." */
		cert_host += 2;
		/* Wildcards can only match the first subdomain component */
		while (*peer_host++ != '.' && *peer_host != '\0')
			;;
	}
	if (strlen(cert_host) == 0 || strlen(peer_host) == 0) {
		return 0;
	}
	return strcmp(cert_host, peer_host) == 0;
}


int check_cert_valid_ip6(const unsigned char *cert_ip_data, const int cert_ip_len, const struct in6_addr *addr6) {
	int i;
	for (i = 0; i < cert_ip_len; i++) {
		if (cert_ip_data[i] != addr6->s6_addr[i]) {
			return 0;
		}
	}
	return 1;
}


int check_cert_valid_ip(const unsigned char *cert_ip_data, const int cert_ip_len, const struct in_addr *addr) {
	int i;
	for (i = 0; i < cert_ip_len; i++) {
		if (cert_ip_data[i] != ((addr->s_addr >> (i * 8)) & 0xFF)) {
			return 0;
		}
	}
	return 1;
}


int check_cert_names(X509 *cert, char *peer_host) {
	char peer_cn[256];
	const GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) *gen_names;
	struct in_addr addr;
	struct in6_addr addr6;
	int peer_host_is_ipv4 = 0, peer_host_is_ipv6 = 0;
	int i, san_count;

	gen_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	san_count = sk_GENERAL_NAME_num(gen_names);
	if (san_count > 0) {
		peer_host_is_ipv4 = (inet_pton(AF_INET, peer_host, &addr) == 1);
		peer_host_is_ipv6 = (peer_host_is_ipv4 ? 0 : inet_pton(AF_INET6, peer_host, &addr6) == 1);
		for (i = 0; i < san_count; i++) {
			gn = sk_GENERAL_NAME_value(gen_names, i);
			if (gn->type == GEN_DNS && !(peer_host_is_ipv4 || peer_host_is_ipv6)) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				if (check_cert_valid_host((char*)ASN1_STRING_get0_data(gn->d.ia5), peer_host)) {
#else
				if (check_cert_valid_host((char*)ASN1_STRING_data(gn->d.ia5), peer_host)) {
#endif
					return 1;
				}
			} else if (gn->type == GEN_IPADD) {
				if (gn->d.ip->length == 4 && peer_host_is_ipv4) {
					if (check_cert_valid_ip(gn->d.ip->data, gn->d.ip->length, &addr)) {
						return 1;
					}
				} else if (gn->d.ip->length == 16 && peer_host_is_ipv6) {
					if (check_cert_valid_ip6(gn->d.ip->data, gn->d.ip->length, &addr6)) {
						return 1;
					}
				}
			}
		}
		message("Host name %s does not match certificate subject alternative names\n", peer_host);
	} else {
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, peer_cn, sizeof(peer_cn));
		message("Host name %s does not match certificate common name %s or any subject alternative names\n", peer_host, peer_cn);
		return check_cert_valid_host(peer_cn, peer_host);
	}
	return 0;
}

/* Initiate an SSL handshake on this stream and encrypt all subsequent data */
int stream_enable_ssl(PTSTREAM *pts, const char *proxy_arg) {
#ifdef USE_SSL
	const SSL_METHOD *meth;
	SSL *ssl;
	SSL_CTX *ctx;
	long res = 1;
	long ssl_options = 0;

	X509* cert = NULL;
	int status;
	struct stat st_buf;
#ifndef DEFAULT_CA_FILE
	const char *ca_file = NULL;
#else
	const char *ca_file = DEFAULT_CA_FILE; /* Default cert file from Makefile */
#endif /* !DEFAULT_CA_FILE */
#ifndef DEFAULT_CA_DIR
	const char *ca_dir = "/etc/ssl/certs/"; /* Default cert directory if none given */
#else
	const char *ca_dir = DEFAULT_CA_DIR;  /* Default cert directory from Makefile */
#endif /* !DEFAULT_CA_DIR */
	long vresult;
	const char *peer_arg = NULL;
	size_t peer_arg_len;
	char peer_arg_fmt[32];
	char *peer_host = NULL;

	/* Initialise the connection */
	SSLeay_add_ssl_algorithms();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	meth = TLS_client_method();
#else
	meth = SSLv23_client_method();
#endif
	SSL_load_error_strings();

	ctx = SSL_CTX_new (meth);
	ssl_options |= SSL_OP_NO_SSLv3;
	SSL_CTX_set_options (ctx, ssl_options);

	if ( !args_info.no_check_cert_flag ) {
		if ( args_info.cacert_given ) {
			if ((status = stat(args_info.cacert_arg, &st_buf)) != 0) {
				message("Error reading certificate path %s\n", args_info.cacert_arg);
				goto fail;
			}
			if (S_ISDIR(st_buf.st_mode)) {
				ca_dir = args_info.cacert_arg;
			} else {
				ca_dir = NULL;
				ca_file = args_info.cacert_arg;
			}
		}
		if (!SSL_CTX_load_verify_locations(ctx, ca_file, ca_dir)) {
			message("Error loading certificate(s) from %s\n", args_info.cacert_arg);
			goto fail;
		}
	}

	/* If given, load client certificate (chain) and key */
	if ( args_info.clientcert_given && args_info.clientkey_given ) {
		if ( 1 != SSL_CTX_use_certificate_chain_file(ctx, args_info.clientcert_arg) ) {
			message("Error loading client certificate (chain) from %s\n", args_info.clientcert_arg);
			goto fail;
		}
		if ( 1 != SSL_CTX_use_PrivateKey_file(ctx, args_info.clientkey_arg, SSL_FILETYPE_PEM) ) {
			message("Error loading client key from %s, or key does not match certificate\n", args_info.clientkey_arg);
			goto fail;
		}
	}

	ssl = SSL_new (ctx);
    if ( ssl == NULL ) {
        message("SSL_new failed\n");
        goto fail;
    }
	
	SSL_set_rfd (ssl, stream_get_incoming_fd(pts));
	SSL_set_wfd (ssl, stream_get_outgoing_fd(pts));	

	/* Determine the host name we are connecting to */
	peer_arg = args_info.host_given ? args_info.host_arg : proxy_arg;
	peer_arg_len = strlen(peer_arg);
	peer_host = alloca(peer_arg_len + 1);
	snprintf( peer_arg_fmt, sizeof(peer_arg_fmt), peer_arg[0] == '[' ? "[%%%zu[^]]]" : "%%%zu[^:]", peer_arg_len);
	if ( sscanf( peer_arg, peer_arg_fmt, peer_host ) != 1 ) {
		goto fail;
	}

	if(!args_info.no_sni_flag) {
		/* SNI support */
		if ( args_info.verbose_flag ) {
			message( "Set SNI hostname to %s\n", peer_host);
		}
		res = SSL_set_tlsext_host_name(ssl, peer_host);
		if ( res != 1 ) {
			message( "SSL_set_tlsext_host_name() failed for host name '%s'. "
				"TLS SNI error, giving up\n", peer_host);
			goto fail;
		}
	}

	if ( SSL_connect (ssl) <= 0) {
        message( "SSL_connect failed\n");
        goto fail;
    }

	if ( !args_info.no_check_cert_flag ) {
		/* Make sure peer presented a certificate */
		cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL) {
			message("No certificate presented\n");
			goto fail;
		}

		/* Check that the certificate is valid */
		vresult = SSL_get_verify_result(ssl);
		if (vresult != X509_V_OK) {
			message("Certificate verification failed (%s)\n",
					X509_verify_cert_error_string(vresult));
			goto fail;
		}

		/* Verify the certificate name matches the host we are connecting to */
		if (!check_cert_names(cert, peer_host)) {
			goto fail;
		}

		X509_free(cert);
	}

	/* Store ssl and ctx parameters */
	pts->ssl = ssl;
	pts->ctx = ctx;
#else
	message("Warning: stream_open(): SSL stream requested but no SSL support available; using unencrypted connection");
#endif /* USE_SSL */

	return 1;

fail:
#ifdef USE_SSL
	if (cert != NULL) {
		X509_free(cert);
	}
#endif /* USE_SSL */
	exit(1);
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
