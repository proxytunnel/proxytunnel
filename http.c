/* Proxytunnel - (C) 2001-2024 Jos Visser / Mark Janssen    */
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

/* http.c - HTTP CONNECT proxy protocol implementation, plus the top
 * level proxy_protocol() dispatcher that decides per-hop whether the
 * current hop is HTTP CONNECT or SOCKS5 (socks5/socks5h). */

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

/* ------------------------------------------------------------------ */
/*                          HTTP-only helpers                          */
/* ------------------------------------------------------------------ */

/*
 * Print each line of buf prefixed with " -> " or " <- ". Used by both
 * proxy_protocol() (outgoing) and analyze_HTTP() (incoming). Mutates a
 * private copy of buf because readline()/strtok mangle the buffer.
 */
static void print_line_prefix(char *buf, char *prefix) {
	char *dup = strdup(buf);
	char *cur = strtok(dup, "\r\n");
	while (cur != NULL) {
		message( "%s%s\n", prefix, cur );
		cur = strtok(NULL, "\r\n");
	}
	free(dup);
}

/*
 * Analyze the proxy's HTTP response. Must be a HTTP/1.? 200 OK (or
 * 407 with NTLM challenge). When NTLM is selected and the server has
 * just issued a Type-2 challenge, proxy_protocol() is recursed into to
 * send the corresponding Type-3 reply on this stream.
 */
void analyze_HTTP(PTSTREAM *pts) {
	char *p;

	/* Strip html error pages for faulty proxies (Stephane Engel <steph[at]macchiati.org>) */
	do {
		if (readline(pts) <= 0) {
			message( "analyze_HTTP: readline failed: Connection closed by remote host\n" );
			exit(2);
		}
		p = strtok( buf, " \t");
	} while (strncmp( p, "HTTP/", 5) != 0 );

	if (strcmp( p, "HTTP/1.0" ) != 0 && strcmp( p, "HTTP/1.1" ) != 0) {
		message( "Unsupported HTTP version number %s\n", p );
		exit( 1 );
	}

	p = strtok( NULL, " ");

	if( strcmp( p, "200" ) != 0 ) {
		if( ! args_info.quiet_flag )
			message( "HTTP return code: %s ", p );

		p += strlen( p ) + 1;

		if( ! args_info.quiet_flag )
			message( "%s", p );

		if (!ntlm_challenge && strcmp( p, "407") != 0) {
			do {
				readline(pts);
				if (strncmp( buf, "Proxy-Authenticate: NTLM ", 25) == 0) {
					if (parse_type2((unsigned char *)&buf[25]) < 0)
						exit(1);
				}
			} while ( strcmp( buf, "\r\n" ) != 0 );
		}

		if (ntlm_challenge == 1) {
			proxy_protocol(pts);
			return;
		}
		exit( 1 );
	}
}

/*
 * Send one HTTP CONNECT request to the proxy reachable via pts and
 * wait for analyze_HTTP() to confirm a 200 (or drive the NTLM
 * handshake). `desc_for_msg` and `tunnel_desc` are used for verbose
 * logging only.
 */
static void http_connect_hop(PTSTREAM *pts,
                             const char *target,
                             const char *user, const char *pass,
                             const char *desc_for_msg,
                             const char *tunnel_desc) {
	/* Build the CONNECT line + Host header */
	if (args_info.verbose_flag)
		message( "\nTunneling to %s (%s)\n", target, tunnel_desc);
	snprintf( buf, sizeof(buf), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target,
		 args_info.host_arg ? args_info.host_arg : target );

	/* Authorization: basic or NTLM (RFC 2617 / RFC 4559). The choice
	 * is steered by --ntlm; user/pass supplied via -P/--proxyauth or
	 * -R/--remproxyauth. For an NTLM handshake we may be called
	 * recursively as the server emits Type-1/Type-2/Type-3 messages. */
	if (user) {
		if ( pass && args_info.ntlm_flag) {
			if (ntlm_challenge == 1) {
				build_type3_response();
				ntlm_challenge = 2;
				strzcat( buf, "Proxy-Authorization: NTLM %s\r\n", ntlm_type3_buf );
			} else if (ntlm_challenge == 0) {
				strzcat( buf, "Proxy-Authorization: NTLM %s\r\n", ntlm_type1_buf );
			}
		} else {
			/* basicauth()'s signature is non-const because the HTTP
			 * variant may mutate its arguments historically; the
			 * values come from args_info so the cast is safe. */
			char *bauth = basicauth((char *)user, (char *)pass);
			if (!bauth) {
				my_perror( "No memory to encode basicauth" );
				exit( 1 );
			}
			strzcat( buf, "Proxy-Authorization: Basic %s\r\n", bauth );
			free( bauth );
		}
	}

	strzcat( buf, "Proxy-Connection: Keep-Alive\r\n");
	/* Add extra header(s); user headers are already \r\n terminated. */
	if ( args_info.header_given )
		strzcat( buf, "%s", args_info.header_arg );

	strzcat( buf, "\r\n" );

	/* Echo the request when verbose. */
	if ( args_info.verbose_flag ) {
		message( "Communication with %s:\n", desc_for_msg );
		print_line_prefix(buf, " -> ");
	}

	/* Ship it. */
	if ( stream_write( pts, buf, strlen( buf )) < 0 ) {
		my_perror( "Socket write error" );
		exit( 1 );
	}

	/* Workaround for some buggy proxies that expect CONNECT over SSL
	 * then drop SSL for the tunnel: disable SSL right before reading
	 * the response so readline() uses plain recv(). */
	if ( args_info.wa_bug_29744_flag && !args_info.encryptremproxy_flag && pts->ssl ) {
		message( "Switching to non-SSL communication (%s)\n", desc_for_msg );
		pts->ssl = 0;
	}

	analyze_HTTP(pts);
}

/*
 * Consume HTTP response headers up to and including the terminating
 * blank line. NTLM uses ntlm_challenge to remember which response
 * belongs to which CONNECT, so when we just emitted a Type-3 reply
 * and got a final 200 we must skip the reader to avoid eating the
 * next hop's traffic.
 */
static void http_consume_response(PTSTREAM *pts) {
	if (ntlm_challenge == 2) {
		ntlm_challenge = 3;
	} else {
		do {
			readline(pts);
		} while ( strcmp( buf, "\r\n" ) != 0 );
	}
}

/*
 * Convenience: does `type` describe a SOCKS5-style proxy?
 */
static inline int is_socks_type(int type) {
	return (type == PROXY_TYPE_SOCKS5 || type == PROXY_TYPE_SOCKS5H);
}

/*
 * Resolve remote hostname on the proxy (socks5h) vs locally (socks5).
 * Returns non-zero iff socks5h semantics apply.
 */
static inline int socks5_resolve_remote(int type) {
	return (type == PROXY_TYPE_SOCKS5H);
}

/* ------------------------------------------------------------------ */
/*                  Per-protocol single-hop dispatchers                */
/* ------------------------------------------------------------------ */

/*
 * Drive the first hop. When -r/--remproxy is given we connect to the
 * remote proxy via the local proxy; otherwise we go straight through
 * the local proxy to the destination.
 *
 * The auth credentials supplied apply to whichever proxy we are
 * connecting to right now, i.e. for the single-hop case they are the
 * local proxy's credentials, and for the two-hop case they also
 * belong to the local proxy.
 */
static void do_first_hop(PTSTREAM *pts) {
	int local_type = args_info.proxytype_arg;
	const char *target;
	const char *user = NULL, *pass = NULL;
	const char *desc = "local proxy";
	const char *tdesc;

	if (args_info.remproxy_given) {
		target = args_info.remproxy_arg;
		tdesc  = "remote proxy";
	} else {
		target = args_info.dest_arg;
		tdesc  = "destination";
	}

	if (args_info.user_given) user = args_info.user_arg;
	if (args_info.pass_given) pass = args_info.pass_arg;

	if (is_socks_type(local_type)) {
		socks5_protocol(pts, target, socks5_resolve_remote(local_type), user, pass);
	} else {
		http_connect_hop(pts, target, user, pass, desc, tdesc);
		/* For HTTP, eat the remainder of the response so the next
		 * hop (or cpio()) sees clean tunnel traffic. Skip when we
		 * are inside an NTLM handshake: the recursive call to
		 * proxy_protocol() will perform the consume. */
		if (ntlm_challenge == 2) {
			ntlm_challenge = 3;
		} else if (ntlm_challenge != 1) {
			http_consume_response(pts);
		}
	}
}

/*
 * Drive the second hop. Only invoked when -r/--remproxy is given. The
 * second hop happens *through* the tunnel established by do_first_hop,
 * so the same PTSTREAM is reused. If --encrypt-remproxy was specified
 * we now upgrade the inner leg to SSL.
 */
static void do_second_hop(PTSTREAM *pts) {
	int remote_type = args_info.remproxytype_arg;
	const char *user = NULL, *pass = NULL;

	/* --encrypt-remproxy: enable SSL between the local proxy and the
	 * remote proxy before issuing the second CONNECT. This is
	 * meaningful for either protocol since after the first hop the
	 * data stream is opaque bytes. */
	if (args_info.encryptremproxy_flag)
		stream_enable_ssl(stunnel, args_info.remproxy_arg);

	if (args_info.remuser_given) user = args_info.remuser_arg;
	if (args_info.rempass_given) pass = args_info.rempass_arg;

	if (is_socks_type(remote_type)) {
		socks5_protocol(pts, args_info.dest_arg,
		                socks5_resolve_remote(remote_type), user, pass);
	} else {
		http_connect_hop(pts, args_info.dest_arg, user, pass,
		                 "remote proxy", "destination");
		if (ntlm_challenge == 2) {
			ntlm_challenge = 3;
		} else if (ntlm_challenge != 1) {
			http_consume_response(pts);
		}
	}
}

/* ------------------------------------------------------------------ */
/*                        Top-level dispatcher                         */
/* ------------------------------------------------------------------ */

/*
 * Orchestrate the proxy handshake. The argument pts is the
 * already-connected (and possibly SSL-wrapped) stream to the local
 * proxy; after returning, pts is the tunnel between us and the final
 * destination, ready for cpio() to relay arbitrary bytes.
 *
 * For the simple case (no --remproxy) only the first hop runs. For
 * a two-hop chain we also run the second hop through the tunnel.
 *
 * The protocol for each hop is selected independently via
 * args_info.proxytype_arg / args_info.remproxytype_arg; mixing of
 * HTTP and SOCKS5 across the two hops is supported.
 */
void proxy_protocol(PTSTREAM *pts) {
	do_first_hop(pts);

	/* Second hop is only relevant in the chain topology and after a
	 * non-NTLM first hop. The original code used `ntlm_challenge < 3`
	 * here, which both skips the second hop when the first one is
	 * still doing NTLM *and* skips after the NTLM handshake finishes
	 * if the user did not actually request --remproxy. We preserve
	 * that exact behavior. */
	if (ntlm_challenge < 3 && args_info.remproxy_given)
		do_second_hop(pts);
}

// vim:noexpandtab:ts=4
