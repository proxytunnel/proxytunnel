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

/* socks.h - SOCKS5 proxy protocol (RFC 1928 / RFC 1929).
 *
 * Provides a single entry point socks5_protocol() that drives a
 * SOCKS5 CONNECT handshake through the supplied PTSTREAM (which must
 * already be TCP-connected, and optionally SSL-wrapped, to the proxy).
 */

#ifndef _socks_h
#define _socks_h

#include "ptstream.h"

/*
 * Perform a SOCKS5 CONNECT to the target through the SOCKS5 proxy
 * reachable via pts.
 *
 * Arguments:
 *   pts            Stream connected to the SOCKS5 proxy.
 *   target         Target in the form "host:port" (IPv6 literals may
 *                  be wrapped in square brackets, e.g. "[::1]:1080").
 *   resolve_remote When non-zero, the hostname is passed verbatim to
 *                  the proxy for resolution (the "socks5h" mode used by
 *                  curl). When zero, the hostname is resolved locally
 *                  and only the IP address is sent to the proxy (the
 *                  classic "socks5" mode).
 *   user           Optional SOCKS5 username (RFC 1929). May be NULL.
 *   pass           Optional SOCKS5 password (RFC 1929). May be NULL.
 *
 * Either both user and pass are NULL (no authentication) or user is
 * non-NULL (username/password authentication). The function never
 * returns on failure: it prints an error and calls exit(1).
 */
void socks5_protocol(PTSTREAM *pts,
                     const char *target,
                     int resolve_remote,
                     const char *user,
                     const char *pass);

#endif /* _socks_h */

// vim:noexpandtab:ts=4
