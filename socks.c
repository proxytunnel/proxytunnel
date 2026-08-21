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

/* socks.c - SOCKS5 protocol implementation (RFC 1928 / RFC 1929).
 *
 * Flow driven by socks5_protocol():
 *   1. SOCKS5 greeting (VER=0x05, methods list).
 *   2. If server selects 0x02, do RFC 1929 username/password auth
 *      (VER=0x01).
 *   3. CONNECT request (VER=0x05, CMD=0x01, ATYP, DST.ADDR, DST.PORT).
 *   4. CONNECT reply (VER=0x05, REP, ATYP, BND.ADDR, BND.PORT).
 *
 * The function writes/reads through the PTSTREAM API so transparently
 * supports plain TCP and SSL-wrapped transports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "proxytunnel.h"
#include "io.h"
#include "cmdline.h"

/* SOCKS5 protocol constants (RFC 1928 / RFC 1929) */
#define SOCKS5_VERSION            0x05
#define SOCKS5_AUTH_VERSION       0x01
#define SOCKS5_CMD_CONNECT        0x01

/* Largest reply we are willing to consume. The destination bound
 * address can be up to 16 bytes for IPv6 plus a 2-byte port. */
#define SOCKS5_MAX_REPLY          64

enum socks5_auth_method {
	SOCKS5_METHOD_NONE     = 0x00,  /* No authentication */
	SOCKS5_METHOD_USERPASS = 0x02,  /* Username/password (RFC 1929) */
	SOCKS5_METHOD_NOACCEPT = 0xFF,  /* No acceptable methods */
};

enum socks5_addr_type {
	SOCKS5_ATYP_IPV4   = 0x01,
	SOCKS5_ATYP_DOMAIN = 0x03,
	SOCKS5_ATYP_IPV6   = 0x04,
};

/*
 * Internal: write exactly `len` bytes from `data` to the stream.
 * Exits the process on failure.
 */
static void socks5_send_all(PTSTREAM *pts, const unsigned char *data, size_t len) {
	int written = stream_write(pts, (void *)data, len);
	if (written < 0 || (size_t)written != len) {
		my_perror("SOCKS5: write to proxy failed");
		exit(1);
	}
}

/*
 * Internal: read exactly `len` bytes from the stream into `data`.
 * Exits the process on failure.
 */
static void socks5_recv_all(PTSTREAM *pts, unsigned char *data, size_t len) {
	size_t got = 0;
	while (got < len) {
		int n = stream_read(pts, (void *)(data + got), len - got);
		if (n <= 0) {
			my_perror("SOCKS5: read from proxy failed");
			exit(1);
		}
		got += (size_t)n;
	}
}

/*
 * Internal: translate a SOCKS5 REP byte to a human-readable string.
 */
static const char *socks5_reply_name(unsigned char rep) {
	switch (rep) {
		case 0x00: return "succeeded";
		case 0x01: return "general SOCKS server failure";
		case 0x02: return "connection not allowed by ruleset";
		case 0x03: return "Network unreachable";
		case 0x04: return "Host unreachable";
		case 0x05: return "Connection refused";
		case 0x06: return "TTL expired";
		case 0x07: return "Command not supported";
		case 0x08: return "Address type not supported";
		default:   return "unknown status";
	}
}

/*
 * Internal: parse "host:port" or "[ipv6]:port" into host/port parts.
 * `host` must be large enough to hold the hostname (including the
 * terminating nul). Returns 0 on success, -1 on parse failure.
 */
static int parse_hostport(const char *input, char *host, size_t host_size, int *port) {
	const char *colon;
	const char *host_begin;
	const char *host_end;
	size_t host_len;

	if (input == NULL || input[0] == '\0') {
		return -1;
	}

	if (input[0] == '[') {
		/* Bracketed IPv6 literal: "[addr]:port" */
		const char *rb = strchr(input, ']');
		if (rb == NULL) {
			return -1;
		}
		host_begin = input + 1;
		host_end = rb;
		colon = rb + 1;
	} else {
		/* Plain hostname or IPv4 literal. Find the LAST ':' so an
		 * unbracketed host name can legitimately contain nothing
		 * else besides the separator. */
		colon = strrchr(input, ':');
		if (colon == NULL || colon == input) {
			return -1;
		}
		host_begin = input;
		host_end = colon;
	}

	host_len = (size_t)(host_end - host_begin);
	if (host_len == 0 || host_len >= host_size) {
		return -1;
	}
	memcpy(host, host_begin, host_len);
	host[host_len] = '\0';

	if (*colon != ':' || *(colon + 1) == '\0') {
		return -1;
	}

	{
		char *endp;
		long p = strtol(colon + 1, &endp, 10);
		if (*endp != '\0' || p <= 0 || p > 65535) {
			return -1;
		}
		*port = (int)p;
	}
	return 0;
}

/*
 * Step 1+2: send the SOCKS5 greeting and, if requested by the server,
 * perform the RFC 1929 username/password handshake.
 *
 * Selection between the "no auth" and "user/pass" methods is automatic:
 * when user is non-NULL we offer both methods in the greeting (since
 * some SOCKS5 server accept 0-length pass), otherwise just the
 * "no auth" method.
 */
static void socks5_greet(PTSTREAM *pts,
                         const char *user, const char *pass) {
	unsigned char greet[4];
	unsigned char resp[2];
	size_t greet_len;

	greet[0] = SOCKS5_VERSION;
	if (user) {
		greet[1] = 2;  /* NMETHODS = 2 */
		greet[2] = SOCKS5_METHOD_NONE;
		greet[3] = SOCKS5_METHOD_USERPASS;
		greet_len = 4;
	} else {
		greet[1] = 1;  /* NMETHODS = 1 */
		greet[2] = SOCKS5_METHOD_NONE;
		greet_len = 3;
	}

	if (args_info.verbose_flag) {
		message(" -> SOCKS5 greeting: ver=0x05 nmethods=%u methods=%s\n",
			(unsigned)greet[1],
			user ? "0x00(no-auth) 0x02(user/pass)" : "0x00(no-auth)");
	}

	socks5_send_all(pts, greet, greet_len);

	/* VER + METHOD */
	socks5_recv_all(pts, resp, 2);

	if (args_info.verbose_flag) {
		message(" <- SOCKS5 greeting reply: ver=0x%02x method=0x%02x\n",
			resp[0], resp[1]);
	}

	if (resp[0] != SOCKS5_VERSION) {
		message("SOCKS5: server returned unsupported version 0x%02x in greeting reply\n",
			resp[0]);
		exit(1);
	}

	if (resp[1] == SOCKS5_METHOD_NOACCEPT) {
		message("SOCKS5: proxy reports no acceptable authentication method\n");
		exit(1);
	} else if (resp[1] == SOCKS5_METHOD_USERPASS) {
		size_t ulen, plen, total;
		unsigned char auth_buf[1 + 1 + 255 + 1 + 255];

		if (!user) {
			message("SOCKS5: proxy requested username/password but --proxyauth/-P was not supplied\n");
			exit(1);
		}

		ulen = strlen(user);
		plen = pass ? strlen(pass) : 0;
		if (ulen > 255 || plen > 255) {
			message("SOCKS5: username or password too long for RFC 1929 (max 255 bytes)\n");
			exit(1);
		}

		/* RFC 1929 request: VER (1) | ULEN (1) | UNAME | PLEN (1) | PASSWD */
		auth_buf[0] = SOCKS5_AUTH_VERSION;
		auth_buf[1] = (unsigned char)ulen;
		memcpy(&auth_buf[2], user, ulen);
		auth_buf[2 + ulen] = (unsigned char)plen;
		if (pass)
			memcpy(&auth_buf[3 + ulen], pass, plen);
		total = 3 + ulen + plen;

		if (args_info.verbose_flag) {
			message(" -> SOCKS5 user/pass auth: ver=0x01 user='%s' pass=<hidden>\n", user);
		}

		socks5_send_all(pts, auth_buf, total);

		/* VER + STATUS */
		socks5_recv_all(pts, resp, 2);
		if (args_info.verbose_flag) {
			message(" <- SOCKS5 auth reply: ver=0x%02x status=0x%02x\n",
				resp[0], resp[1]);
		}
		if (resp[0] != SOCKS5_AUTH_VERSION) {
			message("SOCKS5: invalid username/password reply version 0x%02x\n",
				resp[0]);
			exit(1);
		}
		if (resp[1] != 0x00) {
			message("SOCKS5: username/password authentication failed (status=0x%02x)\n",
				resp[1]);
			exit(1);
		}
	} else if (resp[1] != SOCKS5_METHOD_NONE) {
		message("SOCKS5: proxy selected unsupported method 0x%02x\n", resp[1]);
		exit(1);
	}
}

/*
 * Step 3: issue the SOCKS5 CONNECT request for the parsed host:port.
 *
 * - When resolve_remote is non-zero ("socks5h" mode), the hostname is
 *   sent as a domain (ATYP=0x03) so the proxy does the DNS lookup.
 * - When resolve_remote is zero ("socks5" mode), the hostname is
 *   resolved locally; if it yields multiple addresses we try the
 *   first one and rely on a fresh CONNECT retry for the others if
 *   the proxy ever reports a connection problem (this matches the
 *   behavior of most other SOCKS5 clients).
 *
 * In both cases the port is encoded in network byte order.
 */
static void socks5_connect_request(PTSTREAM *pts,
                                   const char *host, int port,
                                   int resolve_remote) {
	unsigned char req[1 + 1 + 1 + 1 + 1 + 255 + 2 /* ATYP=domain worst case */];
	size_t req_len = 0;

	req[req_len++] = SOCKS5_VERSION;        /* VER */
	req[req_len++] = SOCKS5_CMD_CONNECT;    /* CMD = CONNECT */
	req[req_len++] = 0x00;                  /* RSV */

	if (resolve_remote) {
		size_t dlen = strlen(host);
		if (dlen > 255) {
			message("SOCKS5: hostname too long for ATYP=0x03 (max 255 bytes)\n");
			exit(1);
		}
		req[req_len++] = SOCKS5_ATYP_DOMAIN;
		req[req_len++] = (unsigned char)dlen;
		memcpy(&req[req_len], host, dlen);
		req_len += dlen;
		if (args_info.verbose_flag) {
			message(" -> SOCKS5 CONNECT: ver=0x05 cmd=CONNECT atyp=DOMAIN dst=%s:%d (proxy resolves)\n",
				host, port);
		}
	} else {
		struct addrinfo hints;
		struct addrinfo *result = NULL;
		struct addrinfo *rp;
		char port_str[6];
		int rc;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;

		snprintf(port_str, sizeof(port_str), "%d", port);
		rc = getaddrinfo(host, port_str, &hints, &result);
		if (rc != 0) {
			message("SOCKS5: getaddrinfo() failed for %s: %s\n",
				host, gai_strerror(rc));
			exit(1);
		}

		{
			int written = 0;
			for (rp = result; rp != NULL; rp = rp->ai_next) {
				if (rp->ai_family == AF_INET) {
					const struct sockaddr_in *sa = (const struct sockaddr_in *)rp->ai_addr;
					req[req_len++] = SOCKS5_ATYP_IPV4;
					memcpy(&req[req_len], &sa->sin_addr, 4);
					req_len += 4;
					written = 1;
					break;
				} else if (rp->ai_family == AF_INET6) {
					const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)rp->ai_addr;
					req[req_len++] = SOCKS5_ATYP_IPV6;
					memcpy(&req[req_len], &sa->sin6_addr, 16);
					req_len += 16;
					written = 1;
					break;
				}
			}
			freeaddrinfo(result);
			if (!written) {
				message("SOCKS5: no usable IPv4/IPv6 address for %s\n", host);
				exit(1);
			}
		}

		if (args_info.verbose_flag) {
			message(" -> SOCKS5 CONNECT: ver=0x05 cmd=CONNECT dst=%s:%d (resolved locally)\n",
				host, port);
		}
	}

	/* DST.PORT (2 bytes, network byte order) */
	req[req_len++] = (unsigned char)(((unsigned int)port >> 8) & 0xff);
	req[req_len++] = (unsigned char)((unsigned int)port & 0xff);

	socks5_send_all(pts, req, req_len);
}

/*
 * Step 4: read the CONNECT reply. We parse the variable-length bound
 * address based on the ATYP field but otherwise discard it. Only the
 * REP byte matters for proxytunnel; any REP != 0x00 is a fatal error.
 */
static void socks5_read_connect_reply(PTSTREAM *pts) {
	unsigned char head[4];
	unsigned char tail[SOCKS5_MAX_REPLY];
	size_t addr_len;

	/* VER (1) + REP (1) + RSV (1) + ATYP (1) */
	socks5_recv_all(pts, head, 4);

	if (args_info.verbose_flag) {
		message(" <- SOCKS5 CONNECT reply: ver=0x%02x rep=0x%02x (%s) atyp=0x%02x\n",
			head[0], head[1], socks5_reply_name(head[1]), head[3]);
	}

	if (head[0] != SOCKS5_VERSION) {
		message("SOCKS5: invalid version 0x%02x in CONNECT reply\n", head[0]);
		exit(1);
	}
	if (head[1] != 0x00) {
		message("SOCKS5: CONNECT request rejected: %s (rep=0x%02x)\n",
			socks5_reply_name(head[1]), head[1]);
		exit(1);
	}

	/* Consume the variable-length BND.ADDR + BND.PORT. */
	switch (head[3]) {
		case SOCKS5_ATYP_IPV4:
			addr_len = 4 + 2;
			break;
		case SOCKS5_ATYP_IPV6:
			addr_len = 16 + 2;
			break;
		case SOCKS5_ATYP_DOMAIN: {
			unsigned char len_byte;
			socks5_recv_all(pts, &len_byte, 1);
			addr_len = (size_t)len_byte + 2;
			break;
		}
		default:
			message("SOCKS5: unsupported ATYP 0x%02x in CONNECT reply\n", head[3]);
			exit(1);
	}

	if (addr_len > sizeof(tail)) {
		message("SOCKS5: CONNECT reply bound address too large (%zu bytes)\n", addr_len);
		exit(1);
	}
	/* Discard the bound address; we don't need it. */
	socks5_recv_all(pts, tail, addr_len);
}

void socks5_protocol(PTSTREAM *pts,
                     const char *target,
                     int resolve_remote,
                     const char *user,
                     const char *pass) {
	char host[256];
	int port;

	if (parse_hostport(target, host, sizeof(host), &port) < 0) {
		message("SOCKS5: cannot parse target '%s' (expected host:port or [ipv6]:port)\n",
			target ? target : "(null)");
		exit(1);
	}

	if (args_info.verbose_flag) {
		message("\nSOCKS5: tunneling to %s (resolve=%s, auth=%s)\n",
			target, resolve_remote ? "proxy" : "local", user ? "yes" : "no");
	}

	socks5_greet(pts, user, pass);
	socks5_connect_request(pts, host, port, resolve_remote);
	socks5_read_connect_reply(pts);

	if (args_info.verbose_flag) {
		message("SOCKS5: tunnel established through proxy to %s:%d\n", host, port);
	}
}

// vim:noexpandtab:ts=4
