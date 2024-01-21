/* Proxytunnel - (C) 2001-2020 Jos Visser / Mark Janssen	*/
/* Contact:				  josv@osp.nl / maniac@maniac.nl */

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
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>

#include "proxytunnel.h"
#include "io.h"
#include "config.h"
#include "cmdline.h"
#include "basicauth.h"
#include "ntlm.h"

/* Define DARWIN if compiling on MacOS-X (Darwin), to work around some
 * inconsistencies. (Darwin doesn't know socklen_t) */
#ifdef DARWIN
#define socklen_t int
#endif /* DARWIN */

/* Globals */
int read_fd=0;				  /* The file descriptor to read from */
int write_fd=1;				 /* The file destriptor to write to */

/*
 * Kill the program (signal handler)
 */
void signal_handler( int signal ) {
	if( args_info.verbose_flag )
		message( "Tunnel received signal %d. Ignoring signal.\n", signal );
//	closeall();
}

/*
 * Create and connect the socket that connects to the proxy. Returns
 * the socket that is connected to the proxy
 */
int tunnel_connect() {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV,
		.ai_protocol = 0
	};
	struct addrinfo * result, * rp;
	int rc;
	char service[6];
	int sd;

	if ( args_info.enforceipv4_flag )
		hints.ai_family = AF_INET;
	else if ( args_info.enforceipv6_flag )
		hints.ai_family = AF_INET6;
	rc = snprintf( service, sizeof(service), "%d", args_info.proxyport_arg );
	if( ( rc < 0 ) || ( rc >= sizeof(service) ) ) {
		/* this should never happen */
		message( "snprintf() failed" );
		exit(1);
	}
	rc = getaddrinfo( args_info.proxyhost_arg, service, &hints, &result );
	if( rc != 0 ) {
		message( "getaddrinfo() failed to resolve local proxy: %s\n",
			gai_strerror( rc ) );
		exit(1);
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sd = socket( rp->ai_family, rp->ai_socktype, rp->ai_protocol );
		if( sd < 0 ) {
			continue;
		}
		if( connect( sd, rp->ai_addr, rp->ai_addrlen ) == 0 ) {
			break;
		}
		close(sd);
	}
	if( rp == NULL ) {
		my_perror( "failed to connect to local proxy" );
		exit(1);
	}
	freeaddrinfo(result);

	/* Increase interactivity of tunnel, patch by Ingo Molnar */
	int flag = 1;
	setsockopt( sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

	/* Make sure we get warned when someone hangs up on us */
	signal(SIGHUP,signal_handler);

	if( ! args_info.quiet_flag ) {
		if ( ! args_info.verbose_flag ) {
			if ( args_info.remproxy_given ) {
				message( "Via %s -> %s -> %s\n",
					args_info.proxy_arg,
					args_info.remproxy_arg,
					args_info.dest_arg );
			} else {
				message( "Via %s -> %s\n",
					args_info.proxy_arg,
					args_info.dest_arg );
			}
		} else {
			message( "Connected to %s (local proxy)\n", args_info.proxy_arg );
		}
	}

	/* Return the socket */
	return sd;
}


/* Leave a goodbye message */
void closeall() {
#ifndef CYGWIN
	closelog();
#endif /* CYGWIN */

	/* Close all streams */
	if (stunnel) {
		stream_close(stunnel);
		stunnel = NULL;
	}

	if (std) {
		stream_close(std);
		std = NULL;
	}
	if( args_info.verbose_flag ) {
		message( "Tunnel closed.\n" );
	}
}

/* Get the filled in sockaddr structure to the standalone daemon */
void get_sa_serv(struct sockaddr **sa_serv_pp, socklen_t *sa_serv_len_p)
{
	static union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} sa_serv;
	int set_addr_result = 1;

	memset( &sa_serv, '\0', sizeof( sa_serv ) );

    /* In case a standalone address has been specified ... */
    if ( args_info.standalone_addr_given ) {
		/* ... and it looks like a IPv6 address ... */
		if ( strchr( args_info.standalone_addr, ':' ) ){
			/* ... set IPv6 address family and port, ... */
			sa_serv.v6.sin6_family = AF_INET6;
			sa_serv.v6.sin6_port = htons( args_info.standalone_port );
			/* ... in case a standalone interface has been specified ... */
			if ( args_info.standalone_iface_given ) {
				/* ... try to get and set the interface's index */
				if ( !(sa_serv.v6.sin6_scope_id = if_nametoindex(args_info.standalone_iface)) ) {
					set_addr_result = -2;
				}
			}
			/* If no error happened regarding the interface ... */
			if ( set_addr_result != -2 ) {
				/* ... try to set the presumed IPv6 address. */
				set_addr_result =
					inet_pton(AF_INET6,
						args_info.standalone_addr,
						&sa_serv.v6.sin6_addr);
			}
		/* ... otherwise (if it does not look like a IPv6 address) ... */
		} else {
			/* ... set IPv4 address family and port, ... */
			sa_serv.v4.sin_family = AF_INET;
			sa_serv.v4.sin_port = htons( args_info.standalone_port );
			/* ... try to set the presumed IPv4 address. */
			set_addr_result =
				inet_pton(AF_INET,
					args_info.standalone_addr,
					&sa_serv.v4.sin_addr);
		}
	/* In case no standalone address has been specified ... */
	} else {
		/* ... set IPv6 family, port and any address */
		sa_serv.v6.sin6_family = AF_INET6;
		sa_serv.v6.sin6_port = htons( args_info.standalone_port );
		sa_serv.v6.sin6_addr = in6addr_any;
	}

	/* Bail out on errors */
	switch (set_addr_result) {
		case 0:
			my_perror("Setting server socket IP address failed, possibly malformed");
			exit(1);
		case -1:
			my_perror("Setting server socket address family failed.");
			exit(1);
		case -2:
			my_perror("Setting server socket interface failed, possibly mis-spelled");
			exit(1);
	}

	/* Return pointer to sockaddr struct and its size */
	*sa_serv_pp = (struct sockaddr *)&sa_serv;
	*sa_serv_len_p = sizeof( sa_serv );
	return;
}

/* Log pid and IP address of client */
void log_client(int pid, struct sockaddr_storage *ss_client_p)
{
	char buf[40];

	inet_ntop(ss_client_p->ss_family,
			ss_client_p->ss_family == AF_INET ?
				(void *)&(((struct sockaddr_in *)ss_client_p)->sin_addr) :
				(void *)&(((struct sockaddr_in6 *)ss_client_p)->sin6_addr),
			buf,
			sizeof(buf));
	message( "Started tunnel pid=%d for connection from %s", pid, buf );
	return;
}

/* Run as a standalone daemon */
void do_daemon()
{
	int listen_sd;
	int one = 1;
	struct sockaddr *sa_serv_p;
	socklen_t sa_serv_len;
	struct sockaddr_storage sa_cli;
	socklen_t client_len;
	int pid = 0;
	int sd_client;

	/* Socket descriptor */
	int sd;

	get_sa_serv(&sa_serv_p, &sa_serv_len);

	if ( ( listen_sd = socket( sa_serv_p->sa_family, SOCK_STREAM, IPPROTO_TCP ) ) < 0 ) {
		my_perror( "Server socket creation failed" );
		exit(1);
	}

#ifdef SO_REUSEPORT	 /* doesnt exist everywhere... */
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif /* SO_REUSEPORT */
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if ( bind( listen_sd, sa_serv_p, sa_serv_len ) < 0) {
		my_perror("Server socket bind failed");
		exit(1);
	}

	signal(SIGHUP,SIG_IGN);
	signal(SIGCHLD,SIG_IGN);

#ifdef SETPROCTITLE
	if( ! args_info.proctitle_given )
		setproctitle( "[daemon]\0" );
	else
		setproctitle( "\0" );
#else
	if( args_info.proctitle_given )
		message( "Setting process-title is not supported in this build\n");
#endif /* SETPROCTITLE */

/* For the moment, turn of forking into background on the cygwin platform
 * so users can run it in a command window and ctrl-c it to cancel.
 * Also so we can put logging there, since there's no syslog on cygwin (AFAIK)
 * 	-- Maniac
 */
#ifndef CYGWIN
/*
	if ( ( pid = fork( ) ) < 0 ) {
		my_perror( "Cannot fork into the background" );
		exit(1);
	} else if ( pid > 0 ) {
		message( "Forked into the background with pid %d\n", pid );
		exit(0);
	}
*/

	openlog( program_name, LOG_CONS|LOG_PID,LOG_DAEMON );
	i_am_daemon = 1;
#endif /* CYGWIN */

	atexit( closeall );
	listen( listen_sd, 8 );

	while (1==1) {
		/* 2002/04/21
		 *
		 * Workaround a CYGWIN bug, see:
		 * http://www.gnu.org/software/serveez/manual/BUGS
		 * for bug #B0007
		 *
		 * 2004/06/23: Apparently Solaris needs this too, so 
		 * we'll do it by default, can't hurt
		 *
		 * -- Maniac
		 *
		 * 2024/01/21: Not sure what makes up the workaround
		 *
		 * -- Sven
		 */

		client_len = sizeof( sa_cli );

		sd_client = accept( listen_sd,
			(struct sockaddr *)&sa_cli, &client_len );

		if ( sd_client < 0 ) {
			my_perror( "accept() failed. Bailing out..." );
			exit(1);
		}

		if ( ( pid = fork() ) < 0 ) {
			my_perror( "Cannot fork worker" );
		} else if ( pid == 0 ) {
			read_fd = write_fd = sd_client;

			/* Create a stdin/out stream */
			std = stream_open(read_fd, write_fd);

			/* Create a tunnel stream */
			sd = tunnel_connect();
			stunnel = stream_open(sd, sd);

#ifdef USE_SSL
			/* If --encrypt-proxy is specified, connect to the proxy using SSL */
			if ( args_info.encryptproxy_flag )
				stream_enable_ssl(stunnel, args_info.proxy_arg);
#endif /* USE_SSL */

			/* Open the tunnel */
			proxy_protocol(stunnel);

#ifdef USE_SSL
			/* If --encrypt is specified, wrap all traffic after the proxy handoff in SSL */
			if( args_info.encrypt_flag )
				stream_enable_ssl(stunnel, args_info.dest_arg);
#endif /* USE_SSL */

#ifdef SETPROCTITLE
			if( ! args_info.proctitle_given )
				setproctitle( "[cpio]\0" );
			else
				setproctitle( "\0" );
#else
			if( args_info.proctitle_given )
				message( "Setting process-title is not supported in this build\n");
#endif /* SETPROCTITLE */
	
			/* Run the tunnel - we should stay here indefinitely */
			cpio(std, stunnel);
			exit( 0 );
		}

		log_client(pid, &sa_cli);
		close( sd_client );
	}
}


/* We begin at the beginning */
int main( int argc, char *argv[] ) {
	/* Socket descriptor */
	int sd;

	/* Clear all stream variables (so we know whether we need to clear up) */
	stunnel = NULL;
	std = NULL;

	program_name = argv[0];

	cmdline_parser( argc, argv, &args_info );
#ifdef SETPROCTITLE
	initsetproctitle( argc, argv );
#endif

	/*
	 * This is what we do:
	 * - Check if we need to run as a daemon. If so, a completely
	 *   different mainline is needed...
	 * - Set a signal for the hangup (HUP) signal
	 * - Optionally create the proxy basic authentication cookie
	 * - Connect to the proxy
	 * - Execute the proxy protocol to connect it to the origin server
	 * - Enter copy in-out mode to channel data hence and forth
	 */

	signal( SIGHUP, signal_handler );

	/* If the usename is given, but password is not, prompt for it */
	if( args_info.user_given && !args_info.pass_given ) {
		char *cp;
		cp = getpass_x ("Enter local proxy password for user %s: ", args_info.user_arg);
		if (cp != NULL && strlen (cp) > 0) {
			args_info.pass_arg = strdup (cp);
			args_info.pass_given = 1;
			memset (cp, 0, strlen(cp));
		}
	}

	if( args_info.remuser_given && !args_info.rempass_given ) {
		char *cp;
		cp = getpass_x ("Enter remote proxy password for user %s: ", args_info.remuser_arg);
		if (cp != NULL && strlen (cp) > 0) {
			args_info.rempass_arg = strdup (cp);
			args_info.rempass_given = 1;
			memset (cp, 0, strlen(cp));
		}
	}

	if( args_info.user_given && args_info.pass_given ) {
		if (args_info.ntlm_flag) {
			build_type1();
			if ( args_info.verbose_flag )
				message("Build Type 1 NTLM Message : %s\n", ntlm_type1_buf);
		}
	}

	/* Only one of -E/-e/-R can be specified. */
	if ((args_info.encrypt_flag ? 1 : 0) +
		(args_info.encryptproxy_flag ? 1 : 0) +
		(args_info.encryptremproxy_flag ? 1 : 0) > 1)
	{
		message("Error: only one of --encrypt-proxy, --encrypt-remproxy and --encrypt can be specified for a tunnel\n");
		exit( 1 );
	}

	/* Do we need to run as a standalone daemon? */
	if ( args_info.standalone_arg > 0 ) {
		/* Do processing in the other mainline... */
		do_daemon();
	} else {
		/* Inetd trick */
		if( args_info.inetd_flag ) {
			write_fd=0;
		}

		/* Create a stdin/out stream */
		std = stream_open(read_fd, write_fd);

		/* Create a tunnel stream */
		sd = tunnel_connect();
		stunnel = stream_open(sd, sd);

		/* If --encrypt-proxy is specified, connect to the proxy using SSL */
#ifdef USE_SSL
		if ( args_info.encryptproxy_flag )
			stream_enable_ssl(stunnel, args_info.proxy_arg);
#endif /* USE_SSL */

		/* Open the tunnel */
		proxy_protocol(stunnel);

		/* If --encrypt is specified, wrap all traffic after the proxy handoff in SSL */
#ifdef USE_SSL
		if( args_info.encrypt_flag )
			stream_enable_ssl(stunnel, args_info.dest_arg);
#endif /* USE_SSL */

#ifdef SETPROCTITLE
		if( ! args_info.proctitle_given )
			setproctitle( "[cpio]\0" );
		else
			setproctitle( "\0" );
#else
		if( args_info.proctitle_given )
			message( "Setting process-title is not supported in this build\n");
#endif /* SETPROCTITLE */

		/* Run the tunnel - we should stay here indefinitely */
		cpio(std, stunnel);
	}

	exit( 0 );
}

// vim:noexpandtab:ts=4
