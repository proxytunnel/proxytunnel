/* Proxytunnel - (C) 2001-2020 Jos Visser / Mark Janssen    */
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

/* proxytunnel.h */

#include "cmdline.h"
#include "ptstream.h"

void message( char *s, ... );
void my_perror( char *msg );
void signal_handler( int signal );
int tunnel_connect();
void analyze_HTTP(PTSTREAM *pts);
void proxy_protocol(PTSTREAM *pts);
void closeall();
void do_daemon();
#ifdef SETPROCTITLE
void initsetproctitle(int argc, char *argv[]);
void setproctitle(const char *fmt, ...);
#endif

#if defined(__APPLE__) && defined(__MACH__)
/* Don't include strlcat and strlcpy since they are provided as macros on OSX */
#else
size_t strlcat(char *dst, const char *src, size_t siz);
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

size_t strzcat(char *dst, char *format, ...);
int main( int argc, char *argv[] );
char * readpassphrase(const char *, char *, size_t, int);
char * getpass_x(const char *format, ...);

/* Globals */
extern int read_fd;                    /* The file descriptor to read from */
extern int write_fd;                   /* The file descriptor to write to */
extern char *program_name;             /* Guess what? */
extern int i_am_daemon;                /* Also... */

extern PTSTREAM *stunnel;	/* stream representing the socket from us to proxy */
extern PTSTREAM *std;		/* stream representing stdin/stdout */

/*
 * All the command line options
 */
extern struct gengetopt_args_info args_info;

#define SIZE 65536
extern char buf[SIZE];         /* Data transfer buffer */

/*
 * Small MAX macro
 */

#ifndef MAX
#define MAX( x, y )     ( ( (x)>(y) ) ? (x) : (y) )
#endif

// vim:noexpandtab:ts=4
