/* Proxytunnel - (C) 2001 Jos Visser / Mark Janssen    */
/* Contact:             josv@osp.nl / maniac@maniac.nl */

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
#include <string.h>
#include "config.h"

#ifndef HAVE_GETOPT_LONG
	char * optarg;
#else
#include <getopt.h>
#endif

#include "cmdline.h"


void
cmdline_parser_print_version (void)
{
  printf ("%s %s\n%s\n", PACKAGE, VERSION, AUTHORS);
}

void
cmdline_parser_print_help (void)
{
  cmdline_parser_print_version ();
  printf("\n"
"Purpose:\n"
"  Build generic tunnels trough HTTPS proxy's, supports HTTP authorization\n"
"\n"
"Usage: %s [OPTIONS]...\n\
   -h         --help              Print help and exit\n\
   -V         --version           Print version and exit\n\
   -i         --inetd             Run from inetd (default=off)\n\
   -u STRING  --user=STRING       Username to send to HTTPS proxy for auth\n\
   -s STRING  --pass=STRING       Password to send to HTTPS proxy for auth\n\
   -g STRING  --proxyhost=STRING  HTTPS Proxy host to connect to\n\
   -G INT     --proxyport=INT     HTTPS Proxy portnumber to connect to\n\
   -d STRING  --desthost=STRING   Destination host to built the tunnel to\n\
   -D INT     --destport=INT      Destination portnumber to built the tunnel to\n\
   -v         --verbose           Turn on verbosity (default=off)\n\
", PACKAGE);
}


static char *
gengetopt_strdup (char * s)
{
  char * n, * pn, * ps = s;
  while (*ps) ps++;
  n = (char *) malloc (1 + ps - s);
  if (n != NULL)
    {
      for (ps=s,pn=n; *ps; ps++,pn++)
        *pn = *ps;
      *pn = 0;
    }
  return n;
}


int
cmdline_parser (int argc, char * const *argv, struct gengetopt_args_info *args_info)
{
  int c;	/* Character of the parsed option.  */
  int missing_required_options = 0;	

  args_info->help_given = 0 ;
  args_info->version_given = 0 ;
  args_info->user_given = 0 ;
  args_info->pass_given = 0 ;
  args_info->proxyhost_given = 0 ;
  args_info->proxyport_given = 0 ;
  args_info->desthost_given = 0 ;
  args_info->destport_given = 0 ;
  args_info->verbose_given = 0 ;
  args_info->inetd_given = 0;
#define clear_args() { \
  args_info->user_arg = NULL; \
  args_info->pass_arg = NULL; \
  args_info->proxyhost_arg = NULL; \
  args_info->desthost_arg = NULL; \
  args_info->verbose_flag = 0;\
  args_info->inetd_flag = 0;\
}

  clear_args();

  optarg = 0;

#ifdef HAVE_GETOPT_LONG
  optind = 1;
  opterr = 1;
  optopt = '?';
#endif

  while (1)
    {
      int option_index = 0;

#ifdef HAVE_GETOPT_LONG
      static struct option long_options[] = {
        { "help",	0, NULL, 'h' },
        { "version",	0, NULL, 'V' },
        { "user",	1, NULL, 'u' },
        { "pass",	1, NULL, 's' },
        { "proxyhost",	1, NULL, 'g' },
        { "proxyport",	1, NULL, 'G' },
        { "desthost",	1, NULL, 'd' },
        { "destport",	1, NULL, 'D' },
        { "verbose",	0, NULL, 'v' },
	{ "inetd",	0, NULL, 'i' },
        { NULL,	0, NULL, 0 }
      };

      c = getopt_long (argc, argv, "hViu:s:g:G:d:D:v", long_options, &option_index);
#else
      c = getopt( argc, argv, "hViu:s:g:G:d:D:v" );
#endif

      if (c == -1) break;	/* Exit from `while (1)' loop.  */

      switch (c)
        {
        case 'h':	/* Print help and exit.  */
          clear_args ();
          cmdline_parser_print_help ();
          exit (0);

	case 'i':	/* Run from inetd. */
	  args_info->inetd_flag = !(args_info->inetd_flag);
	  break;

        case 'V':	/* Print version and exit.  */
          clear_args ();
          cmdline_parser_print_version ();
          exit (0);

        case 'u':	/* Username to send to HTTPS proxy for authentication.  */
          if (args_info->user_given)
            {
              fprintf (stderr, "%s: `--user' (`-u') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->user_given = 1;
          args_info->user_arg = gengetopt_strdup (optarg);
          break;

        case 's':	/* Password to send to HTTPS proxy for authentication.  */
          if (args_info->pass_given)
            {
              fprintf (stderr, "%s: `--pass' (`-s') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->pass_given = 1;
          args_info->pass_arg = gengetopt_strdup (optarg);
          break;

        case 'g':	/* HTTPS Proxy host to connect to.  */
          if (args_info->proxyhost_given)
            {
              fprintf (stderr, "%s: `--proxyhost' (`-g') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->proxyhost_given = 1;
          args_info->proxyhost_arg = gengetopt_strdup (optarg);
          break;

        case 'G':	/* HTTPS Proxy host portnumber to connect to.  */
          if (args_info->proxyport_given)
            {
              fprintf (stderr, "%s: `--proxyport' (`-G') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->proxyport_given = 1;
          args_info->proxyport_arg = atoi (optarg);
          break;

        case 'd':	/* Destination host to built the tunnel to.  */
          if (args_info->desthost_given)
            {
              fprintf (stderr, "%s: `--desthost' (`-d') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->desthost_given = 1;
          args_info->desthost_arg = gengetopt_strdup (optarg);
          break;

        case 'D':	/* Destination host portnumber to built the tunnel to.  */
          if (args_info->destport_given)
            {
              fprintf (stderr, "%s: `--destport' (`-D') option given more than once\n", PACKAGE);
              clear_args ();
              exit (1);
            }
          args_info->destport_given = 1;
          args_info->destport_arg = atoi (optarg);
          break;

        case 'v':	/* Turn on verbosity.  */
          args_info->verbose_flag = !(args_info->verbose_flag);
          break;

        case 0:	/* Long option with no short option */

        case '?':	/* Invalid option.  */
          /* `getopt_long' already printed an error message.  */
          exit (1);

        default:	/* bug: option not considered.  */
          fprintf (stderr, "%s: option unknown: %c\n", PACKAGE, c);
          abort ();
        } /* switch */
    } /* while */

  if (! args_info->proxyhost_given)
    {
      fprintf (stderr, "%s: `--proxyhost' (`-g') option required!\n", PACKAGE);
      missing_required_options = 1;
    }

  if (! args_info->proxyport_given)
    {
      fprintf (stderr, "%s: `--proxyport' (`-G') option required!\n", PACKAGE);
      missing_required_options = 1;
    }

  if (! args_info->desthost_given)
    {
      fprintf (stderr, "%s: `--desthost' (`-d') option required!\n", PACKAGE);
      missing_required_options = 1;
    }

  if (! args_info->destport_given)
    {
      fprintf (stderr, "%s: `--destport' (`-D') option required!\n", PACKAGE);
      missing_required_options = 1;
    }

  if ( missing_required_options )
    exit (1);


  return 0;
}
