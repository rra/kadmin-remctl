/* passwd_change.c -- Allow authorized users to change passwords.
   $Id: passwd_change.c,v 0.7 1998/01/14 02:54:16 eagle Exp $

   Written by Russ Allbery <rra@stanford.edu>
   Copyright 1997 by the Board of Trustees, Leland Stanford Jr. University

   This program allows authorized users to change the passwords of other
   users.  It talks to kadmind on the Kerberos auth servers via the
   sunetkadm library and implements a subset of the standard kadmin
   functionality (with more verbose prompting and the ability to read the
   username of the principal whose password should be changed from the
   command line). */

/***************************************************************************
* Includes, defines, prototypes, and global variables
***************************************************************************/

#include <signal.h>             /* signal(), SIGINT, SIGTERM, etc. */
#include <stdio.h>              /* fprintf(), sprintf(), printf(), etc. */
#include <stdlib.h>             /* exit(), malloc(), free() */
#include <string.h>             /* strncpy(), memset() */

#include <com_err.h>            /* Common error handling interface */
#include <kadm_err.h>           /* Interface to kadmin errors */
#include <krb.h>                /* General Kerberos interface */
#include <krb_err.h>            /* Interface to Kerberos errors */
#include <sunet_kadm.h>         /* SUNetID kadmin interface library */

/* The full path to the site-wide password file, for real name mapping. */
#define PASSWD_FILE "/afs/ir/service/etc/passwd.all"

/* Kerberos functions without prototypes. */
int des_read_pw_string ();
int tf_init ();
int tf_get_pname ();
int tf_close ();

/* Local functions. */
static void cleanup (int signal);
static char *find_name (char *username);
static int login ();
static void logout ();
static int reset_passwd (char *principal);

/* Whether we need to log out from the authentication server. */
static int do_fini = 0;

/* The name of this program (will be taken from argv[0]). */
static char *program;


/***************************************************************************
* Signal handling
***************************************************************************/

/* If we need to log out, do so, and then exit.  This is the signal handler
   for the standard fatal signals. */

static void
cleanup (int signal)
{
  if (do_fini) sunetid_kadm_fini ();
  exit (1);
}


/***************************************************************************
* Kerberos authentication
***************************************************************************/

/* Open a connection to kadmind and authenticate to the server.  This
   creates a new ticket file and obtains the changepw.kerberos ticket which
   will then be used to change the user's password. */

static int
login ()
{
  char pass[128];
  char principal[ANAME_SZ];
  char *file, *prompt;
  int status;

  /* First of all, we have to figure out what the admin principal is.  We do
     that by parsing the user's credential cache. */
  file = getenv ("KRBTKFILE");
  if (file == NULL) file = TKT_FILE;
  status = tf_init (file, R_TKT_FIL);
  if (!status) status = tf_get_pname (principal);
  tf_close ();
  if (status)
    {
      com_err (program, status, "while attempting to read ticket file");
      return -1;
    }

  /* Now, we have the user's principal in principal.  Prompt for the user's
     password. */
  prompt = (char *) malloc (22 + strlen (principal));
  if (prompt == NULL)
    {
      fprintf (stderr, "Out of memory\n");
      return -1;
    }
  sprintf (prompt, "Enter password for %s: ", principal);
  status = des_read_pw_string (pass, sizeof (pass), prompt, 0);
  free (prompt);
  if (status)
    {
      fprintf (stderr, "Error reading password.\n");
      return -1;
    }

  /* Now that we have the username and password, grab our special ticket. */
  do_fini = 1;
  status = sunetid_kadm_init (principal, pass, 12, 0);
  memset (pass, '\0', sizeof (pass));

  /* Make sure we succeeded. */
  if (status == INTK_BADPW)
    {
      fprintf (stderr, "Incorrect password.\n");
      return -1;
    }
  else if (status != KSUCCESS)
    {
      fprintf (stderr, "Kerberos error: %s\n", error_message (status));
      return -1;
    }

  /* Success. */
  return 0;
}


/* Log out and close our connection. */
static void
logout ()
{
  if (do_fini)
    {
      sunetid_kadm_fini ();
      do_fini = 0;
    }
}


/***************************************************************************
* Password changing
***************************************************************************/

/* Actually change the password of a user.  We prompt for the new password
   and then call sunetid_kadm_reset_passwd() to do the real work. */

static int
reset_passwd (char *principal)
{
  char pass[128];
  int status;
  char *return_status, *prompt;

  /* Get the new password. */
  prompt = (char *) malloc (20 + strlen (principal));
  if (prompt == NULL)
    {
      fprintf (stderr, "Out of memory\n");
      return -1;
    }
  sprintf (prompt, "New password for %s: ", principal);
  status = des_read_pw_string (pass, sizeof (pass), prompt, 1);
  free (prompt);
  if (status)
    {
      fprintf (stderr, "Error reading password.\n");
      return -2;
    }

  /* Reset the password and log out. */
  printf ("\n");
  status = sunetid_kadm_reset_passwd (principal, pass, &return_status);
  memset (pass, '\0', sizeof (pass));

  /* Make sure we succeeded. */
  if (status)
    {
      if (return_status)
        {
          fprintf (stderr, "%s error: %s\n", program, return_status);
          free (return_status);
        }
      else
        {
          com_err (program, status, "");
          if (status == KADM_UNAUTH || status == KADM_NOENTRY) return -2;
        }
      return -1;
    }
  else
    {
      printf ("Password for %s successfully changed.\n", principal);
      return 0;
    }
}


/***************************************************************************
* Password file scanning
***************************************************************************/

/* Given a username, find their entry in the site password file and read off
   their real name.  This is for a double-check verification that one has
   typed the right account name.  Returns a malloc()d string that the caller
   is responsible for freeing.  Returns NULL on error or if the username
   can't be found. */
static char *
find_name (char *username)
{
  FILE *passwd;
  char buffer[1024];
  char *name, *search, *start, *end;
  int count;

  /* Build our search string, which is the username followed by a :. */
  search = (char *) malloc (strlen (username) + 2);
  if (search == NULL)
    {
      fprintf (stderr, "Out of memory\n");
      return NULL;
    }
  strcpy (search, username);
  strcat (search, ":");

  /* Open the password file. */
  passwd = fopen (PASSWD_FILE, "r");
  if (passwd == NULL)
    {
      fprintf (stderr, "Unable to open site password file.\n");
      free (search);
      return NULL;
    }

  /* Scan through the password file looking for our search string.  If we
     find it, grab the fourth field of the password entry, copy it into
     name, and return it.  Otherwise, return NULL. */
  name = NULL;
  do
    {
      if (!fgets (buffer, sizeof (buffer), passwd)) break;
      if (!strncmp (buffer, search, strlen (search)))
        {
          for (start = buffer, count = 0; *start && count < 4; start++)
            if (*start == ':') count++;
          for (end = start + 1; *end && *end != ':'; end++)
            ;
          *end = '\0';
          name = (char *) malloc (strlen (start) + 1);
          if (name == NULL)
            {
              fprintf (stderr, "Out of memory\n");
              free (search);
              return NULL;
            }
          strcpy (name, start);
        }
    }
  while (name == NULL);
  free (search);
  return name;
}
  

/***************************************************************************
* Main routine
***************************************************************************/

int
main (int argc, char **argv)
{
  char principal[ANAME_SZ], answer[64];
  int status, tries;
  char *name;

  /* Set the name of the program, used by com_err(), stripping off the path
     information first. */
  program = strrchr (argv[0], '/');
  if (program != NULL)
    program++;
  else
    program = argv[0];

  /* Check for a -h or --help flag and spit out a simple usage if one is
     given, just in case someone tries that. */
  if (argc > 1 && (!strcmp (argv[1], "-h") || !strcmp (argv[1], "--help")))
    {
      printf ("Usage: %s [<username>]\n\n", program);
      printf ("Usable by authorized users only, changes the password for "
              "<username>.  The\nusername will be prompted for if not "
              "supplied on the command line.\n");
      exit (0);
    }
  
  /* Initialize the error tables. */
  initialize_krb_error_table ();
  initialize_kadm_error_table ();

  /* Set up our signal handlers for a clean exit. */
  signal (SIGINT, cleanup);
  signal (SIGTERM, cleanup);
  signal (SIGHUP, cleanup);
  signal (SIGQUIT, cleanup);

  /* Authenticate to kadmind. */
  printf ("Authenticating to Kerberos....\n");
  if (login ()) exit (1);
  printf ("\n");
  
  /* If we were given a username on the command line, use it.  Otherwise,
     prompt for a username whose password we're changing. */
  if (argc > 1)
    strncpy (principal, argv[1], sizeof (principal) - 1);
  else
    {
      printf ("Enter username whose password you wish to change: ");
      if (fgets (principal, sizeof (principal), stdin) != NULL)
        /* Kill the newline. */
        principal[strlen (principal) - 1] = '\0';
      else
        {
          fprintf (stderr, "Error reading username.\n");
          exit (1);
        }
    }

  /* Find the real name and print it out to make sure it's right. */
  name = find_name (principal);
  if (name == NULL)
    {
      printf ("That username was not found in the password file."
              "  Continue? ");
      if (!fgets (answer, sizeof (answer), stdin)
          || strncasecmp (answer, "y", 1))
        {
          printf ("Aborted\n\n");
          free (name);
          exit (1);
        }
    }
  else
    {
      printf ("%s\t%s\n\nIs this correct? ", principal, name);
      if (!fgets (answer, sizeof (answer), stdin)
          || strncasecmp (answer, "y", 1))
        {
          printf ("Aborted\n\n");
          free (name);
          exit (1);
        }
    }

  /* Change the password.  Loop up to five times in the case of an error. */
  for (tries = 0; tries < 5; tries++)
    {
      status = reset_passwd (principal);
      if (!status || status == -2 || !do_fini)
        break;
      else
        printf ("\n");
    }
  logout ();
  exit (status ? 1 : 0);
}
