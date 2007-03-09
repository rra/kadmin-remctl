/*  $Id: passwd_change.c,v 0.7 1998/01/14 02:54:16 eagle Exp $
**
**  This program allows authorized users to change the passwords of other
**  users.  It talks to a remctl interface via the libremctl library and only
**  implements password changing, with verbose prompting and the ability to
**  read the username of the principal whose password should be changed from
**  the command line).
**
**  Written by Russ Allbery <rra@stanford.edu>
**  Copyright 1997, 2007 Board of Trustees, Leland Stanford Jr. University
*/

/***************************************************************************
* Includes, defines, prototypes, and global variables
***************************************************************************/

#include <errno.h>              /* errno */
#include <signal.h>             /* signal(), SIGINT, SIGTERM, etc. */
#include <stdio.h>              /* fprintf(), sprintf(), printf(), etc. */
#include <stdlib.h>             /* exit(), malloc(), free() */
#include <string.h>             /* strncpy(), memset(), strerror() */

#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>           /* Kerberos error reporting */
#endif
#include <krb5.h>               /* General Kerberos interface */
#include <remctl.h>             /* remctl client library */

/* The full path to the site-wide password file, for real name mapping. */
#define PASSWD_FILE "/afs/ir/service/etc/passwd.all"

/* The principal name used for password changing. */
#define PRINCIPAL "service/password-change@stanford.edu"

/* The host and port to which the remctl connection should be made. */
#define HOST "lsdb.stanford.edu"
#define PORT 4443

/* The memory cache used for the password change authentication. */
#define CACHE_NAME "FILE:/tmp/security-hole"

/* Local functions. */
static char *find_name (char *username);
static int login (void);
static int reset_password (char *principal);

/* The name of this program (will be taken from argv[0]). */
static char *program;


/***************************************************************************
* Kerberos authentication
***************************************************************************/

/* Open a connection to kadmind and authenticate to the server.  This creates
   a new ticket file and obtains the service/password-change ticket which will
   then be used to change the user's password. */

static int
login (void)
{
  krb5_context ctx;
  krb5_error_code status;
  krb5_ccache ccache;
  krb5_principal princ;
  krb5_creds creds;
  krb5_get_init_creds_opt opts;

  /* First of all, we have to figure out what the admin principal is.  We do
     that by parsing the user's credential cache. */
  status = krb5_init_context(&ctx);
  if (status != 0)
    {
      com_err (program, status, "while initializing Kerberos");
      return -1;
    }
  status = krb5_cc_default(ctx, &ccache);
  if (status != 0)
    {
      com_err (program, status, "while reading ticket cache");
      return -1;
    }
  status = krb5_cc_get_principal (ctx, ccache, &princ);
  if (status != 0)
    {
      com_err (program, status, "while getting principal name");
      krb5_cc_close (ctx, ccache);
      return -1;
    }
  krb5_cc_close (ctx, ccache);

  /* Now, we have the user's principal in principal.  Authenticate. */
  krb5_get_init_creds_opt_init (&opts);
  memset(&creds, 0, sizeof (creds));
  status = krb5_get_init_creds_password (ctx, &creds, princ, NULL,
               krb5_prompter_posix, NULL, 0, PRINCIPAL, &opts);
  if (status != 0)
    {
      com_err (program, status, "while authenticating");
      krb5_free_principal (ctx, princ);
      return -1;
    }

  /* Put the new credentials into a memory cache. */
  status = krb5_cc_resolve (ctx, CACHE_NAME, &ccache);
  if (status != 0)
    {
      com_err (program, status, "while resolving memory cache");
      krb5_free_principal (ctx, princ);
      return -1;
    }
  status = krb5_cc_initialize (ctx, ccache, princ);
  if (status != 0)
    {
      com_err (program, status, "while initializing memory cache");
      return -1;
    }
  krb5_free_principal (ctx, princ);
  status = krb5_cc_store_cred (ctx, ccache, &creds);
  if (status != 0)
    {
      com_err (program, status, "while storing credentials");
      krb5_cc_destroy (ctx, ccache);
      return -1;
    }
  krb5_cc_close (ctx, ccache);
  if (putenv ((char *) "KRB5CCNAME=" CACHE_NAME) != 0)
    {
      fprintf (stderr, "%s: putenv of KRB5CCNAME failed: %s\n", program,
               strerror (errno));
      return -1;
    }
  return 0;
}


/***************************************************************************
* Password changing
***************************************************************************/

/* Prompt for a new password and write it into the given pointer.  Returns 0
   on success, -1 on a retriable failure, and -2 on a permanent failure. */

static int
get_password (char **password)
{
  krb5_prompt prompts[2];
  krb5_context ctx;
  krb5_error_code status;

  /* Set up the prompt structure. */
  prompts[0].prompt = (char *) "New password";
  prompts[0].hidden = 1;
  prompts[0].reply = malloc (sizeof (prompts[0].reply));
  if (prompts[0].reply == NULL)
    {
      fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
               strerror (errno));
      return -2;
    }
  prompts[0].reply->data = malloc (1024);
  if (prompts[0].reply->data == NULL)
    {
      fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
               strerror (errno));
      return -2;
    }
  prompts[0].reply->length = 1024;
  prompts[1].prompt = (char *) "Re-enter new password";
  prompts[1].hidden = 1;
  prompts[1].reply = malloc (sizeof (prompts[0].reply));
  if (prompts[1].reply == NULL)
    {
      fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
               strerror (errno));
      return -2;
    }
  prompts[1].reply->data = malloc (1024);
  if (prompts[0].reply->data == NULL)
    {
      fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
               strerror (errno));
      return -2;
    }
  prompts[1].reply->length = 1024;

  /* Finally, we can do the actual prompt. */
  status = krb5_init_context(&ctx);
  if (status != 0)
    {
      com_err (program, status, "while initializing Kerberos");
      return -2;
    }
  status = krb5_prompter_posix (ctx, NULL, NULL, NULL, 2, prompts);
  if (status != 0)
    {
      com_err (program, status, "while prompting for a password");
      return -2;
    }
  if (strcmp (prompts[0].reply->data, prompts[1].reply->data) != 0)
    {
      printf ("The passwords don't match\n");
      return -1;
    }
  *password = prompts[0].reply->data;
  free (prompts[0].reply);
  free (prompts[1].reply->data);
  free (prompts[1].reply);
  return 0;
}


/* Actually change the password of a user.  We prompt for the new password
   and then call remctl to do the real work. */

static int
reset_password (char *principal)
{
  int status;
  char *password;
  struct remctl_result *result;
  const char *command[5];

  /* Get the new password. */
  do
    {
      status = get_password (&password);
      printf ("\n");
    }
  while (status == -1);
  if (status == -2)
    return -1;

  /* Reset the password. */
  command[0] = "password";
  command[1] = "reset";
  command[2] = principal;
  command[3] = password;
  command[4] = NULL;
  result = remctl (HOST, PORT, PRINCIPAL, command);
  if (result->error != NULL)
    {
      fprintf (stderr, "%s", result->error);
      remctl_result_free (result);
      return -2;
    }
  else
    {
      if (result->stderr_len > 0)
        fwrite (result->stderr_buf, result->stderr_len, 1, stderr);
      if (result->stdout_len > 0)
        fwrite (result->stdout_buf, result->stdout_len, 1, stdout);
      if (result->status == 0 && result->stdout_len == 0)
        {
          printf ("Password for %s successfully changed\n", principal);
          return 0;
        }
      else
        return -1;
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
      fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
               strerror (errno));
      return NULL;
    }
  strcpy (search, username);
  strcat (search, ":");

  /* Open the password file. */
  passwd = fopen (PASSWD_FILE, "r");
  if (passwd == NULL)
    {
      fprintf (stderr, "%s: unable to open site password file: %s\n",
               program, strerror (errno));
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
              fprintf (stderr, "%s: cannot allocate memory: %s\n", program,
                       strerror (errno));
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
  char principal[BUFSIZ], answer[BUFSIZ];
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
          fprintf (stderr, "%s: error reading username: %s\n", program,
                   strerror (errno));
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
      status = reset_password (principal);
      if (!status || status == -2)
        break;
      else
        printf ("\n");
    }
  exit (status ? 1 : 0);
}
