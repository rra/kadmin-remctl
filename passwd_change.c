/*
 * Allow authorized users to change the passwords of other users.
 *
 * This program allows authorized users to change the passwords of other
 * users.  It talks to a remctl interface via the libremctl library and only
 * implements password changing, with verbose prompting and the ability to
 * read the username of the principal whose password should be changed from
 * the command line).
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 1997, 2007, 2010, 2013, 2014
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <ctype.h>
#include <errno.h>
#include <remctl.h>
#include <signal.h>

#include <util/messages-krb5.h>
#include <util/messages.h>
#include <util/xmalloc.h>

/* The full path to the site-wide password file, for real name mapping. */
#ifndef PASSWD_FILE
# define PASSWD_FILE "/full/path/to/passwd/file"
#endif

/* The principal name used for password changing. */
#ifndef PRINCIPAL
# define PRINCIPAL "service/password-change"
#endif

/* The host and port to which the remctl connection should be made. */
#ifndef HOST
# define HOST "password-change.example.org"
#endif
#ifndef PORT
# define PORT 4443
#endif

/* The memory cache used for the password change authentication. */
#define CACHE_NAME "MEMORY:passwd_change"


/*
 * Load a string option from Kerberos appdefaults.
 */
static void
config_string(krb5_context ctx, const char *opt, const char *defval,
              char **result)
{
    krb5_appdefault_string(ctx, "passwd_change", NULL, opt, defval, result);
}


/*
 * Load a number option from Kerberos appdefaults.  The native interface
 * doesn't support numbers, so we actually read a string and then convert.
 */
static void
config_number(krb5_context ctx, const char *opt, int defval, int *result)
{
    char *tmp = NULL;

    krb5_appdefault_string(ctx, "passwd_change", NULL, opt, "", &tmp);
    if (tmp != NULL && tmp[0] != '\0')
        *result = atoi(tmp);
    else
        *result = defval;
    if (tmp != NULL)
        free(tmp);
}


/*
 * Open a connection to kadmind and authenticate to the server.  This creates
 * a new ticket file and obtains the service/password-change ticket which will
 * then be used to change the user's password.  Returns 0 on success and -1 on
 * a failure it's worth retrying.  For some failures, such as memory
 * allocation problems, just dies.
 */
static int
login(krb5_context ctx, char *service)
{
    krb5_error_code status;
    krb5_ccache ccache = NULL;
    krb5_principal princ = NULL;
    krb5_creds creds;
    krb5_get_init_creds_opt *opts;

    /*
     * First of all, we have to figure out what the admin principal is.  We do
     * that by parsing the user's credential cache.
     */
    status = krb5_cc_default(ctx, &ccache);
    if (status != 0) {
        warn_krb5(ctx, status, "cannot open default ticket cache");
        goto fail;
    }
    status = krb5_cc_get_principal(ctx, ccache, &princ);
    if (status != 0) {
        warn_krb5(ctx, status, "cannot get principal name from cache");
        goto fail;
    }
    krb5_cc_close(ctx, ccache);
    ccache = NULL;

    /* Now, we have the user's principal in principal.  Authenticate. */
    status = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (status != 0)
        die_krb5(ctx, status, "cannot allocate credential options");
    krb5_get_init_creds_opt_set_default_flags(ctx, "passwd_change",
                                              princ->realm, opts);
    memset(&creds, 0, sizeof(creds));
    status = krb5_get_init_creds_password(ctx, &creds, princ, NULL,
                 krb5_prompter_posix, NULL, 0, service, opts);
    if (status != 0) {
        warn_krb5(ctx, status, "authentication failed");
        goto fail;
    }

    /* Put the new credentials into a memory cache. */
    status = krb5_cc_resolve(ctx, CACHE_NAME, &ccache);
    if (status != 0)
        die_krb5(ctx, status, "cannot create memory cache");
    status = krb5_cc_initialize(ctx, ccache, princ);
    if (status != 0)
        die_krb5(ctx, status, "cannot initialize memory cache");
    krb5_free_principal(ctx, princ);
    status = krb5_cc_store_cred(ctx, ccache, &creds);
    if (status != 0)
        die_krb5(ctx, status, "cannot store credentials");
    krb5_cc_close(ctx, ccache);
    krb5_free_cred_contents(ctx, &creds);
    if (putenv((char *) "KRB5CCNAME=" CACHE_NAME) != 0)
        sysdie("putenv of KRB5CCNAME failed");
    return 0;

fail:
    if (ccache != NULL)
        krb5_cc_close(ctx, ccache);
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    return -1;
}


/*
 * Prompt for a new password and write it into the given pointer.  Returns 0
 * on success, -1 on a retriable failure, and -2 on a permanent failure.
 */
static int
get_password(krb5_context ctx, char **password)
{
    krb5_prompt prompts[2];
    krb5_error_code status;
    int ret = -2;

    /* Set up the prompt structure. */
    prompts[0].prompt = (char *) "New password";
    prompts[0].hidden = 1;
    prompts[0].reply = xcalloc(1, sizeof(*prompts[0].reply));
    prompts[0].reply->data = xmalloc(BUFSIZ);
    prompts[0].reply->length = BUFSIZ;
    prompts[1].prompt = (char *) "Re-enter new password";
    prompts[1].hidden = 1;
    prompts[1].reply = xcalloc(1, sizeof(*prompts[0].reply));
    prompts[1].reply->data = xmalloc(BUFSIZ);
    prompts[1].reply->length = BUFSIZ;

    /* Finally, we can do the actual prompt. */
    status = krb5_prompter_posix(ctx, NULL, NULL, NULL, 2, prompts);
    if (status != 0) {
        warn_krb5(ctx, status, "cannot prompt for a password");
        goto fail;
    }
    if (strcmp(prompts[0].reply->data, prompts[1].reply->data) != 0) {
        warn("passwords don't match");
        ret = -1;
        goto fail;
    }
    *password = prompts[0].reply->data;
    free(prompts[0].reply);
    free(prompts[1].reply->data);
    free(prompts[1].reply);
    return 0;

fail:
    free(prompts[0].reply->data);
    free(prompts[0].reply);
    free(prompts[1].reply->data);
    free(prompts[1].reply);
    return ret;
}


/*
 * Actually change the password of a user.  We prompt for the new password and
 * then call remctl to do the real work.
 */
static int
reset_password(krb5_context ctx, char *principal, const char *service,
               const char *host, unsigned short port)
{
    int status;
    char *password;
    struct remctl_result *result;
    const char *command[5];

    /* Get the new password. */
    do {
        status = get_password(ctx, &password);
        printf("\n");
    } while (status == -1);
    if (status == -2)
        return -1;

    /* Reset the password. */
    command[0] = "password";
    command[1] = "reset";
    command[2] = principal;
    command[3] = password;
    command[4] = NULL;
    result = remctl(host, port, service, command);
    if (result->error != NULL) {
        warn("%s", result->error);
        remctl_result_free(result);
        return -2;
    } else {
        if (result->stderr_len > 0)
            fwrite(result->stderr_buf, result->stderr_len, 1, stderr);
        if (result->stdout_len > 0)
            fwrite(result->stdout_buf, result->stdout_len, 1, stdout);
        if (result->status == 0 && result->stdout_len == 0) {
            printf("Password for %s successfully changed\n", principal);
            return 0;
        } else if (result->status == 2)
            return -2;
        else
            return -1;
    }
}


/*
 * Given a username, find their entry in the site password file and read off
 * their real name.  This is for a double-check verification that one has
 * typed the right account name.  Returns a malloc()d string that the caller
 * is responsible for freeing.  Returns NULL on error or if the username can't
 * be found.
 */
static char *
find_name(char *username, const char *passwd_file)
{
    FILE *passwd;
    char buffer[1024];
    char *name, *search, *start, *end;
    int count;

    /* Build our search string, which is the username followed by a :. */
    xasprintf(&search, "%s:", username);

    /* Open the password file. */
    passwd = fopen(passwd_file, "r");
    if (passwd == NULL) {
        syswarn("unable to open site password file");
        free(search);
        return NULL;
    }

    /*
     * Scan through the password file looking for our search string.  If we
     * find it, grab the fourth field of the password entry, copy it into
     * name, and return it.  Otherwise, return NULL.
     */
    name = NULL;
    do {
        if (!fgets(buffer, sizeof(buffer), passwd))
            break;
        if (!strncmp(buffer, search, strlen(search))) {
            for (start = buffer, count = 0; *start && count < 4; start++)
                if (*start == ':')
                    count++;
            for (end = start + 1; *end && *end != ':'; end++)
                ;
            *end = '\0';
            name = xstrdup(start);
        }
    } while (name == NULL);
    free(search);
    return name;
}


int
main(int argc, char **argv)
{
    krb5_context ctx;
    char *passwd, *service, *host, *p;
    char principal[BUFSIZ], ans[BUFSIZ];
    int port, status, tries;
    char *name;

    /*
     * Set the name of the program, used for error reporting, stripping off
     * the path information first.
     */
    message_program_name = strrchr (argv[0], '/');
    if (message_program_name != NULL)
        message_program_name++;
    else
        message_program_name = argv[0];

    /*
     * Check for a -h or --help flag and spit out a simple usage if one is
     * given, just in case someone tries that.
     */
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        printf("Usage: %s [<username>]\n\n", message_program_name);
        printf("Usable by authorized users only, changes the password for "
               "<username>.  The\nusername will be prompted for if not "
               "supplied on the command line.\n");
        exit(0);
    }

    /* Obtain a Kerberos context so that we can look up configuration. */
    status = krb5_init_context(&ctx);
    if (status != 0)
        die_krb5(ctx, status, "cannot initialize Kerberos");
    config_string(ctx, "passwd_file", PASSWD_FILE, &passwd);
    config_string(ctx, "service_principal", PRINCIPAL, &service);
    config_string(ctx, "server", HOST, &host);
    config_number(ctx, "port", PORT, &port);

    /* Authenticate to kadmind. */
    printf("Authenticating to Kerberos....\n");
    if (login(ctx, service))
        exit(1);
    printf("\n");
  
    /*
     * If we were given a username on the command line, use it.  Otherwise,
     * prompt for a username whose password we're changing.  Strip whitespace
     * from the username.
     */
    if (argc > 1)
        strncpy(principal, argv[1], sizeof(principal) - 1);
    else {
        printf("Enter username whose password you wish to change: ");
        if (fgets(principal, sizeof(principal), stdin) == NULL)
            sysdie("error reading username");
        p = principal + strlen(principal) - 1;
        while (p > principal && isspace((unsigned char) *p))
             p--;
        p[1] = '\0';
        for (p = principal; isspace((unsigned char) *p); p++)
            ;
        if (p != principal)
            memmove(principal, p, strlen(p) + 1);
    }

    /* Find the real name and print it out to make sure it's right. */
    name = find_name(principal, passwd);
    if (name == NULL) {
        printf("That username was not found in the password file."
               "  Continue? ");
        if (!fgets(ans, sizeof(ans), stdin) || strncasecmp(ans, "y", 1)) {
            printf("Aborted\n\n");
            free(name);
            exit(1);
        }
    } else {
        printf("%s\t%s\n\nIs this correct? ", principal, name);
        if (!fgets(ans, sizeof(ans), stdin) || strncasecmp(ans, "y", 1)) {
            printf("Aborted\n\n");
            free(name);
            exit(1);
        }
    }

    /* Change the password.  Loop up to five times in the case of an error. */
    for (tries = 0; tries < 5; tries++) {
        status = reset_password(ctx, principal, service, host, port);
        if (!status || status == -2)
            break;
        else
            printf("\n");
    }
    exit(status ? 1 : 0);
}
