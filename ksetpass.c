/* $Id$
 *
 * Command-line client to set a Kerberos password.
 *
 * Sets a Kerberos password via the Kerberos password change network protocol
 * using an existing Kerberos ticket.  This is very similar to kpasswd except
 * that it does not reauthenticate; instead, it uses an existing Kerberos
 * ticket cache.  This is primarily useful when pushing passwords into Active
 * Directory.
 *
 * Takes the principal for which to change passwords on the command line and
 * the new password on standard input.  The password should not have a
 * trailing newline unless that's actually part of the password.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 * Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007, 2008 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#else
# include <com_err.h>
#endif
#include <krb5.h>

int
main(int argc, char *argv[])
{
    krb5_context ctx;
    krb5_ccache ccache;
    krb5_principal princ;
    int result_code;
    char password[BUFSIZ];
    krb5_data result_code_string, result_string;
    krb5_error_code ret;
    ssize_t size;

    if (argc != 2) {
        fprintf(stderr, "no principal specified\n");
        exit(1);
    }
    ret = krb5_init_context(&ctx);
    if (ret != 0) {
        com_err("ksetpass", ret, "while initializing Kerberos");
        exit(1);
    }
    ret = krb5_cc_default(ctx, &ccache);
    if (ret != 0) {
        com_err("ksetpass", ret, "while reading ticket cache");
        exit(1);
    }
    ret = krb5_parse_name(ctx, argv[1], &princ);
    if (ret != 0) {
        com_err("ksetpass", ret, "while parsing principal");
        exit(1);
    }
    size = read(0, password, sizeof(password));
    if (size == 0) {
        fprintf(stderr, "no password given on standard input\n");
        exit(1);
    }
    if (size >= (ssize_t) sizeof(password)) {
        fprintf(stderr, "password too long\n");
        exit(1);
    }
    password[size] = '\0';
    ret = krb5_set_password_using_ccache(ctx, ccache, password, princ,
              &result_code, &result_code_string, &result_string);
    if (ret != 0) {
        com_err("ksetpass", ret, "while changing password");
        exit(1);
    }
    if (result_code != 0) {
        fprintf(stderr, "password change failed: (%d) %.*s%s%.*s\n",
                result_code, result_code_string.length,
                result_code_string.data,
                result_string.length ? ": " : "",
                result_string.length, result_string.data);
        exit(1);
    }
    exit(0);
}
