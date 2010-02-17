/*
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
 * Copyright 2006, 2007, 2008, 2010
 *     Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <util/messages-krb5.h>
#include <util/messages.h>

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

    message_program_name = "ksetpass";
    if (argc != 2)
        die("no principal specified");
    ret = krb5_init_context(&ctx);
    if (ret != 0)
        die_krb5(ctx, ret, "cannot initialize Kerberos");
    ret = krb5_cc_default(ctx, &ccache);
    if (ret != 0)
        die_krb5(ctx, ret, "cannot open default ticket cache");
    ret = krb5_parse_name(ctx, argv[1], &princ);
    if (ret != 0)
        die_krb5(ctx, ret, "invalid principal name %s", argv[1]);
    size = read(0, password, sizeof(password));
    if (size < 0)
        sysdie("cannot read password from standard input");
    else if (size == 0)
        die("no password given on standard input");
    if (size >= (ssize_t) sizeof(password))
        die("password too long");
    password[size] = '\0';
    ret = krb5_set_password_using_ccache(ctx, ccache, password, princ,
              &result_code, &result_code_string, &result_string);
    if (ret != 0)
        die_krb5(ctx, ret, "cannot change password for %s", argv[1]);
    if (result_code != 0)
        die("password change failed: (%d) %.*s%s%.*s", result_code,
            result_code_string.length, (char *) result_code_string.data,
            result_string.length ? ": " : "",
            result_string.length, (char *) result_string.data);
    exit(0);
}
