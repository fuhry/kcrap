#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <krb5.h>
#include <profile.h>
#include <com_err.h>

#include "../config.h"

#ifdef USE_KDB_H_STUB
#include "kdb-stub.h"
#else
#include <kdb.h>
#endif

#include "kcrap.h"
#include "kcrap_kdb.h"
#include "modules.h"

#define GCRSEC "kcrap_server"

#ifdef HAVE_KRB5_DB_FETCH_MKEY_KVNO
#define KVNO_ARG_OPT 0,
#else
#define KVNO_ARG_OPT
#endif

static krb5_keyblock master_keyblock;

int kcrap_open_kdb(krb5_context context, profile_t profile, char *kcrap_section, char *realm, char **db_args)
{
    krb5_error_code retval;
    int nentries;
#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    krb5_boolean more;
#endif
    KRB5_DB_ENTRY master_entry;
    krb5_principal master_princ;
    char *dbname;
    char *stash_file;

    /* realm passed in through args means it was specified on the commandline */
    if (realm == NULL)
    {
        /* attempt to fetch from the config file */
        char *temp_realm;
        retval = profile_get_string(profile, kcrap_section, "realm", NULL, NULL, &temp_realm);
        if (retval == 0 && temp_realm != NULL)
        {
            realm = temp_realm;
        }
    }
    if (realm != NULL)
    {
        /* if realm was configured, either through commandline or conf file,
           set the default realm within the krb5 library */
        if ((retval = krb5_set_default_realm(context, realm)))
        {
            com_err("kdb_open", retval, "while setting default realm to '%s'", realm);
            goto free1;
        }
    }

    /* now re-get it to ensure we know the realm name and that it's normalized */
    if ((retval = krb5_get_default_realm(context, &realm)))
    {
        com_err("kdb_open", retval,
                "while attempting to retrieve default realm");
        goto free1;
    }
#ifdef HAVE_KRB5_DB_OPEN
    /* the modern way to open kdb */
    if (db_args == NULL)
    {
        /* if no db_args were passed on the command line, try to get database_name
           from the configuration file. */
        retval = profile_get_string(profile, "realms", realm, "database_name", NULL, &dbname);

        if (retval == 0 && dbname != NULL)
        {
            /* database_name is set in the config, so build db_args with that */
            db_args = malloc(sizeof(char *) * 2);
            if (db_args == NULL)
            {
                com_err("kdb_open", errno, "while allocating memory for db_args");
                goto free1;
            }

            db_args[0] = NULL;
            db_args[1] = NULL;
            if (dbname)
            {
                db_args[0] = malloc(strlen(dbname) + 8);
                strcpy(db_args[0], "dbname=");
                strcat(db_args[0], dbname);
            }
        }
    }
    /* it's ok to fall through and pass NULL for db_args to krb5_db_open, in which
       case it will use all defaults */

    if ((retval = krb5_db_open(context, db_args,
                               KRB5_KDB_OPEN_RO | KRB5_KDB_SRV_TYPE_OTHER)))
    {
        com_err("kdb_open", retval, "while initializing database");
        goto free1;
    }
#elif defined(HAVE_KRB5_DB_SET_NAME)
    if (dbname)
    {
        if ((retval = krb5_db_set_name(context, dbname)))
        {
            com_err("open_kdb", retval, "while setting active database to '%s'", dbname);
            profile_release_string(dbname);
            goto free1;
        }
    }
    if ((retval = krb5_db_init(context)))
    {
        com_err("open_kdb", retval, "while opening kdb database");
        goto free1;
    }
#else
    error out;
#endif

    if ((retval = krb5_db_setup_mkey_name(context, KRB5_KDB_M_NAME, realm, 0, &master_princ)))
    {
        com_err("open_kdb", retval, "while setting up master key name");
        goto free1;
    }
#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    if ((retval = krb5_db_get_principal(context, master_princ, &master_entry, &nentries, &more)))
    {
#else
    if ((retval = krb5_db_get_principal(context, master_princ, 0, &master_entry)))
    {
#endif
        com_err("open_kdb", retval, "while retrieving master entry");
        goto free2;
    }
#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    else if (more)
    {
        retval = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
        com_err("open_kdb", retval, "while retrieving master entry");
        goto free3;
    }
    else if (!nentries)
    {
        retval = KRB5_KDB_NOENTRY;
        com_err("open_kdb", retval, "while retrieving master entry");
        goto free3;
    }
#endif

    if ((retval = profile_get_string(profile, "realms", realm, "key_stash_file", NULL, &stash_file)))
    {
        com_err("open_kdb", retval, "while parsing config file (stash)");
        goto free3;
    }

    bzero(&master_keyblock, sizeof(master_keyblock));
    master_keyblock.enctype = ENCTYPE_UNKNOWN;
    if ((retval = krb5_db_fetch_mkey(context, master_princ, master_keyblock.enctype, FALSE, FALSE, stash_file, KVNO_ARG_OPT 0, &master_keyblock)))
    {
        com_err("kdb_open", retval, "while verifying master key");
        krb5_free_keyblock_contents(context, &master_keyblock);
        goto free4;
    }

free4:
    profile_release_string(stash_file);
free3:
#ifdef HAVE_KRB5_DB_FREE_PRINCIPAL_NENTRIES
    krb5_db_free_principal(context, &master_entry, nentries);
#else
    krb5_db_free_principal(context, master_entry);
#endif
free2:
    krb5_free_principal(context, master_princ);
    if (retval)
        krb5_db_fini(context);
free1:
    profile_release_string(realm);
    if (db_args != NULL)
    {
        for (int i = 0; db_args[i] != NULL; i++)
        {
            free(db_args[i]);
        }

        free(db_args);
    }
    return retval;
}

int kcrap_getkey(krb5_context context, struct kcrap_data principal, krb5_enctype keytype, int *nkeyblocks, struct keyblocks *keyblocks)
{
    KRB5_DB_ENTRY dbe;
    krb5_principal princ;
    int nprincs = 1;
    int retval;
#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    krb5_boolean more;
#endif
    char *pstr;
    int i;
    int count;
    int kvno;
    krb5_timestamp nowtime;

    if (principal.length == 0)
        return EINVAL;

    pstr = malloc(principal.length + 1);
    if (pstr == NULL)
        return errno;
    memcpy(pstr, principal.data, principal.length);
    pstr[principal.length] = 0;

    if ((retval = krb5_parse_name(context, pstr, &princ)))
        goto free0;

#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    if ((retval = krb5_db_get_principal(context, princ, &dbe, &nprincs, &more)))
    {
#else
    if ((retval = krb5_db_get_principal(context, princ, 0, &dbe)))
    {
#endif
        goto free1;
    }
#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
    else if (more)
    {
        retval = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
        goto free2;
    }
    else if (!nprincs)
    {
        retval = KRB5_KDB_NOENTRY;
        goto free2;
    }
#endif

    if ((retval = krb5_timeofday(context, &nowtime)))
    {
        goto free2;
    }

    if (dbe->pw_expiration && dbe->pw_expiration < nowtime)
    {
        retval = KRB5KDC_ERR_KEY_EXP;
        goto free2;
    }
    if (dbe->expiration && dbe->expiration < nowtime)
    {
        retval = KRB5KDC_ERR_NAME_EXP;
        goto free2;
    }

    count = 0;
    kvno = 0;
    for (i = 0; i < dbe->n_key_data; i++)
    {
        if (kvno < dbe->key_data[i].key_data_kvno)
        {
            count = 0;
            kvno = dbe->key_data[i].key_data_kvno;
        }
        count++;
    }
    if (count == 0)
    {
        retval = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        goto free2;
    }

    count = 0;
    for (i = 0; i < dbe->n_key_data && count < *nkeyblocks; i++)
    {
        if (kvno == dbe->key_data[i].key_data_kvno)
        {
            /* XXX: what if we needed to specify a salt? */
            retval = krb5_dbe_decrypt_key_data(context, &master_keyblock, &dbe->key_data[i], &keyblocks[count].key, NULL);
            if (retval == 0)
                count++;
        }
    }

    if (count == 0)
    {
        retval = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
        goto free2;
    }
    else
    {
        *nkeyblocks = count;
    }

free2:
#ifdef HAVE_KRB5_DB_FREE_PRINCIPAL_NENTRIES
    krb5_db_free_principal(context, &dbe, nprincs);
#else
    krb5_db_free_principal(context, dbe);
#endif
free1:
    krb5_free_principal(context, princ);
free0:
    free(pstr);
    return retval;
}
