struct keyblocks
{
    int salttype;
    int kvno;
    krb5_keyblock key;
};

int kcrap_open_kdb(krb5_context context, profile_t profile, char *kcrap_section, char *realm, char **db_args);
int kcrap_getkey(krb5_context context, struct kcrap_data principal, krb5_enctype keytype, int *nkeyblocks, struct keyblocks *keyblocks);

#ifdef HAVE_KRB5_DB_GET_PRINCIPAL_MORE
#define KRB5_DB_ENTRY krb5_db_entry
#else
#define KRB5_DB_ENTRY krb5_db_entry *
#endif