struct keyblocks {
    int salttype;
    int kvno;
    krb5_keyblock key;
};

int kcrap_open_kdb(krb5_context context, profile_t profile, char* kcrap_section);
int kcrap_getkey(krb5_context context, struct kcrap_data principal, krb5_enctype keytype, int *nkeyblocks, struct keyblocks *keyblocks);

