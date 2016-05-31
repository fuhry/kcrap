#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <openssl/des.h>

#include <krb5.h>
#include <profile.h>

#include "../../config.h"
#include "kcrap.h"
#include "../kcrap_kdb.h"
#include "../modules.h"
#include "../util.h"

static krb5_error_code lanman_hash1(unsigned char *pw, unsigned char *chal, unsigned char *resp) {
    DES_cblock key8;
    des_key_schedule ks;

    key8[0] = pw[0] & 0xFE;
    key8[1] = ((pw[0]<<7 &0x80)|(pw[1]>>1 &0x7E));
    key8[2] = ((pw[1]<<6 &0xC0)|(pw[2]>>2 &0x3E));
    key8[3] = ((pw[2]<<5 &0xE0)|(pw[3]>>3 &0x1E));
    key8[4] = ((pw[3]<<4 &0xF0)|(pw[4]>>4 &0x0E));
    key8[5] = ((pw[4]<<3 &0xF8)|(pw[5]>>5 &0x06));
    key8[6] = ((pw[5]<<2 &0xFC)|(pw[6]>>6 &0x02));
    key8[7] = pw[6]<<1 &0xFE;

    DES_set_key_unchecked((const_DES_cblock*)key8, &ks);
    DES_ecb_encrypt((const_DES_cblock*)chal, (const_DES_cblock*)resp, &ks, 1);
    return 0;
}

static int ntlm_auth(krb5_context context, struct kcrap_auth_req_data *req, int *errnum, krb5_data *error_data) {
    int retval;
    int nkeys;
    int i;
    struct keyblocks keyblocks[5];
    unsigned char key21[21];
    unsigned char response[24];
    unsigned char *challenge;

    if (req->server_challenge.length >= 8) {
	challenge = (unsigned char*)req->server_challenge.data;
    } else if (req->client_challenge.length >= 8) {
	challenge = (unsigned char*)req->client_challenge.data;
    } else {
	*errnum = EINVAL;
	error_data->data = strdup("Invalid challenge length");
	error_data->length = strlen(error_data->data);
	return 0;
    }

    if (req->response.length != 24) {
	*errnum = EINVAL;
	error_data->data = strdup("Invalid response length");
	error_data->length = strlen(error_data->data);
	return 0;
    }

    nkeys = sizeof(keyblocks) / sizeof(struct keyblocks);
    if ((retval = kcrap_getkey(context, req->principal, ENCTYPE_ARCFOUR_HMAC, &nkeys, keyblocks)))
	goto fail0;

    for (i = 0; i < nkeys; i++) {
	if (keyblocks[i].key.length != 16) continue;
	memcpy(key21, keyblocks[i].key.contents, 16);
	memset(key21+16, 0, 5);
	krb5_free_keyblock_contents(context, &keyblocks[i].key);

	if ((retval = lanman_hash1(key21   , challenge, response)))
	    goto fail;
	if ((retval = lanman_hash1(key21+7 , challenge, response+8)))
	    goto fail;
	if ((retval = lanman_hash1(key21+14, challenge, response+16)))
	    goto fail;

#ifdef DEBUG_PASSWORD
	fprintf(stderr, "principal:\n");
	dump_data(req->principal.data, req->principal.length);
	fprintf(stderr, "challenge:\n");
	dump_data(challenge, 8);
	fprintf(stderr, "key21:\n");
	dump_data(key21, 16);
	fprintf(stderr, "response:\n");
	dump_data(response, 24);
#endif

	if (memcmp(response, req->response.data, 24) == 0)
	    goto ok;
    }
    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);

    *errnum = 0;
    error_data->data = strdup("Invalid response");
    error_data->length = strlen(error_data->data);
    return 0;
    
    ok:
    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);
    return KCRAP_AUTH_OK;;
	
    fail:
    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);
    fail0:
    *errnum = retval;
    error_data->data = strdup(error_message(retval));
    error_data->length = strlen(error_data->data);
    return 0;
}

static int ntlm_makechal(krb5_context context, struct kcrap_chal_req_data *req, krb5_data *chal, int *errnum, krb5_data *error_data) {
    int retval;

    chal->length = 8;
    chal->data = malloc(chal->length);
    if (chal->data == 0) {
	perror("malloc");
	*errnum = errno;
	error_data->data = strdup(error_message(errno));
	error_data->length = strlen(error_data->data);
	return errno;
    } else {
	if ((retval = krb5_c_random_make_octets(context, chal))) {
	    *errnum = retval;
	    error_data->data = strdup(error_message(retval));
	    error_data->length = strlen(error_data->data);
	    free(chal->data);
	    return retval;
	}
    }
    *errnum = 0;
    return 0;
}


struct kcrap_module ntlm_module = {
    "NTLM",
	ntlm_auth,
	ntlm_makechal
};
