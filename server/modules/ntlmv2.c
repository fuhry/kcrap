#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <openssl/hmac.h>

#include <krb5.h>
#include <profile.h>

#include "../../config.h"
#include "kcrap.h"
#include "../kcrap_kdb.h"
#include "../modules.h"
#include "../util.h"

static int ntlm2_auth(krb5_context context, struct kcrap_auth_req_data *req, int *errnum, krb5_data *error_data) {
    int retval;
    int nkeys;
    struct keyblocks keyblocks[5];
    HMAC_CTX ctx;
    unsigned char *tmpbuf;
    int i, j;
    unsigned char v2hash[EVP_MAX_MD_SIZE];
    unsigned int v2hlen;
    unsigned char resp[EVP_MAX_MD_SIZE];
    unsigned int resplen;

    if (req->server_challenge.length < 1) {
	*errnum = EINVAL;
	error_data->data = strdup("Invalid server challenge length");
	error_data->length = strlen(error_data->data);
	return 0;
    }

    if (req->client_challenge.length < 1) {
	*errnum = EINVAL;
	error_data->data = strdup("Invalid client challenge length");
	error_data->length = strlen(error_data->data);
	return 0;
    }

    if (req->response.length != 16) {
	*errnum = EINVAL;
	error_data->data = strdup("Invalid response length");
	error_data->length = strlen(error_data->data);
	return 0;
    }

    nkeys = sizeof(keyblocks) / sizeof(struct keyblocks);
    if ((retval = kcrap_getkey(context, req->principal, ENCTYPE_ARCFOUR_HMAC, &nkeys, keyblocks)))
	goto fail0;

    tmpbuf = malloc((req->principal.length + req->alt_username.length)*2);
    if (tmpbuf == NULL) {
	retval = errno;
	perror("malloc");
	goto fail;
    }

    j=0;
    for(i=0; i<req->principal.length; i++) {
	tmpbuf[j++] = toupper(req->principal.data[i]);
	tmpbuf[j++] = 0;
    }
    for(i=0; i<req->alt_username.length; i++) {
	tmpbuf[j++] = req->alt_username.data[i];
	tmpbuf[j++] = 0;
    }

    
    for (i = 0; i < nkeys; i++) {
	if (keyblocks[i].key.length != 16) continue;
	
	HMAC(EVP_md5(), (unsigned char*)keyblocks[i].key.contents, 16, tmpbuf, j, v2hash, &v2hlen);
    
#ifdef DEBUG_PASSWORD
	fprintf(stderr, "principal:\n");
	dump_data(tmpbuf, j);
	fprintf(stderr, "principal hash:\n");
	dump_data(v2hash, v2hlen);
#endif

	HMAC_Init(&ctx, v2hash, v2hlen, EVP_md5());
	HMAC_Update(&ctx, (unsigned char*)req->server_challenge.data, req->server_challenge.length);
	HMAC_Update(&ctx, (unsigned char*)req->client_challenge.data, req->client_challenge.length);
	HMAC_Final(&ctx, resp, &resplen);
	HMAC_cleanup(&ctx);
    
	if (resplen != 16) {
	    if (tmpbuf) free(tmpbuf);
	    for (i = 0; i < nkeys; i++)
		krb5_free_keyblock_contents(context, &keyblocks[i].key);
	    *errnum = KRB5_CRYPTO_INTERNAL;
	    error_data->data = strdup("Server internal error: NTLMv2 resplen != 16");
	    error_data->length = strlen(error_data->data);
	    return 0;
	}
    
#ifdef DEBUG_PASSWORD
	fprintf(stderr, "server challenge:\n");
	dump_data(req->server_challenge.data, req->server_challenge.length);
	fprintf(stderr, "client challenge:\n");
	dump_data(req->client_challenge.data, req->client_challenge.length);
	fprintf(stderr, "expected response:\n");
	dump_data(resp, resplen);
	fprintf(stderr, "client response:\n");
	dump_data(req->response.data, req->response.length);
#endif

	if (memcmp(resp, req->response.data, 16) == 0) {
	    *errnum = 0;
	    goto ok;
	}
    }

    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);
    *errnum = 0;
    error_data->data = strdup("Invalid response");
    error_data->length = strlen(error_data->data);
    return 0;

    ok:
    if (tmpbuf) free(tmpbuf);
    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);
    return KCRAP_AUTH_OK;
    
    fail:
    if (tmpbuf) free(tmpbuf);
    for (i = 0; i < nkeys; i++)
	krb5_free_keyblock_contents(context, &keyblocks[i].key);
    fail0:
    *errnum = retval;
    error_data->data = strdup(error_message(retval));
    error_data->length = strlen(error_data->data);
    return 0;
}

static int ntlm2_makechal(krb5_context context, struct kcrap_chal_req_data *req, krb5_data *chal, int *errnum, krb5_data *error_data) {
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


struct kcrap_module ntlmv2_module = {
    "NTLM2",
	ntlm2_auth,
	ntlm2_makechal
};
