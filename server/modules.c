#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <krb5.h>
#include <profile.h>

#include "../config.h"
#include "kcrap.h"
#include "modules.h"

#include "modules_list.h"

int do_auth(krb5_context context, struct kcrap_auth_req_data *req, int *error_num, krb5_data *error_msg) {
    int retval;
    int i;

    if (req->principal.length < 1) {
	*error_num = EINVAL;
	error_msg->data = strdup("Must specify principal");
	error_msg->length = strlen(error_msg->data);
	return 0;
    }
    
    for (i = 0; kcrap_modules[i]; i++) {
	if (req->chal_type.length == strlen(kcrap_modules[i]->type) && memcmp(req->chal_type.data, kcrap_modules[i]->type, req->chal_type.length) == 0) {
	    retval = kcrap_modules[i]->auth_func(context, req, error_num, error_msg);
	    goto done;
	}
    }
    *error_num = KRB5_PREAUTH_BAD_TYPE;
    error_msg->data = strdup("KCRAP type not found");
    error_msg->length = strlen(error_msg->data);
    return 0;
    
    done:
    /* XXX: check server challenge here */
    return retval;
}

int do_makechal(krb5_context context, struct kcrap_chal_req_data *req, krb5_data *chal, krb5_data *chalsum, int *error_num, krb5_data *error_msg) {
    int retval;
    int i;

    if (req->principal.length < 1) {
	*error_num = EINVAL;
	error_msg->data = strdup("Must specify principal");
	error_msg->length = strlen(error_msg->data);
	return 0;
    }

    for (i = 0; kcrap_modules[i]; i++) {
	if (req->chal_type.length == strlen(kcrap_modules[i]->type) && memcmp(req->chal_type.data, kcrap_modules[i]->type, req->chal_type.length) == 0) {
	    retval = kcrap_modules[i]->makechal_func(context, req, chal, error_num, error_msg);
	    goto done;
	}
    }
    *error_num = KRB5_PREAUTH_BAD_TYPE;
    error_msg->data = strdup("KCRAP type not found");
    error_msg->length = strlen(error_msg->data);
    return EINVAL;
    
    done:
    /* XXX: generate server challenge checksum here */
    return retval;
}
