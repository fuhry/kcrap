#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

#include <krb5.h>
#include <profile.h>
#include <com_err.h>

#include "../config.h"
#include "kcrap.h"
#include "kcrap_int.h"

#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif
#ifndef MIN
# define MIN(A,B) (((A)<(B))?(A):(B))
#endif

#define ERRBUF 1024
static char _errmsg[ERRBUF];

const char* kcrap_errmsg() {
    return _errmsg;
}

struct kcrap_context* kcrap_init(char* keytab, char* service) {
    struct kcrap_context *context;
    krb5_error_code retval;
    char *names[4];

    if ((context = calloc(1, sizeof(struct kcrap_context))) == NULL) {
	strncpy(_errmsg, strerror(errno), ERRBUF);
	return NULL;
    }

    for(;;) {
	if ((retval = krb5_init_context(&context->krb5_context)))
	    break;

	if ((retval = krb5_get_profile(context->krb5_context, &context->profile)))
	    break;

	/* keytab */
	if (keytab != NULL) {
	    if ((retval = krb5_kt_resolve(context->krb5_context, keytab, &context->keytab)))
		break;
	}
    
	/* my princ */
	if (service == NULL) service = "host";
	if ((retval = krb5_sname_to_principal(context->krb5_context, NULL, service, KRB5_NT_SRV_HST, &context->sprinc)))
	    break;

	/* Get credentials for server */
	if ((retval = krb5_cc_resolve(context->krb5_context, "MEMORY:kcraplib", &context->ccache))) {
	    break;
	}

	if (krb5_princ_realm(context->krb5_context, context->sprinc)->length == 0) {
	    strncpy(_errmsg, "Invalid realm for service principal", ERRBUF);
	    kcrap_free(context);
	    return NULL;
	}

	names[0] = "realms";
	names[1] = malloc(krb5_princ_realm(context->krb5_context, context->sprinc)->length+1);
	memcpy(names[1], krb5_princ_realm(context->krb5_context, context->sprinc)->data, krb5_princ_realm(context->krb5_context, context->sprinc)->length);
	names[1][krb5_princ_realm(context->krb5_context, context->sprinc)->length] = 0;
	names[2] = "kcrap";
	names[3] = NULL;

	if ((retval = profile_get_values(context->profile, (const char * const *)names, &context->servers))) {
	    free(names[1]);
	    break;
	}
	free(names[1]);
	if (context->servers[0] == NULL) {
	    strncpy(_errmsg, "No KCRAP servers specified for realm", ERRBUF);
	    kcrap_free(context);
	    return NULL;
	}

	return context;
    }

    strncpy(_errmsg, error_message(retval), ERRBUF);
    errno = retval;
    kcrap_free(context);
    return NULL;
}

void kcrap_free(struct kcrap_context *context) {
    if (context == NULL) return;

    if (context->servers) profile_free_list(context->servers);
    if (context->ccache) krb5_cc_close(context->krb5_context, context->ccache);
    if (context->sprinc) krb5_free_principal(context->krb5_context, context->sprinc);
    if (context->keytab) krb5_kt_close(context->krb5_context, context->keytab);
    if (context->profile) profile_release(context->profile);
    if (context->krb5_context) krb5_free_context(context->krb5_context);
    free(context);
    return;
}

static int auth_rep_decode(struct kcrap_context *context, char* buf, int len, krb5_keyblock *keyblock, struct kcrap_auth_rep_data *rep) {
    char tmpbuf[65536];
    int offset = 0;
    krb5_enc_data enc_data;
    int pkt_type;
    krb5_data dec_data;
    int retval;

    GETSHORT(pkt_type, buf, len, offset);
    if (pkt_type != KCRAP_PKT_AUTH_REP) return -1;
    GETDATA(enc_data.ciphertext, buf, len, offset); 
    enc_data.enctype = keyblock->enctype;
    enc_data.kvno = 0;
    
    if (enc_data.ciphertext.length > sizeof(tmpbuf)) return ENOMEM;
    
    dec_data.data = tmpbuf;
    dec_data.length = sizeof(tmpbuf);
    if ((retval = krb5_c_decrypt(context->krb5_context, keyblock, pkt_type, NULL, &enc_data, &dec_data))) {
	return retval;
    }

    offset = 0;
    GETSHORT(rep->pkt_type, dec_data.data, dec_data.length, offset);
    if (pkt_type != rep->pkt_type) return -2;
    memcpy(buf, dec_data.data, dec_data.length);
    GETSHORT(rep->auth_reply, buf, dec_data.length, offset);
    GETDATA(rep->chal_type, buf, dec_data.length, offset);
    GETINT(rep->timestamp, buf, dec_data.length, offset);
    GETINT(rep->nounce, buf, dec_data.length, offset);
    GETDATA(rep->principal, buf, dec_data.length, offset);
    GETDATA(rep->alt_username, buf, dec_data.length, offset);
    GETDATA(rep->server_challenge, buf, dec_data.length, offset);
    GETDATA(rep->server_challenge_cookie, buf, dec_data.length, offset);
    GETDATA(rep->client_challenge, buf, dec_data.length, offset);
    GETDATA(rep->response, buf, dec_data.length, offset);
    GETINT(rep->error_num, buf, dec_data.length, offset);
    GETDATA(rep->error_msg, buf, dec_data.length, offset);
    
    return 0;
}

static int kcrap_recv_rep(struct kcrap_context *context, int sock, int wait_ms, krb5_keyblock *keyblock, struct kcrap_auth_req_data *req, int *auth_status) {
    struct pollfd pfd;
    int len;
    char pktbuf[65536];
    struct kcrap_auth_rep_data rep;
    int retval;
    int error_num = 0;

    pfd.fd = sock;
    pfd.events = pfd.revents = POLLIN;
    while (poll(&pfd, 1, wait_ms) > 0) {
	len = recv(sock, pktbuf, sizeof(pktbuf), 0);
	if (len <= 0) return len;
	if ((retval = auth_rep_decode(context, pktbuf, len, keyblock, &rep))) {
	    continue;
	}
	if (!(req->timestamp == rep.timestamp &&
	      req->nounce == rep.nounce &&
	      DATASAME(req->chal_type, rep.chal_type) &&
	      DATASAME(req->principal, rep.principal) &&
	      DATASAME(req->alt_username, rep.alt_username) &&
	      DATASAME(req->server_challenge, rep.server_challenge) &&
	      DATASAME(req->server_challenge_cookie, rep.server_challenge_cookie) &&
	      DATASAME(req->client_challenge, rep.client_challenge) &&
	      DATASAME(req->response, rep.response)))
	    continue;
	if (rep.auth_reply <= 0) {
	    error_num = rep.error_num;
	    strncpy(_errmsg, rep.error_msg.data, MIN(rep.error_msg.length,ERRBUF));
	    _errmsg[MIN(rep.error_msg.length,ERRBUF-1)] = 0;
	} else {
	    error_num = 0;
	    _errmsg[0] = 0;
	}
	*auth_status = rep.auth_reply;
	return error_num;
    }
    strcpy(_errmsg, "Timed out while receiving reply");
    return EAGAIN;
}

static int kcrap_mk_req(struct kcrap_context *context, struct sockaddr_in *to, krb5_keyblock **keyblock,
		       krb5_data *outdata) {
    int retval;
    krb5_auth_context auth_context = NULL;
    krb5_data inbuf;
    struct hostent *he;
    int again = 0;

    if ((retval = krb5_auth_con_init(context->krb5_context, &auth_context))) {
	snprintf(_errmsg, ERRBUF, "%s while initializing auth context", error_message(retval));
	goto free0;
    }

    if (*keyblock != NULL) {
	if ((retval = krb5_auth_con_setsendsubkey(context->krb5_context, auth_context, *keyblock))) {
	    snprintf(_errmsg, ERRBUF, "%s while setting subkey", error_message(retval));
	    goto free1;
	}
	if ((retval = krb5_auth_con_setrecvsubkey(context->krb5_context, auth_context, *keyblock))) {
	    snprintf(_errmsg, ERRBUF, "%s while setting subkey", error_message(retval));
	    goto free1;
	}
    }
    
    he = gethostbyaddr(&to->sin_addr, sizeof(to->sin_addr), AF_INET);
    if (he == NULL)
	inbuf.data = inet_ntoa(to->sin_addr);
    else
	inbuf.data = he->h_name;
    inbuf.length = strlen(inbuf.data);

    while ((retval = krb5_mk_req(context->krb5_context, &auth_context, AP_OPTS_USE_SUBKEY,
				 "host", inbuf.data, &inbuf, context->ccache, outdata))) {
	krb5_creds my_creds;
	krb5_principal princ;
	char hostname[NI_MAXHOST+1];
	char hname[NI_MAXHOST+6];

	if (again++) {
	    snprintf(_errmsg, ERRBUF, "%s while preparing AP_REQ", error_message(retval));
	    goto free1;
	}

	if (gethostname(hostname, sizeof(hostname)) != 0) {
	    retval = errno;
	    snprintf(_errmsg, ERRBUF, "%s while getting hostname", error_message(retval));
	    goto free1;
	}
	    
	sprintf(hname, "host/%s", hostname);
	memset(&my_creds, 0, sizeof(my_creds));
	if ((retval = krb5_parse_name(context->krb5_context, hname, &princ))) {
	    snprintf(_errmsg, ERRBUF, "%s while parsing hostname", error_message(retval));
	    goto free1;
	}

	krb5_cc_initialize(context->krb5_context, context->ccache, princ);

	if ((retval = krb5_get_init_creds_keytab(context->krb5_context, &my_creds,
						 princ, NULL, 0, NULL, NULL))) {
	    snprintf(_errmsg, ERRBUF, "%s while getting credentials", error_message(retval));
	    krb5_free_principal(context->krb5_context, princ);
	    goto free1;
	}
	
	if ((retval = krb5_cc_store_cred(context->krb5_context, context->ccache, &my_creds))) {
	    snprintf(_errmsg, ERRBUF, "%s while storing credentials", error_message(retval));
	    krb5_free_principal(context->krb5_context, princ);
	    krb5_free_cred_contents(context->krb5_context, &my_creds);
	    goto free1;
	}

	krb5_free_principal(context->krb5_context, princ);
	krb5_free_cred_contents(context->krb5_context, &my_creds);
    }

    if (*keyblock == NULL) {
	if ((retval = krb5_auth_con_getsendsubkey(context->krb5_context, auth_context, keyblock))) {
	    snprintf(_errmsg, ERRBUF, "%s while getting subkey", error_message(retval));
	    krb5_free_data_contents(context->krb5_context, outdata);
	    goto free1;
	}
    }

    free1:
    krb5_auth_con_free(context->krb5_context, auth_context);
    free0:
    return retval;
}

static int kcrap_send(struct kcrap_context *context, int sock, struct sockaddr_in *to, int pkt_type, krb5_data *data, krb5_keyblock **keyblock) {
    krb5_data packet1;
    krb5_enc_data enc_packet;
    char *rawpkt;
    int ret = -1;
    int retval;
    size_t len;
    int offset;

    if ((retval = kcrap_mk_req(context, to, keyblock, &packet1))) {
	goto free0;
    }
	
    if ((retval = krb5_c_encrypt_length(context->krb5_context, (*keyblock)->enctype, data->length, &len))) {
	snprintf(_errmsg, ERRBUF, "%s while getting enc length", error_message(retval));
	goto free3;
    }

    enc_packet.ciphertext.length = len;
    if (NULL == (enc_packet.ciphertext.data = malloc(enc_packet.ciphertext.length))) {
	snprintf(_errmsg, ERRBUF, "%s while malloc enc: %d", error_message(retval), enc_packet.ciphertext.length);
	goto free3;
    }
    enc_packet.enctype = (*keyblock)->enctype;
    enc_packet.kvno = 0;

    if ((retval = krb5_c_encrypt(context->krb5_context, *keyblock, pkt_type, NULL, data, &enc_packet))) {
	snprintf(_errmsg, ERRBUF, "krb5_c_encrypt: %s", error_message(retval));
	goto free4;
    }

    len = sizeof(short)*3 + packet1.length + enc_packet.ciphertext.length;
    if (!(rawpkt = malloc(len))) {
	snprintf(_errmsg, ERRBUF, "malloc: %s", strerror(errno));
	goto free4;
    }

    offset = 0;
    SETSHORT(pkt_type, rawpkt, len, offset);
    SETDATA(packet1, rawpkt, len, offset);
    SETDATA(enc_packet.ciphertext, rawpkt, len, offset);
    
    ret = sendto(sock, rawpkt, len, 0, (struct sockaddr*)to, sizeof(*to));
    if (ret <= 0) {
	snprintf(_errmsg, ERRBUF, "sendto: %s", strerror(errno));
    }
    
    free(rawpkt);

    free4:
    krb5_free_data_contents(context->krb5_context, &enc_packet.ciphertext);
    free3:
    krb5_free_data_contents(context->krb5_context, &packet1);
    free0:
    return ret;
}

static int kcrap_getsock() {
    int sock;
    struct sockaddr_in sa;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	snprintf(_errmsg, ERRBUF, "kcrap_getsock: socket: %s", strerror(errno));
	return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
	snprintf(_errmsg, ERRBUF, "kcrap_getsock: bind: %s", strerror(errno));
	close(sock);
	return -1;
    }
    return sock;
}

#define SETK5DATA(K5NAME, NAME)			\
    (K5NAME).length = (NAME)?strlen(NAME):0;	\
    (K5NAME).data = (NAME)

#define IS_FINAL(RV)				\
    ((RV == 0)					\
     || (RV == EINVAL)				\
     || (RV == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)	\
     || (RV == KRB5_KDB_NOENTRY)		\
     || (RV == KRB5KDC_ERR_KEY_EXP)		\
     || (RV == KRB5KDC_ERR_NAME_EXP)		\
     || (RV == KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE)\
    )

int kcrap_try(struct kcrap_context *context, struct kcrap_auth_req_data *req, int *auth_status) {
    int i;
    int sent = 0;
    int ok = -1;
    int sock;
    krb5_data data;
    char pktbuf[65536];
    int offset = 0;
    int trycount;
    krb5_keyblock *keyblock = NULL;

    *auth_status = 0;

    req->pkt_type = KCRAP_PKT_AUTH_REQ;
    if (req->timestamp == 0) {
	req->timestamp = time(NULL);
	data.data = (char*)&req->nounce;
	data.length = sizeof(req->nounce);
	krb5_c_random_make_octets(context->krb5_context, &data);
    }
    SETSHORT(req->pkt_type, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->chal_type, pktbuf, sizeof(pktbuf), offset);
    SETINT(req->timestamp, pktbuf, sizeof(pktbuf), offset);
    SETINT(req->nounce, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->principal, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->alt_username, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->server_challenge, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->server_challenge_cookie, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->client_challenge, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req->response, pktbuf, sizeof(pktbuf), offset);
    
    data.data = pktbuf;
    data.length = offset;

    if ((sock = kcrap_getsock()) < 0) {
	return errno;
    }
    for (trycount = 0; trycount < 10 && !IS_FINAL(ok);) {
	for (i = 0; context->servers[i] && !IS_FINAL(ok); i++, trycount++) {
	    char *portstr;
	    struct hostent *he;
	    struct sockaddr_in to;
	    int j;
	    char host[NI_MAXHOST+1];

	    strncpy(host, context->servers[i], NI_MAXHOST);
	    host[NI_MAXHOST] = '\0';

	    if ((portstr = strchr(host, ':')) == NULL) continue;
	    *portstr = '\0';
	    portstr++;
	    if (*portstr == '\0') continue;
	    memset(&to, 0, sizeof(to));
	    to.sin_family = AF_INET;
	    to.sin_port = htons(atoi(portstr));
	    if (to.sin_port <= 0) continue;

	    if (inet_aton(host, &to.sin_addr) == 1) {
		if (kcrap_send(context, sock, &to, KCRAP_PKT_AUTH_REQ, &data, &keyblock) <= 0) continue;
		sent++;
		ok = kcrap_recv_rep(context, sock, 200, keyblock, req, auth_status);
	    } else if ((he = gethostbyname(host))) {
		for (j = 0; he->h_addr_list[j] && !IS_FINAL(ok); j++) {
		    to.sin_addr = *(struct in_addr*)(he->h_addr_list[j]);
		    if (kcrap_send(context, sock, &to, KCRAP_PKT_AUTH_REQ, &data, &keyblock) <= 0) continue;
		    sent++;
		    ok = kcrap_recv_rep(context, sock, 200, keyblock, req, auth_status);
		}
	    }
	}
    }
    if (!sent) {
	close(sock);
	if (keyblock) krb5_free_keyblock(context->krb5_context, keyblock);
	if (_errmsg[0] == '\0')
	    strcpy(_errmsg, "No KCRAP servers defined\n");
	return KRB5_KDC_UNREACH;
    }
    if (!IS_FINAL(ok))
	ok = kcrap_recv_rep(context, sock, 5000, keyblock, req, auth_status);
    close(sock);
    if (keyblock) krb5_free_keyblock(context->krb5_context, keyblock);
    return ok;
}

