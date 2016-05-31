/*
 * Test KCRAP server with known challange/response pairs
 * from http://davenport.sourceforge.net/ntlm.html
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

#include "../config.h"
#include "kcrap.h"

#define SDATA(VAR,VAL) (VAR).data = (VAL), (VAR).length = strlen((VAR).data)

#define FILL(DST,SRC) do {			\
    int i = 0;					\
    char tb[3];					\
    tb[2] = 0;					\
    for (i = 0; i*2 < strlen(SRC); i++) {	\
	memcpy(tb, (SRC)+(i*2), 2);		\
	(DST)[i] = strtol(tb, NULL, 16);	\
    }						\
} while (0)

int main(int argc, char* argv[]) {
    struct kcrap_context *context;
    struct kcrap_auth_req_data req;
    int ret;
    int i, cnt = 1;
    char schal[8];
    char cchal[130];
    char resp[24];
    int auth_status;
    
    if (argc > 1) cnt = atoi(argv[1]);

    bzero(&req, sizeof(req));
    bzero(&schal, sizeof(schal));
    bzero(&cchal, sizeof(cchal));
    bzero(&resp, sizeof(resp));
#ifdef T_NTLM
    SDATA(req.chal_type, "NTLM");
    SDATA(req.principal, "user");
    req.server_challenge.length = 8;
    req.server_challenge.data = schal;
    FILL(schal, "0123456789abcdef");
    req.response.length = 24;
    req.response.data = resp;
    FILL(resp, "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6");
#elif defined(T_NTLM2)
    SDATA(req.chal_type, "NTLM2");
    SDATA(req.principal, "user");
    SDATA(req.alt_username, "DOMAIN");
    req.server_challenge.length = 8;
    req.server_challenge.data = schal;
    FILL(schal, "0123456789abcdef");
    req.client_challenge.length = 130;
    req.client_challenge.data = cchal;
    FILL(cchal,
	 "01010000000000000090d336b734c301ffffff0011223344"
	 "0000000002000c0044004f004d00410049004e0001000c005300450052005600"
	 "450052000400140064006f006d00610069006e002e0063006f006d0003002200"
	 "7300650072007600650072002e0064006f006d00610069006e002e0063006f00"
	 "6d000000000000000000"
	 );
    req.response.length = 16;
    req.response.data = resp;
    FILL(resp, "cbabbca713eb795d04c97abc01ee4983");
#elif defined(T_NTLM2S)
    SDATA(req.chal_type, "NTLM2S");
    SDATA(req.principal, "user");
    req.server_challenge.length = 8;
    req.server_challenge.data = schal;
    FILL(schal, "0123456789abcdef");
    req.client_challenge.length = 8;
    req.client_challenge.data = cchal;
    FILL(cchal, "ffffff0011223344");
    req.response.length = 24;
    req.response.data = resp;
    FILL(resp, "10d550832d12b2ccb79d5ad1f4eed3df82aca4c3681dd455");
#else
# error XXX
#endif
    
    context = kcrap_init(NULL, NULL);
    if (context == NULL) {
	fprintf(stderr, "%s\n", kcrap_errmsg());
	exit(1);
    }
    for (i = 0; i < cnt; i++) {
	ret = kcrap_try(context, &req, &auth_status);
	if (ret != 0) {
	    fprintf(stderr, "Error: %s\n", kcrap_errmsg());
	} else if (auth_status == 0) {
	    fprintf(stderr, "Invalid response: %s\n", kcrap_errmsg());
	} else {
	    fprintf(stderr, "Authentication OK\n");
	}
    }
    kcrap_free(context);
    return 0;
}

