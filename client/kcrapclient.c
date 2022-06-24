/*
 * Little KCRAP client based on kcraptest.c
 * from http://www.spock.org/kcrap/
 */

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
#include <ctype.h>

#include "../config.h"
#include "kcrap.h"

// #define OSTREAM stderr
#define OSTREAM stdout

#define SDATA(VAR, VAL) (VAR).data = (VAL), (VAR).length = strlen((VAR).data)

static int fillhex(char *dst, char *src)
{
    int i = 0;
    char tb[3];
    tb[2] = 0;
    for (i = 0; i * 2 < strlen(src); i++)
    {
        memcpy(tb, src + (i * 2), 2);
        if ((!isxdigit(tb[0])) || (!isxdigit(tb[1])))
            return -1;
        dst[i] = strtol(tb, NULL, 16);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct kcrap_context *context;
    struct kcrap_auth_req_data req;
    int ret;
    char schal[8];
    char cchal[130];
    char resp[24];
    int auth_status;

    if (argc != 4)
    {
        fprintf(OSTREAM, "Error: Invalid parameters...\n");
        fprintf(OSTREAM, "Usage: %s <username> <challenge> <response>\n", argv[0]);
        exit(1);
    }

    if (strlen(argv[2]) != 16)
    {
        fprintf(OSTREAM, "Error: Invalid challenge length.\n");
        exit(1);
    }

    if (strlen(argv[3]) != 48)
    {
        fprintf(OSTREAM, "Error: Invalid response length.\n");
        exit(1);
    }

    bzero(&req, sizeof(req));
    bzero(&schal, sizeof(schal));
    bzero(&cchal, sizeof(cchal));
    bzero(&resp, sizeof(resp));
    SDATA(req.chal_type, "NTLM");

    // SDATA(req.principal, "user");
    req.principal.data = argv[1];
    req.principal.length = strlen(argv[1]);

    req.server_challenge.length = 8;
    req.server_challenge.data = schal;
    // FILL(schal, "0123456789abcdef");
    if (fillhex(schal, argv[2]))
    {
        fprintf(OSTREAM, "Error: Invalid challenge string.\n");
        exit(1);
    }

    req.response.length = 24;
    req.response.data = resp;
    // FILL(resp, "25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6");
    if (fillhex(resp, argv[3]))
    {
        fprintf(OSTREAM, "Error: Invalid response string.\n");
        exit(1);
    }

    context = kcrap_init(NULL, NULL);
    if (context == NULL)
    {
        fprintf(OSTREAM, "Error: %s\n", kcrap_errmsg());
        exit(1);
    }

    ret = kcrap_try(context, &req, &auth_status);
    if (ret != 0)
    {
        fprintf(OSTREAM, "Error: %s\n", kcrap_errmsg());
    }
    else if (auth_status == 0)
    {
        fprintf(OSTREAM, "Error: %s\n", kcrap_errmsg());
    }
    else
    {
        // fprintf(OSTREAM, "Authentication OK\n");

        struct kcrap_data extra = kcrap_get_extra_data();

        printf("NT_KEY: ");

        int my_cnt = 0;
        while (my_cnt < extra.length)
            printf("%02x", (unsigned char)extra.data[my_cnt++]);

        printf("\n");

        // Cancelliamo la chiave (md4(key21)) puntato dalla struttura "extra"
        if (extra.length)
        {
            memset(extra.data, 0, extra.length);
        }
    }

    kcrap_free(context);
    exit((ret != 0) || (auth_status == 0));
}
