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

#include <krb5.h>
#include <profile.h>
#include <com_err.h>

#include "../config.h"
#include "kcrap.h"
#include "kcrap_int.h"
#include "kcrap_kdb.h"
#include "modules.h"

#define DEFAULT_CFG_FILE "/etc/kcrap_server.conf"
#define DEFAULT_PID_FILE "/var/run/kcrap_server.pid"
#define KCRAPSEC "kcrap_server"

static profile_t profile;

static int verify_cookie(struct kcrap_auth_req_data *req);
static int handle_auth_req(int sock, krb5_context context, krb5_auth_context auth_context, krb5_data *message, krb5_keyblock *keyblock, struct sockaddr_in *sa);
static int handle_message(int sock, krb5_context context, krb5_principal sprinc, krb5_keytab keytab,
                          char *buf, int buflen, struct sockaddr_in *sa);
static int setup_socket(char *progname);
static void mainloop(int sock, krb5_context context, krb5_principal sprinc, krb5_keytab keytab);
static void usage(char *name);

static void usage(char *name)
{
    fprintf(stderr,
        "KCRAP: Kerberos Challenge-Response Authentication Protocol\n"
        "  Copyright (C) 2007-2008 Jonathan Chen <kcrap+web@spock.org>\n"
        "  Copyright (C) 2012-2022 Dan Fuhry <dan@fuhry.com>\n"
        "\n"
        "usage: %s [-V] [-D] [-f config_file] [-p pidfile] [-k keytab] [-x db_arg=val ...]\n"
        "\n"
        "Allowed arguments are:\n"
        "\n"
        "    -V                  Show program version and exit\n"
        "    -D                  Run in foreground; do not daemonize\n"
        "    -f config_file      Specify path to config file; defaults to " DEFAULT_CFG_FILE "\n"
        "    -p pidfile          Specify path to PID file; defaults to " DEFAULT_PID_FILE "\n"
        "    -k keytab           Specify path to system keytab; defaults to Kerberos default\n"
        "                        (normally /etc/krb5.keytab)\n"
        "    -x db_arg=val ...   Set database arguments. Passed directly to krb5_db_open();\n"
        "                        see the MIT Kerberos V documentation for instructions.\n"
        "\n"
        "Report bugs to Dan Fuhry <dan@fuhry.com>\n\n",
        name);
}

int main(int argc, char *argv[])
{
    char *cfg_file = DEFAULT_CFG_FILE;
    char *pid_file = DEFAULT_PID_FILE;
    krb5_error_code retval;
    int sock;
    krb5_context context;
    krb5_principal sprinc;
    krb5_keytab keytab = NULL;
    int ch;
    int nodetach = 0;
    char *keytab_path = NULL;
    char *realm;
    char **db_args = NULL;
    int db_args_size = 0;

    while ((ch = getopt(argc, argv, "VDf:k:r:x:")) != -1)
    {
        switch (ch)
        {
        case 'V':
            printf("kcrap_server " KCRAP_VERSION "\n");
            exit(0);
        case 'D':
            nodetach++;
            break;
        case 'f':
            cfg_file = optarg;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'k':
            keytab_path = optarg;
            break;
        case 'r':
            realm = strdup(optarg);
            break;
        case 'x':
            db_args_size++;
            {
                char **temp = realloc(db_args, sizeof(char*) * (db_args_size+1));
                if (temp == NULL)
                {
                    com_err(argv[0], errno, "while allocating memory for db_args");
                    exit(1);
                }

                db_args = temp;
            }
            db_args[db_args_size-1] = strdup(optarg);
            db_args[db_args_size] = NULL;
            break;
        default:
            usage(argv[0]);
            exit(1);
            break;
        }
    }

    retval = profile_init_path(cfg_file, &profile);
    if (retval)
    {
        com_err(argv[0], retval, "while reading config file");
        exit(1);
    }

    retval = krb5_init_context_profile(profile, 0, &context);
    if (retval)
    {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

    if (keytab_path != NULL)
    {
        if ((retval = krb5_kt_resolve(context, keytab_path, &keytab)))
        {
            com_err(argv[0], retval, "while resolving keytab file %s", keytab_path);
            exit(1);
        }
    }

    if ((retval = krb5_sname_to_principal(context, NULL, "host", KRB5_NT_SRV_HST, &sprinc)))
    {
        com_err(argv[0], retval, "while generating service name");
        exit(1);
    }

    if (kcrap_open_kdb(context, profile, KCRAPSEC, realm, db_args) != 0)
    {
        exit(1);
    }

    sock = setup_socket(argv[0]);
    if (sock < 0)
    {
        exit(1);
    }

    if (!nodetach)
    {
        retval = fork();
        if (retval < 0)
        {
            perror("fork");
            exit(1);
        }
        else if (retval > 0)
        {
            FILE *f;
            if ((f = fopen(pid_file, "w")))
            {
                fprintf(f, "%d\n", retval);
                fclose(f);
            }
            exit(0);
        }
        chdir("/");
    }

    mainloop(sock, context, sprinc, keytab);
    exit(1);
}

static int setup_socket(char *progname)
{
    int sock;
    krb5_error_code retval;
    int port;
    int on;
    struct sockaddr_in sa;

    retval = profile_get_integer(profile, KCRAPSEC, "port", NULL, 89, &port);
    if (retval)
    {
        com_err(progname, retval, "while parsing config file (port)");
        return -1;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("opening datagram socket");
        return -1;
    }

    on = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

    memset((char *)&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)))
    {
        perror("binding datagram socket");
        return -1;
    }

    return sock;
}

static void mainloop(int sock, krb5_context context, krb5_principal sprinc, krb5_keytab keytab)
{
    while (1)
    {
        socklen_t len;
        struct sockaddr_in sa;
        int ret;
        char pktbuf[65536];

        len = sizeof(sa);
        if ((ret = recvfrom(sock, pktbuf, sizeof(pktbuf), 0, (struct sockaddr *)&sa, &len)) < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            perror("receiving datagram");
            return;
        }
        handle_message(sock, context, sprinc, keytab, pktbuf, ret, &sa);
    }
}

static int handle_message(int sock, krb5_context context, krb5_principal sprinc, krb5_keytab keytab,
                          char *buf, int buflen, struct sockaddr_in *sa)
{
    int offset = 0;
    struct kcrap_req_pkt pkt;
    krb5_error_code retval;
    krb5_data message;
    krb5_auth_context auth_context = NULL;
    krb5_ticket *ticket = NULL;
    krb5_keyblock *keyblock;

    GETSHORT(pkt.pkt_type, buf, buflen, offset);
    if (pkt.pkt_type != KCRAP_PKT_AUTH_REQ)
        return EINVAL;

    GETDATA(pkt.ap_req, buf, buflen, offset);
    GETDATA(pkt.enc_data.ciphertext, buf, buflen, offset);

    /* Check authentication info */
    if ((retval = krb5_rd_req(context, &auth_context, &pkt.ap_req, sprinc, keytab, NULL, &ticket)))
    {
        com_err("", retval, "while reading request");
        goto free0;
    }

    if ((retval = krb5_auth_con_getrecvsubkey(context, auth_context, &keyblock)))
    {
        if ((retval = krb5_auth_con_getkey(context, auth_context, &keyblock)))
        {
            com_err("", retval, "while getting auth context key");
            goto free1;
        }
    }

    pkt.enc_data.enctype = keyblock->enctype;
    pkt.enc_data.kvno = 0;

    message.length = pkt.enc_data.ciphertext.length;
    if ((message.data = malloc(pkt.enc_data.ciphertext.length)) == NULL)
    {
        com_err("", retval, "while decrypting message");
        goto free2;
    }

    if ((retval = krb5_c_decrypt(context, keyblock, pkt.pkt_type, NULL, &pkt.enc_data, &message)))
    {
        com_err("", retval, "while decrypting message");
        goto free3;
    }
    retval = handle_auth_req(sock, context, auth_context, &message, keyblock, sa);
    krb5_free_data_contents(context, &message);

free3:
    free(message.data);
free2:
    krb5_free_keyblock(context, keyblock);
free1:
    krb5_auth_con_free(context, auth_context);
    krb5_free_ticket(context, ticket);
free0:
    return retval;
}

static int handle_auth_req(int sock, krb5_context context, krb5_auth_context auth_context, krb5_data *message, krb5_keyblock *keyblock, struct sockaddr_in *sa)
{
    int offset = 0;
    struct kcrap_auth_req_data req;
    char pktbuf[65536];
    int auth_ok;
    krb5_enc_data enc_packet;
    krb5_data plain_packet;
    char *rawpkt;
    int retval;
    int ret = -1;
    size_t len;
    krb5_data error_msg;
    int error_num;
    struct kcrap_data extra;

    error_num = 0;
    error_msg.length = 0;
    error_msg.data = NULL;

    GETSHORT(req.pkt_type, message->data, message->length, offset);
    if (req.pkt_type != KCRAP_PKT_AUTH_REQ)
        return EINVAL;
    GETDATA(req.chal_type, message->data, message->length, offset);
    GETINT(req.timestamp, message->data, message->length, offset);
    GETINT(req.nounce, message->data, message->length, offset);
    GETDATA(req.principal, message->data, message->length, offset);
    GETDATA(req.alt_username, message->data, message->length, offset);
    GETDATA(req.server_challenge, message->data, message->length, offset);
    GETDATA(req.server_challenge_cookie, message->data, message->length, offset);
    GETDATA(req.client_challenge, message->data, message->length, offset);
    GETDATA(req.response, message->data, message->length, offset);

    memset(&extra, 0, sizeof(struct kcrap_data));
    auth_ok = do_auth(context, &req, &error_num, &error_msg, &extra);

    if (auth_ok)
        auth_ok |= verify_cookie(&req);

    offset = 0;
    SETSHORT(KCRAP_PKT_AUTH_REP, pktbuf, sizeof(pktbuf), offset);
    SETSHORT(auth_ok, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.chal_type, pktbuf, sizeof(pktbuf), offset);
    SETINT(req.timestamp, pktbuf, sizeof(pktbuf), offset);
    SETINT(req.nounce, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.principal, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.alt_username, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.server_challenge, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.server_challenge_cookie, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.client_challenge, pktbuf, sizeof(pktbuf), offset);
    SETDATA(req.response, pktbuf, sizeof(pktbuf), offset);
    SETINT(error_num, pktbuf, sizeof(pktbuf), offset);
    SETDATA(error_msg, pktbuf, sizeof(pktbuf), offset);
    SETDATA(extra, pktbuf, sizeof(pktbuf), offset);

    if ((retval = krb5_c_encrypt_length(context, keyblock->enctype, offset, &len)))
    {
        com_err("", retval, "while getting enc length");
        goto free0;
    }
    enc_packet.ciphertext.length = len;

    if (NULL == (enc_packet.ciphertext.data = malloc(enc_packet.ciphertext.length)))
    {
        com_err("", retval, "while malloc enc");
        goto free0;
    }
    enc_packet.enctype = keyblock->enctype;
    enc_packet.kvno = 0;
    plain_packet.data = pktbuf;
    plain_packet.length = offset;

    if ((retval = krb5_c_encrypt(context, keyblock, KCRAP_PKT_AUTH_REP, NULL, &plain_packet, &enc_packet)))
    {
        com_err("", retval, "at krb5_c_encrypt");
        goto free1;
    }

    len = sizeof(short) * 2 + enc_packet.ciphertext.length;
    if (!(rawpkt = malloc(len)))
    {
        com_err("", retval, "at malloc");
        goto free1;
    }

    offset = 0;
    SETSHORT(KCRAP_PKT_AUTH_REP, rawpkt, len, offset);
    SETDATA(enc_packet.ciphertext, rawpkt, len, offset);

    ret = sendto(sock, rawpkt, offset, 0, (struct sockaddr *)sa, sizeof(*sa));

    free(rawpkt);
free1:
    krb5_free_data_contents(context, &enc_packet.ciphertext);
free0:
    krb5_free_data_contents(context, &error_msg);
    return ret;
}

static int verify_cookie(struct kcrap_auth_req_data *req)
{
    return 0;
}
