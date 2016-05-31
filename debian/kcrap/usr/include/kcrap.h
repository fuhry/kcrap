#define KCRAP_AUTH_OK		0x0001
#define KCRAP_AUTH_COOKIE_OK	0x0002

#define KCRAP_VERSION	"0.2.3"

struct kcrap_context;

struct kcrap_data {
    unsigned int length;
    char* data;
};

struct kcrap_auth_req_data {
    unsigned short pkt_type;
    struct kcrap_data chal_type;
    unsigned int timestamp;
    unsigned int nounce;
    struct kcrap_data principal;
    struct kcrap_data alt_username;
    struct kcrap_data server_challenge;
    struct kcrap_data server_challenge_cookie;
    struct kcrap_data client_challenge;
    struct kcrap_data response;
};

struct kcrap_auth_rep_data {
    unsigned short pkt_type;
    unsigned short auth_reply;
    struct kcrap_data chal_type;
    unsigned int timestamp;
    unsigned int nounce;
    struct kcrap_data principal;
    struct kcrap_data alt_username;
    struct kcrap_data server_challenge;
    struct kcrap_data server_challenge_cookie;
    struct kcrap_data client_challenge;
    struct kcrap_data response;
    unsigned int error_num;
    struct kcrap_data error_msg;
    struct kcrap_data extra_data;
};

struct kcrap_chal_req_data {
    unsigned short pkt_type;
    struct kcrap_data chal_type;
    unsigned int timestamp;
    unsigned int nounce;
    struct kcrap_data principal;
    struct kcrap_data alt_username;
};

struct kcrap_chal_rep_data {
    unsigned short pkt_type;
    struct kcrap_data server_challenge;
    struct kcrap_data server_challenge_cookie;
    struct kcrap_data chal_type;
    unsigned int timestamp;
    unsigned int nounce;
    struct kcrap_data principal;
    struct kcrap_data alt_username;
    unsigned int errnum;
    struct kcrap_data error_data;
};

struct kcrap_context* kcrap_init(char* keytab, char* service);
void kcrap_free(struct kcrap_context *context);
const char* kcrap_errmsg();
const struct kcrap_data kcrap_get_extra_data();

int kcrap_try(struct kcrap_context *context, struct kcrap_auth_req_data *req, int *auth_status);

