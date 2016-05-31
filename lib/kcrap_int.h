struct kcrap_context {
    krb5_context krb5_context;
    profile_t profile;
    krb5_keytab keytab;
    krb5_principal sprinc;
    krb5_ccache ccache;
    char **servers;
};

#define KCRAP_PKT_AUTH_REQ	0x01
#define KCRAP_PKT_AUTH_REP	0x02

struct kcrap_req_pkt {
    short pkt_type;
    krb5_data ap_req;
    krb5_enc_data enc_data;
};

struct kcrap_rep_pkt {
    short pkt_type;
    krb5_enc_data enc_data;
};






#define GETSHORT(NAME, BUF, BUFLEN, OFFSET)			\
    if (OFFSET + 2 > BUFLEN) return EINVAL;			\
    NAME = ntohs(*(short*)(&BUF[OFFSET]));			\
    OFFSET += 2
#define GETINT(NAME, BUF, BUFLEN, OFFSET)			\
    if (OFFSET + 4 > BUFLEN) return EINVAL;			\
    NAME = ntohl(*(uint32_t*)(&BUF[OFFSET]));			\
    OFFSET += 4
#define GETDATA(NAME, BUF, BUFLEN, OFFSET)			\
    GETSHORT(NAME.length, BUF, BUFLEN, OFFSET);			\
    if (OFFSET + NAME.length > BUFLEN) return EINVAL;		\
    NAME.data = &BUF[OFFSET];					\
    OFFSET += NAME.length

#define SETSHORT(NAME, BUF, BUFLEN, OFFSET)			\
    if (OFFSET + 2 > BUFLEN) return EINVAL;			\
    *(short*)(&BUF[OFFSET]) = htons(NAME);			\
    OFFSET += 2
#define SETINT(NAME, BUF, BUFLEN, OFFSET)			\
    if (OFFSET + 4 > BUFLEN) return EINVAL;			\
    *(uint32_t*)(&BUF[OFFSET]) = htonl(NAME);			\
    OFFSET += 4
#define SETDATA(NAME, BUF, BUFLEN, OFFSET) 			\
    SETSHORT(NAME.length, BUF, BUFLEN, OFFSET);			\
    if (OFFSET + NAME.length > BUFLEN) return EINVAL;		\
    memcpy(&BUF[OFFSET], NAME.data, NAME.length);		\
    OFFSET += NAME.length
#define SETDATAP(NAME, BUF, BUFLEN, OFFSET) do {		\
    if (NAME) {							\
	SETDATA((*NAME), BUF, BUFLEN, OFFSET);			\
    } else {							\
	SETSHORT(0, BUF, BUFLEN, OFFSET);			\
    }								\
} while (0)
#define SETSTR(NAME, BUF, BUFLEN, OFFSET) do {			\
    int len = strlen(NAME);					\
    SETSHORT(len, BUF, BUFLEN, OFFSET);				\
    if (OFFSET + len > BUFLEN) return EINVAL;			\
    if (NAME) memcpy(&BUF[OFFSET], NAME, len);			\
    OFFSET += len;						\
} while (0)

#define DATASAME(A,B) (((A).length == (B).length)?(((A).length == 0) || (memcmp((A).data, (B).data, (A).length)==0)):0)

