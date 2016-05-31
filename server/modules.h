struct kcrap_auth_req_data;
struct kcrap_chal_req_data;

struct kcrap_module {
    char* type;
    int (*auth_func)(krb5_context context, struct kcrap_auth_req_data *req, int *error_num, krb5_data *error_msg);
    int (*makechal_func)(krb5_context context, struct kcrap_chal_req_data *req, krb5_data *chal, int *error_num, krb5_data *error_msg);
};


struct kcrap_auth_req_data;

int do_auth(krb5_context context, struct kcrap_auth_req_data *req, int *error_num, krb5_data *error_msg);
int do_makechal(krb5_context context, struct kcrap_chal_req_data *req, krb5_data *chal, krb5_data *chalsum, int *error_num, krb5_data *error_msg);

