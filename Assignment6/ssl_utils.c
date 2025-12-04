#include "common.h"
#include <string.h>
#include <sys/stat.h>

/*
These are utilities that we can use. 
These are all wrapper functions and utilize the OpenSSL library, which
is linked below :)
- Caleb
 */
/* https://docs.openssl.org/master/man3/SSL_library_init/ */

/* Predefined chat room names (Have to update README)*/
const char* PREDEFINED_CHAT_ROOMS[NUM_PREDEFINED_ROOMS] = {
    "KSU-Football",
    "Technology", 
    "General-Chat",
    "Study-Group",
    "Gaming"
};

/* SSL/TLS function declarations */
int init_ssl_library(){
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    return 1;
}

void cleanup_ssl_library(void){
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX* create_ssl_context_server(){
    const SSL_METHOD* method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx){
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set TLS 1.3 version constraints (same as client)
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // Set verification mode for server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

SSL_CTX* create_ssl_context_client(){
    const SSL_METHOD* method = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // set min TLS version
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
     
    // Load CA certificate for verification
    if(SSL_CTX_load_verify_locations(ctx, CA_CERT_PATH, NULL) != 1){
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}


int load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file){
    // load cert
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    // load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    // check private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return 0;
    }
    return 1;
}

int verify_certificate(SSL* ssl, const char* expected_cn){
    X509* cert = SSL_get_peer_certificate(ssl);

    if(!cert) {
        fprintf(stderr, "No certificate received\n");
        return 0;
    }
    
    X509_NAME* subject_name = X509_get_subject_name(cert);
    char common_name_buffer[256];
    
    // X509_NAME_get_text_by_NID() returns the length
    int cn_length = X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name_buffer, sizeof(common_name_buffer));
    int cn_match = 0;

    if(cn_length > 0 && expected_cn){
        /* Ensure null termination */
        if (cn_length >= (int)sizeof(common_name_buffer)) {
            cn_length = sizeof(common_name_buffer) - 1;
        }
        common_name_buffer[cn_length] = '\0';
        
        printf("Certificate CN: %s\n", common_name_buffer);
        
        /* Comparing the names manually */
        int i = 0;
        cn_match = 1;  /* Assume match until proven otherwise */
        
        while (i < cn_length && expected_cn[i] != '\0') {
            if (common_name_buffer[i] != expected_cn[i]) {
                cn_match = 0;
                break;
            }
            i++;
        }
        
        /* Check if both strings ended at the same position */
        if (cn_match && (i != cn_length || expected_cn[i] != '\0')) {
            cn_match = 0;
        }
        
        if (cn_match) {
            printf("Certificate verification SUCCESS: Expected '%s' found\n", expected_cn);
        } else {
            printf("Certificate verification FAILED: Expected '%s', got '%s'\n", expected_cn, common_name_buffer);
        }
    } else {
        printf("Certificate verification FAILED: Could not extract CN\n");
    }
    
    X509_free(cert);
    return cn_match;
}

/* Certificate management for predefined rooms */
char* get_chatserver_cert_path(const char* topic){
    static char path[256];
    snprintf(path, sizeof(path), "certs/servers/chatserver-%s-cert.pem", topic);
    return path;
}

char* get_chatserver_key_path(const char* topic){
    static char path[256];
    snprintf(path, sizeof(path), "certs/private/chatserver-%s-key.pem", topic);
    return path;
}


int certificate_exists_for_topic(const char* topic){
    char* cert_path = get_chatserver_cert_path(topic);
    char* key_path = get_chatserver_key_path(topic);

    struct stat st;

    if (stat(cert_path, &st) != 0) {
        return 0;
    }
    if (stat(key_path, &st) != 0) {
        return 0;
    }
    return 1;
}