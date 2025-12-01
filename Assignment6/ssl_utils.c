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

/* SSL/TLS function declarations */
int init_ssl_library(void){
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    return 1;
}

void cleanup_ssl_library(void){
    EVP_cleanup();
    ERR_free_strings();
}

SSL_CTX* create_ssl_context_server(void);
SSL_CTX* create_ssl_context_client(void);
int load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file);
int verify_certificate(SSL* ssl, const char* expected_cn);

/* Dynamic certificate generation */
int generate_chatserver_certificate(const char* topic);
char* get_chatserver_cert_path(const char* topic);
char* get_chatserver_key_path(const char* topic);
int certificate_exists_for_topic(const char* topic);

/* Certificate validation functions */
int validate_peer_certificate(SSL* ssl, const char* expected_cn);
X509_STORE* load_ca_store(void);