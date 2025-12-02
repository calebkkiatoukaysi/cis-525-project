#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define MAX 100

#define MAX_CLIENTS 5

/* Predefined chat rooms */
#define NUM_PREDEFINED_ROOMS 5

extern const char* PREDEFINED_CHAT_ROOMS[NUM_PREDEFINED_ROOMS];


/* Certificate paths */
#define CA_CERT_PATH "certs/ca/ca-cert.pem"
#define CA_KEY_PATH "certs/ca/ca-key.pem"
#define DIRECTORY_CERT_PATH "certs/servers/directory-server-cert.pem"
#define DIRECTORY_KEY_PATH "certs/private/directory-server-key.pem"

/* Expected certificate names for verification */
#define DIRECTORY_SERVER_CN "directory-server"

/* SSL/TLS function declarations */
int init_ssl_library(void);
void cleanup_ssl_library(void);
SSL_CTX* create_ssl_context_server(void);
SSL_CTX* create_ssl_context_client(void);
int load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file);
int verify_certificate(SSL* ssl, const char* expected_cn);

/* Certificate management for predefined rooms */
char* get_chatserver_cert_path(const char* topic);
char* get_chatserver_key_path(const char* topic);
int certificate_exists_for_topic(const char* topic);
