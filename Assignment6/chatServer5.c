#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "inet.h"
#include "common.h"

#define NICK_MAX 32
#define LINE_MAX 1024
#define MSG_MAX  512

static int is_valid_nick_char(int c) {
    return (c == '_' || (c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

// --- banned functions replacements ---
static size_t s_len_bounded(const char *s, size_t max) {
    size_t n = 0;
    while (n < max && s && s[n] != '\0') n++;
    return n;
}


static int parse_u16(const char *s, unsigned short *out) {
    unsigned long v = 0;
    int saw = 0;
    if (!s || !*s || !out) return 0;
    while (*s) {
        char c = *s++;
        if (c < '0' || c > '9') return 0;
        saw = 1;
        v = v * 10u + (unsigned long)(c - '0');
        if (v > 65535ul) return 0;
    }
    if (!saw) return 0;
    *out = (unsigned short)v;
    return 1;
}




struct client {
    int fd;
    int has_nick;
    char nick[NICK_MAX];
    char inbuf[LINE_MAX];
    size_t inlen;
    LIST_ENTRY(client) entries;

    /* TLS fields */
    SSL  *ssl;
    int   use_tls;
};
LIST_HEAD(client_list, client);


static int set_nonblocking(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) { return -1; }
	if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { return -1; }
	return 0; 
}

// Helper: wait until fd is readable and/or writable (no timeout, per assignment)
static int wait_fd(int fd, int want_read, int want_write){
    fd_set rfds, wfds;
    FD_ZERO(&rfds); FD_ZERO(&wfds);
    if (want_read)  FD_SET(fd, &rfds);
    if (want_write) FD_SET(fd, &wfds);
    return select(fd + 1, &rfds, &wfds, NULL, NULL);
}

// Map SSL_* return codes to select()-driven retries.
// Returns: 1 = try again after readiness, 0 = clean shutdown, -1 = hard error.
static int ssl_want_again(SSL *ssl, int ret, int fd){
    int e = SSL_get_error(ssl, ret);
    if (e == SSL_ERROR_WANT_READ) {
        if (wait_fd(fd, 1, 0) < 0) return -1;
        return 1;
    }
    if (e == SSL_ERROR_WANT_WRITE) {
        if (wait_fd(fd, 0, 1) < 0) return -1;
        return 1;
    }
    if (e == SSL_ERROR_ZERO_RETURN) return 0; // orderly close_notify
    ERR_print_errors_fp(stderr);              // unexpected error
    return -1;
}

// Perform a TLS server handshake (accept) on a non-blocking socket.
// Returns 1 on success, 0 on failure (error or peer closed during handshake).
static int tls_handshake_nb_server(SSL *ssl, int fd){
    if (set_nonblocking(fd) < 0){
        perror("fcntl O_NONBLOCK");
        return 0;
    }
    for (;;){
        int r = SSL_accept(ssl);
        if (r == 1) return 1;              // handshake complete
        int again = ssl_want_again(ssl, r, fd);
        if (again <= 0) return 0;          // 0 = clean shutdown, -1 = error
    }
}

// Non-blocking TLS client handshake 
static int tls_handshake_nb_client(SSL *ssl, int fd){
    if (set_nonblocking(fd) < 0){ perror("fcntl O_NONBLOCK"); return 0; }
    for (;;){
        int r = SSL_connect(ssl);
        if (r == 1) return 1;
        int again = ssl_want_again(ssl, r, fd);
        if (again <= 0) return 0;
    }
}

// Read over TLS without blocking forever.
// Returns: >0 bytes read, 0 on clean TLS shutdown, -1 on error.
static ssize_t tls_read_nb(SSL *ssl, int fd, void *buf, size_t cap){
    for (;;){
        int r = SSL_read(ssl, buf, (int)cap);
        if (r > 0) return r;
        if (r == 0) return 0;               // peer sent close_notify
        int again = ssl_want_again(ssl, r, fd);
        if (again <= 0) return -1;          // error or clean EOF during handshake/IO
    }
}

// Write-all over TLS without blocking forever.
// Returns: 1 on success (all bytes written), 0 on failure.
static int tls_write_all_nb(SSL *ssl, int fd, const void *buf, size_t len){
    const unsigned char *p = (const unsigned char*)buf;
    size_t left = len;
    while (left){
        int r = SSL_write(ssl, p, (int)left);
        if (r > 0){ p += r; left -= (size_t)r; continue; }
        int again = ssl_want_again(ssl, r, fd);
        if (again <= 0) return 0;           // error or EOF mid-write
    }
    return 1;
}

// Create a TLS 1.3 server context for a given chat topic.
// Expects files from your helpers: get_chatserver_cert_path/topic + get_chatserver_key_path/topic.
// Returns an SSL_CTX* on success, or NULL on failure.
static SSL_CTX *make_tls13_server_ctx_for_topic(const char *topic){
    if (!topic || !*topic){
        fprintf(stderr, "TLS: empty topic\n");
        return NULL;
    }

    if (!certificate_exists_for_topic(topic)){
        fprintf(stderr, "TLS: missing cert/key for topic '%s'\n" "cert: %s\n" "key : %s\n",
                topic,
                get_chatserver_cert_path(topic),
                get_chatserver_key_path(topic));
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx){ ERR_print_errors_fp(stderr); return NULL; }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1){
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!load_certificates(ctx, get_chatserver_cert_path(topic), get_chatserver_key_path(topic))){
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}
// Plain write-all for non-TLS clients 
static int raw_write_all(int fd, const void *buf, size_t len){
    const unsigned char *p = (const unsigned char*)buf;
    size_t left = len;
    while (left){
        ssize_t w = write(fd, p, left);
        if (w < 0){
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    return 0;
}

// TLS-aware write-all: uses tls_write_all_nb() when TLS is enabled on this client.
static int client_write_all(struct client *c, const void *buf, size_t len){
    if (c->use_tls){
        int ok = tls_write_all_nb(c->ssl, c->fd, buf, len);
        if (ok) {
            return 0;
        }
        return -1;
    } else {
        return raw_write_all(c->fd, buf, len);
    }
}



// Enable TLS if CHAT_USE_TLS=1
static int want_tls(void){
    const char *v = getenv("CHAT_USE_TLS");
    if (!v) return 0;
    if (v[0] == '1' && v[1] == 0) return 1;
    return 0;
}



int main(int argc, char **argv)
{
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	fd_set readset;

	/* Create communication endpoint */
	int sockfd;			/* Listening socket */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int one = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

    if (argc != 3) {
    fprintf(stderr, "usage: %s \"<topic>\" <port>\n", argv[0]);
    fprintf(stderr, "example: %s \"KSU Football\" 29191\n", argv[0]);
    return EXIT_FAILURE;
    }

    char topic[128];
    snprintf(topic, sizeof topic, "%s", argv[1]);

    unsigned short port = 0;
    if (!parse_u16(argv[2], &port) || port == 0) {
        fprintf(stderr, "error: port must be in 1-65535\n");
        return EXIT_FAILURE;
    }
    
    
	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port);

	/* You will need to get the topic and port from input arguments */
	/* if (int i = 1; i < argc; i++), etc. */

	/* Bind to local IP/port before registering with the Directory Server to ensure
	* that the port is available */
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	/* Create communication endpoint */
	int dir_sockfd;
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family 		= AF_INET;
	dir_serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Connect to the server. */
	if (connect(dir_sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("server: can't connect to directory server");
		return EXIT_FAILURE;
	}

    /* --- TLS to Directory Server (CN must be "directory-server") --- */
    SSL_CTX *dir_ctx = NULL;
    SSL     *dir_ssl = NULL;
    int      dir_use_tls = want_tls();
    if (dir_use_tls) {
        dir_ctx = SSL_CTX_new(TLS_client_method());
        if (!dir_ctx){ ERR_print_errors_fp(stderr); return EXIT_FAILURE; }
        if (SSL_CTX_set_min_proto_version(dir_ctx, TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(dir_ctx, TLS1_3_VERSION) != 1){
            ERR_print_errors_fp(stderr); SSL_CTX_free(dir_ctx); return EXIT_FAILURE;
        }
        if (!SSL_CTX_load_verify_locations(dir_ctx, CA_CERT_PATH, NULL)){
            ERR_print_errors_fp(stderr); SSL_CTX_free(dir_ctx); return EXIT_FAILURE;
        }

        dir_ssl = SSL_new(dir_ctx);
        if (!dir_ssl){ ERR_print_errors_fp(stderr); SSL_CTX_free(dir_ctx); return EXIT_FAILURE; }
        /* optional SNI (safe to add): */ (void)SSL_set_tlsext_host_name(dir_ssl, SERV_HOST_ADDR);
        if (SSL_set_fd(dir_ssl, dir_sockfd) != 1){
            ERR_print_errors_fp(stderr); SSL_free(dir_ssl); SSL_CTX_free(dir_ctx); return EXIT_FAILURE;
        }
        if (!tls_handshake_nb_client(dir_ssl, dir_sockfd)){
            fprintf(stderr, "server: TLS handshake to directory failed\n");
            SSL_free(dir_ssl); SSL_CTX_free(dir_ctx); return EXIT_FAILURE;
        }
        if (!verify_certificate(dir_ssl, DIRECTORY_SERVER_CN)){
            fprintf(stderr, "server: directory CN verification failed\n");
            SSL_shutdown(dir_ssl); SSL_free(dir_ssl); SSL_CTX_free(dir_ctx); return EXIT_FAILURE;
        }
    }



	/* TODO: Register with the directory server */
    char line[256];
    int length = snprintf(line, sizeof line, "REGISTER %s %u\n", topic, (unsigned)port);
    
    if (length < 0 || length >= (int)sizeof line) {
        fprintf(stderr, "server: The topic/port is too long when building REGISTER line\n");
        return EXIT_FAILURE;
    }
    
    /* send REGISTER */
    if (dir_use_tls) {
        if (!tls_write_all_nb(dir_ssl, dir_sockfd, line, (size_t)length)) {
            fprintf(stderr, "server: TLS write REGISTER failed\n");
            SSL_shutdown(dir_ssl);
            SSL_free(dir_ssl);
            SSL_CTX_free(dir_ctx);
            return EXIT_FAILURE;
        }
    } else {
        ssize_t bytes = write(dir_sockfd, line, (size_t)length);
        if (bytes != length) {
            perror("server: write REGISTER to directory");
            return EXIT_FAILURE;
        }
    }

    
    char reply_line[256];
    size_t bytes_in_buffer = 0;
    for (;;) {
        ssize_t bytes_read;
        if (dir_use_tls) {
            bytes_read = tls_read_nb(dir_ssl, dir_sockfd,reply_line + bytes_in_buffer,
                                    sizeof(reply_line) - 1 - bytes_in_buffer);
        } else {
            bytes_read = read(dir_sockfd, reply_line + bytes_in_buffer,
                            sizeof(reply_line) - 1 - bytes_in_buffer);
        }

        if (bytes_read <= 0) {
            fprintf(stderr, "server: directory closed during REGISTER\n");
            if (dir_use_tls) {
                SSL_shutdown(dir_ssl);
                SSL_free(dir_ssl);
                SSL_CTX_free(dir_ctx);
            }
            return EXIT_FAILURE;
        }

        bytes_in_buffer += (size_t)bytes_read;
        reply_line[bytes_in_buffer] = '\0';

        char *newline = memchr(reply_line, '\n', bytes_in_buffer);
        if (!newline) continue;
        *newline = '\0';
        break;
    }

    if (strncmp(reply_line, "OK", 2) == 0) {
        fprintf(stderr, "server: registered topic \"%s\" on port %u\n",
                topic, (unsigned)port);
    } else if (strncmp(reply_line, "ERR ", 4) == 0) {
        fprintf(stderr, "server: directory error: %s\n", reply_line + 4);
        return EXIT_FAILURE;
    } else {
        fprintf(stderr, "server: unexpected directory reply: %s\n", reply_line);
        return EXIT_FAILURE;
    }

    SSL_CTX *srv_ctx = NULL;
    int srv_use_tls = want_tls();
    if (srv_use_tls) {
        srv_ctx = make_tls13_server_ctx_for_topic(topic);
        if(!srv_ctx) {
            fprintf(stderr, "server: failed to create TLS context for topic");
            return EXIT_FAILURE;
        }
        fprintf(stderr, "server: TLS (1.3) enabled for topic '%s'\n", topic);
    }


	/* Now you are ready to accept client connections */
	
    if (listen(sockfd, 5) < 0) {
        perror("server: listen");
        return EXIT_FAILURE;
    }


    static struct client_list clients;
    LIST_INIT(&clients);
	for (;;) {
		/* TODO: Initialize and populate your readset and compute max_fd */
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);
        int max_fd = sockfd;

        struct client *iter;
        LIST_FOREACH(iter, &clients, entries) {
            FD_SET(iter->fd, &readset);
            if (iter->fd > max_fd) max_fd = iter->fd;
        }
		/* FIXME: There should be a select call in here somewhere */
        int ready_count;
        for (;;) {
            ready_count = select(max_fd + 1, &readset, NULL, NULL, NULL);
            if (ready_count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("server: select error");
                return EXIT_FAILURE;
            }
            break;
        }

		/* if FD_ISSET and stuff... */
        if (FD_ISSET(sockfd, &readset)) {
            socklen_t clilen = sizeof(cli_addr);
            int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0) {
                perror("server: accept error");
            } else {
                struct client *nc = calloc(1, sizeof *nc);
                if (!nc) {
                    perror("server: calloc");
                    close(newsockfd);
                } else {
                    nc->fd = newsockfd;
                    nc->has_nick = 0;
                    nc->inlen = 0;
                    nc->nick[0] = '\0';
                    /* TLS handshake for this client if enabled */
                    if (srv_use_tls) {
                        SSL *ssl = SSL_new(srv_ctx);
                        if (!ssl) {
                            ERR_print_errors_fp(stderr);
                            close(newsockfd);
                            free(nc);
                            continue;
                        }
                        if (SSL_set_fd(ssl, newsockfd) != 1) {
                            ERR_print_errors_fp(stderr);
                            SSL_free(ssl);
                            close(newsockfd);
                            free(nc);
                            continue;
                        }
                        if (!tls_handshake_nb_server(ssl, newsockfd)) {
                            fprintf(stderr, "server: TLS handshake failed\n");
                            SSL_free(ssl);
                            close(newsockfd);
                            free(nc);
                            continue;
                        }
                        nc->ssl = ssl;
                        nc->use_tls = 1;
                        fprintf(stderr, "server: TLS established with client\n");
                    } else {
                        nc->ssl = NULL;
                        nc->use_tls = 0;
                    }
                    /* end TLS handshake block */
                    LIST_INSERT_HEAD(&clients, nc, entries);
                }
            }
        }


		/* TODO: Iterate through your client sockets */
        struct client *cc, *next;
                
            for (cc = LIST_FIRST(&clients); cc != NULL; cc = next) {
                next = LIST_NEXT(cc, entries);

                if (!FD_ISSET(cc->fd, &readset)) continue;

                
                char buf[256];
                ssize_t n;
                if (cc->use_tls) {
                    n = tls_read_nb(cc->ssl, cc->fd, buf, sizeof(buf));
                } else {
                    n = read(cc->fd, buf, sizeof(buf));
                }
                if (n == 0 || n < 0) {
                    
                    if (cc->has_nick) {
                        char out[LINE_MAX];
                        int m = snprintf(out, sizeof out, "%s has left the chat\n", cc->nick);
                        struct client *t;
                        LIST_FOREACH(t, &clients, entries) {
                            if (t != cc && t->has_nick) (void)client_write_all(t, out, (size_t)m);
                        }
                    }

                    /* TLS cleanup for this client, if enabled */
                    if (cc->use_tls) {
                        SSL_shutdown(cc->ssl);
                        SSL_free(cc->ssl);
                        cc->ssl = NULL;
                        cc->use_tls = 0;
                    }

                    LIST_REMOVE(cc, entries);
                    close(cc->fd);
                    free(cc);
                    continue;
                } 

                size_t room = sizeof(cc->inbuf) - 1 - cc->inlen;
                if ((size_t)n > room) {
                    const char *msg = "ERR line too long. Disconnecting.\n";
                    (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));

                    /* TLS cleanup for this client, if enabled */
                    if (cc->use_tls) {
                        SSL_shutdown(cc->ssl);
                        SSL_free(cc->ssl);
                        cc->ssl = NULL;
                        cc->use_tls = 0;
                    }

                    LIST_REMOVE(cc, entries);
                    close(cc->fd);
                    free(cc);
                    continue;
                }
                memcpy(cc->inbuf + cc->inlen, buf, (size_t)n);
                cc->inlen += (size_t)n;
                cc->inbuf[cc->inlen] = '\0';

                char *start = cc->inbuf;
                for (;;) {
                    size_t avail = (size_t)(cc->inbuf + cc->inlen - start);
                    char *nl = memchr(start, '\n', avail);
                    if (!nl) break;

                    size_t linelen = (size_t)(nl - start);
                    char cmdline[LINE_MAX];
                    if (linelen >= sizeof cmdline) linelen = sizeof cmdline - 1;
                    memcpy(cmdline, start, linelen);
                    cmdline[linelen] = '\0';


                    if (strncmp(cmdline, "NICK ", 5) == 0) {
                        char nick[NICK_MAX] = {0};
                        if (sscanf(cmdline, "NICK %31s", nick) != 1) {
                            const char *msg = "ERR invalid nickname format\n";
                            (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                        } else {
                            
                            size_t nlen = s_len_bounded(nick, sizeof(nick));
                            int valid = (nlen > 0);
                            for (size_t i = 0; i < nlen && valid; i++) {
                                if (!is_valid_nick_char((unsigned char)nick[i])) valid = 0;
                            }
                            if (!valid) {
                                char msg[192];
                                int m = snprintf(msg, sizeof msg,
                                    "ERR invalid nickname. Use only letters (A-Z/a-z), digits (0-9), or underscore (_), up to %d characters. Example: alice_2\n",
                                    NICK_MAX - 1);
                                (void)client_write_all(cc, msg, (size_t)m);
                            } else {
                                
                                int in_use = 0;
                                struct client *t;
                                LIST_FOREACH(t, &clients, entries) {
                                    if (t != cc && t->has_nick &&
                                        strncmp(t->nick, nick, NICK_MAX) == 0) {
                                        in_use = 1; break;
                                    }
                                }
                                if (in_use) {
                                    const char *msg = "ERR nickname already in use\n";
                                    (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                                } else {
                                    
                                    snprintf(cc->nick, sizeof cc->nick, "%s", nick);
                                    cc->has_nick = 1;

                                    
                                    int named = 0;
                                    LIST_FOREACH(t, &clients, entries) {
                                        if (t->has_nick) named++;
                                    }
                                    if (named == 1) {
                                        const char *msg =
                                            "You are the first user to join the chat\n";
                                        (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                                    } else {
                                        
                                        char out[LINE_MAX];
                                        int m = snprintf(out, sizeof out,
                                                            "%s has joined the chat\n", cc->nick);
                                        LIST_FOREACH(t, &clients, entries) {
                                            if (t != cc && t->has_nick) {
                                                (void)client_write_all(t, out, (size_t)m);
                                            }
                                        }
                                        
                                        char ack[64];
                                        int am = snprintf(ack, sizeof ack, "Welcome, %s!\n", cc->nick);
                                        (void)client_write_all(cc, ack, (size_t)am);
                                    }
                                }
                            }
                        }
                    }
                    else if (strncmp(cmdline, "MSG ", 4) == 0) {
                        if (!cc->has_nick) {
                            const char *msg = "ERR set a nickname first: NICK <name>\n";
                            (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                        } else {
                            char text[MSG_MAX] = {0};
                                if (sscanf(cmdline, "MSG %511[^\n]", text) != 1 || text[0] == '\0') {
                                    const char *msg = "ERR empty or invalid message. Usage: MSG <text>\n";
                                    (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                                } else {
                                char out[LINE_MAX];
                                int m = snprintf(out, sizeof out, "%s: %s\n", cc->nick, text);
                                struct client *t;
                                LIST_FOREACH(t, &clients, entries) {
                                    if (t->has_nick) {
                                        (void)client_write_all(t, out, (size_t)m);
                                    }
                                }
                            }
                        }
                    }
                    else if (strncmp(cmdline, "ERR", 3) == 0) {
                        const char *msg =
                            "ERR unsupported command from client. Use NICK <name> or MSG <text>\n";
                        (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                    }
                    else {
                        const char *msg = "ERR unknown command. Use NICK or MSG\n";
                        (void)client_write_all(cc, msg, s_len_bounded(msg, 1024));
                    }
                    start = nl + 1;
                }

                
                size_t remain = (size_t)(cc->inbuf + cc->inlen - start);
                if (remain && start != cc->inbuf) memmove(cc->inbuf, start, remain);
                cc->inlen = remain;
                cc->inbuf[cc->inlen] = '\0';
            }
	}
	// return or exit(0) is implied; no need to do anything because main() ends
}

