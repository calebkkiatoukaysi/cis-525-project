#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "inet.h"
#include "common.h"

#define MSG_MAX  512

// Forward declarations for functions at end of file
static int set_nonblocking(int fd);
static int wait_fd(int fd, int want_read, int want_write);
static int ssl_want_again(SSL *ssl, int ret, int fd);
static int tls_handshake_nb_client(SSL *ssl, int fd);
static ssize_t tls_read_nb(SSL *ssl, int fd, void *buf, size_t cap);
static int tls_write_all_nb(SSL *ssl, int fd, const void *buf, size_t len);
static int verify_peer_cn_equals(SSL *ssl, const char *expected_cn);
static int want_tls(void);
static int tls_attach_client(SSL_CTX **ctx, SSL **ssl, int sockfd, const char *hostname);




int main()
{
	int				sockfd;
	struct sockaddr_in chat_serv_addr, dir_serv_addr;
	fd_set readset;
	SSL_CTX *dir_ctx = NULL;
	SSL *dir_ssl = NULL;
	int dir_use_tls = 0;

	SSL_CTX *chat_ctx = NULL;
	SSL *chat_ssl = NULL;
	int chat_use_tls = 0;

	// init SSL library
	if(!init_ssl_library()){
		fprintf(stderr, "client: failed to initialize SSL library\n");
		return EXIT_FAILURE;
	}

	/* Set up the address of the directory server. */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family			= AF_INET;
	dir_serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		cleanup_ssl_library();
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("client: can't connect to server");
		cleanup_ssl_library();
		return EXIT_FAILURE;
	}

	if (want_tls()) {
		if (tls_attach_client(&dir_ctx, &dir_ssl, sockfd, SERV_HOST_ADDR) < 0) {
			fprintf(stderr, "client: TLS handshake to directory failed\n");
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		if(!verify_peer_cn_equals(dir_ssl, DIRECTORY_SERVER_CN)) {
			fprintf(stderr, "client: directory CN verification failed\n");
			SSL_shutdown(dir_ssl);
			SSL_free(dir_ssl);
			SSL_CTX_free(dir_ctx);
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		dir_use_tls = 1;
		fprintf(stderr, "client: TLS established to directory; CN=%s\n", DIRECTORY_SERVER_CN);
	}

	/* FIXME: Onewliney the Directory Server is hard-coded in inet.h. You'll need to
	* fetch the chat server IP and port from it before connecting to that chat
	* server */


	/* Your directory server logic here... */
	char chosen_ip[32] = {0};
	int  chosen_port = 0;
	char chosen_topic[128] = {0};

	const char list_cmd[] = "LIST\n";
	size_t list_cmd_len = sizeof(list_cmd) - 1;
	ssize_t bytes_sent = 0;

	if (dir_use_tls) {
		if (!tls_write_all_nb(dir_ssl, sockfd, list_cmd, list_cmd_len)) {
			perror("client: TLS write error");
			SSL_shutdown(dir_ssl);
			SSL_free(dir_ssl);
			if(dir_ctx) {
				SSL_CTX_free(dir_ctx);
			}
			close(sockfd);
			return EXIT_FAILURE;
		}
		bytes_sent = (ssize_t)list_cmd_len;
	}
	else{
		ssize_t bytes_sent = write(sockfd, list_cmd, list_cmd_len);
		if (bytes_sent < 0) {
			perror("client: write LIST");
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		if (bytes_sent != (ssize_t)list_cmd_len) {
			perror("client: write LIST");
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
	}

	struct room {
		char topic[128];
		char ip[32];
		int  port;
	};
	struct room rooms[64];
	int room_count = 0;

	char recvbuf[2048];
	size_t used = 0;

	for (;;) {
		ssize_t bytes_read;
		if (dir_use_tls) {
			bytes_read = tls_read_nb(dir_ssl, sockfd, recvbuf + used, sizeof(recvbuf) - 1 - used);
		} else {
			bytes_read = read(sockfd, recvbuf + used, sizeof(recvbuf) - 1 - used);
		}
		
		if (bytes_read <= 0) {
			fprintf(stderr, "client: directory closed during LIST\n");
			if(dir_use_tls) {
				SSL_shutdown(dir_ssl);
				SSL_free(dir_ssl);
				SSL_CTX_free(dir_ctx);
			}
			close(sockfd);
			return EXIT_FAILURE;
		}
		used += (size_t)bytes_read;
		recvbuf[used] = '\0';

		char *line_start = recvbuf;
		for (;;) {
			size_t avail = (size_t)(recvbuf + used - line_start);
			char *newline = memchr(line_start, '\n', avail);
			if (!newline) break;  
			*newline = '\0';      
			if (strncmp(line_start, ".", 1) == 0) {
				goto have_room_list;  
			}
			char t[128] = {0};
			char ip[32] = {0};
			int  port = 0;

			if (sscanf(line_start, "ROOM \"%127[^\"]\" %31s %d", t, ip, &port) == 3) {
				if (room_count < (int)(sizeof rooms / sizeof rooms[0])) {
					snprintf(rooms[room_count].topic, sizeof rooms[room_count].topic, "%s", t);
					snprintf(rooms[room_count].ip,    sizeof rooms[room_count].ip,    "%s", ip);
					rooms[room_count].port = port;
					room_count++;
				}
			}
			line_start = newline + 1;
		}
		size_t remain = (size_t)(recvbuf + used - line_start);
		if (remain && line_start != recvbuf) memmove(recvbuf, line_start, remain);
		used = remain;
	}

	have_room_list:

	if (room_count == 0) {
		printf("No chat rooms are currently available.\n");
		if(dir_use_tls) {
			SSL_shutdown(dir_ssl);
			SSL_free(dir_ssl);
			SSL_CTX_free(dir_ctx);
		}
		close(sockfd);
		cleanup_ssl_library();
		return EXIT_SUCCESS;
	}

	printf("Available chat rooms:\n");
	for (int i = 0; i < room_count; i++) {
		printf("  %d) %s  (%s:%d)\n", i + 1, rooms[i].topic, rooms[i].ip, rooms[i].port);
	}

	int choice = 0;
	for (;;) {
		char in[64];
		printf("Select a room by number: ");
		fflush(stdout);
		if (!fgets(in, sizeof in, stdin)) {
			fprintf(stderr, "client: stdin closed\n");
			if(dir_use_tls) {
				SSL_shutdown(dir_ssl);
				SSL_free(dir_ssl);
				SSL_CTX_free(dir_ctx);
			}
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		if (sscanf(in, "%d", &choice) == 1 && choice >= 1 && choice <= room_count) {
			break;
		}
		printf("Please enter a number between 1 and %d.\n", room_count);
	}

	snprintf(chosen_ip, sizeof chosen_ip, "%s", rooms[choice - 1].ip);
	chosen_port = rooms[choice - 1].port;
	snprintf(chosen_topic, sizeof chosen_topic, "%s", rooms[choice - 1].topic);

	if (dir_use_tls){ 
		SSL_shutdown(dir_ssl); 
		SSL_free(dir_ssl); 
		SSL_CTX_free(dir_ctx); 
	}
	close(sockfd);

	/* Set up the address of the chat server. */
	memset((char *) &chat_serv_addr, 0, sizeof(chat_serv_addr));
	chat_serv_addr.sin_family			= AF_INET;
	chat_serv_addr.sin_addr.s_addr	= inet_addr(chosen_ip);
	chat_serv_addr.sin_port				= htons((uint16_t)chosen_port);

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		cleanup_ssl_library();
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &chat_serv_addr, sizeof(chat_serv_addr)) < 0) {
		perror("client: can't connect to server");
		close(sockfd);
		cleanup_ssl_library();
		return EXIT_FAILURE;
	}

	// Setup TLS for chat server if enabled 
	if (want_tls()) {
		if (tls_attach_client(&chat_ctx, &chat_ssl, sockfd, chosen_ip) < 0) {
			fprintf(stderr, "client: TLS handshake to chat server failed\n");
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		if(!verify_certificate(chat_ssl, chosen_topic)) {
			fprintf(stderr, "client: chat server CN verification failed\n");
			SSL_shutdown(chat_ssl);
			SSL_free(chat_ssl);
			SSL_CTX_free(chat_ctx);
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		chat_use_tls = 1;
		fprintf(stderr, "client: TLS established to chat server; CN=%s\n", chosen_topic);
	}

	char inbuf[MAX]  = {0};
	char outbuf[MAX] = {0};

	int nick_ok = 0;
	while (!nick_ok) {
		fputs("Enter nickname (A-Z/a-z/0-9/_ up to 31 chars): ", stdout);
		fflush(stdout);

		if (!fgets(inbuf, sizeof inbuf, stdin)) {
			fprintf(stderr, "client: failed to read nickname\n");
			close(sockfd);
			cleanup_ssl_library();
			return EXIT_FAILURE;
		}
		size_t nlen = strnlen(inbuf, sizeof inbuf);
		if (nlen > 0 && inbuf[nlen - 1] == '\n') inbuf[nlen - 1] = '\0';
		if (inbuf[0] == '\0') continue;

		int wlen = snprintf(outbuf, sizeof outbuf, "NICK %.*s\n", 31, inbuf);
		if (wlen <= 0) {
			fprintf(stderr, "client: failed to format NICK command\n");
			continue;
		}

		ssize_t write_result;
		if (chat_use_tls) {
			if (!tls_write_all_nb(chat_ssl, sockfd, outbuf, (size_t)wlen)) {
				fprintf(stderr, "client: TLS write NICK failed\n");
				goto cleanup_and_exit;
			}
			write_result = wlen;
		} else {
			write_result = write(sockfd, outbuf, (size_t)wlen);
		}

		if (write_result < 0) {
			perror("client: write NICK");
			goto cleanup_and_exit;
		}

		/* read one line reply */
		size_t used_nick = 0;
		for (;;) {
			ssize_t nr;
			if (chat_use_tls) {
				nr = tls_read_nb(chat_ssl, sockfd, recvbuf + used_nick, sizeof recvbuf - 1 - used_nick);
			} else {
				nr = read(sockfd, recvbuf + used_nick, sizeof recvbuf - 1 - used_nick);
			}

			if (nr <= 0) {
				fprintf(stderr, "client: server closed during NICK handshake\n");
				goto cleanup_and_exit;
			}
			used_nick += (size_t)nr;
			recvbuf[used_nick] = '\0';
			char *nl = memchr(recvbuf, '\n', used_nick);
			if (!nl) continue; /* keep reading until newline */

			nl[1] = '\0'; /* keep newline for printing */
			if (strncmp(recvbuf, "ERR", 3) == 0) {
				fputs(recvbuf, stdout);      /* server explains the error */
				used_nick = 0; recvbuf[0] = '\0';
				break;                       /* reprompt for nickname */
			} else {
				fputs(recvbuf, stdout);      /* e.g., "Welcome, <nick>!" */
				nick_ok = 1;
				break;
			}
		}
	}

	/* === PA3-style chat loop === */
	for (;;) {
		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		int r = select(sockfd + 1, &readset, NULL, NULL, NULL);
		if (r < 0) {
			perror("client: select");
			break;
		}

		if (FD_ISSET(STDIN_FILENO, &readset)) {
			if (!fgets(inbuf, sizeof inbuf, stdin)) {
				fprintf(stderr, "client: stdin closed, exiting\n");
				break;
			}
			size_t len = strnlen(inbuf, sizeof inbuf);
			if (len > 0 && inbuf[len - 1] == '\n') inbuf[len - 1] = '\0';
			if (inbuf[0] != '\0') {
				int m = snprintf(outbuf, sizeof outbuf, "MSG %.*s\n", (int)(MSG_MAX - 1), inbuf);
				if (m > 0) {
					ssize_t w;
					if (chat_use_tls) {
						if (!tls_write_all_nb(chat_ssl, sockfd, outbuf, (size_t)m)) {
							fprintf(stderr, "client: TLS write MSG failed\n");
							break;
						}
						w = m;
					} else {
						w = write(sockfd, outbuf, (size_t)m);
					}
					if (w < 0) { perror("client: write MSG"); break; }
				}
			}
		}

		if (FD_ISSET(sockfd, &readset)) {
			ssize_t nread;
			if (chat_use_tls) {
				nread = tls_read_nb(chat_ssl, sockfd, recvbuf, sizeof recvbuf - 1);
			} else {
				nread = read(sockfd, recvbuf, sizeof recvbuf - 1);
			}

			if (nread <= 0) {
				fprintf(stderr, "client: server closed connection\n");
				break;
			}
			recvbuf[nread] = '\0';
			fputs(recvbuf, stdout);
		}
	}

cleanup_and_exit:
	if (chat_use_tls) {
		SSL_shutdown(chat_ssl);
		SSL_free(chat_ssl);
		SSL_CTX_free(chat_ctx);
	}
	close(sockfd);
	cleanup_ssl_library();
	return 0;

	// return or exit(0) is implied; no need to do anything because main() ends
}

// TLS client attachment function
static int tls_attach_client(SSL_CTX **ctx, SSL **ssl, int sockfd, const char *hostname) {
	*ctx = create_ssl_context_client();
	if (!*ctx) {
		fprintf(stderr, "Failed to create SSL context\n");
		return -1;
	}

	*ssl = SSL_new(*ctx);
	if (!*ssl) {
		fprintf(stderr, "Failed to create SSL structure\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(*ctx);
		*ctx = NULL;
		return -1;
	}

	if (SSL_set_fd(*ssl, sockfd) != 1) {
		fprintf(stderr, "Failed to set SSL file descriptor\n");
		ERR_print_errors_fp(stderr);
		SSL_free(*ssl);
		SSL_CTX_free(*ctx);
		*ssl = NULL;
		*ctx = NULL;
		return -1;
	}

	if (!tls_handshake_nb_client(*ssl, sockfd)) {
		fprintf(stderr, "TLS handshake failed\n");
		SSL_free(*ssl);
		SSL_CTX_free(*ctx);
		*ssl = NULL;
		*ctx = NULL;
		return -1;
	}

	return 0;
}

static int set_nonblocking(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) { return -1; }
	if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { return -1; }
	return 0; 
}

static int wait_fd(int fd, int want_read, int want_write) {
	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	if (want_read) {
		FD_SET(fd, &rfds);
	}
	if (want_write) {
		FD_SET(fd, &wfds);
	}

	return select(fd + 1, &rfds, &wfds, NULL, NULL);
}

static int ssl_want_again(SSL *ssl, int ret, int fd) {
	int e = SSL_get_error(ssl, ret);
	if (e == SSL_ERROR_WANT_READ) {
		if (wait_fd(fd, 1, 0) < 0) return -1;
		return 1;
	}
	if (e == SSL_ERROR_WANT_WRITE) { 
		if (wait_fd(fd, 0, 1) < 0) return -1;
		return 1; 
	}
	if (e == SSL_ERROR_ZERO_RETURN) { return 0; }
	ERR_print_errors_fp(stderr);              
    return -1;
}

// Perform a TLS client handshake on a non-blocking socket.
// Returns 1 on success, 0 on failure.
static int tls_handshake_nb_client(SSL *ssl, int fd) {
	if (set_nonblocking(fd) < 0) {
		perror("fcntl O_NONBLOCK");
		return 0;
	}
	for (;;) {
		int r = SSL_connect(ssl);
		if (r == 1) { return 1; }
		int again = ssl_want_again(ssl, r, fd);
		if (again <= 0) { return 0; }
	}
}
// TLS read that never blocks forever (select()-driven).
// Returns: >0 bytes read, 0 on clean TLS shutdown, -1 on error.
static ssize_t tls_read_nb(SSL *ssl, int fd, void *buf, size_t cap) {
	for (;;) {
		int r = SSL_read(ssl, buf, (int)cap);
		if (r > 0) { return r; }
		if (r == 0) { return 0; }
		int again = ssl_want_again(ssl, r, fd);
		if (again <= 0) return -1;
	}
}

// TLS write-all that never blocks forever (select()-driven).
// Returns: 1 on success (all bytes written), 0 on failure.
static int tls_write_all_nb(SSL *ssl, int fd, const void *buf, size_t len) {
	const unsigned char *p = (const unsigned char*)buf;
	size_t left = len;
	while (left) {
		int r = SSL_write(ssl, p, (int)left);
		if (r > 0) {
			p += r;
			left -= (size_t)r; 
			continue;
		}
		int again = ssl_want_again(ssl, r, fd);
		if (again <= 0) { return 0; }
	}
	return 1;
}

// Verify that the peer's certificate CN exactly matches expected_cn.
// Also checks the certificate chain result (X509_V_OK).
static int verify_peer_cn_equals(SSL *ssl, const char *expected_cn) {
	if (!ssl || !expected_cn || !*expected_cn) { return 0;}

	int ok = 0;
	X509 *cert = SSL_get1_peer_certificate(ssl);
	if (!cert) {
		fprintf(stderr, "No peer certificate\n");
		return 0;
	}

	long vr = SSL_get_verify_result(ssl);
	if (vr != X509_V_OK) {
		fprintf(stderr, "Certificate chain verification failed: %ld\n", vr);
		goto out;
	}

	X509_NAME *subj = X509_get_subject_name(cert);
	if(!subj) {
		fprintf(stderr, "Missing CN in certificate\n");
		goto out;
	}

	char cn[512];
	int n = X509_NAME_get_text_by_NID(subj, NID_commonName, cn, (int)sizeof(cn));
	if (n <= 0) {
		fprintf(stderr, "Missing CN in certificate\n");
		goto out;
	}
	if (n >= (int)sizeof(cn)) {
		n = (int)sizeof(cn) - 1;
	}
	cn[n] = '\0';

	if (strncmp(cn, expected_cn, strnlen(expected_cn, sizeof(cn)) + 1) != 0) {
		fprintf(stderr, "CN mismatch: expected '%s', got '%s'\n", expected_cn, cn);
		goto out;
	}

	ok = 1;
	out:
		X509_free(cert);
		return ok;
}

static int want_tls(void) {
	return 1;
	// const char *v = getenv("CHAT_USE_TLS");
	// return (v && strncmp(v, "1", 2) == 0);
}