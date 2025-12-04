#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "inet.h"
#include "common.h"

struct conn {
	int fd;
	SSL *ssl;
	int use_tls;
	char inbuf[1024];
	size_t inlen;
	LIST_ENTRY(conn) entries;
};
LIST_HEAD(conn_list, conn);
static struct conn_list conns;

struct room {
	char topic[128];
	char ip[32];
	int port;
	int owner_fd;
	LIST_ENTRY(room) entries;
};
LIST_HEAD(room_list, room);
static struct room_list rooms;

//Non-blocking mode prevents I/O operations from hanging forever
static int set_nonblocking(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0) return -1;
	if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
	return 0;
}

//waits until a socket is ready for reading or writing
static int wait_fd(int fd, int want_read, int want_write) {
	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	if (want_read) FD_SET(fd, &rfds);
	if (want_write) FD_SET(fd, &wfds);
	return select(fd + 1, &rfds, &wfds, NULL, NULL);
}

//Handles SSL operations that didn't complete immediately
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
	if (e == SSL_ERROR_ZERO_RETURN) return 0;
	ERR_print_errors_fp(stderr);
	return -1;
}

//Performs the TLS handshake when a client connects
static int tls_handshake_nb_server(SSL *ssl, int fd) {
	if (set_nonblocking(fd) < 0) {
		perror("fcntl O_NONBLOCK");
		return 0;
	}
	for (;;) {
		int r = SSL_accept(ssl);
		if (r == 1) return 1;
		int again = ssl_want_again(ssl, r, fd);
		if (again <= 0) return 0;
	}
}

//Reads data from a TLS connection
static ssize_t tls_read_nb(SSL *ssl, int fd, void *buf, size_t cap) {
	for (;;) {
		int r = SSL_read(ssl, buf, (int)cap);
		if (r > 0) return r;
		if (r == 0) return 0;
		int again = ssl_want_again(ssl, r, fd);
		if (again <= 0) return -1;
	}
}

//Writes ALL requested data to a TLS connection
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
		if (again <= 0) return 0;
	}
	return 1;
}

static int want_tls(void) {
	const char *v = getenv("CHAT_USE_TLS"); //set to 1 to enable TLS
	return (v && v[0] == '1' && v[1] == '\0');
}

//If connection uses TLS: calls tls_write_all_nb() If plain TCP: calls regular write()
static ssize_t conn_write(struct conn *c, const void *buf, size_t len) {
	if (c->use_tls) {
		if (!tls_write_all_nb(c->ssl, c->fd, buf, len)) return -1;
		return (ssize_t)len;
	}
	return write(c->fd, buf, len);
}

//If connection uses TLS: calls tls_read_nb() If plain TCP: calls regular read()
static ssize_t conn_read(struct conn *c, void *buf, size_t cap) {
	if (c->use_tls) {
		return tls_read_nb(c->ssl, c->fd, buf, cap);
	}
	return read(c->fd, buf, cap);
}

int main(int argc, char **argv)
{
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;
	SSL_CTX *ctx = NULL;
	int use_tls = 0;
	(void)argc;
	(void)argv;

	if (want_tls()) {
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();

		ctx = SSL_CTX_new(TLS_server_method());
		if (!ctx) {
			ERR_print_errors_fp(stderr);
			return EXIT_FAILURE;
		}

		SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

		if (SSL_CTX_use_certificate_file(ctx, "directory_cert.pem", SSL_FILETYPE_PEM) <= 0) { //server certificate
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return EXIT_FAILURE;
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, "directory_key.pem", SSL_FILETYPE_PEM) <= 0) { //server private key
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return EXIT_FAILURE;
		}

		if (!SSL_CTX_check_private_key(ctx)) {
			fprintf(stderr, "Private key does not match certificate\n");
			SSL_CTX_free(ctx);
			return EXIT_FAILURE;
		}

		if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL)) { //CA certificate
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return EXIT_FAILURE;
		}

		use_tls = 1;
		fprintf(stderr, "Directory server: TLS 1.3 enabled\n");
	}

	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		if (ctx) SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	int true_val = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true_val, sizeof(true_val)) < 0) {
		perror("server: can't set stream socket address reuse option");
		close(sockfd);
		if (ctx) SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		close(sockfd);
		if (ctx) SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);

	LIST_INIT(&conns);
	LIST_INIT(&rooms);

	for (;;) {
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		int max_fd = sockfd;

		struct conn *c;
		LIST_FOREACH(c, &conns, entries) {
			FD_SET(c->fd, &readset);
			if (c->fd > max_fd) max_fd = c->fd;
		}

		int ready_count;
		for (;;) {
			ready_count = select(max_fd + 1, &readset, NULL, NULL, NULL);
			if (ready_count < 0) {
				if (errno == EINTR) continue;
				perror("directory: select error");
				if (ctx) SSL_CTX_free(ctx);
				return EXIT_FAILURE;
			}
			break;
		}

		if (FD_ISSET(sockfd, &readset)) {
			socklen_t clilen = sizeof(cli_addr);
			int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) {
				perror("server: accept error");
			} else {
				struct conn *nc = calloc(1, sizeof *nc);
				if (!nc) {
					perror("directory: calloc");
					close(newsockfd);
				} else {
					nc->fd = newsockfd;
					nc->inlen = 0;
					nc->use_tls = 0;
					nc->ssl = NULL;

					if (use_tls) {
						nc->ssl = SSL_new(ctx);
						if (!nc->ssl) {
							ERR_print_errors_fp(stderr);
							close(newsockfd);
							free(nc);
							continue;
						}
						SSL_set_fd(nc->ssl, newsockfd);
						if (!tls_handshake_nb_server(nc->ssl, newsockfd)) {
							fprintf(stderr, "TLS handshake failed\n");
							SSL_free(nc->ssl);
							close(newsockfd);
							free(nc);
							continue;
						}
						nc->use_tls = 1;
						fprintf(stderr, "TLS connection established from %s\n", 
							inet_ntoa(cli_addr.sin_addr));
					}

					LIST_INSERT_HEAD(&conns, nc, entries);
				}
			}
		}

		struct conn *curr, *next;
		for (curr = LIST_FIRST(&conns); curr != NULL; curr = next) {
			next = LIST_NEXT(curr, entries);
			if (!FD_ISSET(curr->fd, &readset)) continue;

			char buf[256];
			ssize_t n = conn_read(curr, buf, sizeof buf);
			if (n <= 0) {
				struct room *r, *rn;
				for (r = LIST_FIRST(&rooms); r != NULL; r = rn) {
					rn = LIST_NEXT(r, entries);
					if (r->owner_fd == curr->fd) {
						LIST_REMOVE(r, entries);
						free(r);
					}
				}
				LIST_REMOVE(curr, entries);
				if (curr->use_tls && curr->ssl) {
					SSL_shutdown(curr->ssl);
					SSL_free(curr->ssl);
				}
				close(curr->fd);
				free(curr);
				continue;
			}

			size_t space_left = sizeof(curr->inbuf) - 1 - curr->inlen;
			if ((size_t)n > space_left) {
				conn_write(curr, "ERR line too long\n", 18);
				curr->inlen = 0;
				curr->inbuf[0] = '\0';
				continue;
			}
			memcpy(curr->inbuf + curr->inlen, buf, (size_t)n);
			curr->inlen += (size_t)n;
			curr->inbuf[curr->inlen] = '\0';

			char *start = curr->inbuf;
			for (;;) {
				size_t avail = (size_t)(curr->inbuf + curr->inlen - start);
				char *newline = memchr(start, '\n', avail);
				if (!newline) break;

				*newline = '\0';
				size_t linelen = (size_t)(newline - start);
				if (linelen && start[linelen - 1] == '\r') start[--linelen] = '\0';

				if (strncmp(start, "LIST", 4) == 0) {
					struct room *r;
					LIST_FOREACH(r, &rooms, entries) {
						char line[256];
						int m = snprintf(line, sizeof line, "ROOM \"%s\" %s %d\n",
										r->topic, r->ip, r->port);
						if (m > 0) conn_write(curr, line, (size_t)m);
					}
					conn_write(curr, ".\n", 2);
				}
				else if (strncmp(start, "REGISTER ", 9) == 0) {
					const char *p = start + 9;
					while (*p == ' ') p++;
					const char *last_space = strrchr(p, ' ');
					if (!last_space) {
						conn_write(curr, "ERR usage: REGISTER <topic> <port>\n", 35);
					} else {
						char port_str[16];
						snprintf(port_str, sizeof port_str, "%s", last_space + 1);
						char *endp = NULL;
						unsigned long pv = strtoul(port_str, &endp, 10);
						if (endp == port_str || *endp != '\0' || pv == 0 || pv > 65535) {
							conn_write(curr, "ERR invalid port\n", 17);
						} else {
							char topic[128];
							size_t tlen = (size_t)(last_space - p);
							if (tlen >= sizeof topic) tlen = sizeof topic - 1;
							memcpy(topic, p, tlen);
							topic[tlen] = '\0';
							if (topic[0] == '"' && tlen >= 2 && topic[tlen - 1] == '"') {
								topic[tlen - 1] = '\0';
								memmove(topic, topic + 1, tlen - 1);
							}

							struct sockaddr_in peer;
							socklen_t plen = sizeof peer;
							char ip[32] = "0.0.0.0";
							if (getpeername(curr->fd, (struct sockaddr *)&peer, &plen) == 0) {
								snprintf(ip, sizeof ip, "%s", inet_ntoa(peer.sin_addr));
							}

							int dup = 0;
							struct room *r;
							LIST_FOREACH(r, &rooms, entries) {
								if (strcmp(r->topic, topic) == 0) { dup = 1; break; }
							}
							if (dup) {
								conn_write(curr, "ERR duplicate topic\n", 20);
							} else {
								struct room *nr = calloc(1, sizeof *nr);
								if (!nr) {
									conn_write(curr, "ERR memory\n", 11);
								} else {
									snprintf(nr->topic, sizeof nr->topic, "%s", topic);
									snprintf(nr->ip, sizeof nr->ip, "%s", ip);
									nr->port = (int)pv;
									nr->owner_fd = curr->fd;
									LIST_INSERT_HEAD(&rooms, nr, entries);
									conn_write(curr, "OK\n", 3);
								}
							}
						}
					}
				}
				else if (strncmp(start, "DEREGISTER ", 11) == 0) {
					const char *p = start + 11;
					while (*p == ' ') p++;

					char topic[128];
					snprintf(topic, sizeof topic, "%s", p);
					size_t tl = strlen(topic);
					if (tl >= 2 && topic[0] == '"' && topic[tl - 1] == '"') {
						topic[tl - 1] = '\0';
						memmove(topic, topic + 1, tl - 1);
					}

					struct room *r, *rn;
					int found = 0;
					for (r = LIST_FIRST(&rooms); r != NULL; r = rn) {
						rn = LIST_NEXT(r, entries);
						if (strcmp(r->topic, topic) == 0) {
							found = 1;
							if (r->owner_fd != curr->fd) {
								conn_write(curr, "ERR not owner\n", 14);
							} else {
								LIST_REMOVE(r, entries);
								free(r);
								conn_write(curr, "OK\n", 3);
							}
							break;
						}
					}
					if (!found) conn_write(curr, "ERR not found\n", 14);
				}
				else {
					conn_write(curr, "ERR unknown command\n", 20);
				}

				start = newline + 1;
			}

			size_t remain = (size_t)(curr->inbuf + curr->inlen - start);
			if (remain && start != curr->inbuf) memmove(curr->inbuf, start, remain);
			curr->inlen = remain;
			curr->inbuf[curr->inlen] = '\0';
		}
	}

	if (ctx) SSL_CTX_free(ctx);
	return 0;
}