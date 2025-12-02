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
#include "inet.h"
#include "common.h"

#define NICK_MAX 32
#define LINE_MAX 1024
#define MSG_MAX  512

static int is_valid_nick_char(int c) {
    return (c == '_' || (c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

struct client {
    int fd;
    int has_nick;
    char nick[NICK_MAX];
    char inbuf[LINE_MAX];
    size_t inlen;
    LIST_ENTRY(client) entries;
};
LIST_HEAD(client_list, client);

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

    char *end = NULL;
    unsigned long p = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0') {
        fprintf(stderr, "error: port must be a decimal integer\n");
        return EXIT_FAILURE;
    }
    if (p == 0 || p > 65535) {
        fprintf(stderr, "error: port must be in 1-65535\n");
        return EXIT_FAILURE;
    }
    unsigned short port = (unsigned short)p;
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


	/* TODO: Register with the directory server */
    char line[256];
    int length = snprintf(line, sizeof line, "REGISTER %s %u\n", topic, (unsigned)port);
    
    if (length < 0 || length >= (int)sizeof line) {
        fprintf(stderr, "server: The topic/port is too long when building REGISTER line\n");
        return EXIT_FAILURE;
    }
    
    ssize_t bytes = write(dir_sockfd, line, (size_t)length);
    if (bytes != length) {
        perror("server: write REGISTER to directory");
        return EXIT_FAILURE;
    }

    char reply_line[256];
    size_t bytes_in_buffer = 0;
    for (;;) {
        ssize_t bytes_read = read(dir_sockfd, reply_line + bytes_in_buffer, sizeof(reply_line) - 1 - bytes_in_buffer);
        if (bytes_read <= 0) {
            fprintf(stderr, "server: directory closed during REGISTER\n");
            return EXIT_FAILURE;
        }
        bytes_in_buffer += (size_t)bytes_read;
        reply_line[bytes_in_buffer] = '\0';

        char *newline = memchr(reply_line, '\n', bytes_in_buffer);
        if (!newline) {
            continue;
        }
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
                ssize_t n = read(cc->fd, buf, sizeof buf);
                if (n == 0 || n < 0) {
                    
                    if (cc->has_nick) {
                        char out[LINE_MAX];
                        int m = snprintf(out, sizeof out, "%s has left the chat\n", cc->nick);
                        struct client *t;
                        LIST_FOREACH(t, &clients, entries) {
                            if (t != cc && t->has_nick) (void)write(t->fd, out, (size_t)m);
                        }
                    }
                    LIST_REMOVE(cc, entries);
                    close(cc->fd);
                    free(cc);
                    continue;
                } 

                size_t room = sizeof(cc->inbuf) - 1 - cc->inlen;
                if ((size_t)n > room) {
                    const char *msg = "ERR line too long. Disconnecting.\n";
                    (void)write(cc->fd, msg, strlen(msg));
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
                    char line[LINE_MAX];
                    if (linelen >= sizeof line) linelen = sizeof line - 1;
                    memcpy(line, start, linelen);
                    line[linelen] = '\0';


                    if (strncmp(line, "NICK ", 5) == 0) {
                        char nick[NICK_MAX] = {0};
                        if (sscanf(line, "NICK %31s", nick) != 1) {
                            const char *msg = "ERR invalid nickname format\n";
                            (void)write(cc->fd, msg, strlen(msg));
                        } else {
                            
                            size_t nlen = strlen(nick);
                            int valid = (nlen > 0);
                            for (size_t i = 0; i < nlen && valid; i++) {
                                if (!is_valid_nick_char((unsigned char)nick[i])) valid = 0;
                            }
                            if (!valid) {
                                char msg[192];
                                int m = snprintf(msg, sizeof msg,
                                    "ERR invalid nickname. Use only letters (A-Z/a-z), digits (0-9), or underscore (_), up to %d characters. Example: alice_2\n",
                                    NICK_MAX - 1);
                                (void)write(cc->fd, msg, (size_t)m);
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
                                    (void)write(cc->fd, msg, strlen(msg));
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
                                        (void)write(cc->fd, msg, strlen(msg));
                                    } else {
                                        
                                        char out[LINE_MAX];
                                        int m = snprintf(out, sizeof out,
                                                            "%s has joined the chat\n", cc->nick);
                                        LIST_FOREACH(t, &clients, entries) {
                                            if (t != cc && t->has_nick) {
                                                (void)write(t->fd, out, (size_t)m);
                                            }
                                        }
                                        
                                        char ack[64];
                                        int am = snprintf(ack, sizeof ack, "Welcome, %s!\n", cc->nick);
                                        (void)write(cc->fd, ack, (size_t)am);
                                    }
                                }
                            }
                        }
                    }
                    else if (strncmp(line, "MSG ", 4) == 0) {
                        if (!cc->has_nick) {
                            const char *msg = "ERR set a nickname first: NICK <name>\n";
                            (void)write(cc->fd, msg, strlen(msg));
                        } else {
                            char text[MSG_MAX] = {0};
                                if (sscanf(line, "MSG %511[^\n]", text) != 1 || strlen(text) == 0) {
                                    const char *msg = "ERR empty or invalid message. Usage: MSG <text>\n";
                                    (void)write(cc->fd, msg, strlen(msg));
                                } else {
                                char out[LINE_MAX];
                                int m = snprintf(out, sizeof out, "%s: %s\n", cc->nick, text);
                                struct client *t;
                                LIST_FOREACH(t, &clients, entries) {
                                    if (t->has_nick) {
                                        (void)write(t->fd, out, (size_t)m);
                                    }
                                }
                            }
                        }
                    }
                    else if (strncmp(line, "ERR", 3) == 0) {
                        const char *msg =
                            "ERR unsupported command from client. Use NICK <name> or MSG <text>\n";
                        (void)write(cc->fd, msg, strlen(msg));
                    }
                    else {
                        const char *msg = "ERR unknown command. Use NICK or MSG\n";
                        (void)write(cc->fd, msg, strlen(msg));
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
