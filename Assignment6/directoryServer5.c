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
#include "inet.h"
#include "common.h"

struct conn {
	int fd;
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


int main(int argc, char **argv)
{
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;
	(void)argc;
	(void)argv;
	/* Create communication endpoint */
	int sockfd;			/* Listening socket */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);

	LIST_INIT(&conns);
	LIST_INIT(&rooms);
	for (;;) {

		/* TODO: Initialize and populate your readset and compute max_fd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		int max_fd = sockfd;

		struct conn *c;
		LIST_FOREACH(c, &conns, entries) {
			FD_SET(c->fd, &readset);
			if (c->fd > max_fd) max_fd = c->fd;
		}
		/* FIXME: There should be a select call in here somewhere */
		int ready_count;
		for (;;) {
			ready_count = select(max_fd + 1, &readset, NULL, NULL, NULL);
			if (ready_count < 0) {
				if (errno == EINTR) {
					continue;
				}
				perror("directory: select error");
				return EXIT_FAILURE;
			}
			break;
		}
		/* Accept a new connection request */
		if (FD_ISSET(sockfd, &readset)) {
			socklen_t clilen = sizeof(cli_addr);
			int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
			if (newsockfd < 0) {
				perror("server: accept error");
			}
			else {
				fprintf(stderr, "%s:%d Accepted client connection from %s\n", __FILE__, __LINE__, inet_ntoa(cli_addr.sin_addr));
				struct conn *nc = calloc(1, sizeof *nc);
				if (!nc) {
					perror("directory: calloc");
					close(newsockfd);
				} else {
					nc->fd   = newsockfd;
					nc->inlen = 0;
					LIST_INSERT_HEAD(&conns, nc, entries);   // <-- THIS is the missing piece
				}
			}
		}
		/* TODO: Iterate through your client sockets */
		struct conn *curr, *next;
		for (curr = LIST_FIRST(&conns); curr != NULL; curr = next) {
			next = LIST_NEXT(curr, entries);
			if (!FD_ISSET(curr->fd, &readset)) continue;

			char buf[256];
			ssize_t n = read(curr->fd, buf, sizeof buf);
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
				close(curr->fd);
				free(curr);
				continue;
			}
			
			size_t space_left = sizeof(curr->inbuf) - 1 - curr->inlen;
			if ((size_t)n > space_left) {
				write(curr->fd, "ERR line too long\n", 18);
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
				if (linelen && start[linelen - 1] == '\r') start[--linelen] = '\0';  /* trim CR */

				

				if (strncmp(start, "LIST", 4) == 0) {
					/* Emit all rooms then '.' line */
					struct room *r;
					LIST_FOREACH(r, &rooms, entries) {
						char line[256];
						int m = snprintf(line, sizeof line, "ROOM \"%s\" %s %d\n",
										r->topic, r->ip, r->port);
						if (m > 0) (void)write(curr->fd, line, (size_t)m);
					}
					(void)write(curr->fd, ".\n", 2);
				}
				else if (strncmp(start, "REGISTER ", 9) == 0) {
					const char *p = start + 9;
					while (*p == ' ') p++;
					const char *last_space = strrchr(p, ' ');
					if (!last_space) {
						(void)write(curr->fd, "ERR usage: REGISTER <topic> <port>\n", 35);
					} else {
						/* port */
						char port_str[16];
						snprintf(port_str, sizeof port_str, "%s", last_space + 1);
						char *endp = NULL;
						unsigned long pv = strtoul(port_str, &endp, 10);
						if (endp == port_str || *endp != '\0' || pv == 0 || pv > 65535) {
							(void)write(curr->fd, "ERR invalid port\n", 17);
						} else {
							/* topic (strip optional surrounding quotes) */
							char topic[128];
							size_t tlen = (size_t)(last_space - p);
							if (tlen >= sizeof topic) tlen = sizeof topic - 1;
							memcpy(topic, p, tlen);
							topic[tlen] = '\0';
							if (topic[0] == '"' && tlen >= 2 && topic[tlen - 1] == '"') {
								topic[tlen - 1] = '\0';
								memmove(topic, topic + 1, tlen - 1);
							}

							/* get peer IP of the registering connection */
							struct sockaddr_in peer;
							socklen_t plen = sizeof peer;
							char ip[32] = "0.0.0.0";
							if (getpeername(curr->fd, (struct sockaddr *)&peer, &plen) == 0) {
								snprintf(ip, sizeof ip, "%s", inet_ntoa(peer.sin_addr));
							}

							/* enforce unique topic */
							int dup = 0;
							struct room *r;
							LIST_FOREACH(r, &rooms, entries) {
								if (strcmp(r->topic, topic) == 0) { dup = 1; break; }
							}
							if (dup) {
								(void)write(curr->fd, "ERR duplicate topic\n", 20);
							} else {
								struct room *nr = calloc(1, sizeof *nr);
								if (!nr) {
									(void)write(curr->fd, "ERR memory\n", 11);
								} else {
									snprintf(nr->topic, sizeof nr->topic, "%s", topic);
									snprintf(nr->ip,    sizeof nr->ip,    "%s", ip);
									nr->port     = (int)pv;
									nr->owner_fd = curr->fd;
									LIST_INSERT_HEAD(&rooms, nr, entries);
									(void)write(curr->fd, "OK\n", 3);
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
								(void)write(curr->fd, "ERR not owner\n", 14);
							} else {
								LIST_REMOVE(r, entries);
								free(r);
								(void)write(curr->fd, "OK\n", 3);
							}
							break;
						}
					}
					if (!found) (void)write(curr->fd, "ERR not found\n", 14);
				}
				else {
					(void)write(curr->fd, "ERR unknown command\n", 20);
				}

				start = newline + 1;
			}

			
			size_t remain = (size_t)(curr->inbuf + curr->inlen - start);
			if (remain && start != curr->inbuf) memmove(curr->inbuf, start, remain);
			curr->inlen = remain;
			curr->inbuf[curr->inlen] = '\0';

		}
	}
}
