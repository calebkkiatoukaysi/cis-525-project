#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "inet.h"
#include "common.h"

#define MSG_MAX  512

int main()
{
	int				sockfd;
	struct sockaddr_in chat_serv_addr, dir_serv_addr;
	fd_set			readset;

	/* Set up the address of the directory server. */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family			= AF_INET;
	dir_serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

	/* FIXME: Onewliney the Directory Server is hard-coded in inet.h. You'll need to
	* fetch the chat server IP and port from it before connecting to that chat
	* server */

	/* Your directory server logic here... */
	char chosen_ip[32] = {0};
	int  chosen_port   = 0;


	const char *list_cmd = "LIST\n";
	ssize_t bytes_sent = write(sockfd, list_cmd, strlen(list_cmd));
	if (bytes_sent != (ssize_t)strlen(list_cmd)) {
		perror("client: write LIST");
		return EXIT_FAILURE;
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
		ssize_t bytes_read = read(sockfd, recvbuf + used, sizeof(recvbuf) - 1 - used);
		if (bytes_read <= 0) {
			fprintf(stderr, "client: directory closed during LIST\n");
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
			if (strcmp(line_start, ".") == 0) {
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
		close(sockfd);               
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
			close(sockfd);
			return EXIT_FAILURE;
		}
		if (sscanf(in, "%d", &choice) == 1 && choice >= 1 && choice <= room_count) {
			break;
		}
		printf("Please enter a number between 1 and %d.\n", room_count);
	}

	snprintf(chosen_ip, sizeof chosen_ip, "%s", rooms[choice - 1].ip);
	chosen_port = rooms[choice - 1].port;

	
	close(sockfd);

	/* Set up the address of the chat server. */
	memset((char *) &chat_serv_addr, 0, sizeof(chat_serv_addr));
	chat_serv_addr.sin_family			= AF_INET;
	chat_serv_addr.sin_addr.s_addr	= inet_addr(chosen_ip);
	chat_serv_addr.sin_port				= htons((uint16_t)chosen_port);

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &chat_serv_addr, sizeof(chat_serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
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
			return EXIT_FAILURE;
		}
		size_t nlen = strlen(inbuf);
		if (nlen > 0 && inbuf[nlen - 1] == '\n') inbuf[nlen - 1] = '\0';
		if (inbuf[0] == '\0') continue;

		int wlen = snprintf(outbuf, sizeof outbuf, "NICK %.*s\n", 31, inbuf);
		if (wlen <= 0 || write(sockfd, outbuf, (size_t)wlen) < 0) {
			perror("client: write NICK");
			close(sockfd);
			return EXIT_FAILURE;
		}

		/* read one line reply */
		size_t used_nick = 0;
		for (;;) {
			ssize_t nr = read(sockfd, recvbuf + used_nick, sizeof recvbuf - 1 - used_nick);
			if (nr <= 0) {
				fprintf(stderr, "client: server closed during NICK handshake\n");
				close(sockfd);
				return EXIT_FAILURE;
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
			size_t len = strlen(inbuf);
			if (len > 0 && inbuf[len - 1] == '\n') inbuf[len - 1] = '\0';
			if (inbuf[0] != '\0') {
				int m = snprintf(outbuf, sizeof outbuf, "MSG %.*s\n", (int)(MSG_MAX - 1), inbuf);
				if (m > 0) {
					ssize_t w = write(sockfd, outbuf, (size_t)m);
					if (w < 0) { perror("client: write MSG"); break; }
				}
			}
		}

		if (FD_ISSET(sockfd, &readset)) {
			ssize_t nread = read(sockfd, recvbuf, sizeof recvbuf - 1);
			if (nread <= 0) {
				fprintf(stderr, "client: server closed connection\n");
				break;
			}
			recvbuf[nread] = '\0';
			fputs(recvbuf, stdout);
		}
	}

	close(sockfd);
	return 0;

	// return or exit(0) is implied; no need to do anything because main() ends
}
