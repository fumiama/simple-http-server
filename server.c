/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344(Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 *
 * Optimized Dec 2023 by Fumiama(源文雨)
 */
/* See feature_test_macros(7) */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#if !__APPLE__
	#include <sys/sendfile.h> 
#else
	static struct sf_hdtr hdtr;
#endif

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: TinyHttpd optimized by Fumiama/1.0\r\n"

enum method_type_enum_t {GET, POST};
typedef enum method_type_enum_t method_type_enum_t;

struct http_request_t {
	const char *path;
	const char *method;
	const char *query_string;
	method_type_enum_t method_type;
};
typedef struct http_request_t http_request_t;

static char* hostnameport;

#define TCPOOL_THREADCNT 32

#define TCPOOL_THREAD_TIMER_T_SZ 65536

#define SERVER_THREAD_BUFSZ ( \
    TCPOOL_THREAD_TIMER_T_SZ    \
    -TCPOOL_THREAD_TIMER_T_HEAD_SZ  \
)

#define TCPOOL_THREAD_CONTEXT   \
    char data[SERVER_THREAD_BUFSZ]

static volatile uintptr_t is_in_cgi[TCPOOL_THREADCNT];

#define TCPOOL_TOUCH_TIMER_CONDITION (is_in_cgi[index])

#define TCPOOL_CLEANUP_THREAD_ACTION(timer) \
    is_in_cgi[timer->index] = 0;

#include "tcpool.h"

static void bad_request(int);
static void cat(int, int, size_t);
static void error_die(const char *);
static void execute_cgi(tcpool_thread_timer_t *, int, const http_request_t *);
static void forbidden(int);
static int get_line(int, char *, int);
static int headers(int, const char *, uint32_t);
static void internal_error(int);
static void not_found(int);
static void serve_file(int, const char *);
static int startup(uint16_t *, int);
static int startupunix(char *, int);
static void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/

/* read & discard headers */
#define discard(buf, client, numchars) \
	while(numchars > 0 && buf[0] != '\n' && buf[0] != '\r') numchars = get_line(client, buf, sizeof(buf))
#define methodequ(str, method) (*(uint32_t*)(method) == *(uint32_t*)(str))
#define skiptext(buf, j, cap) while(!ISspace(buf[j]) && (j < (cap))) j++
#define skipspace(buf, j, cap) while(ISspace(buf[j]) && (j < (cap))) j++
#define getmethod(method_type) ((method_type == GET)?"GET":"POST")
static void accept_action(tcpool_thread_timer_t *p) {
	int client = p->accept_fd;
	char *path, *query_string;
	int numchars, cgi = 0, j; // cgi becomes true if server decides this is a CGI program
	struct stat st;
	method_type_enum_t method_type;

	numchars = get_line(client, p->data, sizeof(p->data));
	j = 0;
	skiptext(p->data, j, numchars - 1);
	p->data[j] = '\0';

	if(methodequ(p->data, "GET")) method_type = GET;
	else if(methodequ(p->data, "POST")) {
		cgi = 1;
		method_type = POST;
	}
	else {
		unimplemented(client);
		discard(p->data, client, numchars);
		close(client);
		return;
	}

	skipspace(p->data, j, numchars - 1);
	path = p->data + j + 1;
	skiptext(p->data, j, numchars - 1);
	p->data[j] = 0;

	if(method_type == GET) {
		query_string = path;
		while((*query_string != '?') && (*query_string != '\0')) query_string++;
		if(*query_string == '?') {
			cgi = 1;
			*query_string = '\0';
			query_string++;
		}
	}

	// skip possible ../
	while((*path == '.' || *path == '/' || *path == '#') && *path != 0) path++;
	path -= 2;
	path[0] = '.'; path[1] = '/';

	printf("[%s] <%s> (%s) = ", getmethod(method_type), path, query_string);
	do {
		// 花括号不可省略
		if(stat(path, &st) == -1) {
			not_found(client);
			break;
		}

		int pathlen = strlen(path) + 1;
		char path_stack[pathlen + 11];	// 11 is for possible /index.html
		memcpy(path_stack, path, pathlen);
		printf("<%d> ", pathlen);
		path = path_stack;

		int query_length = strlen(query_string) + 1;
		char query_string_stack[query_length];
		memcpy(query_string_stack, query_string, query_length);
		query_string = query_string_stack;
		printf("(%d) ", query_length);

		if((st.st_mode & S_IFMT) == S_IFDIR) {
			strcat(path, "/index.html");
			// 花括号不可省略
			if(stat(path, &st) == -1) {
				not_found(client);
				break;
			}
		}
		int content_length = 0;
		int host_chk_passed = !(uintptr_t)hostnameport;
		cgi &= ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH));
		while(numchars > 0) {
			numchars = get_line(client, p->data, sizeof(p->data));
			if(p->data[0] == '\n' || p->data[0] == '\r') {
				numchars = 0;
				break;
			}
			if(!content_length && !strncasecmp(p->data, "Content-Length: ", 16)) {
				content_length = atoi(p->data + 16);
			}
			else if(!host_chk_passed && !strncasecmp(p->data, "Host: ", 6)) {
				if(strncasecmp(p->data+6, hostnameport, strlen(hostnameport))) {
					host_chk_passed = 0;
					break;
				}
				host_chk_passed = 1;
			}
		}
		if(!host_chk_passed) {
			forbidden(client);
			break;
		}
		if(method_type == POST && content_length == -1) bad_request(client);
		else if(!cgi) serve_file(client, path);
		else {
			http_request_t request;
			request.path = path;
			request.method = getmethod(method_type);
			request.method_type = method_type;
			request.query_string = query_string;
			execute_cgi(p, content_length, &request);
		}
	} while(0);
	discard(p->data, client, numchars);
	close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
#define HTTP400 "HTTP/1.0 400 BAD REQUEST\r\nContent-Type: text/html\r\n\r\n<P>Your browser sent a bad request, such as a POST without a Content-Length.\r\n"
static void bad_request(int client) {
	send(client, HTTP400, sizeof(HTTP400)-1, 0);
	puts("400 BAD REQUEST.");
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
static void cat(int client, int fd, size_t size) {
	off_t len = 0;
	#if __APPLE__
		sendfile(fd, client, 0, &len, &hdtr, 0);
	#else
		sendfile(client, fd, &len, size);
	#endif
	// printf("Sendfile: %u bytes.\n", (unsigned int)len);
}

/**********************************************************************/
/* Print out an error message with perror()(for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
static void error_die(const char *sc) {
	perror(sc);
	exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
static void execute_cgi(tcpool_thread_timer_t *timer, int content_length, const http_request_t* request) {
	int cgi_output[2], cgi_input[2];
	pid_t pid;
	int client = timer->accept_fd;

	if(pipe(cgi_output) < 0 || pipe(cgi_input) < 0 || (pid = fork()) < 0) {
		internal_error(client);
		return;
	}
	/* child: CGI script */
	if(pid == 0) {
		dup2(cgi_output[1], STDOUT_FILENO);
		dup2(cgi_input[0], STDIN_FILENO);
		close(cgi_output[0]);
		close(cgi_input[1]);

		execl(request->path, request->path, request->method, request->query_string, NULL);
		exit(EXIT_FAILURE); // a success execl will never return
	}
	/* parent */
	is_in_cgi[timer->index] = 1;
	close(cgi_output[1]);
	close(cgi_input[0]);
	if(request->method_type == POST) {
		#if __APPLE__
			for(int i = 0; i < content_length;) {
				int cnt = recv(client, timer->data, sizeof(timer->data), 0);
				if(cnt > 0) {
					write(cgi_input[1], timer->data, cnt);
					i += cnt;
				} else {
					internal_error(client);
					goto CGI_CLOSE;
				}
			}
		#else
			int len = 0;
			while(len < content_length) {
				int delta = splice(client, NULL, cgi_input[1], NULL, content_length - len, SPLICE_F_GIFT);
				if(delta <= 0) {
					internal_error(client);
					goto CGI_CLOSE;
				}
				len += delta;
			}
		#endif
	}

	uint32_t cnt = 0;
	char* p = (char*)&cnt;
	while(p - (char*)&cnt < sizeof(uint32_t)) {
		int offset = read(cgi_output[0], p, sizeof(uint32_t));
		if(offset > 0) p += offset;
		else {
			internal_error(client);
			goto CGI_CLOSE;
		}
	}
	printf("CGI msg len: %u bytes.\n", cnt);
	if(cnt > 0) {
		int len = 0;
		#if __APPLE__
			int cap = (cnt>sizeof(timer->data))?sizeof(timer->data):cnt;
			while(len < cnt) {
				int n = read(cgi_output[0], timer->data, cap);
				if(n <= 0) {
					internal_error(client);
					goto CGI_CLOSE;
				}
				len += n;
				send(client, timer->data, n, 0);
			}
		#else
			while(len < cnt) {
				int delta = splice(cgi_output[0], NULL, client, NULL, cnt - len, SPLICE_F_GIFT);
				if(delta <= 0) {
					internal_error(client);
					goto CGI_CLOSE;
				}
				len += delta;
			}
		#endif
		printf("CGI send %d bytes\n", len);
	}
CGI_CLOSE:
	close(cgi_output[0]);
	close(cgi_input[1]);
	waitpid(pid, NULL, 0);
	is_in_cgi[timer->index] = 0;
}

/**********************************************************************/
/* Inform the client that the server understood
   the request but refuses to authorize it
 * Parameters: client socket */
/**********************************************************************/
#define HTTP403 "HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<P>Your access is not allowed.\r\n"
static void forbidden(int client) {
	send(client, HTTP403, sizeof(HTTP403)-1, 0);
	puts("403 Forbidden.");
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored(excluding null) */
/**********************************************************************/
static int get_line(int sock, char *buf, int size) {
	int i = 0;
	char c = '\0';
	int n;

	while((i < size - 1) && (c != '\n')) {
		n = recv(sock, &c, 1, 0);
		if(n > 0) {
			if(c == '\r') {
				n = recv(sock, &c, 1, MSG_PEEK);
				/* DEBUG printf("%02X\n", c); */
				if((n > 0) && (c == '\n')) recv(sock, &c, 1, 0);
				else c = '\n';
			}
			buf[i++] = c;
		} else c = '\n';
	}
	buf[i] = '\0';

	return i;
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
#define add_header(h)\
	strcpy(buf + offset, h);\
	offset += sizeof(h) - 1;
#define add_header_para(h, p)\
	sprintf(buf + offset, h,(p));\
	offset += strlen(buf + offset);
#define extisnot(name) (strcmp(filepath+extpos, name))
#define HTTP200 "HTTP/1.0 200 OK\r\n"
#define CONTENT_TYPE "Content-Type: %s\r\n"
#define CONTENT_LEN "Content-Length: %d\r\n"
static int headers(int client, const char *filepath, uint32_t file_size) {
	char buf[1024];
	uint32_t offset = 0;
	uint32_t extpos = strlen(filepath) - 4;
	add_header(HTTP200 SERVER_STRING);
	add_header_para(CONTENT_TYPE, extisnot("html")?(extisnot(".css")?(extisnot(".ico")?"text/plain":"image/x-icon"):"text/css"):"text/html");
	add_header_para(CONTENT_LEN "\r\n", file_size);
	puts("200 OK.");
	return send(client, buf, offset, 0);
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
#define HTTP500 "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<P>Internal Server Error.\r\n"
static void internal_error(int client) {
	send(client, HTTP500, sizeof(HTTP500)-1, 0);
	puts("500 Internal Server Error.");
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
#define HTTP404 "HTTP/1.0 404 NOT FOUND\r\n" SERVER_STRING "Content-Type: text/html\r\n\r\n<HTML><TITLE>Not Found</TITLE>\r\n<BODY><P>The server could not fulfill\r\nyour request because the resource specified\r\nis unavailable or nonexistent.\r\n</BODY></HTML>\r\n"
static void not_found(int client) {
	send(client, HTTP404, sizeof(HTTP404)-1, 0);
	puts("404 Not Found.");
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
static void serve_file(int client, const char *filename) {
	int fd = open(filename, O_RDONLY);
	if(fd < 0) {
		perror("open");
		return not_found(client);
	}
	struct stat statbuf;
	if(fstat(fd, &statbuf)) {
		perror("fstat");
		return not_found(client);
	}
	if(headers(client, filename, (uint32_t)statbuf.st_size) <= 0) {
		perror("send");
		return not_found(client);
	}
	cat(client, fd, (size_t)statbuf.st_size);
	close(fd);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
static int startup(uint16_t *port, int listen_queue_len) {
	int httpd = bind_server(port);
	if(httpd < 0) exit(EXIT_FAILURE);
	if(listen_socket(httpd, listen_queue_len) < 0) exit(EXIT_FAILURE);
	return httpd;
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified path.
 * Parameters: the path to connect on
 * Returns: the socket */
/**********************************************************************/
static int startupunix(char *path, int listen_queue_len) {
	int httpd = bind_server_unix(path);
	if(httpd < 0) exit(EXIT_FAILURE);
	if(listen_socket(httpd, listen_queue_len) < 0) exit(EXIT_FAILURE);
	return httpd;
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
#define HTTP501 "HTTP/1.0 501 Method Not Implemented\r\n" SERVER_STRING "Content-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>Method Not Implemented\r\n</TITLE></HEAD>\r\n<BODY><P>HTTP request method not supported.\r\n</BODY></HTML>\r\n"
static void unimplemented(int client) {
	send(client, HTTP501, sizeof(HTTP501)-1, 0);
	puts("501 Method Not Implemented.");
}

#define argequ(arg) (*(uint16_t*)argv[i] == *(uint16_t*)(arg))
#define USAGE "Usage:\tsimple-http-server [-d] [-h] [-n host.name.com:port] [-p <port|unix socket path>] [-q 16] [-r <rootdir>] [-u <uid>]\n   -d:\trun as daemon.\n   -h:\tdisplay this help.\n   -n:\tcheck hostname and port.\n   -p:\tif not set, we will choose a random port.\n   -q:\tlisten queue length (defalut is 16).\n   -r:\thttp root dir.\n   -u:\trun as this uid."
int main(int argc, char **argv) {
	int as_daemon = 0;
	int queue_len = 16;
	uint16_t port = 0;
	char* socket_path = NULL;
	char *cdir = "./";
	uid_t uid = -1;
	int pid = -1;

	if(argc > 1+1+1+2+2+2+2+2) {
		puts(USAGE);
		exit(EXIT_SUCCESS);
	}

	for(int i = 1; i < argc; i++) {
		if(!as_daemon && argequ("-d")) as_daemon = 1;
		else if(argequ("-h"))  {
			puts(USAGE);
			exit(EXIT_SUCCESS);
		}
		else if(argequ("-n")) hostnameport = argv[++i];
		else if(argequ("-p")) {
			i++;
			if(isdigit(argv[i][0])) port = (uint16_t)atoi(argv[i]);
			else socket_path = argv[i];
		}
		else if(argequ("-q")) queue_len = atoi(argv[++i]);
		else if(argequ("-r")) cdir = argv[++i];
		else if(argequ("-u")) uid = atoi(argv[++i]);
		
		else {
			printf("unknown argument: %s\n", argv[i]);
			puts(USAGE);
			exit(EXIT_FAILURE);
		}
	}

	if(chdir(cdir)) error_die("chdir");

	if(as_daemon && daemon(1, 1) < 0) error_die("daemon");

	int server_sock = (!port&&socket_path)?startupunix(socket_path, queue_len):startup(&port, queue_len);
	if(port) printf("httpd running on 0.0.0.0:%d at %s\n", port, cdir);
	else printf("httpd running on %s at %s\n", socket_path, cdir);

	if(uid > 0) {
		setuid(uid);
		setgid(uid);
	}

	pthread_cleanup_push((void (*)(void*))&close, (void*)((long long)server_sock));
	accept_client(server_sock);
	pthread_cleanup_pop(1);
	return 99;
}
