/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344(Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 *
 * Modified June 2021 by Fumiama(源文雨)
 */
/* See feature_test_macros(7) */
#define _GNU_SOURCE 1
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

#define SERVER_STRING "Server: TinyHttpd modified by Fumiama/1.0\r\n"

enum METHOD_TYPE {GET, POST};
typedef enum METHOD_TYPE METHOD_TYPE;

struct HTTP_REQUEST {
	const char *path;
	const char *method;
	METHOD_TYPE method_type;
	const char *query_string;
};
typedef struct HTTP_REQUEST HTTP_REQUEST;

static void accept_request(void *);
static void bad_request(int);
static void cat(int, FILE *);
static void cannot_execute(int);
static void error_die(const char *);
static void execute_cgi(int, int, const HTTP_REQUEST*);
static uint32_t get_file_size(const char *, int);
static int get_line(int, char *, int);
static void handle_quit(int);
static int headers(int, const char *);
static void not_found(int);
static void serve_file(int, const char *);
static int startup(u_int16_t *);
static int startupunix(char *);
static void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/

/* read & discard headers */
#define discard(client) \
	while((numchars > 0) && strcmp("\n", buf)) numchars = get_line(client, buf, sizeof(buf))
#define methodequ(str, method) (*(uint32_t*)(method) == *(uint32_t*)(str))
#define skiptext(buf, j, cap) while(!ISspace(buf[j]) && (j < (cap))) j++
#define skipspace(buf, j, cap) while(ISspace(buf[j]) && (j < (cap))) j++
#define getmethod(method_type) ((method_type == GET)?"GET":"POST")

static void accept_request(void *cli) {
	int client = (int)cli;
	char buf[1024], *path, *query_string;
	int numchars, cgi = 0, j; // cgi becomes true if server decides this is a CGI program
	struct stat st;
	METHOD_TYPE method_type;

	numchars = get_line(client, buf, sizeof(buf));
	j = 0;
	skiptext(buf, j, numchars - 1);
	buf[j] = '\0';

	if(methodequ(buf, "GET")) method_type = GET;
	else if(methodequ(buf, "POST")) {
		cgi = 1;
		method_type = POST;
	}

	skipspace(buf, j, numchars - 1);
	path = buf + j + 1;
	skiptext(buf, j, numchars - 1);
	buf[j] = 0;

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
	// 花括号不可省略
	if(stat(path, &st) == -1) {
		discard(client);
		not_found(client);
	} else {
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
				discard(client);
				not_found(client);
				close(client);
				return;
			}
		}
		int content_length = 0;
		cgi &= ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH));
		while((numchars > 0) && strcmp("\n", buf)) {
			numchars = get_line(client, buf, sizeof(buf));
			if(!content_length && strcasestr(buf, "Content-Length: ")) {
				content_length = atoi(buf + 16);
			}
		}
		if(method_type == POST && content_length == -1) bad_request(client);
		else if(!cgi) serve_file(client, path);
		else {
			HTTP_REQUEST request;
			request.path = path;
			request.method = getmethod(method_type);
			request.method_type = method_type;
			request.query_string = query_string;
			execute_cgi(client, content_length, &request);
		}
	}
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
static void cat(int client, FILE *resource) {
	off_t len = 0;
	#if __APPLE__
		sendfile(fileno(resource), client, 0, &len, &hdtr, 0);
	#else
		fseek(resource, 0, SEEK_END);
		off_t file_size = ftell(resource);
		rewind(resource);
		sendfile(client, fileno(resource), &len, file_size);
	#endif
	printf("Sendfile: %u bytes.\n", (unsigned int)len);
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
#define HTTP500 "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<P>Internal Server Error.\r\n"
static void cannot_execute(int client) {
	send(client, HTTP500, sizeof(HTTP500)-1, 0);
	puts("500 Internal Server Error.");
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
static void execute_cgi(int client, int content_length, const HTTP_REQUEST* request) {
	int cgi_output[2], cgi_input[2], i;
	pid_t pid;

	if(pipe(cgi_output) < 0 || pipe(cgi_input) < 0 || (pid = fork()) < 0) cannot_execute(client);
	/* child: CGI script */
	else if(pid == 0) {
		char env[255];

		dup2(cgi_output[1], 1);
		dup2(cgi_input[0], 0);
		close(cgi_output[0]);
		close(cgi_input[1]);
		sprintf(env, "REQUEST_METHOD=%s", request->method);
		putenv(env);
		if(request->method_type == GET) {
			sprintf(env, "QUERY_STRING=%s", request->query_string);
			putenv(env);
		}
		else { /* POST */
			sprintf(env, "CONTENT_LENGTH=%d", content_length);
			putenv(env);
		}
		execl(request->path, request->path, request->method, request->query_string, NULL);
		exit(0);
	}
	else { /* parent */
		char buf[1024];

		close(cgi_output[1]);
		close(cgi_input[0]);
		if(request->method_type == POST) {
			#if __APPLE__
				for(i = 0; i < content_length;) {
					int cnt = recv(client, buf, 1024, 0);
					if(cnt > 0) {
						write(cgi_input[1], buf, cnt);
						i += cnt;
					} else {
						cannot_execute(client);
						goto CGI_CLOSE;
					}
				}
			#else
				int len = 0;
				while(len < content_length) {
					int delta = splice(client, NULL, cgi_input[1], NULL, content_length - len, SPLICE_F_GIFT);
					if(delta <= 0) {
						cannot_execute(client);
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
				cannot_execute(client);
				goto CGI_CLOSE;
			}
		}
		printf("CGI msg len: %u bytes.\n", cnt);
		if(cnt > 0) {
			int len = 0;
			#if __APPLE__
				char* data = malloc(cnt);
				while(len < cnt) {
					int n = read(cgi_output[0], data, cnt);
					if(n <= 0) {
						if(data) free(data);
						cannot_execute(client);
						goto CGI_CLOSE;
					}
					len += n;
					send(client, data, len, 0);
				}
				if(data) free(data);
			#else
				while(len < cnt) {
					int delta = splice(cgi_output[0], NULL, client, NULL, cnt - len, SPLICE_F_GIFT);
					if(delta <= 0) {
						cannot_execute(client);
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
		waitpid(pid, &i, 0);
	}
}

/**********************************************************************/
/* Returns the size of a file. */
/* Parameters: path of the file */
/**********************************************************************/
static uint32_t get_file_size(const char *filepath, int client) {
	struct stat statbuf;
	uint32_t sz;
	if(!stat(filepath, &statbuf)) {
		sz = statbuf.st_size;
		printf("[%u] - ", sz);
		return sz;
	}
	else return 0;
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
/* Handle thread quit signal */
/**********************************************************************/
static void handle_quit(int signo) {
	perror("handle");
	pthread_exit(NULL);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
#define ADD_HERDER(h)\
	strcpy(buf + offset, h);\
	offset += sizeof(h) - 1;
#define ADD_HERDER_PARAM(h, p)\
	sprintf(buf + offset, h,(p));\
	offset += strlen(buf + offset);
#define EXTNM_IS_NOT(name)(strcmp(filepath+extpos, name))

#define HTTP200 "HTTP/1.0 200 OK\r\n"
#define CONTENT_TYPE "Content-Type: %s\r\n"
#define CONTENT_LEN "Content-Length: %d\r\n"
static int headers(int client, const char *filepath) {
	char buf[1024];
	uint32_t offset = 0;
	uint32_t extpos = strlen(filepath) - 4;
	uint32_t file_size = get_file_size(filepath, client);
	if(file_size) {
		ADD_HERDER(HTTP200 SERVER_STRING);
		ADD_HERDER_PARAM(CONTENT_TYPE, EXTNM_IS_NOT("html")?(EXTNM_IS_NOT(".css")?(EXTNM_IS_NOT(".ico")?"text/plain":"image/x-icon"):"text/css"):"text/html");
		ADD_HERDER_PARAM(CONTENT_LEN "\r\n", file_size);
		send(client, buf, offset, 0);
		puts("200 OK.");
		return 1;
	} else return 0;
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
	FILE *resource = NULL;

	resource = fopen(filename, "rb");
	if(resource) {
		if(headers(client, filename)) cat(client, resource);
		else not_found(client);
		fclose(resource);
	} else not_found(client);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
#ifdef LISTEN_ON_IPV6
	static socklen_t struct_len = sizeof(struct sockaddr_in6);
	static struct sockaddr_in6 name;
	static struct sockaddr_in6 client_name;
#else
	static socklen_t struct_len = sizeof(struct sockaddr_in);
	static struct sockaddr_in name;
	static struct sockaddr_in client_name;
#endif

static int startup(uint16_t *port) {
	int httpd = 0;

	#ifdef LISTEN_ON_IPV6
		name.sin6_family = AF_INET6;
		name.sin6_port = htons(*port);
		bzero(&(name.sin6_addr), sizeof(name.sin6_addr));
		httpd = socket(PF_INET6, SOCK_STREAM, 0);
	#else
		name.sin_family = AF_INET;
		name.sin_port = htons(*port);
		name.sin_addr.s_addr = INADDR_ANY;
		bzero(&(name.sin_zero), 8);
		httpd = socket(AF_INET, SOCK_STREAM, 0);
	#endif
	if(httpd < 0) error_die("socket");
	if(bind(httpd,(struct sockaddr *)&name, struct_len) < 0) error_die("bind");
	/* if dynamically allocating a port */
	if(*port == 0) {
		if(getsockname(httpd,(struct sockaddr *)&name, &struct_len) == -1) error_die("getsockname");
		#ifdef LISTEN_ON_IPV6
			*port = ntohs(name.sin6_port);
		#else
			*port = ntohs(name.sin_port);
		#endif
	}
	if(listen(httpd, 5) < 0) error_die("listen");
	return httpd;
}

static struct sockaddr_un uname;
static int startupunix(char *path) {
	int httpd = socket(AF_UNIX, SOCK_STREAM, 0);
	uname.sun_family = AF_UNIX;
	strncpy(uname.sun_path, path, sizeof(uname.sun_path));
	uname.sun_path[sizeof(uname.sun_path)-1] = 0; // avoid overlap
	uname.sun_len = strlen(path)+1; // including null
	if(httpd < 0) error_die("unix socket");
	unlink(path); // in case it already exists
	if(bind(httpd, (struct sockaddr *)&uname, (void*)uname.sun_path-(void*)&uname+uname.sun_len) < 0) error_die("bind");
	if(listen(httpd, 5) < 0) error_die("listen");
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

/************************************************************************/
/* simple-http-server
 * Usage: simple-http-server [-d] [-p <port>] [-r <rootdir>] [-u <uid>] */
/************************************************************************/
static pthread_attr_t attr;
static pthread_t accept_thread;
static socklen_t client_name_len = sizeof(client_name);
static int accept_client(int server_sock) {
	signal(SIGCHLD, SIG_IGN);
	signal(SIGQUIT, handle_quit);
	signal(SIGPIPE, handle_quit);
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
	while(1) {
		int client_sock = accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);
		if(client_sock == -1) continue;
		#ifdef LISTEN_ON_IPV6
			uint16_t port = ntohs(client_name.sin6_port);
			struct in6_addr in = client_name.sin6_addr;
			char str[INET6_ADDRSTRLEN];	// 46
			inet_ntop(AF_INET6, &in, str, sizeof(str));
		#else
			uint16_t port = ntohs(client_name.sin_port);
			struct in_addr in = client_name.sin_addr;
			char str[INET_ADDRSTRLEN];	// 16
			inet_ntop(AF_INET, &in, str, sizeof(str));
		#endif
		printf("Accept client %s:%u\n", str, port);
		if(pthread_create(&accept_thread, &attr, &accept_request, client_sock) != 0) perror("pthread_create");
	}
}

#define argequ(arg) (*(uint16_t*)argv[i] == *(uint16_t*)(arg))
#define USAGE "Usage:\tsimple-http-server [-h] [-d] [-p <port|unix socket path>] [-r <rootdir>] [-u <uid>]\n   -h:\tdisplay this help.\n   -d:\trun as daemon.\n   -p:\tif not set, we will choose a random port.\n   -r:\thttp root dir.\n   -u:\trun as this uid."
int main(int argc, char **argv) {
	if(argc > 8) puts(USAGE);
	else {
		int as_daemon = 0;
		uint16_t port = 0;
		char* socket_path = NULL;
		char *cdir = "./";
		uid_t uid = -1;
		int server_sock = -1;
		int pid = -1;

		for(int i = 1; i < argc; i++) {
			if(!as_daemon && argequ("-d")) as_daemon = 1;
			else if(argequ("-p")) {
				i++;
				if(isdigit(argv[i][0])) port = (uint16_t)atoi(argv[i]);
				else socket_path = argv[i];
			}
			else if(argequ("-r")) cdir = argv[++i];
			else if(argequ("-u")) uid = atoi(argv[++i]);
			else if(argequ("-h"))  {
				puts(USAGE);
				exit(EXIT_SUCCESS);
			}
			else {
				printf("unknown argument: %s\n", argv[i]);
				puts(USAGE);
				exit(EXIT_FAILURE);
			}
		}

		if(chdir(cdir)) error_die("chdir");
		server_sock = (!port&&socket_path)?startupunix(socket_path):startup(&port);
		if(port) printf("httpd running on 0.0.0.0:%d at %s\n", port, cdir);
		else printf("httpd running on %s at %s\n", socket_path, cdir);
		if(as_daemon) {
			if(uid > 0) {
				setuid(uid);
				setgid(uid);
			}
			pid = fork();
			if(pid == 0) pid = fork();
			else return 0;
			while(pid > 0) {      // 主进程监控子进程状态，如果子进程异常终止则重启之
				wait(NULL);
				puts("Server subprocess exited. Restart...");
				pid = fork();
			}
			if(pid < 0) perror("fork");
			else accept_client(server_sock);
		} else accept_client(server_sock);
	}
}
