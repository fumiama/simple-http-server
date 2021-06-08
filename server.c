/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 *
 * Modified June 2021 by Fumiama(源文雨)
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

#if !__APPLE__
    #include <sys/sendfile.h> 
#else
    static struct sf_hdtr hdtr;
#endif

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: TinyHttpd modified by Fumiama/1.0\r\n"

static void accept_request(void *);
static void bad_request(int);
static void cat(int, FILE *);
static void cannot_execute(int);
static void error_die(const char *);
static void execute_cgi(int, const char *, const char *, const char *);
static off_t get_file_size(const char *, int);
static int get_line(int, char *, int);
static void handle_quit(int);
static void headers(int, const char *);
static void not_found(int);
static void serve_file(int, const char *);
static int startup(u_short *);
static void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
static void accept_request(void *cli) {
    pthread_detach(pthread_self());
    int client = (int)cli;
    char buf[1024];
    int numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0; /* becomes true if server decides this is a CGI
                    * program */
    char *query_string = NULL;

    numchars = get_line(client, buf, sizeof(buf));
    i = 0;
    j = 0;
    while (!ISspace(buf[j]) && (i < sizeof(method) - 1)) {
        method[i] = buf[j];
        i++;
        j++;
    }
    method[i] = '\0';

    if (strcasecmp(method, "GET") && strcasecmp(method, "POST")) {
        unimplemented(client);
        return;
    }

    if (strcasecmp(method, "POST") == 0) cgi = 1;

    i = 0;
    while (ISspace(buf[j]) && (j < sizeof(buf)))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf))) {
        url[i] = buf[j];
        i++;
        j++;
    }
    url[i] = '\0';

    if (strcasecmp(method, "GET") == 0) {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0')) query_string++;
        if (*query_string == '?') {
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
    }

    //getcwd(path, sizeof(path));
    //strcat(path, url);
    sprintf(path, ".%s", url[1] == '#' ? url + 2 : url);
    if (path[strlen(path) - 1] == '/')
        strcat(path, "index.html");
    if (stat(path, &st) == -1) {
        while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);
    }
    else {
        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            //getcwd(path, sizeof(path));
            strcat(path, "/index.html");
        }
        if ((st.st_mode & S_IXUSR) ||
            (st.st_mode & S_IXGRP) ||
            (st.st_mode & S_IXOTH))
            cgi = 1;
        if (!cgi) serve_file(client, path);
        else execute_cgi(client, path, method, query_string);
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
    printf("Send %u bytes.\n", len);
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
#define HTTP500 "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<P>Internal Server Error.\r\n"
static void cannot_execute(int client) {
    send(client, HTTP500, sizeof(HTTP500)-1, 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
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
static void execute_cgi(int client, const char *path, const char *method, const char *query_string) {
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    int numchars = 1;
    int content_length = -1;

    buf[0] = 'A';
    buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)
        while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else /* POST */
    {
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf)) {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }

    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);

    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    if ((pid = fork()) < 0) {
        cannot_execute(client);
        return;
    }
    /* child: CGI script */
    if (pid == 0) {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        dup2(cgi_output[1], 1);
        dup2(cgi_input[0], 0);
        close(cgi_output[0]);
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else { /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        execl(path, path, method, query_string, NULL);
        exit(0);
    }
    else { /* parent */
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length;) {
                int cnt = recv(client, buf, 1024, 0);
                if(cnt > 0) {
                    write(cgi_input[1], buf, cnt);
                    i += cnt;
                }
            }
        uint32_t cnt = 0;
        if(read(cgi_output[0], (char*)&cnt, sizeof(uint32_t)) > 0) {
            printf("cgi msg cnt: %u bytes.\n", cnt);
            if(cnt > 0) {
                int len = 0;
                char* data = malloc(cnt);
                while(len < cnt) {
                    len += read(cgi_output[0], data, cnt);
                    send(client, data, len, 0);
                }
                if(data) free(data);
                printf("cgi send %d bytes\n", len);
            }
        } else cannot_execute(client);
        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* Returns the size of a file. */
/* Parameters: path of the file */
/**********************************************************************/
static off_t get_file_size(const char *filepath, int client) {
    struct stat statbuf;
    off_t sz;
    if (!stat(filepath, &statbuf)) {
        sz = statbuf.st_size;
        printf("file size: %lu\n", sz);
        return sz;
    }
    else {
        cannot_execute(client);
        error_die("stat");
    }
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
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
static int get_line(int sock, char *buf, int size) {
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n')) {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0) {
            if (c == '\r') {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else c = '\n';
    }
    buf[i] = '\0';

    return (i);
}

/**********************************************************************/
/* Handle thread quit signal
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
    sprintf(buf + offset, h, (p));\
    offset += strlen(buf + offset);
#define EXTNM_IS_NOT(name) (strcmp(filepath+extpos, name))

#define HTTP200 "HTTP/1.0 200 OK\r\n"
#define CONTENT_TYPE "Content-Type: %s\r\n"
#define CONTENT_LEN "Content-Length: %d\r\n"
static void headers(int client, const char *filepath) {
    char buf[1024];
    uint offset = 0;
    uint extpos = strlen(filepath) - 4;

    ADD_HERDER(HTTP200 SERVER_STRING);
    ADD_HERDER_PARAM(CONTENT_TYPE, EXTNM_IS_NOT("html")?(EXTNM_IS_NOT(".css")?(EXTNM_IS_NOT("ico")?"text/plain":"image/x-icon"):"text/css"):"text/html");
    ADD_HERDER_PARAM(CONTENT_LEN "\r\n", get_file_size(filepath, client));
    send(client, buf, offset, 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
#define HTTP404 "HTTP/1.0 404 NOT FOUND\r\n" SERVER_STRING "Content-Type: text/html\r\n\r\n<HTML><TITLE>Not Found</TITLE>\r\n<BODY><P>The server could not fulfill\r\nyour request because the resource specified\r\nis unavailable or nonexistent.\r\n</BODY></HTML>\r\n"
static void not_found(int client) {
    send(client, HTTP404, sizeof(HTTP404)-1, 0);
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
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A';
    buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf)) /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "rb");
    if (resource == NULL) not_found(client);
    else {
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
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
#else
    static socklen_t struct_len = sizeof(struct sockaddr_in);
    static struct sockaddr_in name;
#endif

static int startup(u_short *port) {
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
    if (httpd == -1)
        error_die("socket");
    if (bind(httpd, (struct sockaddr *)&name, struct_len) < 0)
        error_die("bind");
    /* if dynamically allocating a port */
    if (*port == 0) {
        if (getsockname(httpd, (struct sockaddr *)&name, &struct_len) == -1)
            error_die("getsockname");
#ifdef LISTEN_ON_IPV6
        *port = ntohs(name.sin6_port);
#else
        *port = ntohs(name.sin_port);
#endif
    }
    if (listen(httpd, 5) < 0)
        error_die("listen");
    return (httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
#define HTTP501 "HTTP/1.0 501 Method Not Implemented\r\n" SERVER_STRING "Content-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>Method Not Implemented\r\n</TITLE></HEAD>\r\n<BODY><P>HTTP request method not supported.\r\n</BODY></HTML>\r\n"
static void unimplemented(int client) {
    send(client, HTTP501, sizeof(HTTP501)-1, 0);
}

/**********************************************************************/
/* simple-http-server
 * Usage: simple-http-server -d port chdir
/**********************************************************************/
#define ACCEPT_CLI() {\
    while (1) {\
        client_sock = accept(server_sock, (struct sockaddr *)&client_name, &client_name_len);\
        if (client_sock == -1) break;\
        signal(SIGQUIT, handle_quit);\
        signal(SIGPIPE, handle_quit);\
        if (pthread_create(&newthread, NULL, accept_request, client_sock) != 0) perror("pthread_create");\
    }\
    close(client_sock);\
    error_die("accept");\
}

int main(int argc, char **argv) {
    if(argc != 3 && argc != 4) puts("Usage: simple-http-server -d port chdir");
    else {
        int as_daemon = *(uint16_t*)argv[1] == *(uint16_t*)"-d";
        int server_sock = -1;
        u_short port = (u_short)atoi(argv[as_daemon?2:1]);
        int client_sock = -1;
        int pid = -1;
        struct sockaddr_in client_name;
        socklen_t client_name_len = sizeof(client_name);
        pthread_t newthread;

        char *cdir = argv[as_daemon?3:2];
        if(chdir(cdir)) error_die("chdir");
        server_sock = startup(&port);
        printf("httpd running on port %d\n", port);
        if(as_daemon) {
            pid = fork();
            if(pid == 0) pid = fork();
            else return 0;
            while (pid > 0) {      //主进程监控子进程状态，如果子进程异常终止则重启之
                wait(NULL);
                puts("Server subprocess exited. Restart...");
                pid = fork();
            }
            if(pid < 0) perror("fork");
            else ACCEPT_CLI();
        } else ACCEPT_CLI();
    }
}
