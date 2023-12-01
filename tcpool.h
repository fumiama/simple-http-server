#ifndef _TCPOOL_H_
#define _TCPOOL_H_

/* See feature_test_macros(7) */
#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef TCPOOL_THREAD_TIMER_T_SZ
    #define TCPOOL_THREAD_TIMER_T_SZ 1024
#endif

#define TCPOOL_THREAD_TIMER_T_HEAD_SZ ( \
        sizeof(uint32_t)   \
        +sizeof(int)        \
        +sizeof(time_t)     \
        +sizeof(pthread_rwlock_t)   \
        +2*sizeof(pthread_t)        \
        +2*sizeof(pthread_cond_t)   \
        +2*sizeof(pthread_mutex_t)  \
        +sizeof(pthread_rwlock_t)   \
        +2*sizeof(uint8_t)          \
    )

#ifndef TCPOOL_THREADCNT
    #define TCPOOL_THREADCNT 32
#endif

#ifndef TCPOOL_MAXWAITSEC
    #define TCPOOL_MAXWAITSEC 8
#endif

#ifndef TCPOOL_THREAD_CONTEXT
    #define TCPOOL_THREAD_CONTEXT uint8_t __padding[  \
        TCPOOL_THREAD_TIMER_T_SZ        \
        -TCPOOL_THREAD_TIMER_T_HEAD_SZ  \
    ]
#endif

#ifndef TCPOOL_TOUCH_TIMER_CONDITION
    #define TCPOOL_TOUCH_TIMER_CONDITION (0)
#endif

#ifndef TCPOOL_INIT_ACTION
    #define TCPOOL_INIT_ACTION ;
#endif

#ifndef TCPOOL_PREHANDLE_ACCEPT_ACTION
    #define TCPOOL_PREHANDLE_ACCEPT_ACTION(timer) ;
#endif

#ifndef TCPOOL_CLEANUP_THREAD_ACTION
    #define TCPOOL_CLEANUP_THREAD_ACTION(timer) ;
#endif

struct tcpool_thread_timer_t {
    uint32_t index;
    int accept_fd;
    time_t touch;           // lock by mt
    pthread_rwlock_t mt;    // lock touch
    pthread_t thread;
    pthread_t timerthread;
    pthread_cond_t c;       // lock by mc
    pthread_mutex_t mc;     // lock c
    pthread_cond_t tc;      // lock by tmc
    pthread_mutex_t tmc;    // lock tc&hastimerslept
    pthread_rwlock_t mb;    // lock isbusy
    TCPOOL_THREAD_CONTEXT;
    uint8_t isbusy;         // lock by mb
    uint8_t hastimerslept;  // lock by tmc
};
typedef struct tcpool_thread_timer_t tcpool_thread_timer_t;

static tcpool_thread_timer_t tcpool_timers[TCPOOL_THREADCNT];

#define tcpool_timer_pointer_of(x) ((tcpool_thread_timer_t*)(x))

#define tcpool_touch_timer(x) { \
    pthread_rwlock_wrlock(&tcpool_timer_pointer_of(x)->mt); \
    tcpool_timer_pointer_of(x)->touch = time(NULL); \
    printf("Touch timer@%d\n", tcpool_timer_pointer_of(x)->index);\
    pthread_rwlock_unlock(&tcpool_timer_pointer_of(x)->mt); \
}

#ifdef LISTEN_ON_IPV6
    static socklen_t tcpool_struct_len = sizeof(struct sockaddr_in6);
    static struct sockaddr_in6 tcpool_server_addr;
#else
    static socklen_t tcpool_struct_len = sizeof(struct sockaddr_in);
    static struct sockaddr_in tcpool_server_addr;
#endif

static pthread_attr_t __tcpool_thread_attr;
static pthread_key_t __tcpool_pthread_key_index;
static sigjmp_buf __tcpool_jmp2convend[TCPOOL_THREADCNT];

static void accept_action(tcpool_thread_timer_t *timer);
static void accept_client(int fd);
static void accept_timer(void *p);
static int bind_server(uint16_t* port);
static void cleanup_thread(tcpool_thread_timer_t* timer);
static void handle_accept(void *accept_fd_p);
static void handle_int(int signo);
static void handle_kill(int signo);
static void handle_pipe(int signo);
static void handle_quit(int signo);
static void handle_segv(int signo);
static int listen_socket(int fd);

static int bind_server(uint16_t* port) {
    #ifdef LISTEN_ON_IPV6
        tcpool_server_addr.sin6_family = AF_INET6;
        tcpool_server_addr.sin6_port = htons(*port);
        bzero(&(tcpool_server_addr.sin6_addr), sizeof(tcpool_server_addr.sin6_addr));
        int fd = socket(PF_INET6, SOCK_STREAM, 0);
    #else
        tcpool_server_addr.sin_family = AF_INET;
        tcpool_server_addr.sin_port = htons(*port);
        tcpool_server_addr.sin_addr.s_addr = INADDR_ANY;
        bzero(&(tcpool_server_addr.sin_zero), 8);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif
    int on = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
        perror("Set socket option failure");
        return 0;
    }
    if(!~bind(fd, (struct sockaddr *)&tcpool_server_addr, tcpool_struct_len)) {
        perror("Bind server failure");
        return 0;
    }
    #ifdef LISTEN_ON_IPV6
        *port = ntohs(tcpool_server_addr.sin6_port);
        struct in6_addr in = tcpool_server_addr.sin6_addr;
        char str[INET6_ADDRSTRLEN];	// 46
        inet_ntop(AF_INET6, &in, str, sizeof(str));
    #else
        *port = ntohs(tcpool_server_addr.sin_port);
        struct in_addr in = tcpool_server_addr.sin_addr;
        char str[INET_ADDRSTRLEN];	// 16
        inet_ntop(AF_INET, &in, str, sizeof(str));
    #endif
    printf("Bind server successfully on %s:%u\n", str, *port);
    return fd;
}

static int listen_socket(int fd) {
    if(!~listen(fd, TCPOOL_THREADCNT)) {
        perror("Listen failed");
        return 0;
    }
    puts("Listening...");
    return fd;
}

static void handle_quit(int signo) {
    uint32_t index = (uint32_t)((uintptr_t)pthread_getspecific(__tcpool_pthread_key_index));
    printf("Handle sigquit@%d\n", index-1);
    fflush(stdout);
    if(index) {
        sigaction(SIGQUIT, &(const struct sigaction){handle_quit}, NULL);
        siglongjmp(__tcpool_jmp2convend[index-1], signo);
    }
    else pthread_exit(NULL);
}

static void handle_segv(int signo) {
    uint32_t index = (uint32_t)((uintptr_t)pthread_getspecific(__tcpool_pthread_key_index));
    printf("Handle sigsegv@%d\n", index-1);
    fflush(stdout);
    if(index) {
        sigaction(SIGSEGV, &(const struct sigaction){handle_segv}, NULL);
        siglongjmp(__tcpool_jmp2convend[index-1], signo);
    }
    else pthread_exit(NULL);
}

static void handle_kill(int signo) {
    puts("Handle sigkill/sigterm");
    fflush(stdout);
    exit(signo);
}

static void handle_int(int signo) {
    puts("Keyboard interrupted");
    fflush(stdout);
    exit(signo);
}

static void handle_pipe(int signo) {
    uint32_t index = (uint32_t)((uintptr_t)pthread_getspecific(__tcpool_pthread_key_index));
    printf("Pipe error@%d, break loop...\n", index-1);
    fflush(stdout);
    if(index) {
        sigaction(SIGPIPE, &(const struct sigaction){handle_pipe}, NULL);
        siglongjmp(__tcpool_jmp2convend[index-1], signo);
    }
    else pthread_exit(NULL);
}

static void accept_timer(void *p) {
    tcpool_thread_timer_t *timer = tcpool_timer_pointer_of(p);
    uint32_t index = timer->index;
    pthread_t thread = timer->thread;
    uint8_t isbusy;

    sleep(TCPOOL_MAXWAITSEC / 4);
    while(thread && !pthread_kill(thread, 0)) {
        pthread_rwlock_rdlock(&timer->mb);
        isbusy = timer->isbusy;
        pthread_rwlock_unlock(&timer->mb);
        if(!isbusy) {
        TIMER_SLEEP:
            pthread_mutex_lock(&timer->tmc);
            timer->hastimerslept = 1;
            printf("Timer@%d sleep\n", timer->index);
            pthread_cond_wait(&timer->tc, &timer->tmc);
            timer->hastimerslept = 0;
            pthread_mutex_unlock(&timer->tmc);
            printf("Timer@%d wake up\n", timer->index);
            sleep(TCPOOL_MAXWAITSEC / 4);
            thread = timer->thread;
        }
        if(TCPOOL_TOUCH_TIMER_CONDITION) tcpool_touch_timer(p);
        pthread_rwlock_rdlock(&timer->mt);
        time_t waitsec = time(NULL) - timer->touch;
        pthread_rwlock_unlock(&timer->mt);
        printf("Wait@%d sec: %u, max: %u\n", timer->index, (unsigned int)waitsec, TCPOOL_MAXWAITSEC);
        if(waitsec > TCPOOL_MAXWAITSEC) {
            if(thread) {
                pthread_kill(thread, SIGQUIT);
                printf("Kill thread@%d\n", timer->index);
            }
            break;
        }
        sleep(TCPOOL_MAXWAITSEC / 4);
        thread = timer->thread;
    }
    goto TIMER_SLEEP;
}

static void cleanup_thread(tcpool_thread_timer_t* timer) {
    printf("Start cleaning@%d, ", timer->index);

    if(timer->accept_fd) {
        close(timer->accept_fd);
        timer->accept_fd = 0;
        printf("Close accept, ");
    }

    TCPOOL_CLEANUP_THREAD_ACTION(timer);

    timer->thread = 0;
    printf("Clear thread, ");

    pthread_cond_destroy(&timer->c);
    printf("Destroy accept cond, ");

    pthread_mutex_destroy(&timer->mc);
    printf("Destroy accept mutex, ");

    pthread_rwlock_wrlock(&timer->mb);
    timer->isbusy = 0;
    printf("Clear busy, ");
    pthread_rwlock_unlock(&timer->mb);

    puts("Finish cleaning");
}

static void handle_accept(void *p) {
    #ifdef DEBUG
        printf("accept ptr: %p\n", p);
    #endif
    pthread_cleanup_push((void (*)(void*))&cleanup_thread, p);
    puts("Handling accept...");
    pthread_setspecific(__tcpool_pthread_key_index, (void*)((uintptr_t)tcpool_timer_pointer_of(p)->index+1));
    if(sigsetjmp(__tcpool_jmp2convend[tcpool_timer_pointer_of(p)->index], 1)) {
        printf("Long Jump@%d\n", tcpool_timer_pointer_of(p)->index);
        goto CONV_END;
    }
    while(1) {
        accept_action(tcpool_timer_pointer_of(p));
        CONV_END: puts("Conversation end");

        if(tcpool_timer_pointer_of(p)->accept_fd) {
            close(tcpool_timer_pointer_of(p)->accept_fd);
            tcpool_timer_pointer_of(p)->accept_fd = 0;
            puts("Close accept");
        }

        TCPOOL_CLEANUP_THREAD_ACTION(tcpool_timer_pointer_of(p));

        pthread_mutex_lock(&tcpool_timer_pointer_of(p)->mc);

        pthread_rwlock_wrlock(&tcpool_timer_pointer_of(p)->mb);
        tcpool_timer_pointer_of(p)->isbusy = 0;
        pthread_rwlock_unlock(&tcpool_timer_pointer_of(p)->mb);

        puts("Set thread status to idle");
        pthread_cond_wait(&tcpool_timer_pointer_of(p)->c, &tcpool_timer_pointer_of(p)->mc);
    
        pthread_mutex_unlock(&tcpool_timer_pointer_of(p)->mc);
        puts("Thread wakeup");
    }
    pthread_cleanup_pop(1);
}

static void accept_client(int fd) {
    sigaction(SIGINT , &(const struct sigaction){handle_int}, NULL);
    sigaction(SIGQUIT, &(const struct sigaction){handle_quit}, NULL);
    sigaction(SIGKILL, &(const struct sigaction){handle_kill}, NULL);
    sigaction(SIGSEGV, &(const struct sigaction){handle_segv}, NULL);
    sigaction(SIGPIPE, &(const struct sigaction){handle_pipe}, NULL);
    sigaction(SIGTERM, &(const struct sigaction){handle_kill}, NULL);
    pthread_attr_init(&__tcpool_thread_attr);
    pthread_attr_setdetachstate(&__tcpool_thread_attr, PTHREAD_CREATE_DETACHED);
    TCPOOL_INIT_ACTION;
    int i = 0;
    for(; i < TCPOOL_THREADCNT; i++) {
        pthread_rwlock_init(&tcpool_timers[i].mt, NULL);
        pthread_rwlock_init(&tcpool_timers[i].mb, NULL);
    }
    pthread_key_create(&__tcpool_pthread_key_index, NULL);
    while(1) {
        int p = 0;
        while(p < TCPOOL_THREADCNT) {
            pthread_rwlock_rdlock(&tcpool_timers[p].mb);
            if(!tcpool_timers[p].isbusy) break;
            pthread_rwlock_unlock(&tcpool_timers[p].mb);
            p++;
        }
        if(p >= TCPOOL_THREADCNT) {
            puts("Max thread cnt exceeded");
            sleep(1);
            continue;
        }
        printf("Ready for accept on slot No.%d\n", p);
        tcpool_thread_timer_t* timer = &tcpool_timers[p];
        pthread_rwlock_unlock(&timer->mb);
        #ifdef LISTEN_ON_IPV6
            struct sockaddr_in6 client_addr;
        #else
            struct sockaddr_in client_addr;
        #endif
        int accept_fd;
        if((accept_fd=accept(fd, (struct sockaddr *)&client_addr, &tcpool_struct_len))<=0) {
            perror("Accept client error");
            continue;
        }
        pthread_rwlock_wrlock(&timer->mb);
        timer->isbusy = 1;
        pthread_rwlock_unlock(&timer->mb);
        #ifdef LISTEN_ON_IPV6
            uint16_t port = ntohs(client_addr.sin6_port);
            struct in6_addr in = client_addr.sin6_addr;
            char str[INET6_ADDRSTRLEN];	// 46
            inet_ntop(AF_INET6, &in, str, sizeof(str));
        #else
            uint16_t port = ntohs(client_addr.sin_port);
            struct in_addr in = client_addr.sin_addr;
            char str[INET_ADDRSTRLEN];	// 16
            inet_ntop(AF_INET, &in, str, sizeof(str));
        #endif
        time_t t = time(NULL);
        printf("\n> %sAccept client %s:%u at slot No.%d, ", ctime(&t), str, port, p);
        timer->accept_fd = accept_fd;
        timer->index = p;
        pthread_rwlock_wrlock(&timer->mt);
        timer->touch = time(NULL);
        pthread_rwlock_unlock(&timer->mt);
        TCPOOL_PREHANDLE_ACCEPT_ACTION(timer);
        // start or wakeup accept thread
        pthread_t thread = timer->thread;
        if(thread && !pthread_kill(thread, 0)) {
            pthread_mutex_lock(&timer->mc);
            pthread_cond_signal(&timer->c); // wakeup thread
            pthread_mutex_unlock(&timer->mc);
            puts("Pick thread from pool");
        } else {
            pthread_cond_init(&timer->c, NULL);
            pthread_mutex_init(&timer->mc, NULL);
            if (pthread_create(&timer->thread, &__tcpool_thread_attr, (void* (*)(void*))&handle_accept, timer)) {
                perror("Error creating thread");
                cleanup_thread(timer);
                putchar('\n');
                continue;
            }
            puts("Thread created");
        }
        // start or wakeup timer thread
        thread = timer->timerthread;
        if(!thread || pthread_kill(thread, 0)) {
            printf("Creating timer thread...");
            pthread_cond_init(&timer->tc, NULL);
            pthread_mutex_init(&timer->tmc, NULL);
            timer->hastimerslept = 0;
            if (pthread_create(&timer->timerthread, &__tcpool_thread_attr, (void* (*)(void*))&accept_timer, timer)) {
                perror("Error creating timer thread");
                cleanup_thread(timer);
                putchar('\n');
                continue;
            }
            puts("succeeded");
        } else {
            pthread_mutex_lock(&timer->tmc);
            uint8_t hastimerslept = timer->hastimerslept;
            pthread_mutex_unlock(&timer->tmc);
            if(hastimerslept) {
                printf("Waking up timer thread...");
                pthread_mutex_lock(&timer->tmc);
                pthread_cond_signal(&timer->tc); // wakeup thread
                pthread_mutex_unlock(&timer->tmc);
                puts("succeeded");
            } else puts("Timer already running");
        }
    }
}

#endif /* _TCPOOL_H_ */
