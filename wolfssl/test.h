/* test.h */

#ifndef wolfSSL_TEST_H
#define wolfSSL_TEST_H

    #include <stdio.h>
    #include <stdlib.h>
#include <assert.h>
#include <ctype.h>
    #include <errno.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/asn.h>


#if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
    #include <string.h>
    #include "rl_net.h"
    #define SOCKET_T int
    typedef int socklen_t ;
    #define inet_addr wolfSSL_inet_addr
    static unsigned long wolfSSL_inet_addr(const char *cp)
    {
        unsigned int a[4] ; unsigned long ret ;
        sscanf(cp, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]) ;
        ret = ((a[3]<<24) + (a[2]<<16) + (a[1]<<8) + a[0]) ;
        return(ret) ;
    }
    #if defined(HAVE_KEIL_RTX)
        #define XSLEEP_MS(t)  os_dly_wait(t)
    #elif defined(WOLFSSL_CMSIS_RTOS) || defined(WOLFSSL_CMSIS_RTOSv2)
        #define XSLEEP_MS(t)  osDelay(t)
    #endif
#elif defined(WOLFSSL_TIRTOS)
    #include <string.h>
    #include <netdb.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <ti/sysbios/knl/Task.h>
    struct hostent {
        char *h_name; /* official name of host */
        char **h_aliases; /* alias list */
        int h_addrtype; /* host address type */
        int h_length; /* length of address */
        char **h_addr_list; /* list of addresses from name server */
    };
    #define SOCKET_T int
    #define XSLEEP_MS(t) Task_sleep(t/1000)
#elif defined(WOLFSSL_VXWORKS)
    #include <hostLib.h>
    #include <sockLib.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <selectLib.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #include <netdb.h>
    #include <pthread.h>
    #define SOCKET_T int
#elif defined(WOLFSSL_ZEPHYR)
    #include <string.h>
    #include <sys/types.h>
    #include <net/socket.h>
    #define SOCKET_T int
    #define SOL_SOCKET 1
    #define WOLFSSL_USE_GETADDRINFO

    static unsigned long inet_addr(const char *cp)
    {
        unsigned int a[4]; unsigned long ret;
        int i, j;
        for (i=0, j=0; i<4; i++) {
            a[i] = 0;
            while (cp[j] != '.' && cp[j] != '\0') {
                a[i] *= 10;
                a[i] += cp[j] - '0';
                j++;
            }
        }
        ret = ((a[3]<<24) + (a[2]<<16) + (a[1]<<8) + a[0]) ;
        return(ret) ;
    }
#elif defined(NETOS)
    #include <string.h>
    #include <sys/types.h>
    struct hostent {
        char* h_name;        /* official name of host */
        char** h_aliases;    /* alias list */
        int h_addrtype;      /* host address type */
        int h_length;        /* length of address */
        char** h_addr_list;  /* list of addresses from the name server */
    };
#else
    #include <string.h>
    #include <sys/types.h>
#ifndef WOLFSSL_LEANPSK
    #include <unistd.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <pthread.h>
    #include <fcntl.h>
    #ifdef TEST_IPV6
        #include <netdb.h>
    #endif
#endif
    #define SOCKET_T int
    #ifndef SO_NOSIGPIPE
        #include <signal.h>  /* ignore SIGPIPE */
    #endif
    #define SNPRINTF snprintf

    #define XSELECT_WAIT(x,y) do { \
        struct timeval tv = {((x) + ((y) / 1000000)),((y) % 1000000)}; \
        select(0, NULL, NULL, NULL, &tv); \
    } while (0)
    #define XSLEEP_US(u) XSELECT_WAIT(0,u)
    #define XSLEEP_MS(m) XSELECT_WAIT(0,(m)*1000)
#endif /* USE_WINDOWS_API */

#ifndef XSLEEP_MS
    #define XSLEEP_MS(t) sleep(t/1000)
#endif

#ifdef HAVE_CAVIUM
    #include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#endif

#ifndef WOLFSSL_CIPHER_LIST_MAX_SIZE
    #define WOLFSSL_CIPHER_LIST_MAX_SIZE 4096
#endif
/* Buffer for benchmark tests */
#ifndef TEST_BUFFER_SIZE
    #define TEST_BUFFER_SIZE 16384
#endif

#ifndef WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MIN
    static WC_INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }
#endif /* WOLFSSL_HAVE_MIN */

/* Socket Handling */
#ifndef WOLFSSL_SOCKET_INVALID
#if defined(WOLFSSL_TIRTOS)
    #define WOLFSSL_SOCKET_INVALID  ((SOCKET_T)-1)
#else
    #define WOLFSSL_SOCKET_INVALID  (SOCKET_T)(0)
#endif
#endif /* WOLFSSL_SOCKET_INVALID */

#ifndef WOLFSSL_SOCKET_IS_INVALID
#if defined(WOLFSSL_TIRTOS)
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) == WOLFSSL_SOCKET_INVALID)
#else
    #define WOLFSSL_SOCKET_IS_INVALID(s)  ((SOCKET_T)(s) < WOLFSSL_SOCKET_INVALID)
#endif
#endif /* WOLFSSL_SOCKET_IS_INVALID */

#if defined(__MACH__)
    #ifndef _SOCKLEN_T
        typedef int socklen_t;
    #endif
#endif


/* HPUX doesn't use socklent_t for third parameter to accept, unless
   _XOPEN_SOURCE_EXTENDED is defined */
#if !defined(__hpux__) && !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_IAR_ARM)\
 && !defined(WOLFSSL_ROWLEY_ARM)  && !defined(WOLFSSL_KEIL_TCP_NET)
    typedef socklen_t* ACCEPT_THIRD_T;
#else
    #if defined _XOPEN_SOURCE_EXTENDED
        typedef socklen_t* ACCEPT_THIRD_T;
    #else
        typedef int*       ACCEPT_THIRD_T;
    #endif
#endif



    #if !defined(__MINGW32__)
        typedef void*         THREAD_RETURN;
        typedef pthread_t     THREAD_TYPE;
        #define WOLFSSL_THREAD
        #define INFINITE (-1)
        #define WAIT_OBJECT_0 0L
    #elif defined(WOLFSSL_MDK_ARM)|| defined(WOLFSSL_KEIL_TCP_NET)
        typedef unsigned int  THREAD_RETURN;
        typedef int           THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_TIRTOS)
        typedef void          THREAD_RETURN;
        typedef Task_Handle   THREAD_TYPE;
        #ifdef HAVE_STACK_SIZE
          #undef EXIT_TEST
          #define EXIT_TEST(ret)
        #endif
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_ZEPHYR)
        typedef void            THREAD_RETURN;
        typedef struct k_thread THREAD_TYPE;
        #ifdef HAVE_STACK_SIZE
          #undef EXIT_TEST
          #define EXIT_TEST(ret)
        #endif
        #define WOLFSSL_THREAD
    #elif defined(NETOS)
        typedef UINT        THREAD_RETURN;
        typedef TX_THREAD   THREAD_TYPE;
        #define WOLFSSL_THREAD
        #define INFINITE TX_WAIT_FOREVER
        #define WAIT_OBJECT_0 TX_NO_WAIT
    #else
        typedef unsigned int  THREAD_RETURN;
        typedef intptr_t      THREAD_TYPE;
        #define WOLFSSL_THREAD __stdcall
    #endif


#ifdef TEST_IPV6
    typedef struct sockaddr_in6 SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET6
#else
    typedef struct sockaddr_in  SOCKADDR_IN_T;
    #define AF_INET_V    AF_INET
#endif


#define SERVER_DEFAULT_VERSION 3
#define SERVER_DTLS_DEFAULT_VERSION (-2)
#define SERVER_INVALID_VERSION (-99)
#define SERVER_DOWNGRADE_VERSION (-98)
#define CLIENT_DEFAULT_VERSION 3
#define CLIENT_DTLS_DEFAULT_VERSION (-2)
#define CLIENT_INVALID_VERSION (-99)
#define CLIENT_DOWNGRADE_VERSION (-98)
#define EITHER_DOWNGRADE_VERSION (-97)
    #define DEFAULT_MIN_DHKEY_BITS 1024
    #define DEFAULT_MAX_DHKEY_BITS 2048
    #ifndef DEFAULT_MIN_RSAKEY_BITS
    #define DEFAULT_MIN_RSAKEY_BITS 1024
    #endif
    #ifndef DEFAULT_MIN_ECCKEY_BITS
    #define DEFAULT_MIN_ECCKEY_BITS 224
    #endif

/* all certs relative to wolfSSL home directory now */
#if defined(WOLFSSL_NO_CURRDIR) || defined(WOLFSSL_MDK_SHELL)
#define caCertFile        "certs/ca-cert.pem"
#define eccCertFile       "certs/server-ecc.pem"
#define eccKeyFile        "certs/ecc-key.pem"
#define eccKeyPubFile     "certs/ecc-keyPub.pem"
#define eccRsaCertFile    "certs/server-ecc-rsa.pem"
#define svrCertFile       "certs/server-cert.pem"
#define svrKeyFile        "certs/server-key.pem"
#define svrKeyPubFile     "certs/server-keyPub.pem"
#define cliCertFile       "certs/client-cert.pem"
#define cliCertDerFile    "certs/client-cert.der"
#define cliCertFileExt    "certs/client-cert-ext.pem"
#define cliCertDerFileExt "certs/client-cert-ext.der"
#define cliKeyFile        "certs/client-key.pem"
#define cliKeyPubFile     "certs/client-keyPub.pem"
#define dhParamFile       "certs/dh2048.pem"
#define cliEccKeyFile     "certs/ecc-client-key.pem"
#define cliEccKeyPubFile  "certs/ecc-client-keyPub.pem"
#define cliEccCertFile    "certs/client-ecc-cert.pem"
#define caEccCertFile     "certs/ca-ecc-cert.pem"
#define crlPemDir         "certs/crl"
#define edCertFile        "certs/ed25519/server-ed25519-cert.pem"
#define edKeyFile         "certs/ed25519/server-ed25519-priv.pem"
#define edKeyPubFile      "certs/ed25519/server-ed25519-key.pem"
#define cliEdCertFile     "certs/ed25519/client-ed25519.pem"
#define cliEdKeyFile      "certs/ed25519/client-ed25519-priv.pem"
#define cliEdKeyPubFile   "certs/ed25519/client-ed25519-key.pem"
#define caEdCertFile      "certs/ed25519/ca-ed25519.pem"
#define ed448CertFile     "certs/ed448/server-ed448-cert.pem"
#define ed448KeyFile      "certs/ed448/server-ed448-priv.pem"
#define cliEd448CertFile  "certs/ed448/client-ed448.pem"
#define cliEd448KeyFile   "certs/ed448/client-ed448-priv.pem"
#define caEd448CertFile   "certs/ed448/ca-ed448.pem"
#define caCertFolder      "certs/"
#ifdef HAVE_WNR
    /* Whitewood netRandom default config file */
    #define wnrConfig     "wnr-example.conf"
#endif
#elif defined(NETOS) && defined(HAVE_FIPS)
    /* These defines specify the file system volume and root directory used by
     * the FTP server used in the only supported NETOS FIPS solution (at this
     * time), these can be tailored in the event a future FIPS solution is added
     * for an alternate NETOS use-case */
    #define FS_VOLUME1     "FLASH0"
    #define FS_VOLUME1_DIR FS_VOLUME1 "/"
    #define caCertFile     FS_VOLUME1_DIR "certs/ca-cert.pem"
    #define eccCertFile    FS_VOLUME1_DIR "certs/server-ecc.pem"
    #define eccKeyFile     FS_VOLUME1_DIR "certs/ecc-key.pem"
    #define svrCertFile    FS_VOLUME1_DIR "certs/server-cert.pem"
    #define svrKeyFile     FS_VOLUME1_DIR "certs/server-key.pem"
    #define cliCertFile    FS_VOLUME1_DIR "certs/client-cert.pem"
    #define cliKeyFile     FS_VOLUME1_DIR "certs/client-key.pem"
    #define ntruCertFile   FS_VOLUME1_DIR "certs/ntru-cert.pem"
    #define ntruKeyFile    FS_VOLUME1_DIR "certs/ntru-key.raw"
    #define dhParamFile    FS_VOLUME1_DIR "certs/dh2048.pem"
    #define cliEccKeyFile  FS_VOLUME1_DIR "certs/ecc-client-key.pem"
    #define cliEccCertFile FS_VOLUME1_DIR "certs/client-ecc-cert.pem"
    #define caEccCertFile  FS_VOLUME1_DIR "certs/ca-ecc-cert/pem"
    #define crlPemDir      FS_VOLUME1_DIR "certs/crl"
    #ifdef HAVE_WNR
        /* Whitewood netRandom default config file */
        #define wnrConfig  "wnr-example.conf"
    #endif
#else
#define caCertFile        "./certs/ca-cert.pem"
#define eccCertFile       "./certs/server-ecc.pem"
#define eccKeyFile        "./certs/ecc-key.pem"
#define eccKeyPubFile     "./certs/ecc-keyPub.pem"
#define eccRsaCertFile    "./certs/server-ecc-rsa.pem"
#define svrCertFile       "./certs/server-cert.pem"
#define svrKeyFile        "./certs/server-key.pem"
#define svrKeyPubFile     "./certs/server-keyPub.pem"
#define cliCertFile       "./certs/client-cert.pem"
#define cliCertDerFile    "./certs/client-cert.der"
#define cliCertFileExt    "./certs/client-cert-ext.pem"
#define cliCertDerFileExt "./certs/client-cert-ext.der"
#define cliKeyFile        "./certs/client-key.pem"
#define cliKeyPubFile     "./certs/client-keyPub.pem"
#define dhParamFile       "./certs/dh2048.pem"
#define cliEccKeyFile     "./certs/ecc-client-key.pem"
#define cliEccKeyPubFile  "./certs/ecc-client-keyPub.pem"
#define cliEccCertFile    "./certs/client-ecc-cert.pem"
#define caEccCertFile     "./certs/ca-ecc-cert.pem"
#define crlPemDir         "./certs/crl"
#define edCertFile        "./certs/ed25519/server-ed25519-cert.pem"
#define edKeyFile         "./certs/ed25519/server-ed25519-priv.pem"
#define edKeyPubFile      "./certs/ed25519/server-ed25519-key.pem"
#define cliEdCertFile     "./certs/ed25519/client-ed25519.pem"
#define cliEdKeyFile      "./certs/ed25519/client-ed25519-priv.pem"
#define cliEdKeyPubFile   "./certs/ed25519/client-ed25519-key.pem"
#define caEdCertFile      "./certs/ed25519/ca-ed25519.pem"
#define ed448CertFile     "./certs/ed448/server-ed448-cert.pem"
#define ed448KeyFile      "./certs/ed448/server-ed448-priv.pem"
#define cliEd448CertFile  "./certs/ed448/client-ed448.pem"
#define cliEd448KeyFile   "./certs/ed448/client-ed448-priv.pem"
#define caEd448CertFile   "./certs/ed448/ca-ed448.pem"
#define caCertFolder      "./certs/"
#ifdef HAVE_WNR
    /* Whitewood netRandom default config file */
    #define wnrConfig     "./wnr-example.conf"
#endif
#endif

typedef struct tcp_ready {
    word16 ready;              /* predicate */
    word16 port;
    char*  srfName;     /* server ready file name */
#if !defined(__MINGW32__)
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
#endif
#ifdef NETOS
    TX_MUTEX mutex;
#endif
} tcp_ready;


static WC_INLINE void InitTcpReady(tcp_ready* ready)
{
    ready->ready = 0;
    ready->port = 0;
    ready->srfName = NULL;
#if !defined(__MINGW32__)
    pthread_mutex_init(&ready->mutex, 0);
    pthread_cond_init(&ready->cond, 0);
#elif defined(NETOS)
    tx_mutex_create(&ready->mutex, "wolfSSL Lock", TX_INHERIT);
#endif
}

#ifdef NETOS
    struct hostent* gethostbyname(const char* name);
#endif

static WC_INLINE void FreeTcpReady(tcp_ready* ready)
{
#if !defined(__MINGW32__)
    pthread_mutex_destroy(&ready->mutex);
    pthread_cond_destroy(&ready->cond);
#elif defined(NETOS)
    tx_mutex_delete(&ready->mutex);
#else
    (void)ready;
#endif
}

typedef WOLFSSL_METHOD* (*method_provider)(void);
typedef void (*ctx_callback)(WOLFSSL_CTX* ctx);
typedef void (*ssl_callback)(WOLFSSL* ssl);

typedef struct callback_functions {
    method_provider method;
    ctx_callback ctx_ready;
    ssl_callback ssl_ready;
    ssl_callback on_result;
    WOLFSSL_CTX* ctx;
    const char* caPemFile;
    const char* certPemFile;
    const char* keyPemFile;
    int devId;
    int return_code;
    unsigned char isSharedCtx:1;
    unsigned char loadToSSL:1;
    unsigned char ticNoInit:1;
    unsigned char doUdp:1;
} callback_functions;

#if defined(WOLFSSL_SRTP)
typedef struct srtp_test_helper {
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    uint8_t* server_srtp_ekm;
    size_t   server_srtp_ekm_size;
} srtp_test_helper;
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
    tcp_ready* signal;
    callback_functions *callbacks;
#if defined(WOLFSSL_SRTP)
    srtp_test_helper* srtp_helper;
#endif
} func_args;

#ifdef NETOS
    int dc_log_printf(char* format, ...);
    #undef printf
    #define printf dc_log_printf
#endif

void wait_tcp_ready(func_args* args);

#ifdef WOLFSSL_ZEPHYR
typedef void THREAD_FUNC(void*, void*, void*);
#else
typedef THREAD_RETURN WOLFSSL_THREAD THREAD_FUNC(void*);
#endif

void start_thread(THREAD_FUNC fun, func_args* args, THREAD_TYPE* thread);
void join_thread(THREAD_TYPE thread);

/* wolfSSL */
#ifndef TEST_IPV6
    static const char* const wolfSSLIP   = "127.0.0.1";
#else
    static const char* const wolfSSLIP   = "::1";
#endif
static const word16      wolfSSLPort = 11111;



#ifndef MY_EX_USAGE
#define MY_EX_USAGE 2
#endif

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif

#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
    #ifndef EXIT_SUCCESS
        #define EXIT_SUCCESS   0
    #endif
    #define XEXIT(rc)   return rc
    #define XEXIT_T(rc) return (THREAD_RETURN)rc
#else
    #define XEXIT(rc)   exit((int)(rc))
    #define XEXIT_T(rc) exit((int)(rc))
#endif


static WC_INLINE
#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
THREAD_RETURN
#else
WC_NORETURN void
#endif
err_sys(const char* msg)
{
#if !defined(__GNUC__)
    /* scan-build (which pretends to be gnuc) can get confused and think the
     * msg pointer can be null even when hardcoded and then it won't exit,
     * making null pointer checks above the err_sys() call useless.
     * We could just always exit() but some compilers will complain about no
     * possible return, with gcc we know the attribute to handle that with
     * WC_NORETURN. */
    if (msg)
#endif
    {
        fprintf(stderr, "wolfSSL error: %s\n", msg);
    }
    XEXIT_T(EXIT_FAILURE);
}

static WC_INLINE
#if defined(WOLFSSL_FORCE_MALLOC_FAIL_TEST) || defined(WOLFSSL_ZEPHYR)
THREAD_RETURN
#else
WC_NORETURN void
#endif
err_sys_with_errno(const char* msg)
{
#if !defined(__GNUC__)
    /* scan-build (which pretends to be gnuc) can get confused and think the
     * msg pointer can be null even when hardcoded and then it won't exit,
     * making null pointer checks above the err_sys() call useless.
     * We could just always exit() but some compilers will complain about no
     * possible return, with gcc we know the attribute to handle that with
     * WC_NORETURN. */
    if (msg)
#endif
    {
#if defined(HAVE_STRING_H)
        fprintf(stderr, "wolfSSL error: %s: %s\n", msg, strerror(errno));
#else
        fprintf(stderr, "wolfSSL error: %s\n", msg);
#endif
    }
    XEXIT_T(EXIT_FAILURE);
}


extern int   myoptind;
extern char* myoptarg;

#if defined(WOLFSSL_SRTP)

static WC_INLINE void srtp_helper_init(srtp_test_helper *srtp)
{
    srtp->server_srtp_ekm_size = 0;
    srtp->server_srtp_ekm = NULL;

    pthread_mutex_init(&srtp->mutex, 0);
    pthread_cond_init(&srtp->cond, 0);
}

/**
 * strp_helper_get_ekm() - get exported key material of other peer
 * @srtp: srtp_test_helper struct shared with other peer [in]
 * @ekm: where to store the shared buffer pointer [out]
 * @size: size of the shared buffer returned [out]
 *
 * This function wait that the other peer calls strp_helper_set_ekm() and then
 * store the buffer pointer/size in @ekm and @size.
 */
static WC_INLINE void srtp_helper_get_ekm(srtp_test_helper *srtp,
                                          uint8_t **ekm, size_t *size)
{
    pthread_mutex_lock(&srtp->mutex);

    if (srtp->server_srtp_ekm == NULL)
        pthread_cond_wait(&srtp->cond, &srtp->mutex);

    *ekm = srtp->server_srtp_ekm;
    *size = srtp->server_srtp_ekm_size;

    /* reset */
    srtp->server_srtp_ekm = NULL;
    srtp->server_srtp_ekm_size = 0;

    pthread_mutex_unlock(&srtp->mutex);
}

/**
 * strp_helper_set_ekm() - set exported key material of other peer
 * @srtp: srtp_test_helper struct shared with other peer [in]
 * @ekm: pointer to the shared buffer [in]
 * @size: size of the shared buffer [in]
 *
 * This function set the @ekm and wakes up a peer waiting in
 * srtp_helper_get_ekm().
 *
 * used in client_srtp_test()/server_srtp_test()
 */
static WC_INLINE void srtp_helper_set_ekm(srtp_test_helper *srtp,
                                          uint8_t *ekm, size_t size)
{
    pthread_mutex_lock(&srtp->mutex);

    srtp->server_srtp_ekm_size = size;
    srtp->server_srtp_ekm = ekm;
    pthread_cond_signal(&srtp->cond);

    pthread_mutex_unlock(&srtp->mutex);
}

static WC_INLINE void srtp_helper_free(srtp_test_helper *srtp)
{
    pthread_mutex_destroy(&srtp->mutex);
    pthread_cond_destroy(&srtp->cond);
}

#endif /* WOLFSSL_SRTP && !SINGLE_THREADED && POSIX_THREADS */

/**
 *
 * @param argc Number of argv strings
 * @param argv Array of string arguments
 * @param optstring String containing the supported alphanumeric arguments.
 *                  A ':' following a character means that it requires a
 *                  value in myoptarg to be set. A ';' means that the
 *                  myoptarg is optional. myoptarg is set to "" if not
 *                  present.
 * @return Option letter in argument
 */
static WC_INLINE int mygetopt(int argc, char** argv, const char* optstring)
{
    static char* next = NULL;

    char  c;
    char* cp;

    /* Added sanity check because scan-build complains argv[myoptind] access
     * results in a null pointer dereference. */
    if (argv == NULL)  {
        myoptarg = NULL;
        return -1;
    }

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind] == NULL ||
                argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':' || c == ';')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }
    else if (*cp == ';') {
        myoptarg = (char*)"";
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            /* Check if next argument is not a parameter argument */
            if (argv[myoptind] && argv[myoptind][0] != '-') {
                myoptarg = argv[myoptind];
                myoptind++;
            }
        }
    }

    return c;
}

struct mygetopt_long_config {
    const char *name;
    int takes_arg; /* 0=no arg, 1=required arg, 2=optional arg */
    int value;
};

/**
 *
 * @param argc Number of argv strings
 * @param argv Array of string arguments
 * @param optstring String containing the supported alphanumeric arguments.
 *                  A ':' following a character means that it requires a
 *                  value in myoptarg to be set. A ';' means that the
 *                  myoptarg is optional. myoptarg is set to "" if not
 *                  present.
 * @return Option letter in argument
 */
static WC_INLINE int mygetopt_long(int argc, char** argv, const char* optstring,
    const struct mygetopt_long_config *longopts, int *longindex)
{
    static char* next = NULL;

    int  c;
    char* cp;

    /* Added sanity check because scan-build complains argv[myoptind] access
     * results in a null pointer dereference. */
    if (argv == NULL)  {
        myoptarg = NULL;
        return -1;
    }

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0') {
        if (myoptind == 0)
            myoptind++;

        if (myoptind >= argc || argv[myoptind] == NULL ||
                argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') {
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) {
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strncmp(argv[myoptind], "--", 2) == 0) {
            const struct mygetopt_long_config *i;
            c = -1;
            myoptarg = NULL;
            for (i = longopts; i->name; ++i) {
                if (! strcmp(argv[myoptind] + 2, i->name)) {
                    c = i->value;
                    myoptind++;
                    if (longindex)
                        *longindex = (int)((size_t)(i - longopts) / sizeof i[0]);
                    if (i->takes_arg) {
                        if (myoptind < argc) {
                            if (i->takes_arg == 1 || argv[myoptind][0] != '-') {
                                myoptarg = argv[myoptind];
                                myoptind++;
                            }
                        } else if (i->takes_arg != 2) {
                            return -1;
                        }
                    }
                    break;
                }
            }

            return c;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = (int)(unsigned char)*next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':' || c == ';')
        return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }
    else if (*cp == ';') {
        myoptarg = (char*)"";
        if (*next != '\0') {
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) {
            /* Check if next argument is not a parameter argument */
            if (argv[myoptind] && argv[myoptind][0] != '-') {
                myoptarg = argv[myoptind];
                myoptind++;
            }
        }
    }

    return c;
}


#ifdef WOLFSSL_ENCRYPTED_KEYS

static WC_INLINE int PasswordCallBack(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;
    (void)userdata;
    if (userdata != NULL) {
        strncpy(passwd, (char*)userdata, sz);
        return (int)XSTRLEN((char*)userdata);
    }
    else {
        strncpy(passwd, "yassl123", sz);
        return 8;
    }
}

#endif

static const char* client_showpeer_msg[][9] = {
    /* English */
    {
        "SSL version is",
        "SSL cipher suite is",
        "SSL signature algorithm is",
        "SSL curve name is",
        "SSL DH size is",
        "SSL reused session",
        "Alternate cert chain used",
        "peer's cert info:",
        NULL
    },
#ifndef NO_MULTIBYTE_PRINT
    /* Japanese */
    {
        "SSL バージョンは",
        "SSL 暗号スイートは",
        "SSL signature algorithm is",
        "SSL 曲線名は",
        "SSL DH サイズは",
        "SSL 再利用セッション",
        "代替証明チェーンを使用",
        "相手方証明書情報",
        NULL
    },
#endif
};

#if defined(KEEP_OUR_CERT)
static const char* client_showx509_msg[][5] = {
    /* English */
    {
        "issuer",
        "subject",
        "altname",
        "serial number",
        NULL
    },
#ifndef NO_MULTIBYTE_PRINT
    /* Japanese */
    {
        "発行者",
        "サブジェクト",
        "代替名",
        "シリアル番号",
        NULL
    },
#endif
};

/* lng_index is to specify the language for displaying message.              */
/* 0:English, 1:Japanese                                                     */
static WC_INLINE void ShowX509Ex(WOLFSSL_X509* x509, const char* hdr,
                                                                 int lng_index)
{
    char* altName;
    char* issuer;
    char* subject;
    byte  serial[32];
    int   ret;
    int   sz = sizeof(serial);
    const char** words = client_showx509_msg[lng_index];

    if (x509 == NULL) {
        fprintf(stderr, "%s No Cert\n", hdr);
        return;
    }

    issuer  = wolfSSL_X509_NAME_oneline(
                                      wolfSSL_X509_get_issuer_name(x509), 0, 0);
    subject = wolfSSL_X509_NAME_oneline(
                                     wolfSSL_X509_get_subject_name(x509), 0, 0);

    printf("%s\n %s : %s\n %s: %s\n", hdr, words[0], issuer, words[1], subject);

    while ( (altName = wolfSSL_X509_get_next_altname(x509)) != NULL)
        printf(" %s = %s\n", words[2], altName);

    ret = wolfSSL_X509_get_serial_number(x509, serial, &sz);
    if (ret == WOLFSSL_SUCCESS) {
        int  i;
        int  strLen;
        char serialMsg[80];

        /* testsuite has multiple threads writing to stdout, get output
           message ready to write once */
        strLen = sprintf(serialMsg, " %s", words[3]);
        for (i = 0; i < sz; i++)
            sprintf(serialMsg + strLen + (i*3), ":%02x ", serial[i]);
        printf("%s\n", serialMsg);
    }

    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);

}
/* original ShowX509 to maintain compatibility */
static WC_INLINE void ShowX509(WOLFSSL_X509* x509, const char* hdr)
{
    ShowX509Ex(x509, hdr, 0);
}

#endif /* KEEP_PEER_CERT || KEEP_OUR_CERT || SESSION_CERTS */


/* lng_index is to specify the language for displaying message.              */
/* 0:English, 1:Japanese                                                     */
static WC_INLINE void showPeerEx(WOLFSSL* ssl, int lng_index)
{
    WOLFSSL_CIPHER* cipher;
    const char** words = client_showpeer_msg[lng_index];

    const char *name;
    int bits;
    printf("%s %s\n", words[0], wolfSSL_get_version(ssl));

    cipher = wolfSSL_get_current_cipher(ssl);
    printf("%s %s\n", words[1], wolfSSL_CIPHER_get_name(cipher));
    if ((name = wolfSSL_get_curve_name(ssl)) != NULL)
        printf("%s %s\n", words[3], name);
    else if ((bits = wolfSSL_GetDhKey_Sz(ssl)) > 0)
        printf("%s %d bits\n", words[4], bits);
    if (wolfSSL_session_reused(ssl))
        printf("%s\n", words[5]);

  (void)ssl;
}
/* original showPeer to maintain compatibility */
static WC_INLINE void showPeer(WOLFSSL* ssl)
{
    showPeerEx(ssl, 0);
}

static WC_INLINE void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              word16 port, int udp, int sctp)
{
    int useLookup = 0;
    (void)useLookup;
    (void)udp;
    (void)sctp;

    if (addr == NULL) {
        err_sys("invalid argument to build_addr, addr is NULL");
        return;
    }

    XMEMSET(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
    #ifdef WOLFSSL_USE_POPEN_HOST
        char host_ipaddr[4] = { 127, 0, 0, 1 };
        int found = 1;

        if ((XSTRCMP(peer, "localhost") != 0) &&
            (XSTRCMP(peer, "127.0.0.1") != 0)) {
            FILE* fp;
            char host_out[100];
            char cmd[100];

            XSTRNCPY(cmd, "host ", 6);
            XSTRNCAT(cmd, peer, 99 - XSTRLEN(cmd));
            found = 0;
            fp = popen(cmd, "r");
            if (fp != NULL) {
                while (fgets(host_out, sizeof(host_out), fp) != NULL) {
                    int i;
                    int j = 0;
                    for (j = 0; host_out[j] != '\0'; j++) {
                        if ((host_out[j] >= '0') && (host_out[j] <= '9')) {
                            break;
                        }
                    }
                    found = (host_out[j] >= '0') && (host_out[j] <= '9');
                    if (!found) {
                        continue;
                    }

                    for (i = 0; i < 4; i++) {
                        host_ipaddr[i] = atoi(host_out + j);
                        while ((host_out[j] >= '0') && (host_out[j] <= '9')) {
                            j++;
                        }
                        if (host_out[j] == '.') {
                            j++;
                            found &= (i != 3);
                        }
                        else {
                            found &= (i == 3);
                            break;
                        }
                    }
                    if (found) {
                        break;
                    }
                }
                pclose(fp);
            }
        }
        if (found) {
            XMEMCPY(&addr->sin_addr.s_addr, host_ipaddr, sizeof(host_ipaddr));
            useLookup = 1;
        }
    #elif !defined(WOLFSSL_USE_GETADDRINFO)
        #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #elif defined(WOLFSSL_TIRTOS)
            struct hostent* entry = DNSGetHostByName(peer);
        #elif defined(WOLFSSL_VXWORKS)
            struct hostent* entry = (struct hostent*)hostGetByName((char*)peer);
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
            XMEMCPY(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
    #else
        struct zsock_addrinfo hints, *addrInfo;
        char portStr[6];
        XSNPRINTF(portStr, sizeof(portStr), "%d", port);
        XMEMSET(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
        if (getaddrinfo((char*)peer, portStr, &hints, &addrInfo) == 0) {
            XMEMCPY(addr, addrInfo->ai_addr, sizeof(*addr));
            useLookup = 1;
        }
    #endif
        else
            err_sys("no entry for host");
    }
#endif


#ifndef TEST_IPV6
    #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        addr->sin_family = PF_INET;
    #else
        addr->sin_family = AF_INET_V;
    #endif
    addr->sin_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY) {
        addr->sin6_addr = in6addr_any;
    }
    else {
        #if defined(HAVE_GETADDRINFO)
            struct addrinfo  hints;
            struct addrinfo* answer = NULL;
            int    ret;
            char   strPort[80];

            XMEMSET(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_INET_V;
            if (udp) {
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
            }
        #ifdef WOLFSSL_SCTP
            else if (sctp) {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_SCTP;
            }
        #endif
            else {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
            }

            SNPRINTF(strPort, sizeof(strPort), "%d", port);
            strPort[79] = '\0';

            ret = getaddrinfo(peer, strPort, &hints, &answer);
            if (ret < 0 || answer == NULL)
                err_sys("getaddrinfo failed");

            XMEMCPY(addr, answer->ai_addr, answer->ai_addrlen);
            freeaddrinfo(answer);
        #else
            printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
            addr->sin6_addr = in6addr_loopback;
        #endif
    }
#endif
}


static WC_INLINE void tcp_socket(SOCKET_T* sockfd, int udp, int sctp)
{
    (void)sctp;

    if (udp)
        *sockfd = socket(AF_INET_V, SOCK_DGRAM, IPPROTO_UDP);
#ifdef WOLFSSL_SCTP
    else if (sctp)
        *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_SCTP);
#endif
    else
        *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);

    if(WOLFSSL_SOCKET_IS_INVALID(*sockfd)) {
        err_sys_with_errno("socket failed\n");
    }

#ifdef SO_NOSIGPIPE
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_NOSIGPIPE failed\n");
    }
#elif defined(WOLFSSL_MDK_ARM) || defined (WOLFSSL_TIRTOS) ||\
                        defined(WOLFSSL_KEIL_TCP_NET) || defined(WOLFSSL_ZEPHYR)
    /* nothing to define */
#elif defined(NETOS)
    /* TODO: signal(SIGPIPE, SIG_IGN); */
#else  /* no S_NOSIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */

#if defined(TCP_NODELAY)
    if (!udp && !sctp)
    {
        int       on = 1;
        socklen_t len = sizeof(on);
        int       res = setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt TCP_NODELAY failed\n");
    }
#endif
}


static WC_INLINE void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port,
                               int udp, int sctp, WOLFSSL* ssl)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port, udp, sctp);
    if (udp) {
        wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    }
    tcp_socket(sockfd, udp, sctp);

    if (!udp) {
        if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
            err_sys_with_errno("tcp connect failed");
    }
}



static WC_INLINE void udp_connect(SOCKET_T* sockfd, const char* ip, word16 port)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port, 1, 0);
    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp connect failed");
}


enum {
    TEST_SELECT_FAIL,
    TEST_TIMEOUT,
    TEST_RECV_READY,
    TEST_SEND_READY,
    TEST_ERROR_READY
};


#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_TCP_NET) && \
                                 !defined(WOLFSSL_TIRTOS)
static WC_INLINE int tcp_select_ex(SOCKET_T socketfd, int to_sec, int rx)
{
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    SOCKET_T nfds = socketfd + 1;
#if !defined(__INTEGRITY)
    struct timeval timeout = {(to_sec > 0) ? to_sec : 0, 0};
#else
    struct timeval timeout;
#endif
    int result;

    FD_ZERO(&fds);
    FD_SET(socketfd, &fds);
    FD_ZERO(&errfds);
    FD_SET(socketfd, &errfds);

    if (rx)
        recvfds = &fds;
    else
        sendfds = &fds;

#if defined(__INTEGRITY)
    timeout.tv_sec = (long long)(to_sec > 0) ? to_sec : 0, 0;
#endif
    result = select(nfds, recvfds, sendfds, &errfds, &timeout);

    if (result == 0)
        return TEST_TIMEOUT;
    else if (result > 0) {
        if (FD_ISSET(socketfd, &fds)) {
            if (rx)
                return TEST_RECV_READY;
            else
                return TEST_SEND_READY;
        }
        else if(FD_ISSET(socketfd, &errfds))
            return TEST_ERROR_READY;
    }

    return TEST_SELECT_FAIL;
}

static WC_INLINE int tcp_select(SOCKET_T socketfd, int to_sec)
{
    return tcp_select_ex(socketfd, to_sec, 1);
}

static WC_INLINE int tcp_select_tx(SOCKET_T socketfd, int to_sec)
{
    return tcp_select_ex(socketfd, to_sec, 0);
}

#elif defined(WOLFSSL_TIRTOS) || defined(WOLFSSL_KEIL_TCP_NET)
static WC_INLINE int tcp_select(SOCKET_T socketfd, int to_sec)
{
    return TEST_RECV_READY;
}
static WC_INLINE int tcp_select_tx(SOCKET_T socketfd, int to_sec)
{
    return TEST_SEND_READY;
}
#endif /* !WOLFSSL_MDK_ARM */


static WC_INLINE void tcp_listen(SOCKET_T* sockfd, word16* port, int useAnyAddr,
                              int udp, int sctp)
{
    SOCKADDR_IN_T addr;

    /* don't use INADDR_ANY by default, firewall may block, make user switch
       on */
    build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfSSLIP), *port, udp, sctp);
    tcp_socket(sockfd, udp, sctp);

#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_ZEPHYR)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEADDR failed\n");
    }
#ifdef SO_REUSEPORT
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEPORT failed\n");
    }
#endif
#endif

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp bind failed");
    if (!udp) {
        #ifdef WOLFSSL_KEIL_TCP_NET
            #define SOCK_LISTEN_MAX_QUEUE 1
        #else
            #define SOCK_LISTEN_MAX_QUEUE 5
        #endif
        if (listen(*sockfd, SOCK_LISTEN_MAX_QUEUE) != 0)
                err_sys_with_errno("tcp listen failed");
    }
    #if !defined(WOLFSSL_TIRTOS)  && !defined(WOLFSSL_ZEPHYR)
        if (*port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    *port = XNTOHS(addr.sin_port);
                #else
                    *port = XNTOHS(addr.sin6_port);
                #endif
            }
        }
    #endif
}


#if 0
static WC_INLINE int udp_read_connect(SOCKET_T sockfd)
{
    SOCKADDR_IN_T cliaddr;
    byte          b[1500];
    int           n;
    socklen_t     len = sizeof(cliaddr);

    n = (int)recvfrom(sockfd, (char*)b, sizeof(b), MSG_PEEK,
                      (struct sockaddr*)&cliaddr, &len);
    if (n > 0) {
        if (connect(sockfd, (const struct sockaddr*)&cliaddr,
                    sizeof(cliaddr)) != 0)
            err_sys("udp connect failed");
    }
    else
        err_sys("recvfrom failed");

    return sockfd;
}
#endif

static WC_INLINE void udp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              int useAnyAddr, word16 port, func_args* args)
{
    SOCKADDR_IN_T addr;

    (void)args;
    build_addr(&addr, (useAnyAddr ? INADDR_ANY : wolfSSLIP), port, 1, 0);
    tcp_socket(sockfd, 1, 0);


#if !defined(WOLFSSL_MDK_ARM)  && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_ZEPHYR)
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEADDR failed\n");
    }
#ifdef SO_REUSEPORT
    {
        int       res, on  = 1;
        socklen_t len = sizeof(on);
        res = setsockopt(*sockfd, SOL_SOCKET, SO_REUSEPORT, &on, len);
        if (res < 0)
            err_sys_with_errno("setsockopt SO_REUSEPORT failed\n");
    }
#endif
#endif

    if (bind(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys_with_errno("tcp bind failed");

    #if !defined(WOLFSSL_TIRTOS)
        if (port == 0) {
            socklen_t len = sizeof(addr);
            if (getsockname(*sockfd, (struct sockaddr*)&addr, &len) == 0) {
                #ifndef TEST_IPV6
                    port = XNTOHS(addr.sin_port);
                #else
                    port = XNTOHS(addr.sin6_port);
                #endif
            }
        }
    #endif

#if !defined(__MINGW32__)
    /* signal ready to accept data */
    {
    tcp_ready* ready = args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
    }
#elif defined (WOLFSSL_TIRTOS)
    /* Need mutex? */
    tcp_ready* ready = args->signal;
    ready->ready = 1;
    ready->port = port;
#elif defined(NETOS)
    {
        tcp_ready* ready = args->signal;
        (void)tx_mutex_get(&ready->mutex, TX_WAIT_FOREVER);
        ready->ready = 1;
        ready->port = port;
        (void)tx_mutex_put(&ready->mutex);
    }
#else
    (void)port;
#endif

    *clientfd = *sockfd;
}

static WC_INLINE void tcp_accept(SOCKET_T* sockfd, SOCKET_T* clientfd,
                              func_args* args, word16 port, int useAnyAddr,
                              int udp, int sctp, int ready_file, int do_listen,
                              SOCKADDR_IN_T *client_addr, socklen_t *client_len)
{
    tcp_ready* ready = NULL;

    (void) ready; /* Account for case when "ready" is not used */

    if (udp) {
        udp_accept(sockfd, clientfd, useAnyAddr, port, args);
        return;
    }

    if(do_listen) {
        tcp_listen(sockfd, &port, useAnyAddr, udp, sctp);

    #if defined(NO_MAIN_DRIVER) && !defined(__MINGW32__)
        /* signal ready to tcp_accept */
        if (args)
            ready = args->signal;
        if (ready) {
            pthread_mutex_lock(&ready->mutex);
            ready->ready = 1;
            ready->port = port;
            pthread_cond_signal(&ready->cond);
            pthread_mutex_unlock(&ready->mutex);
        }
    #elif defined (WOLFSSL_TIRTOS)
        /* Need mutex? */
        if (args)
            ready = args->signal;
        if (ready) {
            ready->ready = 1;
            ready->port = port;
        }
    #elif defined(NETOS)
        /* signal ready to tcp_accept */
        if (args)
            ready = args->signal;
        if (ready) {
            (void)tx_mutex_get(&ready->mutex, TX_WAIT_FOREVER);
            ready->ready = 1;
            ready->port = port;
            (void)tx_mutex_put(&ready->mutex);
        }
    #endif

        if (ready_file) {
        #if !defined(NO_FILESYSTEM) || defined(FORCE_BUFFER_TEST) && \
            !defined(NETOS)
            XFILE srf = (XFILE)NULL;
            if (args)
                ready = args->signal;

            if (ready) {
                srf = XFOPEN(ready->srfName, "w");

                if (srf) {
                    /* let's write port sever is listening on to ready file
                       external monitor can then do ephemeral ports by passing
                       -p 0 to server on supported platforms with -R ready_file
                       client can then wait for existence of ready_file and see
                       which port the server is listening on. */
                    fprintf(srf, "%d\n", (int)port);
                    fclose(srf);
                }
            }
        #endif
        }
    }

    *clientfd = accept(*sockfd, (struct sockaddr*)client_addr,
                      (ACCEPT_THIRD_T)client_len);
    if(WOLFSSL_SOCKET_IS_INVALID(*clientfd)) {
        err_sys_with_errno("tcp accept failed");
    }
}


static WC_INLINE void tcp_set_nonblocking(SOCKET_T* sockfd)
{
    #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
        || defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS) \
        || defined(WOLFSSL_ZEPHYR)
         /* non blocking not supported, for now */
    #else
        int flags = fcntl(*sockfd, F_GETFL, 0);
        if (flags < 0)
            err_sys_with_errno("fcntl get failed");
        flags = fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK);
        if (flags < 0)
            err_sys_with_errno("fcntl set failed");
    #endif
}




#if defined(WOLFSSL_USER_CURRTIME)
    extern   double current_time(int reset);

#elif defined(WOLFSSL_TIRTOS)
    extern double current_time();
#elif defined(WOLFSSL_ZEPHYR)
    extern double current_time();
#else

#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_TCP_NET) && !defined(WOLFSSL_CHIBIOS)
    #ifndef NETOS
        #include <sys/time.h>
    #endif

    static WC_INLINE double current_time(int reset)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        (void)reset;

        return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
    }
#else
    extern double current_time(int reset);
#endif
#endif /* USE_WINDOWS_API */



    #if !defined(NO_FILESYSTEM) || \
        (defined(NO_FILESYSTEM) && defined(FORCE_BUFFER_TEST)) && \
        !defined(NETOS)

    /* reads file size, allocates buffer, reads into buffer, returns buffer */
    static WC_INLINE int load_file(const char* fname, byte** buf, size_t* bufLen)
    {
        int ret;
        long int fileSz;
        XFILE lFile;

        if (fname == NULL || buf == NULL || bufLen == NULL)
            return BAD_FUNC_ARG;

        /* set defaults */
        *buf = NULL;
        *bufLen = 0;

        /* open file (read-only binary) */
        lFile = XFOPEN(fname, "rb");
        if (!lFile) {
            fprintf(stderr, "Error loading %s\n", fname);
            return BAD_PATH_ERROR;
        }

        fseek(lFile, 0, SEEK_END);
        fileSz = (int)ftell(lFile);
        rewind(lFile);
        if (fileSz  > 0) {
            *bufLen = (size_t)fileSz;
            *buf = (byte*)malloc(*bufLen);
            if (*buf == NULL) {
                ret = MEMORY_E;
                fprintf(stderr,
                        "Error allocating %lu bytes\n", (unsigned long)*bufLen);
            }
            else {
                size_t readLen = fread(*buf, *bufLen, 1, lFile);

                /* check response code */
                ret = (readLen > 0) ? 0 : -1;
            }
        }
        else {
            ret = BUFFER_E;
        }
        fclose(lFile);

        return ret;
    }

    enum {
        WOLFSSL_CA   = 1,
        WOLFSSL_CERT = 2,
        WOLFSSL_KEY  = 3,
        WOLFSSL_CERT_CHAIN = 4,
    };

    static WC_INLINE void load_buffer(WOLFSSL_CTX* ctx, const char* fname, int type)
    {
        int format = WOLFSSL_FILETYPE_PEM;
        byte* buff = NULL;
        size_t sz = 0;

        if (load_file(fname, &buff, &sz) != 0) {
            err_sys("can't open file for buffer load "
                    "Please run from wolfSSL home directory if not");
        }

        /* determine format */
        if (strstr(fname, ".der"))
            format = WOLFSSL_FILETYPE_ASN1;

        if (type == WOLFSSL_CA) {
            if (wolfSSL_CTX_load_verify_buffer(ctx, buff, (long)sz, format)
                                              != WOLFSSL_SUCCESS)
                err_sys("can't load buffer ca file");
        }
        else if (type == WOLFSSL_CERT) {
            if (wolfSSL_CTX_use_certificate_buffer(ctx, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer cert file");
        }
        else if (type == WOLFSSL_KEY) {
            if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer key file");
        }
        else if (type == WOLFSSL_CERT_CHAIN) {
            if (wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buff,
                    (long)sz, format) != WOLFSSL_SUCCESS)
                err_sys("can't load cert chain buffer");
        }

        if (buff)
            free(buff);
    }

    static WC_INLINE void load_ssl_buffer(WOLFSSL* ssl, const char* fname, int type)
    {
        int format = WOLFSSL_FILETYPE_PEM;
        byte* buff = NULL;
        size_t sz = 0;

        if (load_file(fname, &buff, &sz) != 0) {
            err_sys("can't open file for buffer load "
                    "Please run from wolfSSL home directory if not");
        }

        /* determine format */
        if (strstr(fname, ".der"))
            format = WOLFSSL_FILETYPE_ASN1;

        if (type == WOLFSSL_CA) {
            /* verify certs (CA's) use the shared ctx->cm (WOLFSSL_CERT_MANAGER) */
            WOLFSSL_CTX* ctx = wolfSSL_get_SSL_CTX(ssl);
            if (wolfSSL_CTX_load_verify_buffer(ctx, buff, (long)sz, format)
                                              != WOLFSSL_SUCCESS)
                err_sys("can't load buffer ca file");
        }
        else if (type == WOLFSSL_CERT) {
            if (wolfSSL_use_certificate_buffer(ssl, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer cert file");
        }
        else if (type == WOLFSSL_KEY) {
            if (wolfSSL_use_PrivateKey_buffer(ssl, buff, (long)sz,
                        format) != WOLFSSL_SUCCESS)
                err_sys("can't load buffer key file");
        }
        else if (type == WOLFSSL_CERT_CHAIN) {
            if (wolfSSL_use_certificate_chain_buffer_format(ssl, buff,
                    (long)sz, format) != WOLFSSL_SUCCESS)
                err_sys("can't load cert chain buffer");
        }

        if (buff)
            free(buff);
    }

    #ifdef TEST_PK_PRIVKEY
    static WC_INLINE int load_key_file(const char* fname, byte** derBuf, word32* derLen)
    {
        int ret;
        byte* buf = NULL;
        size_t bufLen;

        ret = load_file(fname, &buf, &bufLen);
        if (ret != 0)
            return ret;

        *derBuf = (byte*)malloc(bufLen);
        if (*derBuf == NULL) {
            free(buf);
            return MEMORY_E;
        }

        ret = wc_KeyPemToDer(buf, (word32)bufLen, *derBuf, (word32)bufLen, NULL);
        if (ret < 0) {
            free(buf);
            free(*derBuf);
            return ret;
        }
        *derLen = ret;
        free(buf);

        return 0;
    }
    #endif /* TEST_PK_PRIVKEY */

    #endif /* !NO_FILESYSTEM || (NO_FILESYSTEM && FORCE_BUFFER_TEST) */

enum {
    VERIFY_OVERRIDE_ERROR,
    VERIFY_FORCE_FAIL,
    VERIFY_USE_PREVERFIY,
    VERIFY_OVERRIDE_DATE_ERR,
};
static THREAD_LS_T int myVerifyAction = VERIFY_OVERRIDE_ERROR;

/* The verify callback is called for every certificate only when
 * --enable-opensslextra is defined because it sets WOLFSSL_ALWAYS_VERIFY_CB and
 * WOLFSSL_VERIFY_CB_ALL_CERTS.
 * Normal cases of the verify callback only occur on certificate failures when the
 * wolfSSL_set_verify(ssl, SSL_VERIFY_PEER, myVerifyCb); is called
*/

static WC_INLINE int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ];
    (void)preverify;

    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->error:        Failure error code (0 indicates no failure)
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     * store->discardSessionCerts: When set to non-zero value session certs
        will be discarded (only with SESSION_CERTS)
     */

    fprintf(stderr, "In verification callback, error = %d, %s\n", store->error,
                                 wolfSSL_ERR_error_string(store->error, buffer));
    printf("\tPeer certs: %d\n", store->totalCerts);
    #ifdef SHOW_CERTS
    {   int i;
        for (i=0; i<store->totalCerts; i++) {
            WOLFSSL_BUFFER_INFO* cert = &store->certs[i];
            printf("\t\tCert %d: Ptr %p, Len %u\n", i, cert->buffer, cert->length);
        }
    }
    #endif /* SHOW_CERTS */

    printf("\tSubject's domain name at %d is %s\n", store->error_depth, store->domain);

    /* Testing forced fail case by return zero */
    if (myVerifyAction == VERIFY_FORCE_FAIL) {
        return 0; /* test failure case */
    }

    if (myVerifyAction == VERIFY_OVERRIDE_DATE_ERR &&
        (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
        printf("Overriding cert date error as example for bad clock testing\n");
        return 1;
    }

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0 && myVerifyAction == VERIFY_OVERRIDE_ERROR) {
        printf("\tAllowing failed certificate check, testing only "
            "(shouldn't do this in production)\n");
    }

    /* A non-zero return code indicates failure override */
    return (myVerifyAction == VERIFY_OVERRIDE_ERROR) ? 1 : preverify;
}


#ifdef HAVE_EXT_CACHE

static WC_INLINE WOLFSSL_SESSION* mySessGetCb(WOLFSSL* ssl,
        const unsigned char* id, int id_len, int* copy)
{
    (void)ssl;
    (void)id;
    (void)id_len;
    (void)copy;

    /* using internal cache, this is for testing only */
    return NULL;
}

static WC_INLINE int mySessNewCb(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
    (void)ssl;
    (void)session;

    /* using internal cache, this is for testing only */
    return 0;
}

static WC_INLINE void mySessRemCb(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session)
{
    (void)ctx;
    (void)session;

    /* using internal cache, this is for testing only */
}

#endif /* HAVE_EXT_CACHE */



static WC_INLINE void SetDH(WOLFSSL* ssl)
{
    /* dh1024 p */
    static const unsigned char p[] =
    {
        0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
        0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
        0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
        0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
        0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
        0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
        0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
        0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
        0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
        0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
        0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
    };

    /* dh1024 g */
    static const unsigned char g[] =
    {
      0x02,
    };

    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
}

static WC_INLINE void SetDHCtx(WOLFSSL_CTX* ctx)
{
    /* dh1024 p */
    static const unsigned char p[] =
    {
        0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
        0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
        0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
        0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
        0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
        0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
        0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
        0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
        0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
        0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
        0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
    };

    /* dh1024 g */
    static const unsigned char g[] =
    {
      0x02,
    };

    wolfSSL_CTX_SetTmpDH(ctx, p, sizeof(p), g, sizeof(g));
}


static WC_INLINE void CaCb(unsigned char* der, int sz, int type)
{
    (void)der;
    printf("Got CA cache add callback, derSz = %d, type = %d\n", sz, type);
}



/* Wolf Root Directory Helper */
/* KEIL-RL File System does not support relative directory */
#if !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOLFSSL_TIRTOS)
    /* Maximum depth to search for WolfSSL root */
    #define MAX_WOLF_ROOT_DEPTH 5

    static WC_INLINE int ChangeToWolfRoot(void)
    {
        #if !defined(NO_FILESYSTEM) || defined(FORCE_BUFFER_TEST) && \
            !defined(NETOS)
            int depth, res;
            XFILE keyFile;
            for(depth = 0; depth <= MAX_WOLF_ROOT_DEPTH; depth++) {
                keyFile = XFOPEN(dhParamFile, "rb");
                if (keyFile != NULL) {
                    fclose(keyFile);
                    return depth;
                }
            #if defined(NETOS)
                return 0;
            #else
                res = chdir("../");
            #endif
                if (res < 0) {
                    printf("chdir to ../ failed!\n");
                    break;
                }
            }

            err_sys("wolf root not found");
            return -1;
        #else
            return 0;
        #endif
    }
#endif /* !defined(WOLFSSL_MDK_ARM) && !defined(WOLFSSL_KEIL_FS) && !defined(WOLFSSL_TIRTOS) */

#ifdef HAVE_STACK_SIZE

typedef THREAD_RETURN WOLFSSL_THREAD (*thread_func)(void* args);
#define STACK_CHECK_VAL 0x01

struct stack_size_debug_context {
  unsigned char *myStack;
  size_t stackSize;
#ifdef HAVE_STACK_SIZE_VERBOSE
  size_t *stackSizeHWM_ptr;
  thread_func fn;
  void *args;
#endif
};

#ifdef HAVE_STACK_SIZE_VERBOSE

/* per-subtest stack high water mark tracking.
 *
 * enable with
 *
 * ./configure --enable-stacksize=verbose [...]
 */

static THREAD_RETURN debug_stack_size_verbose_shim(struct stack_size_debug_context *shim_args) {
  StackSizeCheck_myStack = shim_args->myStack;
  StackSizeCheck_stackSize = shim_args->stackSize;
  StackSizeCheck_stackSizeHWM_ptr = shim_args->stackSizeHWM_ptr;
  return shim_args->fn(shim_args->args);
}

static WC_INLINE int StackSizeSetOffset(const char *funcname, void *p)
{
    if (StackSizeCheck_myStack == NULL)
        return -BAD_FUNC_ARG;

    StackSizeCheck_stackOffsetPointer = p;

    printf("setting stack relative offset reference mark in %s to +%lu\n",
        funcname, (unsigned long)((char*)(StackSizeCheck_myStack +
                                  StackSizeCheck_stackSize) - (char *)p));

    return 0;
}

static WC_INLINE ssize_t StackSizeHWM(void)
{
    size_t i;
    ssize_t used;

    if (StackSizeCheck_myStack == NULL)
        return -BAD_FUNC_ARG;

    for (i = 0; i < StackSizeCheck_stackSize; i++) {
        if (StackSizeCheck_myStack[i] != STACK_CHECK_VAL) {
            break;
        }
    }

    used = StackSizeCheck_stackSize - i;
    if ((ssize_t)*StackSizeCheck_stackSizeHWM_ptr < used)
      *StackSizeCheck_stackSizeHWM_ptr = used;

    return used;
}

static WC_INLINE ssize_t StackSizeHWM_OffsetCorrected(void)
{
    ssize_t used = StackSizeHWM();
    if (used < 0)
        return used;
    if (StackSizeCheck_stackOffsetPointer)
        used -= (ssize_t)(((char *)StackSizeCheck_myStack + StackSizeCheck_stackSize) - (char *)StackSizeCheck_stackOffsetPointer);
    return used;
}

static
#ifdef __GNUC__
__attribute__((unused)) __attribute__((noinline))
#endif
int StackSizeHWMReset(void)
{
    volatile ssize_t i;

    if (StackSizeCheck_myStack == NULL)
        return -BAD_FUNC_ARG;

    for (i = (ssize_t)((char *)&i - (char *)StackSizeCheck_myStack) - (ssize_t)sizeof i - 1; i >= 0; --i)
    {
        StackSizeCheck_myStack[i] = STACK_CHECK_VAL;
    }

    return 0;
}

#define STACK_SIZE_CHECKPOINT(...) ({  \
    ssize_t HWM = StackSizeHWM_OffsetCorrected();    \
    __VA_ARGS__;                                     \
    printf("    relative stack peak usage = %ld bytes\n", (long int)HWM);  \
    StackSizeHWMReset();                             \
    })

#define STACK_SIZE_CHECKPOINT_WITH_MAX_CHECK(max, ...) ({  \
    ssize_t HWM = StackSizeHWM_OffsetCorrected();    \
    int _ret;                                        \
    __VA_ARGS__;                                     \
    printf("    relative stack peak usage = %ld bytes\n", (long int)HWM);  \
    _ret = StackSizeHWMReset();                      \
    if ((max >= 0) && (HWM > (ssize_t)(max))) {      \
        fprintf(stderr,                              \
            "    relative stack usage at %s L%d exceeds designated max %ld bytes.\n", \
            __FILE__, __LINE__, (long int)(max));    \
        _ret = -1;                                   \
    }                                                \
    _ret;                                            \
    })


#ifdef __GNUC__
#define STACK_SIZE_INIT() (void)StackSizeSetOffset(__FUNCTION__, __builtin_frame_address(0))
#endif

#endif /* HAVE_STACK_SIZE_VERBOSE */

static WC_INLINE int StackSizeCheck(func_args* args, thread_func tf)
{
    size_t         i;
    int            ret;
    void*          status;
    unsigned char* myStack = NULL;
    size_t         stackSize = 1024*1024*2;
    pthread_attr_t myAttr;
    pthread_t      threadId;
#ifdef HAVE_STACK_SIZE_VERBOSE
    struct stack_size_debug_context shim_args;
#endif

#ifdef PTHREAD_STACK_MIN
    if (stackSize < PTHREAD_STACK_MIN)
        stackSize = PTHREAD_STACK_MIN;
#endif

    ret = posix_memalign((void**)&myStack, sysconf(_SC_PAGESIZE), stackSize);
    if (ret != 0 || myStack == NULL) {
        err_sys_with_errno("posix_memalign failed\n");
        return -1;
    }

    XMEMSET(myStack, STACK_CHECK_VAL, stackSize);

    ret = pthread_attr_init(&myAttr);
    if (ret != 0)
        err_sys("attr_init failed");

    ret = pthread_attr_setstack(&myAttr, myStack, stackSize);
    if (ret != 0)
        err_sys("attr_setstackaddr failed");

#ifdef HAVE_STACK_SIZE_VERBOSE
    StackSizeCheck_stackSizeHWM = 0;
    shim_args.myStack = myStack;
    shim_args.stackSize = stackSize;
    shim_args.stackSizeHWM_ptr = &StackSizeCheck_stackSizeHWM;
    shim_args.fn = tf;
    shim_args.args = args;
    ret = pthread_create(&threadId, &myAttr, (thread_func)debug_stack_size_verbose_shim, (void *)&shim_args);
#else
    ret = pthread_create(&threadId, &myAttr, tf, args);
#endif
    if (ret != 0) {
        printf("ret = %d\n", ret);
        perror("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(threadId, &status);
    if (ret != 0)
        err_sys("pthread_join failed");

    for (i = 0; i < stackSize; i++) {
        if (myStack[i] != STACK_CHECK_VAL) {
            break;
        }
    }

    free(myStack);
#ifdef HAVE_STACK_SIZE_VERBOSE
    printf("stack used = %lu\n", StackSizeCheck_stackSizeHWM > (stackSize - i)
        ? (unsigned long)StackSizeCheck_stackSizeHWM
        : (unsigned long)(stackSize - i));
#else
    {
      size_t used = stackSize - i;
      printf("stack used = %lu\n", (unsigned long)used);
    }
#endif

    return (int)((size_t)status);
}

static WC_INLINE int StackSizeCheck_launch(func_args* args, thread_func tf, pthread_t *threadId, void **stack_context)
{
    int ret;
    unsigned char* myStack = NULL;
    size_t stackSize = 1024*1024*2;
    pthread_attr_t myAttr;

#ifdef PTHREAD_STACK_MIN
    if (stackSize < PTHREAD_STACK_MIN)
        stackSize = PTHREAD_STACK_MIN;
#endif

    struct stack_size_debug_context *shim_args = (struct stack_size_debug_context *)malloc(sizeof *shim_args);
    if (! shim_args) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    ret = posix_memalign((void**)&myStack, sysconf(_SC_PAGESIZE), stackSize);
    if (ret != 0 || myStack == NULL) {
        err_sys_with_errno("posix_memalign failed\n");
        free(shim_args);
        return -1;
    }

    XMEMSET(myStack, STACK_CHECK_VAL, stackSize);

    ret = pthread_attr_init(&myAttr);
    if (ret != 0)
        err_sys("attr_init failed");

    ret = pthread_attr_setstack(&myAttr, myStack, stackSize);
    if (ret != 0)
        err_sys("attr_setstackaddr failed");

    shim_args->myStack = myStack;
    shim_args->stackSize = stackSize;
#ifdef HAVE_STACK_SIZE_VERBOSE
    shim_args->stackSizeHWM_ptr = &StackSizeCheck_stackSizeHWM;
    shim_args->fn = tf;
    shim_args->args = args;
    ret = pthread_create(threadId, &myAttr, (thread_func)debug_stack_size_verbose_shim, (void *)shim_args);
#else
    ret = pthread_create(threadId, &myAttr, tf, args);
#endif
    if (ret != 0) {
        fprintf(stderr,"pthread_create failed: %s",strerror(ret));
        exit(EXIT_FAILURE);
    }

    *stack_context = (void *)shim_args;

    return 0;
}

static WC_INLINE int StackSizeCheck_reap(pthread_t threadId, void *stack_context)
{
    struct stack_size_debug_context *shim_args = (struct stack_size_debug_context *)stack_context;
    size_t i;
    void *status;
    int ret = pthread_join(threadId, &status);
    if (ret != 0)
        err_sys("pthread_join failed");

    for (i = 0; i < shim_args->stackSize; i++) {
        if (shim_args->myStack[i] != STACK_CHECK_VAL) {
            break;
        }
    }

    free(shim_args->myStack);
#ifdef HAVE_STACK_SIZE_VERBOSE
    printf("stack used = %lu\n",
        *shim_args->stackSizeHWM_ptr > (shim_args->stackSize - i)
        ? (unsigned long)*shim_args->stackSizeHWM_ptr
        : (unsigned long)(shim_args->stackSize - i));
#else
    {
      size_t used = shim_args->stackSize - i;
      printf("stack used = %lu\n", (unsigned long)used);
    }
#endif
    free(shim_args);

    return (int)((size_t)status);
}


#endif /* HAVE_STACK_SIZE */

#ifndef STACK_SIZE_CHECKPOINT
#define STACK_SIZE_CHECKPOINT(...) (__VA_ARGS__)
#endif
#ifndef STACK_SIZE_INIT
#define STACK_SIZE_INIT()
#endif

#ifdef STACK_TRAP

/* good settings
   --enable-debug --disable-shared C_EXTRA_FLAGS="-DUSER_TIME -DTFM_TIMING_RESISTANT -DPOSITIVE_EXP_ONLY -DSTACK_TRAP"

*/

#ifdef HAVE_STACK_SIZE
    /* client only for now, setrlimit will fail if pthread_create() called */
    /* STACK_SIZE does pthread_create() on client */
    #error "can't use STACK_TRAP with STACK_SIZE, setrlimit will fail"
#endif /* HAVE_STACK_SIZE */

static WC_INLINE void StackTrap(void)
{
    struct rlimit  rl;
    if (getrlimit(RLIMIT_STACK, &rl) != 0)
        err_sys_with_errno("getrlimit failed");
    printf("rlim_cur = %llu\n", rl.rlim_cur);
    rl.rlim_cur = 1024*21;  /* adjust trap size here */
    if (setrlimit(RLIMIT_STACK, &rl) != 0)
        err_sys_with_errno("setrlimit failed");
}

#else /* STACK_TRAP */

static WC_INLINE void StackTrap(void)
{
}

#endif /* STACK_TRAP */





static WC_INLINE int SimulateWantWriteIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    static int wantWriteFlag = 1;

    int sent;
    int sd = *(int*)ctx;

    (void)ssl;

    if (!wantWriteFlag)
    {
        wantWriteFlag = 1;

        sent = wolfIO_Send(sd, buf, sz, 0);
        if (sent < 0) {
            int err = errno;

            if (err == SOCKET_EWOULDBLOCK || err == SOCKET_EAGAIN) {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            }
            else if (err == SOCKET_ECONNRESET) {
                return WOLFSSL_CBIO_ERR_CONN_RST;
            }
            else if (err == SOCKET_EINTR) {
                return WOLFSSL_CBIO_ERR_ISR;
            }
            else if (err == SOCKET_EPIPE) {
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }
            else {
                return WOLFSSL_CBIO_ERR_GENERAL;
            }
        }

        return sent;
    }
    else
    {
        wantWriteFlag = 0;
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
}

#if defined(__hpux__) || defined(__MINGW32__) || defined (WOLFSSL_TIRTOS)

/* HP/UX doesn't have strsep, needed by test/suites.c */
static WC_INLINE char* strsep(char **stringp, const char *delim)
{
    char* start;
    char* end;

    start = *stringp;
    if (start == NULL)
        return NULL;

    if ((end = strpbrk(start, delim))) {
        *end++ = '\0';
        *stringp = end;
    } else {
        *stringp = NULL;
    }

    return start;
}

#endif /* __hpux__ and others */

/* Create unique filename, len is length of tempfn name, assuming
   len does not include null terminating character,
   num is number of characters in tempfn name to randomize */
static WC_INLINE const char* mymktemp(char *tempfn, int len, int num)
{
    int x, size;
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";
    WC_RNG rng;
    byte   out = 0;

    if (tempfn == NULL || len < 1 || num < 1 || len <= num) {
        fprintf(stderr, "Bad input\n");
        return NULL;
    }

    size = len - 1;

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "InitRng failed\n");
        return NULL;
    }

    for (x = size; x > size - num; x--) {
        if (wc_RNG_GenerateBlock(&rng,(byte*)&out, sizeof(out)) != 0) {
            fprintf(stderr, "RNG_GenerateBlock failed\n");
            return NULL;
        }
        tempfn[x] = alphanum[out % (sizeof(alphanum) - 1)];
    }
    tempfn[len] = '\0';

    wc_FreeRng(&rng);
    (void)rng; /* for WC_NO_RNG case */

    return tempfn;
}





static WC_INLINE word16 GetRandomPort(void)
{
    word16 port = 0;

    /* Generate random port for testing */
    WC_RNG rng;
    if (wc_InitRng(&rng) == 0) {
        if (wc_RNG_GenerateBlock(&rng, (byte*)&port, sizeof(port)) == 0) {
            port |= 0xC000; /* Make sure its in the 49152 - 65535 range */
        }
        wc_FreeRng(&rng);
    }
    (void)rng; /* for WC_NO_RNG case */
    return port;
}




#endif /* wolfSSL_TEST_H */
