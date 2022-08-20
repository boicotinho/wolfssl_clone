/* wolfio.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY

#ifdef _WIN32_WCE
    /* On WinCE winsock2.h must be included before windows.h for socket stuff */
    #include <winsock2.h>
#endif

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfio.h>


/*
Possible IO enable options:
 * WOLFSSL_USER_IO:     Disables default Embed* callbacks and     default: off
                        allows user to define their own using
                        wolfSSL_CTX_SetIORecv and wolfSSL_CTX_SetIOSend
 * USE_WOLFSSL_IO:      Enables the wolfSSL IO functions          default: on
 * HAVE_HTTP_CLIENT:    Enables HTTP client API's                 default: off
                                     (unless HAVE_OCSP or HAVE_CRL_IO defined)
 * HAVE_IO_TIMEOUT:     Enables support for connect timeout       default: off
 */


/* if user writes own I/O callbacks they can define WOLFSSL_USER_IO to remove
   automatic setting of default I/O functions EmbedSend() and EmbedReceive()
   but they'll still need SetCallback xxx() at end of file
*/


/* Translates return codes returned from
 * send() and recv() if need be.
 */
static WC_INLINE int TranslateReturnCode(int old, int sd)
{
    (void)sd;


    return old;
}

static WC_INLINE int wolfSSL_LastError(int err)
{
    (void)err; /* Suppress unused arg */

    return errno;
}

static int TranslateIoError(int err)
{
    if (err > 0)
        return err;

    err = wolfSSL_LastError(err);
#if SOCKET_EWOULDBLOCK != SOCKET_EAGAIN
    if ((err == SOCKET_EWOULDBLOCK) || (err == SOCKET_EAGAIN))
#else
    if (err == SOCKET_EWOULDBLOCK)
#endif
    {
        WOLFSSL_MSG("\tWould block");
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    else if (err == SOCKET_ECONNRESET) {
        WOLFSSL_MSG("\tConnection reset");
        return WOLFSSL_CBIO_ERR_CONN_RST;
    }
    else if (err == SOCKET_EINTR) {
        WOLFSSL_MSG("\tSocket interrupted");
        return WOLFSSL_CBIO_ERR_ISR;
    }
    else if (err == SOCKET_EPIPE) {
        WOLFSSL_MSG("\tBroken pipe");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    else if (err == SOCKET_ECONNABORTED) {
        WOLFSSL_MSG("\tConnection aborted");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    WOLFSSL_MSG("\tGeneral error");
    return WOLFSSL_CBIO_ERR_GENERAL;
}




/* The receive embedded callback
 *  return : nb bytes read, or error
 */
int EmbedReceive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int recvd;
    int sd = *(int*)ctx;

    recvd = wolfIO_Recv(sd, buf, sz, ssl->rflags);
    if (recvd < 0) {
        WOLFSSL_MSG("Embed Receive error");
        return TranslateIoError(recvd);
    }
    else if (recvd == 0) {
        WOLFSSL_MSG("Embed receive connection closed");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    return recvd;
}

/* The send embedded callback
 *  return : nb bytes sent, or error
 */
int EmbedSend(WOLFSSL* ssl, char *buf, int sz, void *ctx)
{
    int sent;
    int sd = *(int*)ctx;


    sent = wolfIO_Send(sd, buf, sz, ssl->wflags);
    if (sent < 0) {
        WOLFSSL_MSG("Embed Send error");
        return TranslateIoError(sent);
    }

    return sent;
}






int wolfIO_Recv(SOCKET_T sd, char *buf, int sz, int rdFlags)
{
    int recvd;

    recvd = (int)RECV_FUNCTION(sd, buf, sz, rdFlags);
    recvd = TranslateReturnCode(recvd, sd);

    return recvd;
}

int wolfIO_Send(SOCKET_T sd, char *buf, int sz, int wrFlags)
{
    int sent;

    sent = (int)SEND_FUNCTION(sd, buf, sz, wrFlags);
    sent = TranslateReturnCode(sent, sd);

    return sent;
}






void wolfSSL_CTX_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv CBIORecv)
{
    if (ctx) {
        ctx->CBIORecv = CBIORecv;
    }
}


void wolfSSL_CTX_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend CBIOSend)
{
    if (ctx) {
        ctx->CBIOSend = CBIOSend;
    }
}


/* sets the IO callback to use for receives at WOLFSSL level */
void wolfSSL_SSLSetIORecv(WOLFSSL *ssl, CallbackIORecv CBIORecv)
{
    if (ssl) {
        ssl->CBIORecv = CBIORecv;
    }
}


/* sets the IO callback to use for sends at WOLFSSL level */
void wolfSSL_SSLSetIOSend(WOLFSSL *ssl, CallbackIOSend CBIOSend)
{
    if (ssl) {
        ssl->CBIOSend = CBIOSend;
    }
}


void wolfSSL_SetIOReadCtx(WOLFSSL* ssl, void *rctx)
{
    if (ssl)
        ssl->IOCB_ReadCtx = rctx;
}


void wolfSSL_SetIOWriteCtx(WOLFSSL* ssl, void *wctx)
{
    if (ssl)
        ssl->IOCB_WriteCtx = wctx;
}


void* wolfSSL_GetIOReadCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->IOCB_ReadCtx;

    return NULL;
}


void* wolfSSL_GetIOWriteCtx(WOLFSSL* ssl)
{
    if (ssl)
        return ssl->IOCB_WriteCtx;

    return NULL;
}


void wolfSSL_SetIOReadFlags(WOLFSSL* ssl, int flags)
{
    if (ssl)
        ssl->rflags = flags;
}


void wolfSSL_SetIOWriteFlags(WOLFSSL* ssl, int flags)
{
    if (ssl)
        ssl->wflags = flags;
}





#ifdef HAVE_NETX

/* The NetX receive callback
 *  return :  bytes read, or error
 */
int NetX_Receive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    NetX_Ctx* nxCtx = (NetX_Ctx*)ctx;
    ULONG left;
    ULONG total;
    ULONG copied = 0;
    UINT  status;

    (void)ssl;

    if (nxCtx == NULL || nxCtx->nxSocket == NULL) {
        WOLFSSL_MSG("NetX Recv NULL parameters");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if (nxCtx->nxPacket == NULL) {
        status = nx_tcp_socket_receive(nxCtx->nxSocket, &nxCtx->nxPacket,
                                       nxCtx->nxWait);
        if (status != NX_SUCCESS) {
            WOLFSSL_MSG("NetX Recv receive error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    if (nxCtx->nxPacket) {
        status = nx_packet_length_get(nxCtx->nxPacket, &total);
        if (status != NX_SUCCESS) {
            WOLFSSL_MSG("NetX Recv length get error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        left = total - nxCtx->nxOffset;
        status = nx_packet_data_extract_offset(nxCtx->nxPacket, nxCtx->nxOffset,
                                               buf, sz, &copied);
        if (status != NX_SUCCESS) {
            WOLFSSL_MSG("NetX Recv data extract offset error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        nxCtx->nxOffset += copied;

        if (copied == left) {
            WOLFSSL_MSG("NetX Recv Drained packet");
            nx_packet_release(nxCtx->nxPacket);
            nxCtx->nxPacket = NULL;
            nxCtx->nxOffset = 0;
        }
    }

    return copied;
}


/* The NetX send callback
 *  return : bytes sent, or error
 */
int NetX_Send(WOLFSSL* ssl, char *buf, int sz, void *ctx)
{
    NetX_Ctx*       nxCtx = (NetX_Ctx*)ctx;
    NX_PACKET*      packet;
    NX_PACKET_POOL* pool;   /* shorthand */
    UINT            status;

    (void)ssl;

    if (nxCtx == NULL || nxCtx->nxSocket == NULL) {
        WOLFSSL_MSG("NetX Send NULL parameters");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    pool = nxCtx->nxSocket->nx_tcp_socket_ip_ptr->nx_ip_default_packet_pool;
    status = nx_packet_allocate(pool, &packet, NX_TCP_PACKET,
                                nxCtx->nxWait);
    if (status != NX_SUCCESS) {
        WOLFSSL_MSG("NetX Send packet alloc error");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    status = nx_packet_data_append(packet, buf, sz, pool, nxCtx->nxWait);
    if (status != NX_SUCCESS) {
        nx_packet_release(packet);
        WOLFSSL_MSG("NetX Send data append error");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    status = nx_tcp_socket_send(nxCtx->nxSocket, packet, nxCtx->nxWait);
    if (status != NX_SUCCESS) {
        nx_packet_release(packet);
        WOLFSSL_MSG("NetX Send socket send error");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return sz;
}


/* like set_fd, but for default NetX context */
void wolfSSL_SetIO_NetX(WOLFSSL* ssl, NX_TCP_SOCKET* nxSocket, ULONG waitOption)
{
    if (ssl) {
        ssl->nxCtx.nxSocket = nxSocket;
        ssl->nxCtx.nxWait   = waitOption;
    }
}

#endif /* HAVE_NETX */


#ifdef MICRIUM

/* Micrium uTCP/IP port, using the NetSock API
 * TCP and UDP are currently supported with the callbacks below.
 *
 * WOLFSSL_SESSION_EXPORT is not yet supported, would need EmbedGetPeer()
 * and EmbedSetPeer() callbacks implemented.
 *
 * HAVE_CRL is not yet supported, would need an EmbedCrlLookup()
 * callback implemented.
 *
 * HAVE_OCSP is not yet supported, would need an EmbedOCSPLookup()
 * callback implemented.
 */

/* The Micrium uTCP/IP send callback
 * return : bytes sent, or error
 */
int MicriumSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    NET_SOCK_ID sd = *(int*)ctx;
    NET_SOCK_RTN_CODE ret;
    NET_ERR err;

    ret = NetSock_TxData(sd, buf, sz, ssl->wflags, &err);
    if (ret < 0) {
        WOLFSSL_MSG("Embed Send error");

        if (err == NET_ERR_TX) {
            WOLFSSL_MSG("\tWould block");
            return WOLFSSL_CBIO_ERR_WANT_WRITE;

        } else {
            WOLFSSL_MSG("\tGeneral error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}

/* The Micrium uTCP/IP receive callback
 *  return : nb bytes read, or error
 */
int MicriumReceive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    NET_SOCK_ID sd = *(int*)ctx;
    NET_SOCK_RTN_CODE ret;
    NET_ERR err;


    ret = NetSock_RxData(sd, buf, sz, ssl->rflags, &err);
    if (ret < 0) {
        WOLFSSL_MSG("Embed Receive error");

        if (err == NET_ERR_RX || err == NET_SOCK_ERR_RX_Q_EMPTY ||
            err == NET_ERR_FAULT_LOCK_ACQUIRE) {
            if (!wolfSSL_dtls(ssl) || wolfSSL_dtls_get_using_nonblock(ssl)) {
                WOLFSSL_MSG("\tWould block");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                WOLFSSL_MSG("\tSocket timeout");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }

        } else if (err == NET_SOCK_ERR_CLOSED) {
            WOLFSSL_MSG("Embed receive connection closed");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;

        } else {
            WOLFSSL_MSG("\tGeneral error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}

/* The Micrium uTCP/IP receivefrom callback
 *  return : nb bytes read, or error
 */
int MicriumReceiveFrom(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    WOLFSSL_DTLS_CTX* dtlsCtx = (WOLFSSL_DTLS_CTX*)ctx;
    NET_SOCK_ID       sd = dtlsCtx->rfd;
    NET_SOCK_ADDR     peer;
    NET_SOCK_ADDR_LEN peerSz = sizeof(peer);
    NET_SOCK_RTN_CODE ret;
    NET_ERR err;
    int dtls_timeout = wolfSSL_dtls_get_current_timeout(ssl);

    WOLFSSL_ENTER("MicriumReceiveFrom()");

    if (ssl->options.handShakeDone)
        dtls_timeout = 0;

    if (!wolfSSL_dtls_get_using_nonblock(ssl)) {
        /* needs timeout in milliseconds */
        NetSock_CfgTimeoutRxQ_Set(sd, dtls_timeout * 1000, &err);
        if (err != NET_SOCK_ERR_NONE) {
            WOLFSSL_MSG("NetSock_CfgTimeoutRxQ_Set failed");
        }
    }

    ret = NetSock_RxDataFrom(sd, buf, sz, ssl->rflags, &peer, &peerSz,
                             0, 0, 0, &err);
    if (ret < 0) {
        WOLFSSL_MSG("Embed Receive From error");

        if (err == NET_ERR_RX || err == NET_SOCK_ERR_RX_Q_EMPTY ||
            err == NET_ERR_FAULT_LOCK_ACQUIRE) {
            if (wolfSSL_dtls_get_using_nonblock(ssl)) {
                WOLFSSL_MSG("\tWould block");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                WOLFSSL_MSG("\tSocket timeout");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        } else {
            WOLFSSL_MSG("\tGeneral error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else {
        if (dtlsCtx->peer.sz > 0
                && peerSz != (NET_SOCK_ADDR_LEN)dtlsCtx->peer.sz
                && XMEMCMP(&peer, dtlsCtx->peer.sa, peerSz) != 0) {
            WOLFSSL_MSG("\tIgnored packet from invalid peer");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
    }

    return ret;
}

/* The Micrium uTCP/IP sendto callback
 *  return : nb bytes sent, or error
 */
int MicriumSendTo(WOLFSSL* ssl, char *buf, int sz, void *ctx)
{
    WOLFSSL_DTLS_CTX* dtlsCtx = (WOLFSSL_DTLS_CTX*)ctx;
    NET_SOCK_ID sd = dtlsCtx->wfd;
    NET_SOCK_RTN_CODE ret;
    NET_ERR err;

    WOLFSSL_ENTER("MicriumSendTo()");

    ret = NetSock_TxDataTo(sd, buf, sz, ssl->wflags,
                           (NET_SOCK_ADDR*)dtlsCtx->peer.sa,
                           (NET_SOCK_ADDR_LEN)dtlsCtx->peer.sz,
                           &err);
    if (err < 0) {
        WOLFSSL_MSG("Embed Send To error");

        if (err == NET_ERR_TX) {
            WOLFSSL_MSG("\tWould block");
            return WOLFSSL_CBIO_ERR_WANT_WRITE;

        } else {
            WOLFSSL_MSG("\tGeneral error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}

/* Micrium DTLS Generate Cookie callback
 *  return : number of bytes copied into buf, or error
 */
int MicriumGenerateCookie(WOLFSSL* ssl, byte *buf, int sz, void *ctx)
{
    NET_SOCK_ADDR peer;
    NET_SOCK_ADDR_LEN peerSz = sizeof(peer);
    byte digest[WC_SHA_DIGEST_SIZE];
    int  ret = 0;

    (void)ctx;

    XMEMSET(&peer, 0, sizeof(peer));
    if (wolfSSL_dtls_get_peer(ssl, (void*)&peer,
                              (unsigned int*)&peerSz) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("getpeername failed in MicriumGenerateCookie");
        return GEN_COOKIE_E;
    }

    ret = wc_ShaHash((byte*)&peer, peerSz, digest);
    if (ret != 0)
        return ret;

    if (sz > WC_SHA_DIGEST_SIZE)
        sz = WC_SHA_DIGEST_SIZE;
    XMEMCPY(buf, digest, sz);

    return sz;
}

#endif /* MICRIUM */

#if defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)

#include <os/os_error.h>
#include <os/os_mbuf.h>
#include <os/os_mempool.h>

#define MB_NAME "wolfssl_mb"

typedef struct Mynewt_Ctx {
        struct mn_socket *mnSocket;          /* send/recv socket handler */
        struct mn_sockaddr_in mnSockAddrIn;  /* socket address */
        struct os_mbuf *mnPacket;            /* incoming packet handle
                                                for short reads */
        int reading;                         /* reading flag */

        /* private */
        void *mnMemBuffer;                   /* memory buffer for mempool */
        struct os_mempool mnMempool;         /* mempool */
        struct os_mbuf_pool mnMbufpool;      /* mbuf pool */
} Mynewt_Ctx;

void mynewt_ctx_clear(void *ctx) {
    Mynewt_Ctx *mynewt_ctx = (Mynewt_Ctx*)ctx;
    if(!mynewt_ctx) return;

    if(mynewt_ctx->mnPacket) {
        os_mbuf_free_chain(mynewt_ctx->mnPacket);
        mynewt_ctx->mnPacket = NULL;
    }
    os_mempool_clear(&mynewt_ctx->mnMempool);
    XFREE(mynewt_ctx->mnMemBuffer, 0, 0);
    XFREE(mynewt_ctx, 0, 0);
}

/* return Mynewt_Ctx instance */
void* mynewt_ctx_new() {
    int rc = 0;
    Mynewt_Ctx *mynewt_ctx;
    int mem_buf_count = MYNEWT_VAL(WOLFSSL_MNSOCK_MEM_BUF_COUNT);
    int mem_buf_size = MYNEWT_VAL(WOLFSSL_MNSOCK_MEM_BUF_SIZE);
    int mempool_bytes = OS_MEMPOOL_BYTES(mem_buf_count, mem_buf_size);

    mynewt_ctx = (Mynewt_Ctx *)XMALLOC(sizeof(struct Mynewt_Ctx),
                                       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if(!mynewt_ctx) return NULL;

    XMEMSET(mynewt_ctx, 0, sizeof(Mynewt_Ctx));
    mynewt_ctx->mnMemBuffer = (void *)XMALLOC(mempool_bytes, 0, 0);
    if(!mynewt_ctx->mnMemBuffer) {
        mynewt_ctx_clear((void*)mynewt_ctx);
        return NULL;
    }

    rc = os_mempool_init(&mynewt_ctx->mnMempool,
                         mem_buf_count, mem_buf_size,
                         mynewt_ctx->mnMemBuffer, MB_NAME);
    if(rc != 0) {
        mynewt_ctx_clear((void*)mynewt_ctx);
        return NULL;
    }
    rc = os_mbuf_pool_init(&mynewt_ctx->mnMbufpool, &mynewt_ctx->mnMempool,
                           mem_buf_count, mem_buf_size);
    if(rc != 0) {
        mynewt_ctx_clear((void*)mynewt_ctx);
        return NULL;
    }

    return mynewt_ctx;
}

static void mynewt_sock_writable(void *arg, int err);
static void mynewt_sock_readable(void *arg, int err);
static const union mn_socket_cb mynewt_sock_cbs = {
    .socket.writable = mynewt_sock_writable,
    .socket.readable = mynewt_sock_readable,
};
static void mynewt_sock_writable(void *arg, int err)
{
    /* do nothing */
}
static void mynewt_sock_readable(void *arg, int err)
{
    Mynewt_Ctx *mynewt_ctx = (Mynewt_Ctx *)arg;
    if (err && mynewt_ctx->reading) {
        mynewt_ctx->reading = 0;
    }
}

/* The Mynewt receive callback
 *  return :  bytes read, or error
 */
int Mynewt_Receive(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    Mynewt_Ctx *mynewt_ctx = (Mynewt_Ctx*)ctx;
    int rc = 0;
    struct mn_sockaddr_in from;
    struct os_mbuf *m;
    int read_sz = 0;
    word16 total;

    if (mynewt_ctx == NULL || mynewt_ctx->mnSocket == NULL) {
        WOLFSSL_MSG("Mynewt Recv NULL parameters");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if(mynewt_ctx->mnPacket == NULL) {
        mynewt_ctx->mnPacket = os_mbuf_get_pkthdr(&mynewt_ctx->mnMbufpool, 0);
        if(mynewt_ctx->mnPacket == NULL) {
            return MEMORY_E;
        }

        mynewt_ctx->reading = 1;
        while(mynewt_ctx->reading && rc == 0) {
            rc = mn_recvfrom(mynewt_ctx->mnSocket, &m, (struct mn_sockaddr *) &from);
            if(rc == MN_ECONNABORTED) {
                rc = 0;
                mynewt_ctx->reading = 0;
                break;
            }
            if (!(rc == 0 || rc == MN_EAGAIN)) {
                WOLFSSL_MSG("Mynewt Recv receive error");
                mynewt_ctx->reading = 0;
                break;
            }
            if(rc == 0) {
                int len = OS_MBUF_PKTLEN(m);
                if(len == 0) {
                    break;
                }
                rc = os_mbuf_appendfrom(mynewt_ctx->mnPacket, m, 0, len);
                if(rc != 0) {
                    WOLFSSL_MSG("Mynewt Recv os_mbuf_appendfrom error");
                    break;
                }
                os_mbuf_free_chain(m);
                m = NULL;
            } else if(rc == MN_EAGAIN) {
                /* continue to until reading all of packet data. */
                rc = 0;
                break;
            }
        }
        if(rc != 0) {
            mynewt_ctx->reading = 0;
            os_mbuf_free_chain(mynewt_ctx->mnPacket);
            mynewt_ctx->mnPacket = NULL;
            return rc;
        }
    }

    if(mynewt_ctx->mnPacket) {
        total = OS_MBUF_PKTLEN(mynewt_ctx->mnPacket);
        read_sz = (total >= sz)? sz : total;

        os_mbuf_copydata(mynewt_ctx->mnPacket, 0, read_sz, (void*)buf);
        os_mbuf_adj(mynewt_ctx->mnPacket, read_sz);

        if (read_sz == total) {
            WOLFSSL_MSG("Mynewt Recv Drained packet");
            os_mbuf_free_chain(mynewt_ctx->mnPacket);
            mynewt_ctx->mnPacket = NULL;
        }
    }

    return read_sz;
}

/* The Mynewt send callback
 *  return : bytes sent, or error
 */
int Mynewt_Send(WOLFSSL* ssl, char *buf, int sz, void *ctx)
{
    Mynewt_Ctx *mynewt_ctx = (Mynewt_Ctx*)ctx;
    int rc = 0;
    struct os_mbuf *m;
    int write_sz = 0;
    m = os_msys_get_pkthdr(sz, 0);
    if (!m) {
        WOLFSSL_MSG("Mynewt Send os_msys_get_pkthdr error");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    rc = os_mbuf_copyinto(m, 0, buf, sz);
    if (rc != 0) {
        WOLFSSL_MSG("Mynewt Send os_mbuf_copyinto error");
        os_mbuf_free_chain(m);
        return rc;
    }
    rc = mn_sendto(mynewt_ctx->mnSocket, m, (struct mn_sockaddr *)&mynewt_ctx->mnSockAddrIn);
    if(rc != 0) {
        WOLFSSL_MSG("Mynewt Send mn_sendto error");
        os_mbuf_free_chain(m);
        return rc;
    }
    write_sz = sz;
    return write_sz;
}

/* like set_fd, but for default NetX context */
void wolfSSL_SetIO_Mynewt(WOLFSSL* ssl, struct mn_socket* mnSocket, struct mn_sockaddr_in* mnSockAddrIn)
{
    if (ssl && ssl->mnCtx) {
        Mynewt_Ctx *mynewt_ctx = (Mynewt_Ctx *)ssl->mnCtx;
        mynewt_ctx->mnSocket = mnSocket;
        XMEMCPY(&mynewt_ctx->mnSockAddrIn, mnSockAddrIn, sizeof(struct mn_sockaddr_in));
        mn_socket_set_cbs(mynewt_ctx->mnSocket, mnSocket, &mynewt_sock_cbs);
    }
}

#endif /* defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP) */


#ifdef WOLFSSL_GNRC

#include <net/sock.h>
#include <net/sock/tcp.h>
#include <stdio.h>

/* GNRC TCP/IP port, using the native tcp/udp socket api.
 * TCP and UDP are currently supported with the callbacks below.
 *
 */
/* The GNRC tcp send callback
 * return : bytes sent, or error
 */

int GNRC_SendTo(WOLFSSL* ssl, char* buf, int sz, void* _ctx)
{
    sock_tls_t *ctx = (sock_tls_t *)_ctx;
    int ret = 0;
    (void)ssl;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    ret = sock_udp_send(&ctx->conn.udp, (unsigned char *)buf, sz, &ctx->peer_addr);
    if (ret == 0)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return ret;
}

/* The GNRC TCP/IP receive callback
 *  return : nb bytes read, or error
 */
int GNRC_ReceiveFrom(WOLFSSL *ssl, char *buf, int sz, void *_ctx)
{
    sock_udp_ep_t ep;
    int ret;
    word32 timeout = wolfSSL_dtls_get_current_timeout(ssl) * 1000000;
    sock_tls_t *ctx = (sock_tls_t *)_ctx;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    (void)ssl;
    if (wolfSSL_get_using_nonblock(ctx->ssl)) {
        timeout = 0;
    }
    ret = sock_udp_recv(&ctx->conn.udp, buf, sz, timeout, &ep);
    if (ret > 0) {
        if (ctx->peer_addr.port == 0)
            XMEMCPY(&ctx->peer_addr, &ep, sizeof(sock_udp_ep_t));
    }
    if (ret == -ETIMEDOUT) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return ret;
}

/* GNRC DTLS Generate Cookie callback
 *  return : number of bytes copied into buf, or error
 */
#define GNRC_MAX_TOKEN_SIZE (32)
int GNRC_GenerateCookie(WOLFSSL* ssl, byte *buf, int sz, void *_ctx)
{
    sock_tls_t *ctx = (sock_tls_t *)_ctx;
    if (!ctx)
        return WOLFSSL_CBIO_ERR_GENERAL;
    byte token[GNRC_MAX_TOKEN_SIZE];
    byte digest[WC_SHA_DIGEST_SIZE];
    int  ret = 0;
    size_t token_size = sizeof(sock_udp_ep_t);
    (void)ssl;
    if (token_size > GNRC_MAX_TOKEN_SIZE)
        token_size = GNRC_MAX_TOKEN_SIZE;
    XMEMSET(token, 0, GNRC_MAX_TOKEN_SIZE);
    XMEMCPY(token, &ctx->peer_addr, token_size);
    ret = wc_ShaHash(token, token_size, digest);
    if (ret != 0)
        return ret;
    if (sz > WC_SHA_DIGEST_SIZE)
        sz = WC_SHA_DIGEST_SIZE;
    XMEMCPY(buf, digest, sz);
    return sz;
}

#endif /* WOLFSSL_GNRC */

#ifdef WOLFSSL_LWIP_NATIVE
int LwIPNativeSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    err_t ret;
    WOLFSSL_LWIP_NATIVE_STATE* nlwip = (WOLFSSL_LWIP_NATIVE_STATE*)ctx;

    ret = tcp_write(nlwip->pcb, buf, sz, TCP_WRITE_FLAG_COPY);
    if (ret != ERR_OK) {
        sz = -1;
    }

    return sz;
}


int LwIPNativeReceive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    struct pbuf *current, *head;
    WOLFSSL_LWIP_NATIVE_STATE* nlwip;
    int ret = 0;

    if (ctx == NULL) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    nlwip = (WOLFSSL_LWIP_NATIVE_STATE*)ctx;

    current = nlwip->pbuf;
    if (current == NULL || sz > current->tot_len) {
        WOLFSSL_MSG("LwIP native pbuf list is null or not enough data, want read");
        ret = WOLFSSL_CBIO_ERR_WANT_READ;
    }
    else {
        int read = 0; /* total amount read */
        head = nlwip->pbuf; /* save pointer to current head */

        /* loop through buffers reading data */
        while (current != NULL) {
            int len; /* current amount to be read */

            len = (current->len - nlwip->pulled < sz) ?
                                            (current->len - nlwip->pulled) : sz;

            if (read + len > sz) {
                /* should never be hit but have sanity check before use */
                return WOLFSSL_CBIO_ERR_GENERAL;
            }

            /* check if is a partial read from before */
            XMEMCPY(&buf[read],
                   (const char *)&(((char *)(current->payload))[nlwip->pulled]),

                    len);
            nlwip->pulled = nlwip->pulled + len;
            if (nlwip->pulled >= current->len) {
                WOLFSSL_MSG("Native LwIP read full pbuf");
                nlwip->pbuf = current->next;
                current = nlwip->pbuf;
                nlwip->pulled = 0;
            }
            read = read + len;
            ret  = read;

            /* read enough break out */
            if (read >= sz) {
                /* if more pbuf's are left in the chain then increment the
                 * ref count for next in chain and free all from begining till
                 * next */
                if (current != NULL) {
                    pbuf_ref(current);
                }

                /* ack and start free'ing from the current head of the chain */
                pbuf_free(head);
                break;
            }
        }
    }
    WOLFSSL_LEAVE("LwIPNativeReceive", ret);
    return ret;
}


static err_t LwIPNativeReceiveCB(void* cb, struct tcp_pcb* pcb,
                                struct pbuf* pbuf, err_t err)
{
    WOLFSSL_LWIP_NATIVE_STATE* nlwip;

    if (cb == NULL || pcb == NULL) {
        WOLFSSL_MSG("Expected callback was null, abort");
        return ERR_ABRT;
    }

    nlwip = (WOLFSSL_LWIP_NATIVE_STATE*)cb;
    if (pbuf == NULL && err == ERR_OK) {
        return ERR_OK;
    }

    if (nlwip->pbuf == NULL) {
        nlwip->pbuf = pbuf;
    }
    else {
        if (nlwip->pbuf != pbuf) {
            tcp_recved(nlwip->pcb, pbuf->tot_len);
            pbuf_cat(nlwip->pbuf, pbuf); /* add chain to head */
        }
    }

    if (nlwip->recv_fn) {
        return nlwip->recv_fn(nlwip->arg, pcb, pbuf, err);
    }

    WOLFSSL_LEAVE("LwIPNativeReceiveCB", nlwip->pbuf->tot_len);
    return ERR_OK;
}


static err_t LwIPNativeSentCB(void* cb, struct tcp_pcb* pcb, u16_t len)
{
    WOLFSSL_LWIP_NATIVE_STATE* nlwip;

    if (cb == NULL || pcb == NULL) {
        WOLFSSL_MSG("Expected callback was null, abort");
        return ERR_ABRT;
    }

    nlwip = (WOLFSSL_LWIP_NATIVE_STATE*)cb;
    if (nlwip->sent_fn) {
        return nlwip->sent_fn(nlwip->arg, pcb, len);
    }
    return ERR_OK;
}


int wolfSSL_SetIO_LwIP(WOLFSSL* ssl, void* pcb,
                          tcp_recv_fn recv_fn, tcp_sent_fn sent_fn, void *arg)
{
    if (ssl == NULL || pcb == NULL)
        return BAD_FUNC_ARG;

    ssl->lwipCtx.pcb = (struct tcp_pcb *)pcb;
    ssl->lwipCtx.recv_fn = recv_fn; /*  recv user callback */
    ssl->lwipCtx.sent_fn = sent_fn; /*  sent user callback */
    ssl->lwipCtx.arg  = arg;
    ssl->lwipCtx.pbuf = 0;
    ssl->lwipCtx.pulled = 0;
    ssl->lwipCtx.wait   = 0;

    /* wolfSSL_LwIP_recv/sent_cb invokes recv/sent user callback in them. */
    tcp_recv(pcb, LwIPNativeReceiveCB);
    tcp_sent(pcb, LwIPNativeSentCB);
    tcp_arg (pcb, (void *)&ssl->lwipCtx);
    wolfSSL_SetIOReadCtx(ssl, &ssl->lwipCtx);
    wolfSSL_SetIOWriteCtx(ssl, &ssl->lwipCtx);

    return ERR_OK;
}
#endif

#ifdef WOLFSSL_ISOTP
static int isotp_send_single_frame(struct isotp_wolfssl_ctx *ctx, char *buf,
        word16 length)
{
    /* Length will be at most 7 bytes to get here. Packet is length and type
     * for the first byte, then up to 7 bytes of data */
    ctx->frame.data[0] = ((byte)length) | (ISOTP_FRAME_TYPE_SINGLE << 4);
    XMEMCPY(&ctx->frame.data[1], buf, length);
    ctx->frame.length = length + 1;
    return ctx->send_fn(&ctx->frame, ctx->arg);
}

static int isotp_send_flow_control(struct isotp_wolfssl_ctx *ctx,
        byte overflow)
{
    int ret;
    /* Overflow is set it if we have been asked to receive more data than the
     * user allocated a buffer for */
    if (overflow) {
        ctx->frame.data[0] = ISOTP_FLOW_CONTROL_ABORT |
            (ISOTP_FRAME_TYPE_CONTROL << 4);
    } else {
        ctx->frame.data[0] = ISOTP_FLOW_CONTROL_CTS |
            (ISOTP_FRAME_TYPE_CONTROL << 4);
    }
    /* Set the number of frames between flow control to infinite */
    ctx->frame.data[1] = ISOTP_FLOW_CONTROL_FRAMES;
    /* User specified frame delay */
    ctx->frame.data[2] = ctx->receive_delay;
    ctx->frame.length = ISOTP_FLOW_CONTROL_PACKET_SIZE;
    ret = ctx->send_fn(&ctx->frame, ctx->arg);
    return ret;
}

static int isotp_receive_flow_control(struct isotp_wolfssl_ctx *ctx)
{
    int ret;
    enum isotp_frame_type type;
    enum isotp_flow_control flow_control;
    ret = ctx->recv_fn(&ctx->frame, ctx->arg, ISOTP_DEFAULT_TIMEOUT);
    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    } else if (ret < 0) {
        WOLFSSL_MSG("ISO-TP error receiving flow control packet");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    /* Flow control is the frame type and flow response for the first byte,
     * number of frames until the next flow control packet for the second
     * byte, time between frames for the third byte */
    type = ctx->frame.data[0] >> 4;

    if (type != ISOTP_FRAME_TYPE_CONTROL) {
        WOLFSSL_MSG("ISO-TP frames out of sequence");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    flow_control = ctx->frame.data[0] & 0xf;

    ctx->flow_counter = 0;
    ctx->flow_packets = ctx->frame.data[1];
    ctx->frame_delay = ctx->frame.data[2];

    return flow_control;
}

static int isotp_send_consecutive_frame(struct isotp_wolfssl_ctx *ctx)
{
    /* Sequence is 0 - 15 and then starts again, the first frame has an
     * implied sequence of '0' */
    ctx->sequence += 1;
    if (ctx->sequence > ISOTP_MAX_SEQUENCE_COUNTER) {
        ctx->sequence = 0;
    }
    ctx->flow_counter++;
    /* First byte it type and sequence number, up to 7 bytes of data */
    ctx->frame.data[0] = ctx->sequence | (ISOTP_FRAME_TYPE_CONSECUTIVE << 4);
    if (ctx->buf_length > ISOTP_MAX_CONSECUTIVE_FRAME_DATA_SIZE) {
        XMEMCPY(&ctx->frame.data[1], ctx->buf_ptr,
                ISOTP_MAX_CONSECUTIVE_FRAME_DATA_SIZE);
        ctx->buf_ptr += ISOTP_MAX_CONSECUTIVE_FRAME_DATA_SIZE;
        ctx->buf_length -= ISOTP_MAX_CONSECUTIVE_FRAME_DATA_SIZE;
        ctx->frame.length = ISOTP_CAN_BUS_PAYLOAD_SIZE;
    } else {
        XMEMCPY(&ctx->frame.data[1], ctx->buf_ptr, ctx->buf_length);
        ctx->frame.length = ctx->buf_length + 1;
        ctx->buf_length = 0;
    }
    return ctx->send_fn(&ctx->frame, ctx->arg);

}

static int isotp_send_first_frame(struct isotp_wolfssl_ctx *ctx, char *buf,
        word16 length)
{
    int ret;
    ctx->sequence = 0;
    /* Set to 1 to trigger a flow control straight away, the flow control
     * packet will set these properly */
    ctx->flow_packets = ctx->flow_counter = 1;
    /* First frame has 1 nibble for type, 3 nibbles for length followed by
     * 6 bytes for data*/
    ctx->frame.data[0] = (length >> 8) | (ISOTP_FRAME_TYPE_FIRST << 4);
    ctx->frame.data[1] = length & 0xff;
    XMEMCPY(&ctx->frame.data[2], buf, ISOTP_FIRST_FRAME_DATA_SIZE);
    ctx->buf_ptr = buf + ISOTP_FIRST_FRAME_DATA_SIZE;
    ctx->buf_length = length - ISOTP_FIRST_FRAME_DATA_SIZE;
    ctx->frame.length = ISOTP_CAN_BUS_PAYLOAD_SIZE;
    ret = ctx->send_fn(&ctx->frame, ctx->arg);
    if (ret <= 0) {
        WOLFSSL_MSG("ISO-TP error sending first frame");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    while(ctx->buf_length) {
        /* The receiver can set how often to get a flow control packet. If it
         * is time, then get the packet. Note that this will always happen
         * after the first packet */
        if ((ctx->flow_packets > 0) &&
                (ctx->flow_counter == ctx->flow_packets)) {
            ret = isotp_receive_flow_control(ctx);
        }
        /* Frame delay <= 0x7f is in ms, 0xfX is X * 100 us */
        if (ctx->frame_delay) {
            if (ctx->frame_delay <= ISOTP_MAX_MS_FRAME_DELAY) {
                ctx->delay_fn(ctx->frame_delay * 1000);
            } else {
                ctx->delay_fn((ctx->frame_delay & 0xf) * 100);
            }
        }
        switch (ret) {
            /* Clear to send */
            case ISOTP_FLOW_CONTROL_CTS:
                if (isotp_send_consecutive_frame(ctx) < 0) {
                    WOLFSSL_MSG("ISO-TP error sending consecutive frame");
                    return WOLFSSL_CBIO_ERR_GENERAL;
                }
                break;
            /* Receiver says "WAIT", so we wait for another flow control
             * packet, or abort if we have waited too long */
            case ISOTP_FLOW_CONTROL_WAIT:
                ctx->wait_counter += 1;
                if (ctx->wait_counter > ISOTP_DEFAULT_WAIT_COUNT) {
                    WOLFSSL_MSG("ISO-TP receiver told us to wait too many"
                            " times");
                    return WOLFSSL_CBIO_ERR_WANT_WRITE;
                }
                break;
            /* Receiver is not ready to receive packet, so abort */
            case ISOTP_FLOW_CONTROL_ABORT:
                WOLFSSL_MSG("ISO-TP receiver aborted transmission");
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            default:
                WOLFSSL_MSG("ISO-TP got unexpected flow control packet");
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    return 0;
}

int ISOTP_Send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int ret;
    struct isotp_wolfssl_ctx *isotp_ctx;
    (void) ssl;

    if (!ctx) {
        WOLFSSL_MSG("ISO-TP requires wolfSSL_SetIO_ISOTP to be called first");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    isotp_ctx = (struct isotp_wolfssl_ctx*) ctx;

    /* ISO-TP cannot send more than 4095 bytes, this limits the packet size
     * and wolfSSL will try again with the remaining data */
    if (sz > ISOTP_MAX_DATA_SIZE) {
        sz = ISOTP_MAX_DATA_SIZE;
    }
    /* Can't send whilst we are receiving */
    if (isotp_ctx->state != ISOTP_CONN_STATE_IDLE) {
        return WOLFSSL_ERROR_WANT_WRITE;
    }
    isotp_ctx->state = ISOTP_CONN_STATE_SENDING;

    /* Assuming normal addressing */
    if (sz <= ISOTP_SINGLE_FRAME_DATA_SIZE) {
        ret = isotp_send_single_frame(isotp_ctx, buf, (word16)sz);
    } else {
        ret = isotp_send_first_frame(isotp_ctx, buf, (word16)sz);
    }
    isotp_ctx->state = ISOTP_CONN_STATE_IDLE;

    if (ret == 0) {
        return sz;
    }
    return ret;
}

static int isotp_receive_single_frame(struct isotp_wolfssl_ctx *ctx)
{
    byte data_size;

    /* 1 nibble for data size which will be 1 - 7 in a regular 8 byte CAN
     * packet */
    data_size = (byte)ctx->frame.data[0] & 0xf;
    if (ctx->receive_buffer_size < (int)data_size) {
        WOLFSSL_MSG("ISO-TP buffer is too small to receive data");
        return BUFFER_E;
    }
    XMEMCPY(ctx->receive_buffer, &ctx->frame.data[1], data_size);
    return data_size;
}

static int isotp_receive_multi_frame(struct isotp_wolfssl_ctx *ctx)
{
    int ret;
    word16 data_size;
    byte delay = 0;

    /* Increase receive timeout for enforced ms delay */
    if (ctx->receive_delay <= ISOTP_MAX_MS_FRAME_DELAY) {
        delay = ctx->receive_delay;
    }
    /* Still processing first frame.
     * Full data size is lower nibble of first byte for the most significant
     * followed by the second byte for the rest. Last 6 bytes are data */
    data_size = ((ctx->frame.data[0] & 0xf) << 8) + ctx->frame.data[1];
    XMEMCPY(ctx->receive_buffer, &ctx->frame.data[2], ISOTP_FIRST_FRAME_DATA_SIZE);
    /* Need to send a flow control packet to either cancel or continue
     * transmission of data */
    if (ctx->receive_buffer_size < data_size) {
        isotp_send_flow_control(ctx, TRUE);
        WOLFSSL_MSG("ISO-TP buffer is too small to receive data");
        return BUFFER_E;
    }
    isotp_send_flow_control(ctx, FALSE);

    ctx->buf_length = ISOTP_FIRST_FRAME_DATA_SIZE;
    ctx->buf_ptr = ctx->receive_buffer + ISOTP_FIRST_FRAME_DATA_SIZE;
    data_size -= ISOTP_FIRST_FRAME_DATA_SIZE;
    ctx->sequence = 1;

    while(data_size) {
        enum isotp_frame_type type;
        byte sequence;
        byte frame_len;
        ret = ctx->recv_fn(&ctx->frame, ctx->arg, ISOTP_DEFAULT_TIMEOUT +
                (delay / 1000));
        if (ret == 0) {
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
        type = ctx->frame.data[0] >> 4;
        /* Consecutive frames have sequence number as lower nibble */
        sequence = ctx->frame.data[0] & 0xf;
        if (type != ISOTP_FRAME_TYPE_CONSECUTIVE) {
            WOLFSSL_MSG("ISO-TP frames out of sequence");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        if (sequence != ctx->sequence) {
            WOLFSSL_MSG("ISO-TP frames out of sequence");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        /* Last 7 bytes or whatever we got after the first byte is data */
        frame_len = ctx->frame.length - 1;
        XMEMCPY(ctx->buf_ptr, &ctx->frame.data[1], frame_len);
        ctx->buf_ptr += frame_len;
        ctx->buf_length += frame_len;
        data_size -= frame_len;

        /* Sequence is 0 - 15 (first 0 is implied for first packet */
        ctx->sequence++;
        if (ctx->sequence > ISOTP_MAX_SEQUENCE_COUNTER) {
            ctx->sequence = 0;
        }
    }
    return ctx->buf_length;

}

/* The wolfSSL receive callback, needs to buffer because we need to grab all
 * incoming data, even if wolfSSL doesn't want it all yet */
int ISOTP_Receive(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    enum isotp_frame_type type;
    int ret;
    struct isotp_wolfssl_ctx *isotp_ctx;
    (void) ssl;

    if (!ctx) {
        WOLFSSL_MSG("ISO-TP requires wolfSSL_SetIO_ISOTP to be called first");
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    isotp_ctx = (struct isotp_wolfssl_ctx*)ctx;

    /* Is buffer empty? If so, fill it */
    if (!isotp_ctx->receive_buffer_len) {
        /* Can't send whilst we are receiving */
        if (isotp_ctx->state != ISOTP_CONN_STATE_IDLE) {
            return WOLFSSL_ERROR_WANT_READ;
        }
        isotp_ctx->state = ISOTP_CONN_STATE_RECEIVING;
        do {
            ret = isotp_ctx->recv_fn(&isotp_ctx->frame, isotp_ctx->arg,
                    ISOTP_DEFAULT_TIMEOUT);
        } while (ret == 0);
        if (ret == 0) {
            isotp_ctx->state = ISOTP_CONN_STATE_IDLE;
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        } else if (ret < 0) {
            isotp_ctx->state = ISOTP_CONN_STATE_IDLE;
            WOLFSSL_MSG("ISO-TP receive error");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        type = (enum isotp_frame_type) isotp_ctx->frame.data[0] >> 4;

        if (type == ISOTP_FRAME_TYPE_SINGLE) {
            isotp_ctx->receive_buffer_len =
                isotp_receive_single_frame(isotp_ctx);
        } else if (type == ISOTP_FRAME_TYPE_FIRST) {
            isotp_ctx->receive_buffer_len =
                isotp_receive_multi_frame(isotp_ctx);
        } else {
            /* Should never get here */
            isotp_ctx->state = ISOTP_CONN_STATE_IDLE;
            WOLFSSL_MSG("ISO-TP frames out of sequence");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        if (isotp_ctx->receive_buffer_len <= 1) {
            isotp_ctx->state = ISOTP_CONN_STATE_IDLE;
            return isotp_ctx->receive_buffer_len;
        } else {
            isotp_ctx->receive_buffer_ptr = isotp_ctx->receive_buffer;
        }
        isotp_ctx->state = ISOTP_CONN_STATE_IDLE;
    }

    /* Return from the buffer */
    if (isotp_ctx->receive_buffer_len >= sz) {
        XMEMCPY(buf, isotp_ctx->receive_buffer_ptr, sz);
        isotp_ctx->receive_buffer_ptr+= sz;
        isotp_ctx->receive_buffer_len-= sz;
        return sz;
    } else {
        XMEMCPY(buf, isotp_ctx->receive_buffer_ptr,
                isotp_ctx->receive_buffer_len);
        sz = isotp_ctx->receive_buffer_len;
        isotp_ctx->receive_buffer_len = 0;
        return sz;
    }
}

int wolfSSL_SetIO_ISOTP(WOLFSSL *ssl, isotp_wolfssl_ctx *ctx,
        can_recv_fn recv_fn, can_send_fn send_fn, can_delay_fn delay_fn,
        word32 receive_delay, char *receive_buffer, int receive_buffer_size,
        void *arg)
{
    if (!ctx || !recv_fn || !send_fn || !delay_fn || !receive_buffer) {
        WOLFSSL_MSG("ISO-TP has missing required parameter");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    ctx->recv_fn = recv_fn;
    ctx->send_fn = send_fn;
    ctx->arg = arg;
    ctx->delay_fn = delay_fn;
    ctx->frame_delay = 0;
    ctx->receive_buffer = receive_buffer;
    ctx->receive_buffer_size = receive_buffer_size;
    ctx->receive_buffer_len = 0;
    ctx->state = ISOTP_CONN_STATE_IDLE;

    wolfSSL_SetIOReadCtx(ssl, ctx);
    wolfSSL_SetIOWriteCtx(ssl, ctx);

    /* Delay of 100 - 900us is 0xfX where X is value / 100. Delay of
     * >= 1000 is divided by 1000. > 127ms is invalid */
    if (receive_delay < 1000) {
        ctx->receive_delay = 0xf0 + (receive_delay / 100);
    } else if (receive_delay <= ISOTP_MAX_MS_FRAME_DELAY * 1000) {
        ctx->receive_delay = receive_delay / 1000;
    } else {
        WOLFSSL_MSG("ISO-TP delay parameter out of bounds");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return 0;
}
#endif
#endif /* WOLFCRYPT_ONLY */
