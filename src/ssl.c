/* ssl.c
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

#if !defined(WOLFCRYPT_ONLY)

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/kdf.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

    #include <errno.h>


#if !defined(WOLFSSL_ALLOW_NO_SUITES) && !defined(WOLFCRYPT_ONLY)
    #ifdef WOLFSSL_CERT_GEN
        /* need access to Cert struct for creating certificate */
        #include <wolfssl/wolfcrypt/asn_public.h>
    #endif
#endif

#if !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_KEY_GEN)
    #include <wolfssl/openssl/evp.h>
    /* openssl headers end, wolfssl internal headers next */
#endif

#include <wolfssl/wolfcrypt/wc_encrypt.h>

    #include <wolfssl/wolfcrypt/rsa.h>




#ifdef NO_ASN
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#endif /* !WOLFCRYPT_ONLY || OPENSSL_EXTRA */

/*
 * OPENSSL_COMPATIBLE_DEFAULTS:
 *     Enable default behaviour that is compatible with OpenSSL. For example
 *     SSL_CTX by default doesn't verify the loaded certs. Enabling this
 *     should make porting to new projects easier.
 * WOLFSSL_CHECK_ALERT_ON_ERR:
 *     Check for alerts during the handshake in the event of an error.
 * NO_SESSION_CACHE_REF:
 *     wolfSSL_get_session on a client will return a reference to the internal
 *     ClientCache by default for backwards compatibility. This define will
 *     make wolfSSL_get_session return a reference to ssl->session. The returned
 *     pointer will be freed with the related WOLFSSL object.
 */

#define WOLFSSL_EVP_INCLUDED
#include "wolfcrypt/src/evp.c"

#ifndef WOLFCRYPT_ONLY

#define WOLFSSL_PK_INCLUDED
#include "src/pk.c"



#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif



void fabio_print(char const* msg, void const* buf, word32 len);

/* prevent multiple mutex initializations */
static volatile WOLFSSL_GLOBAL int initRefCount = 0;
static WOLFSSL_GLOBAL wolfSSL_Mutex count_mutex;   /* init ref count mutex */
static WOLFSSL_GLOBAL int count_mutex_valid = 0;

/* Create a new WOLFSSL_CTX struct and return the pointer to created struct.
   WOLFSSL_METHOD pointer passed in is given to ctx to manage.
   This function frees the passed in WOLFSSL_METHOD struct on failure and on
   success is freed when ctx is freed.
 */
WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap)
{
    WOLFSSL_CTX* ctx = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_new_ex");

    if (initRefCount == 0) {
        /* user no longer forced to call Init themselves */
        int ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_Init failed");
            WOLFSSL_LEAVE("WOLFSSL_CTX_new", 0);
            if (method != NULL) {
                XFREE(method, heap, DYNAMIC_TYPE_METHOD);
            }
            return NULL;
        }
    }

    if (method == NULL)
        return ctx;

    ctx = (WOLFSSL_CTX*)XMALLOC(sizeof(WOLFSSL_CTX), heap, DYNAMIC_TYPE_CTX);
    if (ctx) {
        int ret;

        ret = InitSSL_Ctx(ctx, method, heap);
        if (ret < 0) {
            WOLFSSL_MSG("Init CTX failed");
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }
    else {
        WOLFSSL_MSG("Alloc CTX failed, method freed");
        XFREE(method, heap, DYNAMIC_TYPE_METHOD);
    }

#ifdef OPENSSL_COMPATIBLE_DEFAULTS
    if (ctx) {
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        wolfSSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        if (wolfSSL_CTX_set_min_proto_version(ctx,
                SSL3_VERSION) != WOLFSSL_SUCCESS ||
                wolfSSL_CTX_set_group_messages(ctx) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Setting OpenSSL CTX defaults failed");
            wolfSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }
#endif

    WOLFSSL_LEAVE("WOLFSSL_CTX_new", 0);
    return ctx;
}


WOLFSSL_ABI
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
#ifdef WOLFSSL_HEAP_TEST
    /* if testing the heap hint then set top level CTX to have test value */
    return wolfSSL_CTX_new_ex(method, (void*)WOLFSSL_HEAP_TEST);
#else
    return wolfSSL_CTX_new_ex(method, NULL);
#endif
}

/* increases CTX reference count to track proper time to "free" */
int wolfSSL_CTX_up_ref(WOLFSSL_CTX* ctx)
{
    int refCount = SSL_CTX_RefCount(ctx, 1);
    return ((refCount > 1) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE);
}

WOLFSSL_ABI
void wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("SSL_CTX_free");
    if (ctx) {
        FreeSSL_Ctx(ctx);
    }

    WOLFSSL_LEAVE("SSL_CTX_free", 0);
}


/**
 * Sets whether Encrypt-Then-MAC extension can be negotiated against context.
 * The default value: enabled.
 *
 * ctx  SSL/TLS context.
 * set  Whether to allow or not: 1 is allow and 0 is disallow.
 * returns WOLFSSL_SUCCESS
 */
int wolfSSL_CTX_AllowEncryptThenMac(WOLFSSL_CTX *ctx, int set)
{
    ctx->disallowEncThenMac = !set;
    return WOLFSSL_SUCCESS;
}

/**
 * Sets whether Encrypt-Then-MAC extension can be negotiated against context.
 * The default value comes from context.
 *
 * ctx  SSL/TLS context.
 * set  Whether to allow or not: 1 is allow and 0 is disallow.
 * returns WOLFSSL_SUCCESS
 */
int wolfSSL_AllowEncryptThenMac(WOLFSSL *ssl, int set)
{
    ssl->options.disallowEncThenMac = !set;
    return WOLFSSL_SUCCESS;
}



WOLFSSL_ABI
WOLFSSL* wolfSSL_new(WOLFSSL_CTX* ctx)
{
    WOLFSSL* ssl = NULL;
    int ret = 0;

    WOLFSSL_ENTER("SSL_new");

    if (ctx == NULL)
        return ssl;

    ssl = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), ctx->heap, DYNAMIC_TYPE_SSL);
    if (ssl)
        if ( (ret = InitSSL(ssl, ctx, 0)) < 0) {
            FreeSSL(ssl, ctx->heap);
            ssl = 0;
        }

    WOLFSSL_LEAVE("SSL_new", ret);
    (void)ret;

    return ssl;
}


WOLFSSL_ABI
void wolfSSL_free(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_free");
    if (ssl)
        FreeSSL(ssl, ssl->ctx->heap);
    WOLFSSL_LEAVE("SSL_free", 0);
}


int wolfSSL_is_server(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    return ssl->options.side == WOLFSSL_SERVER_END;
}

#ifdef HAVE_WRITE_DUP

/*
 * Release resources around WriteDup object
 *
 * ssl WOLFSSL object
 *
 * no return, destruction so make best attempt
*/
void FreeWriteDup(WOLFSSL* ssl)
{
    int doFree = 0;

    WOLFSSL_ENTER("FreeWriteDup");

    if (ssl->dupWrite) {
        if (wc_LockMutex(&ssl->dupWrite->dupMutex) == 0) {
            ssl->dupWrite->dupCount--;
            if (ssl->dupWrite->dupCount == 0) {
                doFree = 1;
            } else {
                WOLFSSL_MSG("WriteDup count not zero, no full free");
            }
            wc_UnLockMutex(&ssl->dupWrite->dupMutex);
        }
    }

    if (doFree) {
        WOLFSSL_MSG("Doing WriteDup full free, count to zero");
        wc_FreeMutex(&ssl->dupWrite->dupMutex);
        XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
    }
}


/*
 * duplicate existing ssl members into dup needed for writing
 *
 * dup write only WOLFSSL
 * ssl existing WOLFSSL
 *
 * 0 on success
*/
static int DupSSL(WOLFSSL* dup, WOLFSSL* ssl)
{
    /* shared dupWrite setup */
    ssl->dupWrite = (WriteDup*)XMALLOC(sizeof(WriteDup), ssl->heap,
                                       DYNAMIC_TYPE_WRITEDUP);
    if (ssl->dupWrite == NULL) {
        return MEMORY_E;
    }
    XMEMSET(ssl->dupWrite, 0, sizeof(WriteDup));

    if (wc_InitMutex(&ssl->dupWrite->dupMutex) != 0) {
        XFREE(ssl->dupWrite, ssl->heap, DYNAMIC_TYPE_WRITEDUP);
        ssl->dupWrite = NULL;
        return BAD_MUTEX_E;
    }
    ssl->dupWrite->dupCount = 2;    /* both sides have a count to start */
    dup->dupWrite = ssl->dupWrite; /* each side uses */

    /* copy write parts over to dup writer */
    XMEMCPY(&dup->specs,   &ssl->specs,   sizeof(CipherSpecs));
    XMEMCPY(&dup->options, &ssl->options, sizeof(Options));
    XMEMCPY(&dup->keys,    &ssl->keys,    sizeof(Keys));
    XMEMCPY(&dup->encrypt, &ssl->encrypt, sizeof(Ciphers));
    /* dup side now owns encrypt/write ciphers */
    XMEMSET(&ssl->encrypt, 0, sizeof(Ciphers));

    dup->IOCB_WriteCtx = ssl->IOCB_WriteCtx;
    dup->CBIOSend = ssl->CBIOSend;
    dup->wfd    = ssl->wfd;
    dup->wflags = ssl->wflags;
    dup->hmac   = ssl->hmac;

    /* unique side dup setup */
    dup->dupSide = WRITE_DUP_SIDE;
    ssl->dupSide = READ_DUP_SIDE;

    return 0;
}


/*
 * duplicate a WOLFSSL object post handshake for writing only
 * turn existing object into read only.  Allows concurrent access from two
 * different threads.
 *
 * ssl existing WOLFSSL object
 *
 * return dup'd WOLFSSL object on success
*/
WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl)
{
    WOLFSSL* dup = NULL;
    int ret = 0;

    (void)ret;
    WOLFSSL_ENTER("wolfSSL_write_dup");

    if (ssl == NULL) {
        return ssl;
    }

    if (ssl->options.handShakeDone == 0) {
        WOLFSSL_MSG("wolfSSL_write_dup called before handshake complete");
        return NULL;
    }

    if (ssl->dupWrite) {
        WOLFSSL_MSG("wolfSSL_write_dup already called once");
        return NULL;
    }

    dup = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), ssl->ctx->heap, DYNAMIC_TYPE_SSL);
    if (dup) {
        if ( (ret = InitSSL(dup, ssl->ctx, 1)) < 0) {
            FreeSSL(dup, ssl->ctx->heap);
            dup = NULL;
        } else if ( (ret = DupSSL(dup, ssl)) < 0) {
            FreeSSL(dup, ssl->ctx->heap);
            dup = NULL;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_write_dup", ret);

    return dup;
}


/*
 * Notify write dup side of fatal error or close notify
 *
 * ssl WOLFSSL object
 * err Notify err
 *
 * 0 on success
*/
int NotifyWriteSide(WOLFSSL* ssl, int err)
{
    int ret;

    WOLFSSL_ENTER("NotifyWriteSide");

    ret = wc_LockMutex(&ssl->dupWrite->dupMutex);
    if (ret == 0) {
        ssl->dupWrite->dupErr = err;
        ret = wc_UnLockMutex(&ssl->dupWrite->dupMutex);
    }

    return ret;
}


#endif /* HAVE_WRITE_DUP */


/* set if to use old poly 1 for yes 0 to use new poly */
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value)
{
    (void)ssl;
    (void)value;

    WOLFSSL_ENTER("SSL_use_old_poly");
    WOLFSSL_MSG("Warning SSL connection auto detects old/new and this function"
            "is depreciated");
    ssl->options.oldPoly = (word16)value;
    WOLFSSL_LEAVE("SSL_use_old_poly", 0);
    return 0;
}


WOLFSSL_ABI
int wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    int ret;

    WOLFSSL_ENTER("SSL_set_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_set_read_fd(ssl, fd);
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_set_write_fd(ssl, fd);
    }

    return ret;
}


int wolfSSL_set_read_fd(WOLFSSL* ssl, int fd)
{
    WOLFSSL_ENTER("SSL_set_read_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->rfd = fd;      /* not used directly to allow IO callbacks */
    ssl->IOCB_ReadCtx  = &ssl->rfd;


    WOLFSSL_LEAVE("SSL_set_read_fd", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}


int wolfSSL_set_write_fd(WOLFSSL* ssl, int fd)
{
    WOLFSSL_ENTER("SSL_set_write_fd");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->wfd = fd;      /* not used directly to allow IO callbacks */
    ssl->IOCB_WriteCtx  = &ssl->wfd;


    WOLFSSL_LEAVE("SSL_set_write_fd", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}


/**
  * Get the name of cipher at priority level passed in.
  */
char* wolfSSL_get_cipher_list(int priority)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();

    if (priority >= GetCipherNamesSize() || priority < 0) {
        return 0;
    }

    return (char*)ciphers[priority].name;
}


/**
  * Get the name of cipher at priority level passed in.
  */
char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority)
{

    if (ssl == NULL) {
        return NULL;
    }
    else {
        const char* cipher;

        if ((cipher = wolfSSL_get_cipher_name_internal(ssl)) != NULL) {
            if (priority == 0) {
                return (char*)cipher;
            }
            else {
                return NULL;
            }
        }
        else {
            return wolfSSL_get_cipher_list(priority);
        }
    }
}


int wolfSSL_get_ciphers(char* buf, int len)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();
    int ciphersSz = GetCipherNamesSize();
    int i;
    int cipherNameSz;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimited by a : */
    for (i = 0; i < ciphersSz; i++) {
        cipherNameSz = (int)XSTRLEN(ciphers[i].name);
        if (cipherNameSz + 1 < len) {
            XSTRNCPY(buf, ciphers[i].name, len);
            buf += cipherNameSz;

            if (i < ciphersSz - 1)
                *buf++ = ':';
            *buf = 0;

            len -= cipherNameSz + 1;
        }
        else
            return BUFFER_E;
    }
    return WOLFSSL_SUCCESS;
}


/* places a list of all supported cipher suites in TLS_* format into "buf"
 * return WOLFSSL_SUCCESS on success */
int wolfSSL_get_ciphers_iana(char* buf, int len)
{
    const CipherSuiteInfo* ciphers = GetCipherNames();
    int ciphersSz = GetCipherNamesSize();
    int i;
    int cipherNameSz;

    if (buf == NULL || len <= 0)
        return BAD_FUNC_ARG;

    /* Add each member to the buffer delimited by a : */
    for (i = 0; i < ciphersSz; i++) {
        if (ciphers[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS)
            continue;
        cipherNameSz = (int)XSTRLEN(ciphers[i].name_iana);
        if (cipherNameSz + 1 < len) {
            XSTRNCPY(buf, ciphers[i].name_iana, len);
            buf += cipherNameSz;

            if (i < ciphersSz - 1)
                *buf++ = ':';
            *buf = 0;

            len -= cipherNameSz + 1;
        }
        else
            return BUFFER_E;
    }
    return WOLFSSL_SUCCESS;
}


const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf, int len)
{
    const char* cipher;

    if (ssl == NULL)
        return NULL;

    cipher = wolfSSL_get_cipher_name_iana(ssl);
    len = min(len, (int)(XSTRLEN(cipher) + 1));
    XMEMCPY(buf, cipher, len);
    return buf;
}

int wolfSSL_get_fd(const WOLFSSL* ssl)
{
    int fd = -1;
    WOLFSSL_ENTER("SSL_get_fd");
    if (ssl) {
        fd = ssl->rfd;
    }
    WOLFSSL_LEAVE("SSL_get_fd", fd);
    return fd;
}


int wolfSSL_dtls(WOLFSSL* ssl)
{
    int dtlsOpt = 0;
    if (ssl)
        dtlsOpt = ssl->options.dtls;
    return dtlsOpt;
}

/* Set whether mutual authentication is required for connections.
 * Server side only.
 *
 * ctx  The SSL/TLS CTX object.
 * req  1 to indicate required and 0 when not.
 * returns BAD_FUNC_ARG when ctx is NULL, SIDE_ERROR when not a server and
 * 0 on success.
 */
int wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (ctx->method->side == WOLFSSL_CLIENT_END)
        return SIDE_ERROR;

    ctx->mutualAuth = (byte)req;

    return 0;
}

/* Set whether mutual authentication is required for the connection.
 * Server side only.
 *
 * ssl  The SSL/TLS object.
 * req  1 to indicate required and 0 when not.
 * returns BAD_FUNC_ARG when ssl is NULL, or not using TLS v1.3,
 * SIDE_ERROR when not a client and 0 on success.
 */
int wolfSSL_mutual_auth(WOLFSSL* ssl, int req)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    if (ssl->options.side == WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    ssl->options.mutualAuth = (word16)req;

    return 0;
}


#ifndef WOLFSSL_LEANPSK
int wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
}

int wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz)
{
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
}




#ifdef WOLFSSL_SRTP

static const WOLFSSL_SRTP_PROTECTION_PROFILE gSrtpProfiles[] = {
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 80-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_80", SRTP_AES128_CM_SHA1_80, (((128 + 112) * 2) / 8) },
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 32-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_32", SRTP_AES128_CM_SHA1_32, (((128 + 112) * 2) / 8) },
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 80-bits */
    {"SRTP_NULL_SHA1_80", SRTP_NULL_SHA1_80, ((112 * 2) / 8)},
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 32-bits */
    {"SRTP_NULL_SHA1_32", SRTP_NULL_SHA1_32, ((112 * 2) / 8)},
    /* AES GCM 128, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:128bits + master_salt:96bits) * 2 = 448 bits (56) */
    {"SRTP_AEAD_AES_128_GCM", SRTP_AEAD_AES_128_GCM, (((128 + 96) * 2) / 8) },
    /* AES GCM 256, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:256bits + master_salt:96bits) * 2 = 704 bits (88) */
    {"SRTP_AEAD_AES_256_GCM", SRTP_AEAD_AES_256_GCM, (((256 + 96) * 2) / 8) },
};

static const WOLFSSL_SRTP_PROTECTION_PROFILE* DtlsSrtpFindProfile(
    const char* profile_str, word32 profile_str_len, unsigned long id)
{
    int i;
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    for (i=0;
         i<(int)(sizeof(gSrtpProfiles)/sizeof(WOLFSSL_SRTP_PROTECTION_PROFILE));
         i++) {
        if (profile_str != NULL) {
            word32 srtp_profile_len = (word32)XSTRLEN(gSrtpProfiles[i].name);
            if (srtp_profile_len == profile_str_len &&
                XMEMCMP(gSrtpProfiles[i].name, profile_str, profile_str_len)
                                                                         == 0) {
                profile = &gSrtpProfiles[i];
                break;
            }
        }
        else if (id != 0 && gSrtpProfiles[i].id == id) {
            profile = &gSrtpProfiles[i];
            break;
        }
    }
    return profile;
}

/* profile_str: accepts ":" colon separated list of SRTP profiles */
static int DtlsSrtpSelProfiles(word16* id, const char* profile_str)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile;
    const char *current, *next = NULL;
    word32 length = 0, current_length;

    *id = 0; /* reset destination ID's */

    if (profile_str == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* loop on end of line or colon ":" */
    next = profile_str;
    length = (word32)XSTRLEN(profile_str);
    do {
        current = next;
        next = XSTRSTR(current, ":");
        current_length = (!next) ? (word32)XSTRLEN(current)
                                 : (word32)(next - current);
        if (current_length < length)
            length = current_length;
        profile = DtlsSrtpFindProfile(current, current_length, 0);
        if (profile != NULL) {
            *id |= (1 << profile->id); /* selected bit based on ID */
        }
    } while (next != NULL && next++); /* ++ needed to skip ':' */
    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_set_tlsext_use_srtp(WOLFSSL_CTX* ctx, const char* profile_str)
{
    int ret = WOLFSSL_FAILURE;
    if (ctx != NULL) {
        ret = DtlsSrtpSelProfiles(&ctx->dtlsSrtpProfiles, profile_str);
    }
    return ret;
}
int wolfSSL_set_tlsext_use_srtp(WOLFSSL* ssl, const char* profile_str)
{
    int ret = WOLFSSL_FAILURE;
    if (ssl != NULL) {
        ret = DtlsSrtpSelProfiles(&ssl->dtlsSrtpProfiles, profile_str);
    }
    return ret;
}

const WOLFSSL_SRTP_PROTECTION_PROFILE* wolfSSL_get_selected_srtp_profile(
    WOLFSSL* ssl)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    if (ssl) {
        profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    }
    return profile;
}
#ifndef NO_WOLFSSL_STUB
WOLF_STACK_OF(WOLFSSL_SRTP_PROTECTION_PROFILE)* wolfSSL_get_srtp_profiles(
    WOLFSSL* ssl)
{
    /* Not yet implemented - should return list of available SRTP profiles
     * ssl->dtlsSrtpProfiles */
    (void)ssl;
    return NULL;
}
#endif

int wolfSSL_export_dtls_srtp_keying_material(WOLFSSL* ssl,
    unsigned char* out, size_t* olen)
{
    int ret = WOLFSSL_FAILURE;
    const char* label = "EXTRACTOR-dtls_srtp";
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    byte seed[SEED_LEN];

    if (ssl == NULL || olen == NULL) {
        return BAD_FUNC_ARG;
    }

    profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    if (profile == NULL) {
        WOLFSSL_MSG("Not using DTLS SRTP");
        return EXT_MISSING;
    }
    if (out == NULL) {
        *olen = profile->kdfBits;
        return LENGTH_ONLY_E;
    }

    if (*olen < (size_t)profile->kdfBits) {
        return BUFFER_E;
    }

#ifdef WOLFSSL_HAVE_PRF
    XMEMCPY(seed, ssl->arrays->clientRandom, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, ssl->arrays->serverRandom, RAN_LEN);

    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(out, profile->kdfBits,   /* out: generated keys / salt */
        ssl->arrays->masterSecret, SECRET_LEN,  /* existing master secret */
        (const byte*)label, (int)XSTRLEN(label),/* label */
        seed, SEED_LEN,                         /* seed: client/server random */
        IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
        ssl->heap, INVALID_DEVID);
    if (ret == 0) {
        *olen = profile->kdfBits;
        ret = WOLFSSL_SUCCESS;
    }
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration */
    ret = PRF_MISSING;
#endif

    return ret;
}

#endif /* WOLFSSL_SRTP */


#ifdef WOLFSSL_DTLS_DROP_STATS

int wolfSSL_dtls_get_drop_stats(WOLFSSL* ssl,
                                word32* macDropCount, word32* replayDropCount)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_dtls_get_drop_stats()");

    if (ssl == NULL)
        ret = BAD_FUNC_ARG;
    else {
        ret = WOLFSSL_SUCCESS;
        if (macDropCount != NULL)
            *macDropCount = ssl->macDropCount;
        if (replayDropCount != NULL)
            *replayDropCount = ssl->replayDropCount;
    }

    WOLFSSL_LEAVE("wolfSSL_dtls_get_drop_stats()", ret);
    return ret;
}

#endif /* WOLFSSL_DTLS_DROP_STATS */




#endif /* WOLFSSL_LEANPSK */


/* return underlying connect or accept, WOLFSSL_SUCCESS on ok */
int wolfSSL_negotiate(WOLFSSL* ssl)
{
    int err = WOLFSSL_FATAL_ERROR;

    WOLFSSL_ENTER("wolfSSL_negotiate");

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
            err = wolfSSL_connect(ssl);
    }

    (void)ssl;

    WOLFSSL_LEAVE("wolfSSL_negotiate", err);

    return err;
}


WOLFSSL_ABI
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl)
{
    if (ssl) {
        return ssl->rng;
    }

    return NULL;
}


#ifndef WOLFSSL_LEANPSK
/* object size based on build */
int wolfSSL_GetObjectSize(void)
{
#ifdef SHOW_SIZES
    printf("sizeof suites           = %lu\n", (unsigned long)sizeof(Suites));
    printf("sizeof ciphers(2)       = %lu\n", (unsigned long)sizeof(Ciphers));
    printf("\tsizeof aes          = %lu\n", (unsigned long)sizeof(Aes));
    printf("\tsizeof chacha       = %lu\n", (unsigned long)sizeof(ChaCha));
    printf("sizeof cipher specs     = %lu\n", (unsigned long)sizeof(CipherSpecs));
    printf("sizeof keys             = %lu\n", (unsigned long)sizeof(Keys));
    printf("sizeof Hashes(2)        = %lu\n", (unsigned long)sizeof(Hashes));
#ifndef NO_MD5
    printf("\tsizeof MD5          = %lu\n", (unsigned long)sizeof(wc_Md5));
#endif
    printf("\tsizeof SHA          = %lu\n", (unsigned long)sizeof(wc_Sha));
    printf("\tsizeof SHA224       = %lu\n", (unsigned long)sizeof(wc_Sha224));
    printf("\tsizeof SHA256       = %lu\n", (unsigned long)sizeof(wc_Sha256));
    printf("\tsizeof SHA384       = %lu\n", (unsigned long)sizeof(wc_Sha384));
    printf("\tsizeof SHA512       = %lu\n", (unsigned long)sizeof(wc_Sha512));
    printf("sizeof Buffers          = %lu\n", (unsigned long)sizeof(Buffers));
    printf("sizeof Options          = %lu\n", (unsigned long)sizeof(Options));
    printf("sizeof Arrays           = %lu\n", (unsigned long)sizeof(Arrays));
    printf("sizeof RsaKey           = %lu\n", (unsigned long)sizeof(RsaKey));
    printf("sizeof ecc_key          = %lu\n", (unsigned long)sizeof(ecc_key));
    printf("sizeof WOLFSSL_CIPHER    = %lu\n", (unsigned long)sizeof(WOLFSSL_CIPHER));
    printf("sizeof WOLFSSL_SESSION   = %lu\n", (unsigned long)sizeof(WOLFSSL_SESSION));
    printf("sizeof WOLFSSL           = %lu\n", (unsigned long)sizeof(WOLFSSL));
    printf("sizeof WOLFSSL_CTX       = %lu\n", (unsigned long)sizeof(WOLFSSL_CTX));
#endif

    return sizeof(WOLFSSL);
}

int wolfSSL_CTX_GetObjectSize(void)
{
    return sizeof(WOLFSSL_CTX);
}

int wolfSSL_METHOD_GetObjectSize(void)
{
    return sizeof(WOLFSSL_METHOD);
}
#endif




/* return max record layer size plaintext input size */
int wolfSSL_GetMaxOutputSize(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_GetMaxOutputSize");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.handShakeState != HANDSHAKE_DONE) {
        WOLFSSL_MSG("Handshake not complete yet");
        return BAD_FUNC_ARG;
    }

    return wolfSSL_GetMaxFragSize(ssl, OUTPUT_RECORD_SIZE);
}


/* return record layer size of plaintext input size */
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz)
{
    int maxSize;

    WOLFSSL_ENTER("wolfSSL_GetOutputSize");

    if (inSz < 0)
        return BAD_FUNC_ARG;

    maxSize = wolfSSL_GetMaxOutputSize(ssl);
    if (maxSize < 0)
        return maxSize;   /* error */
    if (inSz > maxSize)
        return INPUT_SIZE_E;

    return BuildMessage(ssl, NULL, 0, NULL, inSz, application_data, 0, 1, 0, CUR_ORDER);
}


int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ctx, short keySz)
{
    if (ctx == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ctx was null");
        return BAD_FUNC_ARG;
    }

    ctx->minEccKeySz     = keySz / 8;
    ctx->cm->minEccKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz)
{
    if (ssl == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ssl was null");
        return BAD_FUNC_ARG;
    }

    ssl->options.minEccKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz)
{
    if (ctx == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ctx was null");
        return BAD_FUNC_ARG;
    }

    ctx->minRsaKeySz     = keySz / 8;
    ctx->cm->minRsaKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz)
{
    if (ssl == NULL || keySz < 0 || keySz % 8 != 0) {
        WOLFSSL_MSG("Key size must be divisible by 8 or ssl was null");
        return BAD_FUNC_ARG;
    }

    ssl->options.minRsaKeySz = keySz / 8;
    return WOLFSSL_SUCCESS;
}

/* server Diffie-Hellman parameters, WOLFSSL_SUCCESS on ok */
int wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                    const unsigned char* g, int gSz)
{
    WOLFSSL_ENTER("wolfSSL_SetTmpDH");

    if (ssl == NULL || p == NULL || g == NULL)
        return BAD_FUNC_ARG;

    if ((word16)pSz < ssl->options.minDhKeySz)
        return DH_KEY_SIZE_E;
    if ((word16)pSz > ssl->options.maxDhKeySz)
        return DH_KEY_SIZE_E;

    /* this function is for server only */
    if (ssl->options.side == WOLFSSL_CLIENT_END)
        return SIDE_ERROR;

    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
        ssl->options.dhKeyTested = 0;
        ssl->options.dhDoKeyTest = 1;
    #endif

    if (ssl->buffers.serverDH_P.buffer && ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
    }
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
    }

    ssl->buffers.weOwnDH = 1;  /* SSL owns now */
    ssl->buffers.serverDH_P.buffer = (byte*)XMALLOC(pSz, ssl->heap,
                                                    DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_P.buffer == NULL)
            return MEMORY_E;

    ssl->buffers.serverDH_G.buffer = (byte*)XMALLOC(gSz, ssl->heap,
                                                    DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_G.buffer == NULL) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        return MEMORY_E;
    }

    ssl->buffers.serverDH_P.length = pSz;
    ssl->buffers.serverDH_G.length = gSz;

    XMEMCPY(ssl->buffers.serverDH_P.buffer, p, pSz);
    XMEMCPY(ssl->buffers.serverDH_G.buffer, g, gSz);

    ssl->options.haveDH = 1;

    if (ssl->options.side != WOLFSSL_NEITHER_END) {
        word16 havePSK;
        word16 haveRSA;
        int    keySz   = 0;

        havePSK = 0;
        haveRSA = 1;
        keySz = ssl->buffers.keySz;
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, ssl->options.haveStaticECC,
                   ssl->options.haveFalconSig, ssl->options.haveAnon,
                   ssl->options.side);
    }

    WOLFSSL_LEAVE("wolfSSL_SetTmpDH", 0);

    return WOLFSSL_SUCCESS;
}


#if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
/* Enables or disables the session's DH key prime test. */
int wolfSSL_SetEnableDhKeyTest(WOLFSSL* ssl, int enable)
{
    WOLFSSL_ENTER("wolfSSL_SetEnableDhKeyTest");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (!enable)
        ssl->options.dhDoKeyTest = 0;
    else
        ssl->options.dhDoKeyTest = 1;

    WOLFSSL_LEAVE("wolfSSL_SetEnableDhKeyTest", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif


/* server ctx Diffie-Hellman parameters, WOLFSSL_SUCCESS on ok */
int wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p, int pSz,
                         const unsigned char* g, int gSz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetTmpDH");
    if (ctx == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

    if ((word16)pSz < ctx->minDhKeySz)
        return DH_KEY_SIZE_E;
    if ((word16)pSz > ctx->maxDhKeySz)
        return DH_KEY_SIZE_E;

    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
    {
        WC_RNG rng;
        int error, freeKey = 0;
        DhKey checkKey[1];

        error = wc_InitRng(&rng);
        if (!error)
            error = wc_InitDhKey(checkKey);
        if (!error) {
            freeKey = 1;
            error = wc_DhSetCheckKey(checkKey,
                                 p, pSz, g, gSz, NULL, 0, 0, &rng);
        }
        if (freeKey)
            wc_FreeDhKey(checkKey);
        wc_FreeRng(&rng);
        if (error)
            return error;

        ctx->dhKeyTested = 1;
    }
    #endif

    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_P.buffer = NULL;
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_G.buffer = NULL;

    ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ctx->serverDH_P.buffer == NULL)
       return MEMORY_E;

    ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ctx->serverDH_G.buffer == NULL) {
        XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ctx->serverDH_P.buffer = NULL;
        return MEMORY_E;
    }

    ctx->serverDH_P.length = pSz;
    ctx->serverDH_G.length = gSz;

    XMEMCPY(ctx->serverDH_P.buffer, p, pSz);
    XMEMCPY(ctx->serverDH_G.buffer, g, gSz);

    ctx->haveDH = 1;

    WOLFSSL_LEAVE("wolfSSL_CTX_SetTmpDH", 0);
    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits)
{
    if (ctx == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

    ctx->minDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits)
{
    if (ssl == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

    ssl->options.minDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits)
{
    if (ctx == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

    ctx->maxDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits)
{
    if (ssl == NULL || keySz_bits > 16000 || keySz_bits % 8 != 0)
        return BAD_FUNC_ARG;

    ssl->options.maxDhKeySz = keySz_bits / 8;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_GetDhKey_Sz(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return (ssl->options.dhKeySz * 8);
}



WOLFSSL_ABI
int wolfSSL_write(WOLFSSL* ssl, const void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("SSL_write()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;


#ifdef HAVE_WRITE_DUP
    { /* local variable scope */
        int dupErr = 0;   /* local copy */

        ret = 0;

        if (ssl->dupWrite && ssl->dupSide == READ_DUP_SIDE) {
            WOLFSSL_MSG("Read dup side cannot write");
            return WRITE_DUP_WRITE_E;
        }
        if (ssl->dupWrite) {
            if (wc_LockMutex(&ssl->dupWrite->dupMutex) != 0) {
                return BAD_MUTEX_E;
            }
            dupErr = ssl->dupWrite->dupErr;
            ret = wc_UnLockMutex(&ssl->dupWrite->dupMutex);
        }

        if (ret != 0) {
            ssl->error = ret;  /* high priority fatal error */
            return WOLFSSL_FATAL_ERROR;
        }
        if (dupErr != 0) {
            WOLFSSL_MSG("Write dup error from other side");
            ssl->error = dupErr;
            return WOLFSSL_FATAL_ERROR;
        }
    }
#endif

    errno = 0;

    ret = SendData(ssl, data, sz);

    WOLFSSL_LEAVE("SSL_write()", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}

static int wolfSSL_read_internal(WOLFSSL* ssl, void* data, int sz, int peek)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_read_internal()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;


#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite && ssl->dupSide == WRITE_DUP_SIDE) {
        WOLFSSL_MSG("Write dup side cannot read");
        return WRITE_DUP_READ_E;
    }
#endif

        errno = 0;


    ret = ReceiveData(ssl, (byte*)data, sz, peek);

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite) {
        if (ssl->error != 0 && ssl->error != WANT_READ
        ) {
            int notifyErr;

            WOLFSSL_MSG("Notifying write side of fatal read error");
            notifyErr  = NotifyWriteSide(ssl, ssl->error);
            if (notifyErr < 0) {
                ret = ssl->error = notifyErr;
            }
        }
    }
#endif

    WOLFSSL_LEAVE("wolfSSL_read_internal()", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}


int wolfSSL_peek(WOLFSSL* ssl, void* data, int sz)
{
    WOLFSSL_ENTER("wolfSSL_peek()");

    return wolfSSL_read_internal(ssl, data, sz, TRUE);
}


WOLFSSL_ABI
int wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    WOLFSSL_ENTER("wolfSSL_read()");

    return wolfSSL_read_internal(ssl, data, sz, FALSE);
}




/* helpers to set the device id, WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_SetDevId(WOLFSSL* ssl, int devId)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->devId = devId;

    return WOLFSSL_SUCCESS;
}

WOLFSSL_ABI
int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->devId = devId;

    return WOLFSSL_SUCCESS;
}

/* helpers to get device id and heap */
WOLFSSL_ABI
int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    int devId = INVALID_DEVID;
    if (ssl != NULL)
        devId = ssl->devId;
    if (ctx != NULL && devId == INVALID_DEVID)
        devId = ctx->devId;
    return devId;
}
void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    void* heap = NULL;
    if (ctx != NULL)
        heap = ctx->heap;
    else if (ssl != NULL)
        heap = ssl->heap;
    return heap;
}



WOLFSSL_ABI
int wolfSSL_UseSNI(WOLFSSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size, ssl->heap);
}


WOLFSSL_ABI
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, byte type, const void* data,
                                                                    word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size, ctx->heap);
}




#ifdef HAVE_TRUSTED_CA

WOLFSSL_API int wolfSSL_UseTrustedCA(WOLFSSL* ssl, byte type,
            const byte* certId, word32 certIdSz)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (type == WOLFSSL_TRUSTED_CA_PRE_AGREED) {
        if (certId != NULL || certIdSz != 0)
            return BAD_FUNC_ARG;
    }
    else if (type == WOLFSSL_TRUSTED_CA_X509_NAME) {
        if (certId == NULL || certIdSz == 0)
            return BAD_FUNC_ARG;
    }
    else if (type == WOLFSSL_TRUSTED_CA_KEY_SHA1 ||
            type == WOLFSSL_TRUSTED_CA_CERT_SHA1) {
        if (certId == NULL || certIdSz != WC_SHA_DIGEST_SIZE)
            return BAD_FUNC_ARG;
    }
    else
        return BAD_FUNC_ARG;

    return TLSX_UseTrustedCA(&ssl->extensions,
            type, certId, certIdSz, ssl->heap);
}

#endif /* HAVE_TRUSTED_CA */





#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl, byte status_type, byte options)
{
    if (ssl == NULL || ssl->options.side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ssl->extensions, status_type,
                                                options, ssl->heap, ssl->devId);
}


int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    if (ctx == NULL || ctx->method->side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ctx->extensions, status_type,
                                                options, ctx->heap, ctx->devId);
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

/* Elliptic Curves */

static int isValidCurveGroup(word16 name)
{
    switch (name) {
        case WOLFSSL_ECC_SECP160K1:
        case WOLFSSL_ECC_SECP160R1:
        case WOLFSSL_ECC_SECP160R2:
        case WOLFSSL_ECC_SECP192K1:
        case WOLFSSL_ECC_SECP192R1:
        case WOLFSSL_ECC_SECP224K1:
        case WOLFSSL_ECC_SECP224R1:
        case WOLFSSL_ECC_SECP256K1:
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
        case WOLFSSL_ECC_SECP521R1:
        case WOLFSSL_ECC_BRAINPOOLP256R1:
        case WOLFSSL_ECC_BRAINPOOLP384R1:
        case WOLFSSL_ECC_BRAINPOOLP512R1:
        case WOLFSSL_ECC_X25519:
        case WOLFSSL_ECC_X448:

        case WOLFSSL_FFDHE_2048:
        case WOLFSSL_FFDHE_3072:
        case WOLFSSL_FFDHE_4096:
        case WOLFSSL_FFDHE_6144:
        case WOLFSSL_FFDHE_8192:

            return 1;

        default:
            return 0;
    }
}

int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name)
{
    if (ssl == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ssl->options.userCurves = 1;

    return TLSX_UseSupportedCurve(&ssl->extensions, name, ssl->heap);
}


int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx, word16 name)
{
    if (ctx == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ctx->userCurves = 1;

    return TLSX_UseSupportedCurve(&ctx->extensions, name, ctx->heap);
}


/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN

WOLFSSL_ABI
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                    word32 protocol_name_listSz, byte options)
{
    char    *list, *ptr, **token;
    word16  len;
    int     idx = 0;
    int     ret = WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_UseALPN");

    if (ssl == NULL || protocol_name_list == NULL)
        return BAD_FUNC_ARG;

    if (protocol_name_listSz > (WOLFSSL_MAX_ALPN_NUMBER *
                                WOLFSSL_MAX_ALPN_PROTO_NAME_LEN +
                                WOLFSSL_MAX_ALPN_NUMBER)) {
        WOLFSSL_MSG("Invalid arguments, protocol name list too long");
        return BAD_FUNC_ARG;
    }

    if (!(options & WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) &&
        !(options & WOLFSSL_ALPN_FAILED_ON_MISMATCH)) {
            WOLFSSL_MSG("Invalid arguments, options not supported");
            return BAD_FUNC_ARG;
        }


    list = (char *)XMALLOC(protocol_name_listSz+1, ssl->heap,
                           DYNAMIC_TYPE_ALPN);
    if (list == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_ERROR;
    }

    token = (char **)XMALLOC(sizeof(char *) * (WOLFSSL_MAX_ALPN_NUMBER+1), ssl->heap, DYNAMIC_TYPE_ALPN);
    if (token == NULL) {
        XFREE(list, ssl->heap, DYNAMIC_TYPE_ALPN);
        WOLFSSL_MSG("Memory failure");
        return MEMORY_ERROR;
    }
    XMEMSET(token, 0, sizeof(char *) * (WOLFSSL_MAX_ALPN_NUMBER+1));

    XSTRNCPY(list, protocol_name_list, protocol_name_listSz);
    list[protocol_name_listSz] = '\0';

    /* read all protocol name from the list */
    token[idx] = XSTRTOK(list, ",", &ptr);
    while (idx < WOLFSSL_MAX_ALPN_NUMBER && token[idx] != NULL)
        token[++idx] = XSTRTOK(NULL, ",", &ptr);

    /* add protocol name list in the TLS extension in reverse order */
    while ((idx--) > 0) {
        len = (word16)XSTRLEN(token[idx]);

        ret = TLSX_UseALPN(&ssl->extensions, token[idx], len, options,
                                                                     ssl->heap);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("TLSX_UseALPN failure");
            break;
        }
    }

    XFREE(token, ssl->heap, DYNAMIC_TYPE_ALPN);
    XFREE(list, ssl->heap, DYNAMIC_TYPE_ALPN);

    return ret;
}

int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name, word16 *size)
{
    return TLSX_ALPN_GetRequest(ssl ? ssl->extensions : NULL,
                               (void **)protocol_name, size);
}

int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list, word16 *listSz)
{
    if (list == NULL || listSz == NULL)
        return BAD_FUNC_ARG;

    if (ssl->alpn_client_list == NULL)
        return BUFFER_ERROR;

    *listSz = (word16)XSTRLEN(ssl->alpn_client_list);
    if (*listSz == 0)
        return BUFFER_ERROR;

    *list = (char *)XMALLOC((*listSz)+1, ssl->heap, DYNAMIC_TYPE_TLSX);
    if (*list == NULL)
        return MEMORY_ERROR;

    XSTRNCPY(*list, ssl->alpn_client_list, (*listSz)+1);
    (*list)[*listSz] = 0;

    return WOLFSSL_SUCCESS;
}


/* used to free memory allocated by wolfSSL_ALPN_GetPeerProtocol */
int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    XFREE(*list, ssl->heap, DYNAMIC_TYPE_TLSX);
    *list = NULL;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_ALPN */

/* Secure Renegotiation */

/* user is forcing ability to use secure renegotiation, we discourage it */
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl)
{
    int ret = BAD_FUNC_ARG;

    if (ssl)
        ret = TLSX_UseSecureRenegotiation(&ssl->extensions, ssl->heap);

    if (ret == WOLFSSL_SUCCESS) {
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_RENEGOTIATION_INFO);

        if (extension)
            ssl->secure_renegotiation = (SecureRenegotiation*)extension->data;
    }

    return ret;
}

int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->useSecureReneg = 1;
    return WOLFSSL_SUCCESS;
}


/* do a secure renegotiation handshake, user forced, we discourage */
static int _Rehandshake(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->secure_renegotiation == NULL) {
        WOLFSSL_MSG("Secure Renegotiation not forced on by user");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation->enabled == 0) {
        WOLFSSL_MSG("Secure Renegotiation not enabled at extension level");
        return SECURE_RENEGOTIATION_E;
    }

    /* If the client started the renegotiation, the server will already
     * have processed the client's hello. */
    if (ssl->options.side != WOLFSSL_SERVER_END ||
        ssl->options.acceptState != ACCEPT_FIRST_REPLY_DONE) {

        if (ssl->options.handShakeState != HANDSHAKE_DONE) {
            if (!ssl->options.handShakeDone) {
                WOLFSSL_MSG("Can't renegotiate until initial "
                            "handshake complete");
                return SECURE_RENEGOTIATION_E;
            }
            else {
                WOLFSSL_MSG("Renegotiation already started. "
                            "Moving it forward.");
                ret = wolfSSL_negotiate(ssl);
                if (ret == WOLFSSL_SUCCESS)
                    ssl->secure_rene_count++;
                return ret;
            }
        }

#ifndef NO_FORCE_SCR_SAME_SUITE
        /* force same suite */
        if (ssl->suites) {
            ssl->suites->suiteSz = SUITE_LEN;
            ssl->suites->suites[0] = ssl->options.cipherSuite0;
            ssl->suites->suites[1] = ssl->options.cipherSuite;
        }
#endif

        /* reset handshake states */
        ssl->options.sendVerify = 0;
        ssl->options.serverState = NULL_STATE;
        ssl->options.clientState = NULL_STATE;
        ssl->options.connectState  = CONNECT_BEGIN;
        ssl->options.acceptState   = ACCEPT_BEGIN_RENEG;
        ssl->options.handShakeState = NULL_STATE;
        ssl->options.processReply  = 0;  /* TODO, move states in internal.h */

        XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

        ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;


        ret = InitHandshakeHashes(ssl);
        if (ret != 0) {
            ssl->error = ret;
            return WOLFSSL_FATAL_ERROR;
        }
    }
    ret = wolfSSL_negotiate(ssl);
    if (ret == WOLFSSL_SUCCESS)
        ssl->secure_rene_count++;
    return ret;
}


/* do a secure renegotiation handshake, user forced, we discourage */
int wolfSSL_Rehandshake(WOLFSSL* ssl)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_Rehandshake");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;


    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* Reset option to send certificate verify. */
        ssl->options.sendVerify = 0;
    }
    else {
        /* Reset resuming flag to do full secure handshake. */
        ssl->options.resuming = 0;
    }
    /* CLIENT/SERVER: Reset peer authentication for full secure handshake. */
    ssl->options.peerAuthGood = 0;

        ret = _Rehandshake(ssl);

    return ret;
}



/* do a secure resumption handshake, user forced, we discourage */
int wolfSSL_SecureResume(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SecureResume");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->error = SIDE_ERROR;
        return WOLFSSL_FATAL_ERROR;
    }

    return _Rehandshake(ssl);
}


long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_secure_renegotiation_support");

    if (!ssl || !ssl->secure_renegotiation)
        return WOLFSSL_FAILURE;
    return ssl->secure_renegotiation->enabled;
}





int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->haveEMS = 0;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.haveEMS = 0;

    return WOLFSSL_SUCCESS;
}



#ifndef WOLFSSL_LEANPSK

int wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_send()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->wflags;

    ssl->wflags = flags;
    ret = wolfSSL_write(ssl, data, sz);
    ssl->wflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_send()", ret);

    return ret;
}


int wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags)
{
    int ret;
    int oldFlags;

    WOLFSSL_ENTER("wolfSSL_recv()");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    oldFlags = ssl->rflags;

    ssl->rflags = flags;
    ret = wolfSSL_read(ssl, data, sz);
    ssl->rflags = oldFlags;

    WOLFSSL_LEAVE("wolfSSL_recv()", ret);

    return ret;
}
#endif


/* WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_shutdown(WOLFSSL* ssl)
{
    int  ret = WOLFSSL_FATAL_ERROR;
    WOLFSSL_ENTER("SSL_shutdown()");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        WOLFSSL_MSG("quiet shutdown, no close notify sent");
        ret = WOLFSSL_SUCCESS;
    }
    else {
        /* try to send close notify, not an error if can't */
        if (!ssl->options.isClosed && !ssl->options.connReset &&
                                      !ssl->options.sentNotify) {
            ssl->error = SendAlert(ssl, alert_warning, close_notify);
            if (ssl->error < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.sentNotify = 1;  /* don't send close_notify twice */
            if (ssl->options.closeNotify)
                ret = WOLFSSL_SUCCESS;
            else {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                WOLFSSL_LEAVE("SSL_shutdown()", ret);
                return ret;
            }
        }

#ifdef WOLFSSL_SHUTDOWNONCE
        if (ssl->options.isClosed || ssl->options.connReset) {
            /* Shutdown has already occurred.
             * Caller is free to ignore this error. */
            return SSL_SHUTDOWN_ALREADY_DONE_E;
        }
#endif

        /* call wolfSSL_shutdown again for bidirectional shutdown */
        if (ssl->options.sentNotify && !ssl->options.closeNotify) {
            ret = ProcessReply(ssl);
            if (ret == ZERO_RETURN) {
                /* simulate OpenSSL behavior */
                ssl->error = WOLFSSL_ERROR_SYSCALL;
                ret = WOLFSSL_SUCCESS;
            } else if (ssl->error == WOLFSSL_ERROR_NONE) {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
            } else {
                WOLFSSL_ERROR(ssl->error);
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }


    WOLFSSL_LEAVE("SSL_shutdown()", ret);

    return ret;
}


/* get current error state value */
int wolfSSL_state(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    return ssl->error;
}


WOLFSSL_ABI
int wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    WOLFSSL_ENTER("SSL_get_error");

    if (ret > 0)
        return WOLFSSL_ERROR_NONE;
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    WOLFSSL_LEAVE("SSL_get_error", ssl->error);

    /* make sure converted types are handled in SetErrorString() too */
    if (ssl->error == WANT_READ)
        return WOLFSSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WANT_WRITE)
        return WOLFSSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    else if (ssl->error == ZERO_RETURN)
        return WOLFSSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
    return ssl->error;
}


/* retrieve alert history, WOLFSSL_SUCCESS on ok */
int wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h)
{
    if (ssl && h) {
        *h = ssl->alert_history;
    }
    return WOLFSSL_SUCCESS;
}


/* return TRUE if current error is want read */
int wolfSSL_want_read(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_want_read");
    if (ssl->error == WANT_READ)
        return 1;

    return 0;
}


/* return TRUE if current error is want write */
int wolfSSL_want_write(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_want_write");
    if (ssl->error == WANT_WRITE)
        return 1;

    return 0;
}


char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    static char tmp[WOLFSSL_MAX_ERROR_SZ] = {0};

    WOLFSSL_ENTER("ERR_error_string");
    if (data) {
        SetErrorString((int)errNumber, data);
        return data;
    }
    else {
        SetErrorString((int)errNumber, tmp);
        return tmp;
    }
}


void wolfSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string_n");
    if (len >= WOLFSSL_MAX_ERROR_SZ)
        wolfSSL_ERR_error_string(e, buf);
    else {
        char tmp[WOLFSSL_MAX_ERROR_SZ];

        WOLFSSL_MSG("Error buffer too short, truncating");
        if (len) {
            wolfSSL_ERR_error_string(e, tmp);
            XMEMCPY(buf, tmp, len-1);
            buf[len-1] = '\0';
        }
    }
}


/* don't free temporary arrays at end of handshake */
void wolfSSL_KeepArrays(WOLFSSL* ssl)
{
    if (ssl)
        ssl->options.saveArrays = 1;
}


/* user doesn't need temporary arrays anymore, Free */
void wolfSSL_FreeArrays(WOLFSSL* ssl)
{
    if (ssl && ssl->options.handShakeState == HANDSHAKE_DONE) {
        ssl->options.saveArrays = 0;
        FreeArrays(ssl, 1);
    }
}

/* Set option to indicate that the resources are not to be freed after
 * handshake.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.keepResources = 1;

    return 0;
}

/* Free the handshake resources after handshake.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    FreeHandshakeResources(ssl);

    return 0;
}

/* Use the client's order of preference when matching cipher suites.
 *
 * ssl  The SSL/TLS context object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->useClientOrder = 1;

    return 0;
}

/* Use the client's order of preference when matching cipher suites.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL and 0 on success.
 */
int wolfSSL_UseClientSuites(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.useClientOrder = 1;

    return 0;
}


const byte* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify)
{
    if (ssl == NULL)
        return NULL;

    if ( (ssl->options.side == WOLFSSL_CLIENT_END && !verify) ||
         (ssl->options.side == WOLFSSL_SERVER_END &&  verify) )
        return ssl->keys.client_write_MAC_secret;
    else
        return ssl->keys.server_write_MAC_secret;
}




WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;
    if (ctx)
        cm = ctx->cm;
    return cm;
}

WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap)
{
    WOLFSSL_CERT_MANAGER* cm;

    WOLFSSL_ENTER("wolfSSL_CertManagerNew");

    cm = (WOLFSSL_CERT_MANAGER*) XMALLOC(sizeof(WOLFSSL_CERT_MANAGER), heap,
                                         DYNAMIC_TYPE_CERT_MANAGER);
    if (cm) {
        XMEMSET(cm, 0, sizeof(WOLFSSL_CERT_MANAGER));
        cm->refCount = 1;

        if (wc_InitMutex(&cm->caLock) != 0) {
            WOLFSSL_MSG("Bad mutex init");
            wolfSSL_CertManagerFree(cm);
            return NULL;
        }
        if (wc_InitMutex(&cm->refMutex) != 0) {
            WOLFSSL_MSG("Bad mutex init");
            wolfSSL_CertManagerFree(cm);
            return NULL;
        }

        #ifdef WOLFSSL_TRUST_PEER_CERT
        if (wc_InitMutex(&cm->tpLock) != 0) {
            WOLFSSL_MSG("Bad mutex init");
            wolfSSL_CertManagerFree(cm);
            return NULL;
        }
        #endif

        /* set default minimum key size allowed */
            cm->minRsaKeySz = MIN_RSAKEY_SZ;
            cm->minEccKeySz = MIN_ECCKEY_SZ;

            cm->heap = heap;
    }

    return cm;
}


WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void)
{
    return wolfSSL_CertManagerNew_ex(NULL);
}


void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER* cm)
{
    int doFree = 0;
    WOLFSSL_ENTER("wolfSSL_CertManagerFree");

    if (cm) {
        if (wc_LockMutex(&cm->refMutex) != 0) {
            WOLFSSL_MSG("Couldn't lock cm mutex");
        }
        cm->refCount--;
        if (cm->refCount == 0)
            doFree = 1;
        wc_UnLockMutex(&cm->refMutex);
        if (doFree) {
            FreeSignerTable(cm->caTable, CA_TABLE_SIZE, cm->heap);
            wc_FreeMutex(&cm->caLock);

            #ifdef WOLFSSL_TRUST_PEER_CERT
            FreeTrustedPeerTable(cm->tpTable, TP_TABLE_SIZE, cm->heap);
            wc_FreeMutex(&cm->tpLock);
            #endif
            if (wc_FreeMutex(&cm->refMutex) != 0) {
                WOLFSSL_MSG("Couldn't free refMutex mutex");
            }
            XFREE(cm, cm->heap, DYNAMIC_TYPE_CERT_MANAGER);
        }
    }

}

int wolfSSL_CertManager_up_ref(WOLFSSL_CERT_MANAGER* cm)
{
    if (cm) {
        if (wc_LockMutex(&cm->refMutex) != 0) {
            WOLFSSL_MSG("Failed to lock cm mutex");
            return WOLFSSL_FAILURE;
        }
        cm->refCount++;
        wc_UnLockMutex(&cm->refMutex);

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


/* Unload the CA signer list */
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER("wolfSSL_CertManagerUnloadCAs");

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (wc_LockMutex(&cm->caLock) != 0)
        return BAD_MUTEX_E;

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, cm->heap);

    wc_UnLockMutex(&cm->caLock);


    return WOLFSSL_SUCCESS;
}


#ifdef WOLFSSL_TRUST_PEER_CERT
int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER("wolfSSL_CertManagerUnload_trust_peers");

    if (cm == NULL)
        return BAD_FUNC_ARG;

    if (wc_LockMutex(&cm->tpLock) != 0)
        return BAD_MUTEX_E;

    FreeTrustedPeerTable(cm->tpTable, TP_TABLE_SIZE, cm->heap);

    wc_UnLockMutex(&cm->tpLock);


    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)

void wolfSSL_ERR_print_errors_fp(XFILE fp, int err)
{
    char data[WOLFSSL_MAX_ERROR_SZ + 1];

    WOLFSSL_ENTER("wolfSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    XFPRINTF(fp, "%s", data);
}

#if defined(DEBUG_WOLFSSL_VERBOSE)
void wolfSSL_ERR_dump_errors_fp(XFILE fp)
{
    wc_ERR_print_errors_fp(fp);
}

void wolfSSL_ERR_print_errors_cb (int (*cb)(const char *str, size_t len,
                                            void *u), void *u)
{
    wc_ERR_print_errors_cb(cb, u);
}
#endif
#endif

/*
 * TODO This ssl parameter needs to be changed to const once our ABI checker
 *      stops flagging qualifier additions as ABI breaking.
 */
WOLFSSL_ABI
int wolfSSL_pending(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return ssl->buffers.clearOutputBuffer.length;
}

int wolfSSL_has_pending(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_has_pending");
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    return ssl->buffers.clearOutputBuffer.length > 0;
}

#ifndef WOLFSSL_LEANPSK
/* turn on handshake group messages for context */
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
       return BAD_FUNC_ARG;

    ctx->groupMessages = 1;

    return WOLFSSL_SUCCESS;
}
#endif


/* connect enough to get peer cert chain */
int wolfSSL_connect_cert(WOLFSSL* ssl)
{
    int  ret;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->options.certOnly = 1;
    ret = wolfSSL_connect(ssl);
    ssl->options.certOnly   = 0;

    return ret;
}


#ifndef WOLFSSL_LEANPSK
/* turn on handshake group messages for ssl object */
int wolfSSL_set_group_messages(WOLFSSL* ssl)
{
    if (ssl == NULL)
       return BAD_FUNC_ARG;

    ssl->options.groupMessages = 1;

    return WOLFSSL_SUCCESS;
}


/* make minVersion the internal equivalent SSL version */
static int SetMinVersionHelper(byte* minVersion, int version)
{

    switch (version) {
#if defined(WOLFSSL_ALLOW_SSLV3)
        case WOLFSSL_SSLV3:
            *minVersion = SSLv3_MINOR;
            break;
#endif

        #ifdef WOLFSSL_ALLOW_TLSV10
        case WOLFSSL_TLSV1:
            *minVersion = TLSv1_MINOR;
            break;
        #endif

        case WOLFSSL_TLSV1_1:
            *minVersion = TLSv1_1_MINOR;
            break;
        case WOLFSSL_TLSV1_2:
            *minVersion = TLSv1_2_MINOR;
            break;

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

    return WOLFSSL_SUCCESS;
}


/* Set minimum downgrade version allowed, WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetMinVersion");

    if (ctx == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    return SetMinVersionHelper(&ctx->minDowngrade, version);
}


/* Set minimum downgrade version allowed, WOLFSSL_SUCCESS on ok */
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version)
{
    WOLFSSL_ENTER("wolfSSL_SetMinVersion");

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    return SetMinVersionHelper(&ssl->options.minDowngrade, version);
}


/* Function to get version as WOLFSSL_ enum value for wolfSSL_SetVersion */
int wolfSSL_GetVersion(const WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->version.major == SSLv3_MAJOR) {
        switch (ssl->version.minor) {
            case SSLv3_MINOR :
                return WOLFSSL_SSLV3;
            case TLSv1_MINOR :
                return WOLFSSL_TLSV1;
            case TLSv1_1_MINOR :
                return WOLFSSL_TLSV1_1;
            case TLSv1_2_MINOR :
                return WOLFSSL_TLSV1_2;
            case TLSv1_3_MINOR :
                return WOLFSSL_TLSV1_3;
            default:
                break;
        }
    }

    return VERSION_ERROR;
}

int wolfSSL_SetVersion(WOLFSSL* ssl, int version)
{
    word16 haveRSA = 1;
    word16 havePSK = 0;
    int    keySz   = 0;

    WOLFSSL_ENTER("wolfSSL_SetVersion");

    if (ssl == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return BAD_FUNC_ARG;
    }

    switch (version) {
#if defined(WOLFSSL_ALLOW_SSLV3)
        case WOLFSSL_SSLV3:
            ssl->version = MakeSSLv3();
            break;
#endif

        #ifdef WOLFSSL_ALLOW_TLSV10
        case WOLFSSL_TLSV1:
            ssl->version = MakeTLSv1();
            break;
        #endif

        case WOLFSSL_TLSV1_1:
            ssl->version = MakeTLSv1_1();
            break;
        case WOLFSSL_TLSV1_2:
            ssl->version = MakeTLSv1_2();
            break;

        default:
            WOLFSSL_MSG("Bad function argument");
            return BAD_FUNC_ARG;
    }

        keySz = ssl->buffers.keySz;

    InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
               ssl->options.haveDH, ssl->options.haveECDSAsig,
               ssl->options.haveECC, ssl->options.haveStaticECC,
               ssl->options.haveFalconSig, ssl->options.haveAnon,
               ssl->options.side);

    return WOLFSSL_SUCCESS;
}
#endif /* !leanpsk */



/* Make a work from the front of random hash */
static WC_INLINE word32 MakeWordFromHash(const byte* hashID)
{
    return ((word32)hashID[0] << 24) | ((word32)hashID[1] << 16) |
           ((word32)hashID[2] <<  8) |  (word32)hashID[3];
}




/* hash is the SHA digest of name, just use first 32 bits as hash */
static WC_INLINE word32 HashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % CA_TABLE_SIZE;
}


/* does CA already exist on signer list */
int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash)
{
    Signer* signers;
    int     ret = 0;
    word32  row;

    if (cm == NULL || hash == NULL) {
        return ret;
    }

    row = HashSigner(hash);

    if (wc_LockMutex(&cm->caLock) != 0) {
        return ret;
    }
    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;

    #ifndef NO_SKID
        subjectHash = signers->subjectKeyIdHash;
    #else
        subjectHash = signers->subjectNameHash;
    #endif

        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = 1; /* success */
            break;
        }
        signers = signers->next;
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}


#ifdef WOLFSSL_TRUST_PEER_CERT
/* hash is the SHA digest of name, just use first 32 bits as hash */
static WC_INLINE word32 TrustedPeerHashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % TP_TABLE_SIZE;
}

/* does trusted peer already exist on signer list */
int AlreadyTrustedPeer(WOLFSSL_CERT_MANAGER* cm, DecodedCert* cert)
{
    TrustedPeerCert* tp;
    int     ret = 0;
    word32  row = TrustedPeerHashSigner(cert->subjectHash);

    if (wc_LockMutex(&cm->tpLock) != 0)
        return  ret;
    tp = cm->tpTable[row];
    while (tp) {
        if (XMEMCMP(cert->subjectHash, tp->subjectNameHash,
                SIGNER_DIGEST_SIZE) == 0)
            ret = 1;
    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet) {
            /* Compare SKID as well if available */
            if (ret == 1 && XMEMCMP(cert->extSubjKeyId, tp->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE) != 0)
                ret = 0;
        }
    #endif
        if (ret == 1)
            break;
        tp = tp->next;
    }
    wc_UnLockMutex(&cm->tpLock);

    return ret;
}


/* return Trusted Peer if found, otherwise NULL
    type is what to match on
 */
TrustedPeerCert* GetTrustedPeer(void* vp, DecodedCert* cert)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    TrustedPeerCert* ret = NULL;
    TrustedPeerCert* tp  = NULL;
    word32  row;

    if (cm == NULL || cert == NULL)
        return NULL;

    row = TrustedPeerHashSigner(cert->subjectHash);

    if (wc_LockMutex(&cm->tpLock) != 0)
        return ret;

    tp = cm->tpTable[row];
    while (tp) {
        if (XMEMCMP(cert->subjectHash, tp->subjectNameHash,
                SIGNER_DIGEST_SIZE) == 0)
            ret = tp;
    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet) {
            /* Compare SKID as well if available */
            if (ret != NULL && XMEMCMP(cert->extSubjKeyId, tp->subjectKeyIdHash,
                    SIGNER_DIGEST_SIZE) != 0)
                ret = NULL;
        }
    #endif
        if (ret != NULL)
            break;
        tp = tp->next;
    }
    wc_UnLockMutex(&cm->tpLock);

    return ret;
}


int MatchTrustedPeer(TrustedPeerCert* tp, DecodedCert* cert)
{
    if (tp == NULL || cert == NULL)
        return BAD_FUNC_ARG;

    /* subject key id or subject hash has been compared when searching
       tpTable for the cert from function GetTrustedPeer */

    /* compare signatures */
    if (tp->sigLen == cert->sigLength) {
        if (XMEMCMP(tp->sig, cert->signature, cert->sigLength)) {
            return WOLFSSL_FAILURE;
        }
    }
    else {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


/* return CA if found, otherwise NULL */
Signer* GetCA(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row = 0;

    if (cm == NULL || hash == NULL)
        return NULL;

    row = HashSigner(hash);

    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;

    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;
        #ifndef NO_SKID
            subjectHash = signers->subjectKeyIdHash;
        #else
            subjectHash = signers->subjectNameHash;
        #endif
        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}


#ifndef NO_SKID
/* return CA if found, otherwise NULL. Walk through hash table. */
Signer* GetCAByName(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row;

    if (cm == NULL)
        return NULL;

    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;

    for (row = 0; row < CA_TABLE_SIZE && ret == NULL; row++) {
        signers = cm->caTable[row];
        while (signers && ret == NULL) {
            if (XMEMCMP(hash, signers->subjectNameHash,
                        SIGNER_DIGEST_SIZE) == 0) {
                ret = signers;
            }
            signers = signers->next;
        }
    }
    wc_UnLockMutex(&cm->caLock);

    return ret;
}
#endif


#ifdef WOLFSSL_TRUST_PEER_CERT
/* add a trusted peer cert to linked list */
int AddTrustedPeer(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int verify)
{
    int ret, row;
    TrustedPeerCert* peerCert;
    DecodedCert* cert;
    DerBuffer*   der = *pDer;

    WOLFSSL_MSG("Adding a Trusted Peer Cert");

    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), cm->heap,
                                 DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        FreeDer(&der);
        return MEMORY_E;
    }

    InitDecodedCert(cert, der->buffer, der->length, cm->heap);
    if ((ret = ParseCert(cert, TRUSTED_PEER_TYPE, verify, cm)) != 0) {
        FreeDecodedCert(cert);
        XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
        FreeDer(&der);
        return ret;
    }
    WOLFSSL_MSG("\tParsed new trusted peer cert");

    peerCert = (TrustedPeerCert*)XMALLOC(sizeof(TrustedPeerCert), cm->heap,
                                                             DYNAMIC_TYPE_CERT);
    if (peerCert == NULL) {
        FreeDecodedCert(cert);
        XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
        FreeDer(&der);
        return MEMORY_E;
    }
    XMEMSET(peerCert, 0, sizeof(TrustedPeerCert));

    #ifndef IGNORE_NAME_CONSTRAINTS
        if (peerCert->permittedNames)
            FreeNameSubtrees(peerCert->permittedNames, cm->heap);
        if (peerCert->excludedNames)
            FreeNameSubtrees(peerCert->excludedNames, cm->heap);
    #endif

    if (AlreadyTrustedPeer(cm, cert)) {
        WOLFSSL_MSG("\tAlready have this CA, not adding again");
        FreeTrustedPeer(peerCert, cm->heap);
        (void)ret;
    }
    else {
        /* add trusted peer signature */
        peerCert->sigLen = cert->sigLength;
        peerCert->sig = (byte *)XMALLOC(cert->sigLength, cm->heap,
                                                        DYNAMIC_TYPE_SIGNATURE);
        if (peerCert->sig == NULL) {
            FreeDecodedCert(cert);
            XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
            FreeTrustedPeer(peerCert, cm->heap);
            FreeDer(&der);
            return MEMORY_E;
        }
        XMEMCPY(peerCert->sig, cert->signature, cert->sigLength);

        /* add trusted peer name */
        peerCert->nameLen = cert->subjectCNLen;
        peerCert->name    = cert->subjectCN;
        #ifndef IGNORE_NAME_CONSTRAINTS
            peerCert->permittedNames = cert->permittedNames;
            peerCert->excludedNames  = cert->excludedNames;
        #endif

        /* add SKID when available and hash of name */
        #ifndef NO_SKID
            XMEMCPY(peerCert->subjectKeyIdHash, cert->extSubjKeyId,
                    SIGNER_DIGEST_SIZE);
        #endif
            XMEMCPY(peerCert->subjectNameHash, cert->subjectHash,
                    SIGNER_DIGEST_SIZE);
            peerCert->next    = NULL; /* If Key Usage not set, all uses valid. */
            cert->subjectCN = 0;
        #ifndef IGNORE_NAME_CONSTRAINTS
            cert->permittedNames = NULL;
            cert->excludedNames = NULL;
        #endif

            row = TrustedPeerHashSigner(peerCert->subjectNameHash);

            if (wc_LockMutex(&cm->tpLock) == 0) {
                peerCert->next = cm->tpTable[row];
                cm->tpTable[row] = peerCert;   /* takes ownership */
                wc_UnLockMutex(&cm->tpLock);
            }
            else {
                WOLFSSL_MSG("\tTrusted Peer Cert Mutex Lock failed");
                FreeDecodedCert(cert);
                XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
                FreeTrustedPeer(peerCert, cm->heap);
                FreeDer(&der);
                return BAD_MUTEX_E;
            }
        }

    WOLFSSL_MSG("\tFreeing parsed trusted peer cert");
    FreeDecodedCert(cert);
    XFREE(cert, cm->heap, DYNAMIC_TYPE_DCERT);
    WOLFSSL_MSG("\tFreeing der trusted peer cert");
    FreeDer(&der);
    WOLFSSL_MSG("\t\tOK Freeing der trusted peer cert");
    WOLFSSL_LEAVE("AddTrustedPeer", ret);

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


/* owns der, internal now uses too */
/* type flag ids from user or from chain received during verify
   don't allow chain ones to be added w/o isCA extension */
int AddCA(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int type, int verify)
{
    int         ret;
    Signer*     signer = NULL;
    word32      row;
    byte*       subjectHash;
    DecodedCert  cert[1];
    DerBuffer*   der = *pDer;

    WOLFSSL_MSG("Adding a CA");

    if (cm == NULL) {
        FreeDer(pDer);
        return BAD_FUNC_ARG;
    }


    InitDecodedCert(cert, der->buffer, der->length, cm->heap);
    ret = ParseCert(cert, CA_TYPE, verify, cm);
    WOLFSSL_MSG("\tParsed new CA");

#ifndef NO_SKID
    subjectHash = cert->extSubjKeyId;
#else
    subjectHash = cert->subjectHash;
#endif

    /* check CA key size */
    if (verify) {
        switch (cert->keyOID) {
            case RSAk:
                if (cm->minRsaKeySz < 0 ||
                                   cert->pubKeySize < (word16)cm->minRsaKeySz) {
                    ret = RSA_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA RSA key size error");
                }
                break;
            case ECDSAk:
                if (cm->minEccKeySz < 0 ||
                                   cert->pubKeySize < (word16)cm->minEccKeySz) {
                    ret = ECC_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA ECC key size error");
                }
                break;

            default:
                WOLFSSL_MSG("\tNo key size check done on CA");
                break; /* no size check if key type is not in switch */
        }
    }

    if (ret == 0 && cert->isCA == 0 && type != WOLFSSL_USER_CA) {
        WOLFSSL_MSG("\tCan't add as CA if not actually one");
        ret = NOT_CA_ERROR;
    }
#ifndef ALLOW_INVALID_CERTSIGN
    else if (ret == 0 && cert->isCA == 1 && type != WOLFSSL_USER_CA &&
        !cert->selfSigned && (cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
        /* Intermediate CA certs are required to have the keyCertSign
        * extension set. User loaded root certs are not. */
        WOLFSSL_MSG("\tDoesn't have key usage certificate signing");
        ret = NOT_CA_ERROR;
    }
#endif
    else if (ret == 0 && AlreadySigner(cm, subjectHash)) {
        WOLFSSL_MSG("\tAlready have this CA, not adding again");
        (void)ret;
    }
    else if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner(cm->heap);
        if (!signer)
            ret = MEMORY_ERROR;
    }
    if (ret == 0 && signer != NULL) {
    #ifdef WOLFSSL_SIGNER_DER_CERT
        ret = AllocDer(&signer->derCert, der->length, der->type, NULL);
    }
    if (ret == 0 && signer != NULL) {
        XMEMCPY(signer->derCert->buffer, der->buffer, der->length);
    #endif
        signer->keyOID         = cert->keyOID;
        if (cert->pubKeyStored) {
            signer->publicKey      = cert->publicKey;
            signer->pubKeySize     = cert->pubKeySize;
        }
        if (cert->subjectCNStored) {
            signer->nameLen        = cert->subjectCNLen;
            signer->name           = cert->subjectCN;
        }
        signer->pathLength     = cert->pathLength;
        signer->maxPathLen     = cert->maxPathLen;
        signer->pathLengthSet  = cert->pathLengthSet;
        signer->selfSigned     = cert->selfSigned;
    #ifndef IGNORE_NAME_CONSTRAINTS
        signer->permittedNames = cert->permittedNames;
        signer->excludedNames  = cert->excludedNames;
    #endif
    #ifndef NO_SKID
        XMEMCPY(signer->subjectKeyIdHash, cert->extSubjKeyId,
                SIGNER_DIGEST_SIZE);
    #endif
        XMEMCPY(signer->subjectNameHash, cert->subjectHash,
                SIGNER_DIGEST_SIZE);
        signer->keyUsage = cert->extKeyUsageSet ? cert->extKeyUsage
                                                : 0xFFFF;
        signer->next    = NULL; /* If Key Usage not set, all uses valid. */
        cert->publicKey = 0;    /* in case lock fails don't free here.   */
        cert->subjectCN = 0;
    #ifndef IGNORE_NAME_CONSTRAINTS
        cert->permittedNames = NULL;
        cert->excludedNames = NULL;
    #endif

    #ifndef NO_SKID
        row = HashSigner(signer->subjectKeyIdHash);
    #else
        row = HashSigner(signer->subjectNameHash);
    #endif

        if (wc_LockMutex(&cm->caLock) == 0) {
            signer->next = cm->caTable[row];
            cm->caTable[row] = signer;   /* takes ownership */
            wc_UnLockMutex(&cm->caLock);
            if (cm->caCacheCallback)
                cm->caCacheCallback(der->buffer, (int)der->length, type);
        }
        else {
            WOLFSSL_MSG("\tCA Mutex Lock failed");
            ret = BAD_MUTEX_E;
            FreeSigner(signer, cm->heap);
        }
    }
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    /* Verify CA by TSIP so that generated tsip key is going to be able to */
    /* be used for peer's cert verification                                */
    /* TSIP is only able to handle USER CA, and only one CA.               */
    /* Therefore, it doesn't need to call TSIP again if there is already   */
    /* verified CA.                                                        */
    if ( ret == 0 && signer != NULL ) {
        signer->cm_idx = row;
        if (type == WOLFSSL_USER_CA) {
            if ((ret = wc_Renesas_cmn_RootCertVerify(cert->source, cert->maxIdx,
                 cert->sigCtx.CertAtt.pubkey_n_start,
                 cert->sigCtx.CertAtt.pubkey_n_len - 1,
                 cert->sigCtx.CertAtt.pubkey_e_start,
                cert->sigCtx.CertAtt.pubkey_e_len - 1,
                 row/* cm index */))
                < 0)
                WOLFSSL_MSG("Renesas_RootCertVerify() failed");
            else
                WOLFSSL_MSG("Renesas_RootCertVerify() succeed or skipped");
        }
    }
#endif /* TSIP or SCE */

    WOLFSSL_MSG("\tFreeing Parsed CA");
    FreeDecodedCert(cert);
    WOLFSSL_MSG("\tFreeing der CA");
    FreeDer(pDer);
    WOLFSSL_MSG("\t\tOK Freeing der CA");

    WOLFSSL_LEAVE("AddCA", ret);

    return ret == 0 ? WOLFSSL_SUCCESS : ret;
}







WOLFSSL_ABI
int wolfSSL_Init(void)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_Init");

    #if FIPS_VERSION_GE(5,1)
        ret = wolfCrypt_SetPrivateKeyReadEnable_fips(1, WC_KEYTYPE_ALL);
        if (ret != 0)
            return ret;
        else
            ret = WOLFSSL_SUCCESS;
    #endif

    if (initRefCount == 0) {
        /* Initialize crypto for use with TLS connection */
        if (wolfCrypt_Init() != 0) {
            WOLFSSL_MSG("Bad wolfCrypt Init");
            ret = WC_INIT_E;
        }

#ifdef HAVE_GLOBAL_RNG
        if ((ret == WOLFSSL_SUCCESS) && (wc_InitMutex(&globalRNGMutex) != 0)) {
            WOLFSSL_MSG("Bad Init Mutex rng");
            ret = BAD_MUTEX_E;
        }
        else {
            globalRNGMutex_valid = 1;
        }
#endif

    #ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
    #endif


        if ((ret == WOLFSSL_SUCCESS) && (wc_InitMutex(&count_mutex) != 0)) {
            WOLFSSL_MSG("Bad Init Mutex count");
            ret = BAD_MUTEX_E;
        }
        else {
            count_mutex_valid = 1;
        }

    }

    if ((ret == WOLFSSL_SUCCESS) && (wc_LockMutex(&count_mutex) != 0)) {
        WOLFSSL_MSG("Bad Lock Mutex count");
        ret = BAD_MUTEX_E;
    }
    else {
        initRefCount++;
        wc_UnLockMutex(&count_mutex);
    }

    if (ret != WOLFSSL_SUCCESS) {
        initRefCount = 1; /* Force cleanup */
        (void)wolfSSL_Cleanup(); /* Ignore any error from cleanup */
    }

    return ret;
}




/* process user cert chain to pass during the handshake */
static int ProcessUserChain(WOLFSSL_CTX* ctx, const unsigned char* buff,
                         long sz, int format, int type, WOLFSSL* ssl,
                         long* used, EncryptedInfo* info, int verify)
{
    int ret = 0;
    void* heap = wolfSSL_CTX_GetHeap(ctx, ssl);

    if ((type == CA_TYPE) && (ctx == NULL)) {
        WOLFSSL_MSG("Need context for CA load");
        return BAD_FUNC_ARG;
    }

    /* we may have a user cert chain, try to consume */
    if ((type == CERT_TYPE || type == CA_TYPE) && (info->consumed < sz)) {
        byte   staticBuffer[FILE_BUFFER_SIZE];  /* tmp chain buffer */
        byte*  chainBuffer = staticBuffer;
        int    dynamicBuffer = 0;
        word32 bufferSz;
        long   consumed = info->consumed;
        word32 idx = 0;
        int    gotOne = 0;

        /* Calculate max possible size, including max headers */
        bufferSz = (word32)(sz - consumed) + (CERT_HEADER_SZ * MAX_CHAIN_DEPTH);
        if (bufferSz > sizeof(staticBuffer)) {
            WOLFSSL_MSG("Growing Tmp Chain Buffer");
            /* will shrink to actual size */
            chainBuffer = (byte*)XMALLOC(bufferSz, heap, DYNAMIC_TYPE_FILE);
            if (chainBuffer == NULL) {
                return MEMORY_E;
            }
            dynamicBuffer = 1;
        }

        WOLFSSL_MSG("Processing Cert Chain");
        while (consumed < sz) {
            DerBuffer* part = NULL;
            word32 remain = (word32)(sz - consumed);
            info->consumed = 0;

            if (format == WOLFSSL_FILETYPE_PEM) {
            #ifdef WOLFSSL_PEM_TO_DER
                ret = PemToDer(buff + consumed, remain, type, &part,
                               heap, info, NULL);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
            else {
                int length = remain;
                if (format == WOLFSSL_FILETYPE_ASN1) {
                    /* get length of der (read sequence) */
                    word32 inOutIdx = 0;
                    if (GetSequence(buff + consumed, &inOutIdx, &length,
                            remain) < 0) {
                        ret = ASN_NO_PEM_HEADER;
                    }
                    length += inOutIdx; /* include leading sequence */
                }
                info->consumed = length;
                if (ret == 0) {
                    ret = AllocDer(&part, length, type, heap);
                    if (ret == 0) {
                        XMEMCPY(part->buffer, buff + consumed, length);
                    }
                }
            }
            if (ret == 0) {
                gotOne = 1;
                if ((idx + part->length + CERT_HEADER_SZ) > bufferSz) {
                    WOLFSSL_MSG("   Cert Chain bigger than buffer");
                    ret = BUFFER_E;
                }
                else {
                    c32to24(part->length, &chainBuffer[idx]);
                    idx += CERT_HEADER_SZ;
                    XMEMCPY(&chainBuffer[idx], part->buffer, part->length);
                    idx += part->length;
                    consumed  += info->consumed;
                    if (used)
                        *used += info->consumed;
                }

                /* add CA's to certificate manager */
                if (type == CA_TYPE) {
                    /* verify CA unless user set to no verify */
                    ret = AddCA(ctx->cm, &part, WOLFSSL_USER_CA, verify);
                    gotOne = 0; /* don't exit loop for CA type */
                }
            }

            FreeDer(&part);

            if (ret == ASN_NO_PEM_HEADER && gotOne) {
                WOLFSSL_MSG("We got one good cert, so stuff at end ok");
                break;
            }

            if (ret < 0) {
                WOLFSSL_MSG("   Error in Cert in Chain");
                if (dynamicBuffer)
                    XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);
                return ret;
            }
            WOLFSSL_MSG("   Consumed another Cert in Chain");
        }
        WOLFSSL_MSG("Finished Processing Cert Chain");

        /* only retain actual size used */
        ret = 0;
        if (idx > 0) {
            if (ssl) {
                if (ssl->buffers.weOwnCertChain) {
                    FreeDer(&ssl->buffers.certChain);
                }
                ret = AllocDer(&ssl->buffers.certChain, idx, type, heap);
                if (ret == 0) {
                    XMEMCPY(ssl->buffers.certChain->buffer, chainBuffer,
                            idx);
                    ssl->buffers.weOwnCertChain = 1;
                }
            } else if (ctx) {
                FreeDer(&ctx->certChain);
                ret = AllocDer(&ctx->certChain, idx, type, heap);
                if (ret == 0) {
                    XMEMCPY(ctx->certChain->buffer, chainBuffer, idx);
                }
            }
        }

        if (dynamicBuffer)
            XFREE(chainBuffer, heap, DYNAMIC_TYPE_FILE);
    }

    return ret;
}

static int ProcessBufferTryDecode(WOLFSSL_CTX* ctx, WOLFSSL* ssl, DerBuffer* der,
    int* keySz, word32* idx, int* resetSuites, int* keyFormat, void* heap, int devId)
{
    int ret = 0;

    (void)heap;
    (void)devId;

    if (ctx == NULL && ssl == NULL)
        return BAD_FUNC_ARG;
    if (!der || !keySz || !idx || !resetSuites || !keyFormat)
        return BAD_FUNC_ARG;

    if ((*keyFormat == 0 || *keyFormat == RSAk)) {
        /* make sure RSA key can be used */
        RsaKey  key[1];


        ret = wc_InitRsaKey_ex(key, heap, devId);
        if (ret == 0) {
            *idx = 0;
            ret = wc_RsaPrivateKeyDecode(der->buffer, idx, key, der->length);
            if (ret != 0) {
                ret = 0; /* continue trying other algorithms */
            }
            else {
                /* check that the size of the RSA key is enough */
                int minRsaSz = ssl ? ssl->options.minRsaKeySz :
                    ctx->minRsaKeySz;
                *keySz = wc_RsaEncryptSize((RsaKey*)key);
                if (*keySz < minRsaSz) {
                    ret = RSA_KEY_SIZE_E;
                    WOLFSSL_MSG("Private Key size too small");
                }

                if (ssl) {
                    ssl->buffers.keyType = rsa_sa_algo;
                    ssl->buffers.keySz = *keySz;
                }
                else {
                    ctx->privateKeyType = rsa_sa_algo;
                    ctx->privateKeySz = *keySz;
                }

                *keyFormat = RSAk;

                if (ssl && ssl->options.side == WOLFSSL_SERVER_END) {
                    ssl->options.haveStaticECC = 0;
                    *resetSuites = 1;
                }
            }

            wc_FreeRsaKey(key);
        }

        if (ret != 0)
            return ret;
    }
    if ((*keyFormat == 0 || *keyFormat == ECDSAk)) {
        /* make sure ECC key can be used */
        ecc_key  key[1];


        if (wc_ecc_init_ex(key, heap, devId) == 0) {
            *idx = 0;
            ret = wc_EccPrivateKeyDecode(der->buffer, idx, key, der->length);
            if (ret == 0) {
                /* check for minimum ECC key size and then free */
                int minKeySz = ssl ? ssl->options.minEccKeySz :
                                                        ctx->minEccKeySz;
                *keySz = wc_ecc_size(key);
                if (*keySz < minKeySz) {
                    WOLFSSL_MSG("ECC private key too small");
                    ret = ECC_KEY_SIZE_E;
                }

                *keyFormat = ECDSAk;
                if (ssl) {
                    ssl->options.haveStaticECC = 1;
                    ssl->buffers.keyType = ecc_dsa_sa_algo;
                    ssl->buffers.keySz = *keySz;
                }
                else {
                    ctx->haveStaticECC = 1;
                    ctx->privateKeyType = ecc_dsa_sa_algo;
                    ctx->privateKeySz = *keySz;
                }

                if (ssl && ssl->options.side == WOLFSSL_SERVER_END) {
                    *resetSuites = 1;
                }
            }
            else {
                ret = 0; /* continue trying other algorithms */
            }

            wc_ecc_free(key);
        }

        if (ret != 0)
            return ret;
    }
    return ret;
}

/* process the buffer buff, length sz, into ctx of format and type
   used tracks bytes consumed, userChain specifies a user cert chain
   to pass during the handshake */
int ProcessBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                         long sz, int format, int type, WOLFSSL* ssl,
                         long* used, int userChain, int verify)
{
    DerBuffer*    der = NULL;
    int           ret = 0;
    int           done = 0;
    int           keyFormat = 0;
    int           resetSuites = 0;
    void*         heap = wolfSSL_CTX_GetHeap(ctx, ssl);
    int           devId = wolfSSL_CTX_GetDevId(ctx, ssl);
    word32        idx = 0;
    int           keySz = 0;
#if (defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)) || \
     defined(HAVE_PKCS8)
    word32        algId = 0;
#endif
    EncryptedInfo  info[1];

    (void)devId;
    (void)idx;
    (void)keySz;

    if (used)
        *used = sz;     /* used bytes default to sz, PEM chain may shorten*/

    /* check args */
    if (format != WOLFSSL_FILETYPE_ASN1 && format != WOLFSSL_FILETYPE_PEM)
        return WOLFSSL_BAD_FILETYPE;

    if (ctx == NULL && ssl == NULL)
        return BAD_FUNC_ARG;


    XMEMSET(info, 0, sizeof(EncryptedInfo));
#if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
    if (ctx) {
        info->passwd_cb       = ctx->passwd_cb;
        info->passwd_userdata = ctx->passwd_userdata;
    }
#endif

    if (format == WOLFSSL_FILETYPE_PEM) {
    #ifdef WOLFSSL_PEM_TO_DER
        ret = PemToDer(buff, sz, type, &der, heap, info, &keyFormat);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
    else {
        /* ASN1 (DER) */
        int length = (int)sz;
        if (format == WOLFSSL_FILETYPE_ASN1) {
            /* get length of der (read sequence or octet string) */
            word32 inOutIdx = 0;
            if (GetSequence(buff, &inOutIdx, &length, (word32)sz) >= 0) {
                length += inOutIdx; /* include leading sequence */
            }
            /* get length using octect string (allowed for private key types) */
            else if (type == PRIVATEKEY_TYPE &&
                    GetOctetString(buff, &inOutIdx, &length, (word32)sz) >= 0) {
                length += inOutIdx; /* include leading oct string */
            }
            else {
                ret = ASN_PARSE_E;
            }
        }

        info->consumed = length;

        if (ret == 0) {
            ret = AllocDer(&der, (word32)length, type, heap);
            if (ret == 0) {
                XMEMCPY(der->buffer, buff, length);
            }

        #ifdef HAVE_PKCS8
            /* if private key try and remove PKCS8 header */
            if (type == PRIVATEKEY_TYPE) {
                if ((ret = ToTraditional_ex(der->buffer, der->length,
                                                                 &algId)) > 0) {
                    /* Found PKCS8 header */
                    /* ToTraditional_ex moves buff and returns adjusted length */
                    der->length = ret;
                    keyFormat = algId;
                }
                ret = 0; /* failures should be ignored */
            }
        #endif
        }
    }

    if (used) {
        *used = info->consumed;
    }

    /* process user chain */
    if (ret >= 0) {
        /* Chain should have server cert first, then intermediates, then root.
         * First certificate in chain is processed below after ProcessUserChain
         *   and is loaded into ssl->buffers.certificate.
         * Remainder are processed using ProcessUserChain and are loaded into
         *   ssl->buffers.certChain. */
        if (userChain) {
            ret = ProcessUserChain(ctx, buff, sz, format, type, ssl, used, info,
                                   verify);
            if (ret == ASN_NO_PEM_HEADER) { /* Additional chain is optional */
                unsigned long pemErr;
                CLEAR_ASN_NO_PEM_HEADER_ERROR(pemErr);
                ret = 0;
            }
        }
    }

    /* info is only used for private key with DER or PEM, so free now */
    if (ret < 0 || type != PRIVATEKEY_TYPE) {
    }

    /* check for error */
    if (ret < 0) {
        FreeDer(&der);
        done = 1;
    }

    if (done == 1) {
        /* No operation, just skip the next section */
    }
    /* Handle DER owner */
    else if (type == CA_TYPE) {
        if (ctx == NULL) {
            WOLFSSL_MSG("Need context for CA load");
            FreeDer(&der);
            return BAD_FUNC_ARG;
        }
        /* verify CA unless user set to no verify */
        ret = AddCA(ctx->cm, &der, WOLFSSL_USER_CA, verify);
        done = 1;
    }
#ifdef WOLFSSL_TRUST_PEER_CERT
    else if (type == TRUSTED_PEER_TYPE) {
        /* add trusted peer cert. der is freed within */
        if (ctx != NULL)
            ret = AddTrustedPeer(ctx->cm, &der, !ctx->verifyNone);
        else
            ret = AddTrustedPeer(SSL_CM(ssl), &der, !ssl->options.verifyNone);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error adding trusted peer");
        }
        done = 1;
    }
#endif /* WOLFSSL_TRUST_PEER_CERT */
    else if (type == CERT_TYPE) {
        if (ssl) {
             /* Make sure previous is free'd */
            if (ssl->buffers.weOwnCert) {
                FreeDer(&ssl->buffers.certificate);
            #ifdef KEEP_OUR_CERT
                wolfSSL_X509_free(ssl->ourCert);
                ssl->ourCert = NULL;
            #endif
            }
            ssl->buffers.certificate = der;
        #ifdef KEEP_OUR_CERT
            ssl->keepCert = 1; /* hold cert for ssl lifetime */
        #endif
            ssl->buffers.weOwnCert = 1;
        }
        else if (ctx) {
            FreeDer(&ctx->certificate); /* Make sure previous is free'd */
        #ifdef KEEP_OUR_CERT
            if (ctx->ourCert) {
                if (ctx->ownOurCert)
                    wolfSSL_X509_free(ctx->ourCert);
                ctx->ourCert = NULL;
            }
        #endif
            ctx->certificate = der;
        }
    }
    else if (type == PRIVATEKEY_TYPE) {
        if (ssl) {
             /* Make sure previous is free'd */
            if (ssl->buffers.weOwnKey) {
                FreeDer(&ssl->buffers.key);
            }
            ssl->buffers.key = der;
            ssl->buffers.weOwnKey = 1;
        }
        else if (ctx) {
            FreeDer(&ctx->privateKey);
            ctx->privateKey = der;
        }
    }
    else {
        FreeDer(&der);
        return WOLFSSL_BAD_CERTTYPE;
    }

    if (done == 1) {
        /* No operation, just skip the next section */
    }
    else if (type == PRIVATEKEY_TYPE) {
        ret = ProcessBufferTryDecode(ctx, ssl, der, &keySz, &idx, &resetSuites,
                &keyFormat, heap, devId);

    #if defined(WOLFSSL_ENCRYPTED_KEYS) && !defined(NO_PWDBASED)
        /* for WOLFSSL_FILETYPE_PEM, PemToDer manages the decryption */
        /* If private key type PKCS8 header wasn't already removed (algoId == 0) */
        if ((ret != 0 || keyFormat == 0)
            && format != WOLFSSL_FILETYPE_PEM && info->passwd_cb && algId == 0)
        {
            int   passwordSz = NAME_SZ;
            char  password[NAME_SZ];
            /* get password */
            ret = info->passwd_cb(password, passwordSz, PEM_PASS_READ,
                info->passwd_userdata);
            if (ret >= 0) {
                passwordSz = ret;

                /* PKCS8 decrypt */
                ret = ToTraditionalEnc(der->buffer, der->length,
                                       password, passwordSz, &algId);
                if (ret >= 0) {
                    der->length = ret;
                }
                /* ignore failures and try parsing as unencrypted */

                ForceZero(password, passwordSz);
            }

            ret = ProcessBufferTryDecode(ctx, ssl, der, &keySz, &idx,
                &resetSuites, &keyFormat, heap, devId);
        }
    #endif /* WOLFSSL_ENCRYPTED_KEYS && !NO_PWDBASED */


        if (ret != 0)
            return ret;
        if (keyFormat == 0) {
            WOLFSSL_ERROR(WOLFSSL_BAD_FILE);
            return WOLFSSL_BAD_FILE;
        }

        (void)devId;
    }
    else if (type == CERT_TYPE) {
        DecodedCert  cert[1];


        WOLFSSL_MSG("Checking cert signature type");
        InitDecodedCert(cert, der->buffer, der->length, heap);

        if (DecodeToKey(cert, 0) < 0) {
            WOLFSSL_MSG("Decode to key failed");
            FreeDecodedCert(cert);
            return WOLFSSL_BAD_FILE;
        }

        if (ssl && ssl->options.side == WOLFSSL_SERVER_END) {
            resetSuites = 1;
        }
        if (ssl && ssl->ctx->haveECDSAsig) {
            WOLFSSL_MSG("SSL layer setting cert, CTX had ECDSA, turning off");
            ssl->options.haveECDSAsig = 0;   /* may turn back on next */
        }

        switch (cert->signatureOID) {
            case CTC_SHAwECDSA:
            case CTC_SHA256wECDSA:
            case CTC_SHA384wECDSA:
            case CTC_SHA512wECDSA:
            case CTC_ED25519:
            case CTC_ED448:
                WOLFSSL_MSG("ECDSA/ED25519/ED448 cert signature");
                if (ssl)
                    ssl->options.haveECDSAsig = 1;
                else if (ctx)
                    ctx->haveECDSAsig = 1;
                break;
            case CTC_FALCON_LEVEL1:
            case CTC_FALCON_LEVEL5:
                WOLFSSL_MSG("Falcon cert signature");
                if (ssl)
                    ssl->options.haveFalconSig = 1;
                else if (ctx)
                    ctx->haveFalconSig = 1;
                break;
            default:
                WOLFSSL_MSG("Not ECDSA cert signature");
                break;
        }

        if (ssl) {
            ssl->pkCurveOID = cert->pkCurveOID;
        #ifndef WC_STRICT_SIG
            if (cert->keyOID == ECDSAk) {
                ssl->options.haveECC = 1;
            }
            else if (cert->keyOID == RSAk) {
                ssl->options.haveRSA = 1;
            }
        #else
            ssl->options.haveECC = ssl->options.haveECDSAsig;
        #endif
        }
        else if (ctx) {
            ctx->pkCurveOID = cert->pkCurveOID;
        #ifndef WC_STRICT_SIG
            if (cert->keyOID == ECDSAk) {
                ctx->haveECC = 1;
            }
            else if (cert->keyOID == RSAk) {
                ctx->haveRSA = 1;
            }
        #else
            ctx->haveECC = ctx->haveECDSAsig;
        #endif
        }

        /* check key size of cert unless specified not to */
        switch (cert->keyOID) {
            case RSAk:
                /* Determine RSA key size by parsing public key */
                idx = 0;
                ret = wc_RsaPublicKeyDecode_ex(cert->publicKey, &idx,
                    cert->pubKeySize, NULL, (word32*)&keySz, NULL, NULL);
                if (ret < 0)
                    break;

                if (ssl && !ssl->options.verifyNone) {
                    if (ssl->options.minRsaKeySz < 0 ||
                          keySz < (int)ssl->options.minRsaKeySz) {
                        ret = RSA_KEY_SIZE_E;
                        WOLFSSL_MSG("Certificate RSA key size too small");
                    }
                }
                else if (ctx && !ctx->verifyNone) {
                    if (ctx->minRsaKeySz < 0 ||
                                  keySz < (int)ctx->minRsaKeySz) {
                        ret = RSA_KEY_SIZE_E;
                        WOLFSSL_MSG("Certificate RSA key size too small");
                    }
                }
                break;
            case ECDSAk:
                /* Determine ECC key size based on curve */
                keySz = wc_ecc_get_curve_size_from_id(
                    wc_ecc_get_oid(cert->pkCurveOID, NULL, NULL));

                if (ssl && !ssl->options.verifyNone) {
                    if (ssl->options.minEccKeySz < 0 ||
                          keySz < (int)ssl->options.minEccKeySz) {
                        ret = ECC_KEY_SIZE_E;
                        WOLFSSL_MSG("Certificate ECC key size error");
                    }
                }
                else if (ctx && !ctx->verifyNone) {
                    if (ctx->minEccKeySz < 0 ||
                                  keySz < (int)ctx->minEccKeySz) {
                        ret = ECC_KEY_SIZE_E;
                        WOLFSSL_MSG("Certificate ECC key size error");
                    }
                }
                break;

            default:
                WOLFSSL_MSG("No key size check done on certificate");
                break; /* do no check if not a case for the key */
        }


        FreeDecodedCert(cert);

        if (ret != 0) {
            done = 1;
        }
    }

    if (done == 1) {
    #if !defined(NO_WOLFSSL_CM_VERIFY)
        if ((type == CA_TYPE) || (type == CERT_TYPE)) {
            /* Call to over-ride status */
            if ((ctx != NULL) && (ctx->cm != NULL) &&
                (ctx->cm->verifyCallback != NULL)) {
                ret = CM_VerifyBuffer_ex(ctx->cm, buff,
                        sz, format, (ret == WOLFSSL_SUCCESS ? 0 : ret));
            }
        }
    #endif /* NO_WOLFSSL_CM_VERIFY */

        return ret;
    }


    if (ssl && resetSuites) {
        word16 havePSK = 0;
        word16 haveRSA = 0;

            haveRSA = 1;
            keySz = ssl->buffers.keySz;

        /* let's reset suites */
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA,
                   havePSK, ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, ssl->options.haveStaticECC,
                   ssl->options.haveFalconSig, ssl->options.haveAnon,
                   ssl->options.side);
    }

    return WOLFSSL_SUCCESS;
}


/* CA PEM file for verification, may have multiple/chain certs to process */
static int ProcessChainBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                        long sz, int format, int type, WOLFSSL* ssl, int verify)
{
    long used   = 0;
    int  ret    = 0;
    int  gotOne = 0;

    WOLFSSL_MSG("Processing CA PEM file");
    while (used < sz) {
        long consumed = 0;

        ret = ProcessBuffer(ctx, buff + used, sz - used, format, type, ssl,
                            &consumed, 0, verify);

        if (ret < 0) {

            if (consumed > 0) { /* Made progress in file */
                WOLFSSL_ERROR(ret);
                WOLFSSL_MSG("CA Parse failed, with progress in file.");
                WOLFSSL_MSG("Search for other certs in file");
            }
            else {
                WOLFSSL_MSG("CA Parse failed, no progress in file.");
                WOLFSSL_MSG("Do not continue search for other certs in file");
                break;
            }
        }
        else {
            WOLFSSL_MSG("   Processed a CA");
            gotOne = 1;
        }
        used += consumed;
    }

    if (gotOne) {
        WOLFSSL_MSG("Processed at least one valid CA. Other stuff OK");
        return WOLFSSL_SUCCESS;
    }
    return ret;
}


static WC_INLINE WOLFSSL_METHOD* cm_pick_method(void)
{
        #if defined(WOLFSSL_ALLOW_SSLV3)
            return wolfSSLv3_client_method();
        #elif defined(WOLFSSL_ALLOW_TLSV10)
            return wolfTLSv1_client_method();
        #else
            return wolfTLSv1_1_client_method();
        #endif
}


/* like load verify locations, 1 for success, < 0 for error */
int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER* cm,
                                   const unsigned char* in, long sz, int format)
{
    int ret = WOLFSSL_FATAL_ERROR;
    WOLFSSL_CTX* tmp;

    WOLFSSL_ENTER("wolfSSL_CertManagerLoadCABuffer");

    if (cm == NULL) {
        WOLFSSL_MSG("No CertManager error");
        return ret;
    }
    tmp = wolfSSL_CTX_new(cm_pick_method());

    if (tmp == NULL) {
        WOLFSSL_MSG("CTX new failed");
        return ret;
    }

    /* for tmp use */
    wolfSSL_CertManagerFree(tmp->cm);
    tmp->cm = cm;

    ret = wolfSSL_CTX_load_verify_buffer(tmp, in, sz, format);

    /* don't loose our good one */
    tmp->cm = NULL;
    wolfSSL_CTX_free(tmp);

    return ret;
}


/* turn on CRL if off and compiled in, set options */
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm, int options)
{
    int ret = WOLFSSL_SUCCESS;

    (void)options;

    WOLFSSL_ENTER("wolfSSL_CertManagerEnableCRL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

        ret = NOT_COMPILED_IN;

    return ret;
}


int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER("wolfSSL_CertManagerDisableCRL");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->crlEnabled = 0;

    return WOLFSSL_SUCCESS;
}

#ifndef NO_WOLFSSL_CM_VERIFY
void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm, VerifyCallback vc)
{
    WOLFSSL_ENTER("wolfSSL_CertManagerSetVerify");
    if (cm == NULL)
        return;

    cm->verifyCallback = vc;
}
#endif /* NO_WOLFSSL_CM_VERIFY */

/* Verify the certificate, WOLFSSL_SUCCESS for ok, < 0 for error */
int CM_VerifyBuffer_ex(WOLFSSL_CERT_MANAGER* cm, const byte* buff,
                                    long sz, int format, int err_val)
{
    int ret = 0;
    DerBuffer* der = NULL;
    DecodedCert  cert[1];

    WOLFSSL_ENTER("wolfSSL_CertManagerVerifyBuffer");


    if (format == WOLFSSL_FILETYPE_PEM) {
#ifdef WOLFSSL_PEM_TO_DER
        ret = PemToDer(buff, sz, CERT_TYPE, &der, cm->heap, NULL, NULL);
        if (ret != 0) {
            FreeDer(&der);
            return ret;
        }
        InitDecodedCert(cert, der->buffer, der->length, cm->heap);
#else
        ret = NOT_COMPILED_IN;
#endif
    }
    else {
        InitDecodedCert(cert, buff, (word32)sz, cm->heap);
    }

    if (ret == 0)
        ret = ParseCertRelative(cert, CERT_TYPE, 1, cm);



#ifndef NO_WOLFSSL_CM_VERIFY
    /* if verify callback has been set */
    if (cm->verifyCallback) {
        buffer certBuf;
        ProcPeerCertArgs  args[1];

        certBuf.buffer = (byte*)buff;
        certBuf.length = (unsigned int)sz;
        XMEMSET(args, 0, sizeof(ProcPeerCertArgs));

        args->totalCerts = 1;
        args->certs = &certBuf;
        args->dCert = cert;
        args->dCertInit = 1;

        if (err_val != 0) {
            ret = err_val;
        }
        ret = DoVerifyCallback(cm, NULL, ret, args);
    }
#else
    (void)err_val;
#endif

    FreeDecodedCert(cert);
    FreeDer(&der);

    return ret == 0 ? WOLFSSL_SUCCESS : ret;
}

/* Verify the certificate, WOLFSSL_SUCCESS for ok, < 0 for error */
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm, const byte* buff,
                                    long sz, int format)
{
    return CM_VerifyBuffer_ex(cm, buff, sz, format, 0);
}

/* turn on OCSP if off and compiled in, set options */
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm, int options)
{
    int ret = WOLFSSL_SUCCESS;

    (void)options;

    WOLFSSL_ENTER("wolfSSL_CertManagerEnableOCSP");
    if (cm == NULL)
        return BAD_FUNC_ARG;

        ret = NOT_COMPILED_IN;

    return ret;
}


int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER("wolfSSL_CertManagerDisableOCSP");
    if (cm == NULL)
        return BAD_FUNC_ARG;

    cm->ocspEnabled = 0;

    return WOLFSSL_SUCCESS;
}

/* turn on OCSP Stapling if off and compiled in, set options */
int wolfSSL_CertManagerEnableOCSPStapling(WOLFSSL_CERT_MANAGER* cm)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_CertManagerEnableOCSPStapling");

    if (cm == NULL)
        return BAD_FUNC_ARG;

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    cm->ocspStaplingEnabled = 1;
#else
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

int wolfSSL_CertManagerDisableOCSPStapling(WOLFSSL_CERT_MANAGER* cm)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_CertManagerDisableOCSPStapling");

    if (cm == NULL)
        return BAD_FUNC_ARG;

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    cm->ocspStaplingEnabled = 0;
#else
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

/* require OCSP stapling response */
int wolfSSL_CertManagerEnableOCSPMustStaple(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CertManagerEnableOCSPMustStaple");

    if (cm == NULL)
        return BAD_FUNC_ARG;

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
        cm->ocspMustStaple = 1;
    ret = WOLFSSL_SUCCESS;
#else
    ret = NOT_COMPILED_IN;
#endif

    return ret;
}

int wolfSSL_CertManagerDisableOCSPMustStaple(WOLFSSL_CERT_MANAGER* cm)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CertManagerDisableOCSPMustStaple");

    if (cm == NULL)
        return BAD_FUNC_ARG;

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
        cm->ocspMustStaple = 0;
    ret = WOLFSSL_SUCCESS;
#else
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}


/* macro to get verify settings for AddCA */
#define GET_VERIFY_SETTING_CTX(ctx) \
    ((ctx) && (ctx)->verifyNone ? NO_VERIFY : VERIFY)
#define GET_VERIFY_SETTING_SSL(ssl) \
    ((ssl)->options.verifyNone ? NO_VERIFY : VERIFY)

#ifndef NO_FILESYSTEM

/* process a file with name fname into ctx of format and type
   userChain specifies a user certificate chain to pass during handshake */
int ProcessFile(WOLFSSL_CTX* ctx, const char* fname, int format, int type,
                WOLFSSL* ssl, int userChain, WOLFSSL_CRL* crl, int verify)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE  file;
    void*  heapHint = wolfSSL_CTX_GetHeap(ctx, ssl);
#ifndef NO_CODING
    const char* header = NULL;
    const char* footer = NULL;
#endif

    (void)crl;
    (void)heapHint;

    if (fname == NULL) return WOLFSSL_BAD_FILE;

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) return WOLFSSL_BAD_FILE;
    if (XFSEEK(file, 0, XSEEK_END) != 0) {
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > MAX_WOLFSSL_FILE_SIZE || sz <= 0) {
        WOLFSSL_MSG("ProcessFile file size error");
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    if (sz > (long)sizeof(staticBuffer)) {
        WOLFSSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*)XMALLOC(sz, heapHint, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ((size_t)XFREAD(myBuffer, 1, sz, file) != (size_t)sz)
        ret = WOLFSSL_BAD_FILE;
    else {
        /* Try to detect type by parsing cert header and footer */
        if (type == DETECT_CERT_TYPE) {
#ifndef NO_CODING
            if (wc_PemGetHeaderFooter(CA_TYPE, &header, &footer) == 0 &&
               (XSTRNSTR((char*)myBuffer, header, (int)sz) != NULL)) {
                type = CA_TYPE;
            }
            else if (wc_PemGetHeaderFooter(CERT_TYPE, &header, &footer) == 0 &&
                    (XSTRNSTR((char*)myBuffer, header, (int)sz) != NULL)) {
                type = CERT_TYPE;
            }
            else
#endif
            {
                WOLFSSL_MSG("Failed to detect certificate type");
                if (dynamic)
                    XFREE(myBuffer, heapHint, DYNAMIC_TYPE_FILE);
                XFCLOSE(file);
                return WOLFSSL_BAD_CERTTYPE;
            }
        }
        if ((type == CA_TYPE || type == TRUSTED_PEER_TYPE)
                                          && format == WOLFSSL_FILETYPE_PEM) {
            ret = ProcessChainBuffer(ctx, myBuffer, sz, format, type, ssl,
                                     verify);
        }
        else
            ret = ProcessBuffer(ctx, myBuffer, sz, format, type, ssl, NULL,
                                userChain, verify);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, heapHint, DYNAMIC_TYPE_FILE);

    return ret;
}

/* loads file then loads each file in path, no c_rehash */
int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx, const char* file,
                                     const char* path, word32 flags)
{
    int ret = WOLFSSL_SUCCESS;
#ifndef NO_WOLFSSL_DIR
    int fileRet;
    int successCount = 0;
    int failCount = 0;
#endif
    int verify;

    WOLFSSL_MSG("wolfSSL_CTX_load_verify_locations_ex");

    if (ctx == NULL || (file == NULL && path == NULL)) {
        return WOLFSSL_FAILURE;
    }

    verify = GET_VERIFY_SETTING_CTX(ctx);
    if (flags & WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY)
        verify = VERIFY_SKIP_DATE;

    if (file) {
        ret = ProcessFile(ctx, file, WOLFSSL_FILETYPE_PEM, CA_TYPE, NULL, 0,
                          NULL, verify);
#ifndef NO_WOLFSSL_DIR
        if (ret == WOLFSSL_SUCCESS)
            successCount++;
#endif
#if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
        ret = wolfSSL_CTX_trust_peer_cert(ctx, file, WOLFSSL_FILETYPE_PEM);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_CTX_trust_peer_cert error");
        }
#endif
    }

    if (ret == WOLFSSL_SUCCESS && path) {
#ifndef NO_WOLFSSL_DIR
        char* name = NULL;
        ReadDirCtx readCtx[1];

        /* try to load each regular file in path */
        fileRet = wc_ReadDirFirst(readCtx, path, &name);
        while (fileRet == 0 && name) {
            WOLFSSL_MSG(name); /* log file name */
            ret = ProcessFile(ctx, name, WOLFSSL_FILETYPE_PEM, CA_TYPE,
                              NULL, 0, NULL, verify);
            if (ret != WOLFSSL_SUCCESS) {
                /* handle flags for ignoring errors, skipping expired certs or
                   by PEM certificate header error */
                if ( (flags & WOLFSSL_LOAD_FLAG_IGNORE_ERR) ||
                    ((flags & WOLFSSL_LOAD_FLAG_PEM_CA_ONLY) &&
                       (ret == ASN_NO_PEM_HEADER))) {
                    /* Do not fail here if a certificate fails to load,
                       continue to next file */
                    unsigned long err;
                    CLEAR_ASN_NO_PEM_HEADER_ERROR(err);
                }
                else {
                    WOLFSSL_ERROR(ret);
                    WOLFSSL_MSG("Load CA file failed, continuing");
                    failCount++;
                }
            }
            else {
    #if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
                ret = wolfSSL_CTX_trust_peer_cert(ctx, file, WOLFSSL_FILETYPE_PEM);
                if (ret != WOLFSSL_SUCCESS) {
                    WOLFSSL_MSG("wolfSSL_CTX_trust_peer_cert error. Ignoring"
                            "this error.");
                }
    #endif
                successCount++;
            }
            fileRet = wc_ReadDirNext(readCtx, path, &name);
        }
        wc_ReadDirClose(readCtx);

        /* pass directory read failure to response code */
        if (fileRet != WC_READDIR_NOFILE) {
            ret = fileRet;
        }
        /* report failure if no files were loaded or there were failures */
        else if (successCount == 0 || failCount > 0) {
            /* use existing error code if exists */
            {
                ret = WOLFSSL_FAILURE;
            }
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }

#else
        ret = NOT_COMPILED_IN;
        (void)flags;
#endif
    }

    return ret;
}

WOLFSSL_ABI
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                     const char* path)
{
    int ret = wolfSSL_CTX_load_verify_locations_ex(ctx, file, path,
        WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);

    return WS_RETURN_CODE(ret,WOLFSSL_FAILURE);
}


#ifdef WOLFSSL_TRUST_PEER_CERT
/* Used to specify a peer cert to match when connecting
    ctx : the ctx structure to load in peer cert
    file: the string name of cert file
    type: type of format such as PEM/DER
 */
int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX* ctx, const char* file, int type)
{
    WOLFSSL_ENTER("wolfSSL_CTX_trust_peer_cert");

    if (ctx == NULL || file == NULL) {
        return WOLFSSL_FAILURE;
    }

    return ProcessFile(ctx, file, type, TRUSTED_PEER_TYPE, NULL, 0, NULL,
                       GET_VERIFY_SETTING_CTX(ctx));
}

int wolfSSL_trust_peer_cert(WOLFSSL* ssl, const char* file, int type)
{
    WOLFSSL_ENTER("wolfSSL_trust_peer_cert");

    if (ssl == NULL || file == NULL) {
        return WOLFSSL_FAILURE;
    }

    return ProcessFile(NULL, file, type, TRUSTED_PEER_TYPE, ssl, 0, NULL,
                       GET_VERIFY_SETTING_SSL(ssl));
}
#endif /* WOLFSSL_TRUST_PEER_CERT */


/* Verify the certificate, WOLFSSL_SUCCESS for ok, < 0 for error */
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* fname,
                             int format)
{
    int    ret = WOLFSSL_FATAL_ERROR;
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    long   sz = 0;
    XFILE  file = XFOPEN(fname, "rb");

    WOLFSSL_ENTER("wolfSSL_CertManagerVerify");

    if (file == XBADFILE) return WOLFSSL_BAD_FILE;
    if(XFSEEK(file, 0, XSEEK_END) != 0) {
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > MAX_WOLFSSL_FILE_SIZE || sz <= 0) {
        WOLFSSL_MSG("CertManagerVerify file size error");
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    if (sz > (long)sizeof(staticBuffer)) {
        WOLFSSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, cm->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ((size_t)XFREAD(myBuffer, 1, sz, file) != (size_t)sz)
        ret = WOLFSSL_BAD_FILE;
    else
        ret = wolfSSL_CertManagerVerifyBuffer(cm, myBuffer, sz, format);

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, cm->heap, DYNAMIC_TYPE_FILE);

    return ret;
}

/* like load verify locations, 1 for success, < 0 for error */
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* file,
                             const char* path)
{
    int ret = WOLFSSL_FATAL_ERROR;
    WOLFSSL_CTX* tmp;

    WOLFSSL_ENTER("wolfSSL_CertManagerLoadCA");

    if (cm == NULL) {
        WOLFSSL_MSG("No CertManager error");
        return ret;
    }
    tmp = wolfSSL_CTX_new(cm_pick_method());

    if (tmp == NULL) {
        WOLFSSL_MSG("CTX new failed");
        return ret;
    }

    /* for tmp use */
    wolfSSL_CertManagerFree(tmp->cm);
    tmp->cm = cm;

    ret = wolfSSL_CTX_load_verify_locations(tmp, file, path);

    /* don't lose our good one */
    tmp->cm = NULL;
    wolfSSL_CTX_free(tmp);

    return ret;
}


#endif /* NO_FILESYSTEM */



#ifndef NO_FILESYSTEM


#ifdef WOLFSSL_DER_LOAD

/* Add format parameter to allow DER load of CA files */
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                          int format)
{
    WOLFSSL_ENTER("wolfSSL_CTX_der_load_verify_locations");
    if (ctx == NULL || file == NULL)
        return WOLFSSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_TYPE, NULL, 0, NULL,
                    GET_VERIFY_SETTING_CTX(ctx)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

#endif /* WOLFSSL_DER_LOAD */



WOLFSSL_ABI
int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file,
                                     int format)
{
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_file");

    if (ProcessFile(ctx, file, format, CERT_TYPE, NULL, 0, NULL,
                    GET_VERIFY_SETTING_CTX(ctx)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


WOLFSSL_ABI
int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file,
                                    int format)
{
    WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey_file");

    if (ProcessFile(ctx, file, format, PRIVATEKEY_TYPE, NULL, 0, NULL,
                    GET_VERIFY_SETTING_CTX(ctx)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


#endif /* NO_FILESYSTEM */


/* Sets the max chain depth when verifying a certificate chain. Default depth
 * is set to MAX_CHAIN_DEPTH.
 *
 * ctx   WOLFSSL_CTX structure to set depth in
 * depth max depth
 */
void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx, int depth) {
    WOLFSSL_ENTER("wolfSSL_CTX_set_verify_depth");

    if (ctx == NULL || depth < 0 || depth > MAX_CHAIN_DEPTH) {
        WOLFSSL_MSG("Bad depth argument, too large or less than 0");
        return;
    }

    ctx->verifyDepth = (byte)depth;
}


/* get cert chaining depth using ssl struct */
long wolfSSL_get_verify_depth(WOLFSSL* ssl)
{
    if(ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    return MAX_CHAIN_DEPTH;
}


/* get cert chaining depth using ctx struct */
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    return MAX_CHAIN_DEPTH;
}


#ifndef NO_FILESYSTEM


WOLFSSL_ABI
int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX* ctx, const char* file)
{
    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_file");

    if (ProcessFile(ctx, file, WOLFSSL_FILETYPE_PEM, CERT_TYPE, NULL, 1, NULL,
                    GET_VERIFY_SETTING_CTX(ctx)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

   return WOLFSSL_FAILURE;
}


int wolfSSL_CTX_use_certificate_chain_file_format(WOLFSSL_CTX* ctx,
                                                  const char* file, int format)
{
    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_file_format");

    if (ProcessFile(ctx, file, format, CERT_TYPE, NULL, 1, NULL,
                    GET_VERIFY_SETTING_CTX(ctx)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

   return WOLFSSL_FAILURE;
}



/* server Diffie-Hellman parameters */
static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
                                        const char* fname, int format)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE  file;

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) return WOLFSSL_BAD_FILE;
    if(XFSEEK(file, 0, XSEEK_END) != 0) {
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > MAX_WOLFSSL_FILE_SIZE || sz <= 0) {
        WOLFSSL_MSG("SetTmpDH file size error");
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    if (sz > (long)sizeof(staticBuffer)) {
        WOLFSSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return WOLFSSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ((size_t)XFREAD(myBuffer, 1, sz, file) != (size_t)sz)
        ret = WOLFSSL_BAD_FILE;
    else {
        if (ssl)
            ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
        else
            ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }

    XFCLOSE(file);
    if (dynamic)
        XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

    return ret;
}

/* server Diffie-Hellman parameters */
int wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* fname, int format)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return wolfSSL_SetTmpDH_file_wrapper(ssl->ctx, ssl, fname, format);
}


/* server Diffie-Hellman parameters */
int wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* fname, int format)
{
    return wolfSSL_SetTmpDH_file_wrapper(ctx, NULL, fname, format);
}


#endif /* NO_FILESYSTEM */

#ifndef NO_CHECK_PRIVATE_KEY
/* Check private against public in certificate for match
 *
 * Returns WOLFSSL_SUCCESS on good private key
 *         WOLFSSL_FAILURE if mismatched */
static int check_cert_key(DerBuffer* cert, DerBuffer* key, void* heap,
    int devId, int isKeyLabel, int isKeyId)
{
    DecodedCert  der[1];
    word32 size;
    byte*  buff;
    int    ret = WOLFSSL_FAILURE;

    WOLFSSL_ENTER("check_cert_key");

    if (cert == NULL || key == NULL) {
        return WOLFSSL_FAILURE;
    }


    size = cert->length;
    buff = cert->buffer;
    InitDecodedCert(der, buff, size, heap);
    if (ParseCertRelative(der, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        FreeDecodedCert(der);
        return WOLFSSL_FAILURE;
    }

    size = key->length;
    buff = key->buffer;
    {
        ret = wc_CheckPrivateKeyCert(buff, size, der);
        ret = (ret == 1) ? WOLFSSL_SUCCESS: WOLFSSL_FAILURE;
    }
    FreeDecodedCert(der);

    (void)devId;
    (void)isKeyLabel;
    (void)isKeyId;

    return ret;
}

/* Check private against public in certificate for match
 *
 * ctx  WOLFSSL_CTX structure to check private key in
 *
 * Returns WOLFSSL_SUCCESS on good private key
 *         WOLFSSL_FAILURE if mismatched. */
int wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return WOLFSSL_FAILURE;
    }
    return check_cert_key(ctx->certificate, ctx->privateKey, ctx->heap,
        ctx->privateKeyDevId, ctx->privateKeyLabel, ctx->privateKeyId);
}
#endif /* !NO_CHECK_PRIVATE_KEY */





int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, const unsigned char* der,
                                 int derSz)
{
    long idx;

    WOLFSSL_ENTER("wolfSSL_use_certificate_ASN1");
    if (der != NULL && ssl != NULL) {
        if (ProcessBuffer(NULL, der, derSz, WOLFSSL_FILETYPE_ASN1, CERT_TYPE,
                ssl, &idx, 0, GET_VERIFY_SETTING_SSL(ssl)) == WOLFSSL_SUCCESS) {
            return WOLFSSL_SUCCESS;
        }
    }

    (void)idx;
    return WOLFSSL_FAILURE;
}

#ifndef NO_FILESYSTEM

WOLFSSL_ABI
int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format)
{
    WOLFSSL_ENTER("wolfSSL_use_certificate_file");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ProcessFile(ssl->ctx, file, format, CERT_TYPE,
                ssl, 0, NULL, GET_VERIFY_SETTING_SSL(ssl)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


WOLFSSL_ABI
int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format)
{
    WOLFSSL_ENTER("wolfSSL_use_PrivateKey_file");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE,
                ssl, 0, NULL, GET_VERIFY_SETTING_SSL(ssl)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


WOLFSSL_ABI
int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char* file)
{
    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_use_certificate_chain_file");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ProcessFile(ssl->ctx, file, WOLFSSL_FILETYPE_PEM, CERT_TYPE,
               ssl, 1, NULL, GET_VERIFY_SETTING_SSL(ssl)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }

   return WOLFSSL_FAILURE;
}

int wolfSSL_use_certificate_chain_file_format(WOLFSSL* ssl, const char* file,
                                              int format)
{
    /* process up to MAX_CHAIN_DEPTH plus subject cert */
    WOLFSSL_ENTER("wolfSSL_use_certificate_chain_file_format");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 1,
                    NULL, GET_VERIFY_SETTING_SSL(ssl)) == WOLFSSL_SUCCESS) {
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* !NO_FILESYSTEM */


/* Set Temp CTX EC-DHE size in octets, can be 14 - 66 (112 - 521 bit) */
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* if 0 then get from loaded private key */
    if (sz == 0) {
        /* applies only to ECDSA */
        if (ctx->privateKeyType != ecc_dsa_sa_algo)
            return WOLFSSL_SUCCESS;

        if (ctx->privateKeySz == 0) {
            WOLFSSL_MSG("Must set private key/cert first");
            return BAD_FUNC_ARG;
        }

        sz = (word16)ctx->privateKeySz;
    }

    /* check size */
    if (sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ctx->eccTempKeySz = sz;

    return WOLFSSL_SUCCESS;
}


/* Set Temp SSL EC-DHE size in octets, can be 14 - 66 (112 - 521 bit) */
int wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    /* check size */
    if (sz < ECC_MINSIZE || sz > ECC_MAXSIZE)
        return BAD_FUNC_ARG;

    ssl->eccTempKeySz = sz;

    return WOLFSSL_SUCCESS;
}




typedef struct {
    byte verifyPeer:1;
    byte verifyNone:1;
    byte failNoCert:1;
    byte failNoCertxPSK:1;
    byte verifyPostHandshake:1;
} SetVerifyOptions;

static SetVerifyOptions ModeToVerifyOptions(int mode)
{
    SetVerifyOptions opts;
    XMEMSET(&opts, 0, sizeof(SetVerifyOptions));

    if (mode != WOLFSSL_VERIFY_DEFAULT) {
        opts.verifyNone = (mode == WOLFSSL_VERIFY_NONE);
        if (!opts.verifyNone) {
            opts.verifyPeer =
                    (mode & WOLFSSL_VERIFY_PEER) != 0;
            opts.failNoCertxPSK =
                    (mode & WOLFSSL_VERIFY_FAIL_EXCEPT_PSK) != 0;
            opts.failNoCert =
                    (mode & WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0;
        }
    }

    return opts;
}

WOLFSSL_ABI
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode, VerifyCallback vc)
{
    SetVerifyOptions opts;

    WOLFSSL_ENTER("wolfSSL_CTX_set_verify");
    if (ctx == NULL)
        return;

    opts = ModeToVerifyOptions(mode);

    ctx->verifyNone     = opts.verifyNone;
    ctx->verifyPeer     = opts.verifyPeer;
    ctx->failNoCert     = opts.failNoCert;
    ctx->failNoCertxPSK = opts.failNoCertxPSK;

    ctx->verifyCallback = vc;
}



void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback vc)
{
    SetVerifyOptions opts;

    WOLFSSL_ENTER("wolfSSL_set_verify");
    if (ssl == NULL)
        return;

    opts = ModeToVerifyOptions(mode);

    ssl->options.verifyNone = opts.verifyNone;
    ssl->options.verifyPeer = opts.verifyPeer;
    ssl->options.failNoCert = opts.failNoCert;
    ssl->options.failNoCertxPSK = opts.failNoCertxPSK;

    ssl->verifyCallback = vc;
}

void wolfSSL_set_verify_result(WOLFSSL *ssl, long v)
{
    WOLFSSL_ENTER("wolfSSL_set_verify_result");

    if (ssl == NULL)
        return;

    (void)v;
    WOLFSSL_STUB("wolfSSL_set_verify_result");
}


/* store user ctx for verify callback */
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCertCbCtx");
    if (ssl)
        ssl->verifyCbCtx = ctx;
}


/* store user ctx for verify callback */
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCertCbCtx");
    if (ctx)
        ctx->verifyCbCtx = userCtx;
}


/* store context CA Cache addition callback */
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb)
{
    if (ctx && ctx->cm)
        ctx->cm->caCacheCallback = cb;
}


#if defined(PERSIST_CERT_CACHE)

#if !defined(NO_FILESYSTEM)

/* Persist cert cache to file */
int wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER("wolfSSL_CTX_save_cert_cache");

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_SaveCertCache(ctx->cm, fname);
}


/* Persist cert cache from file */
int wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    WOLFSSL_ENTER("wolfSSL_CTX_restore_cert_cache");

    if (ctx == NULL || fname == NULL)
        return BAD_FUNC_ARG;

    return CM_RestoreCertCache(ctx->cm, fname);
}

#endif /* NO_FILESYSTEM */

/* Persist cert cache to memory */
int wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem,
                                   int sz, int* used)
{
    WOLFSSL_ENTER("wolfSSL_CTX_memsave_cert_cache");

    if (ctx == NULL || mem == NULL || used == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    return CM_MemSaveCertCache(ctx->cm, mem, sz, used);
}


/* Restore cert cache from memory */
int wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz)
{
    WOLFSSL_ENTER("wolfSSL_CTX_memrestore_cert_cache");

    if (ctx == NULL || mem == NULL || sz <= 0)
        return BAD_FUNC_ARG;

    return CM_MemRestoreCertCache(ctx->cm, mem, sz);
}


/* get how big the the cert cache save buffer needs to be */
int wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_cert_cache_memsize");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return CM_GetCertCacheMemSize(ctx->cm);
}

#endif /* PERSIST_CERT_CACHE */




void wolfSSL_load_error_strings(void)
{
    /* compatibility only */
}


int wolfSSL_library_init(void)
{
    WOLFSSL_ENTER("SSL_library_init");
    if (wolfSSL_Init() == WOLFSSL_SUCCESS)
        return WOLFSSL_SUCCESS;
    else
        return WOLFSSL_FATAL_ERROR;
}






#if defined(PERSIST_CERT_CACHE)


#define WOLFSSL_CACHE_CERT_VERSION 1

typedef struct {
    int version;                 /* cache cert layout version id */
    int rows;                    /* hash table rows, CA_TABLE_SIZE */
    int columns[CA_TABLE_SIZE];  /* columns per row on list */
    int signerSz;                /* sizeof Signer object */
} CertCacheHeader;

/* current cert persistence layout is:

   1) CertCacheHeader
   2) caTable

   update WOLFSSL_CERT_CACHE_VERSION if change layout for the following
   PERSIST_CERT_CACHE functions
*/


/* Return memory needed to persist this signer, have lock */
static WC_INLINE int GetSignerMemory(Signer* signer)
{
    int sz = sizeof(signer->pubKeySize) + sizeof(signer->keyOID)
           + sizeof(signer->nameLen)    + sizeof(signer->subjectNameHash);

#if !defined(NO_SKID)
        sz += (int)sizeof(signer->subjectKeyIdHash);
#endif

    /* add dynamic bytes needed */
    sz += signer->pubKeySize;
    sz += signer->nameLen;

    return sz;
}


/* Return memory needed to persist this row, have lock */
static WC_INLINE int GetCertCacheRowMemory(Signer* row)
{
    int sz = 0;

    while (row) {
        sz += GetSignerMemory(row);
        row = row->next;
    }

    return sz;
}


/* get the size of persist cert cache, have lock */
static WC_INLINE int GetCertCacheMemSize(WOLFSSL_CERT_MANAGER* cm)
{
    int sz;
    int i;

    sz = sizeof(CertCacheHeader);

    for (i = 0; i < CA_TABLE_SIZE; i++)
        sz += GetCertCacheRowMemory(cm->caTable[i]);

    return sz;
}


/* Store cert cache header columns with number of items per list, have lock */
static WC_INLINE void SetCertHeaderColumns(WOLFSSL_CERT_MANAGER* cm, int* columns)
{
    int     i;
    Signer* row;

    for (i = 0; i < CA_TABLE_SIZE; i++) {
        int count = 0;
        row = cm->caTable[i];

        while (row) {
            ++count;
            row = row->next;
        }
        columns[i] = count;
    }
}


/* Restore whole cert row from memory, have lock, return bytes consumed,
   < 0 on error, have lock */
static WC_INLINE int RestoreCertRow(WOLFSSL_CERT_MANAGER* cm, byte* current,
                                 int row, int listSz, const byte* end)
{
    int idx = 0;

    if (listSz < 0) {
        WOLFSSL_MSG("Row header corrupted, negative value");
        return PARSE_ERROR;
    }

    while (listSz) {
        Signer* signer;
        byte*   publicKey;
        byte*   start = current + idx;  /* for end checks on this signer */
        int     minSz = sizeof(signer->pubKeySize) + sizeof(signer->keyOID) +
                      sizeof(signer->nameLen) + sizeof(signer->subjectNameHash);
        #ifndef NO_SKID
                minSz += (int)sizeof(signer->subjectKeyIdHash);
        #endif

        if (start + minSz > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            return BUFFER_E;
        }
        signer = MakeSigner(cm->heap);
        if (signer == NULL)
            return MEMORY_E;

        /* pubKeySize */
        XMEMCPY(&signer->pubKeySize, current + idx, sizeof(signer->pubKeySize));
        idx += (int)sizeof(signer->pubKeySize);

        /* keyOID */
        XMEMCPY(&signer->keyOID, current + idx, sizeof(signer->keyOID));
        idx += (int)sizeof(signer->keyOID);

        /* publicKey */
        if (start + minSz + signer->pubKeySize > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            FreeSigner(signer, cm->heap);
            return BUFFER_E;
        }
        publicKey = (byte*)XMALLOC(signer->pubKeySize, cm->heap,
                                   DYNAMIC_TYPE_KEY);
        if (publicKey == NULL) {
            FreeSigner(signer, cm->heap);
            return MEMORY_E;
        }

        XMEMCPY(publicKey, current + idx, signer->pubKeySize);
        signer->publicKey = publicKey;
        idx += signer->pubKeySize;

        /* nameLen */
        XMEMCPY(&signer->nameLen, current + idx, sizeof(signer->nameLen));
        idx += (int)sizeof(signer->nameLen);

        /* name */
        if (start + minSz + signer->pubKeySize + signer->nameLen > end) {
            WOLFSSL_MSG("Would overread restore buffer");
            FreeSigner(signer, cm->heap);
            return BUFFER_E;
        }
        signer->name = (char*)XMALLOC(signer->nameLen, cm->heap,
                                      DYNAMIC_TYPE_SUBJECT_CN);
        if (signer->name == NULL) {
            FreeSigner(signer, cm->heap);
            return MEMORY_E;
        }

        XMEMCPY(signer->name, current + idx, signer->nameLen);
        idx += signer->nameLen;

        /* subjectNameHash */
        XMEMCPY(signer->subjectNameHash, current + idx, SIGNER_DIGEST_SIZE);
        idx += SIGNER_DIGEST_SIZE;

        #ifndef NO_SKID
            /* subjectKeyIdHash */
            XMEMCPY(signer->subjectKeyIdHash, current + idx,SIGNER_DIGEST_SIZE);
            idx += SIGNER_DIGEST_SIZE;
        #endif

        signer->next = cm->caTable[row];
        cm->caTable[row] = signer;

        --listSz;
    }

    return idx;
}


/* Store whole cert row into memory, have lock, return bytes added */
static WC_INLINE int StoreCertRow(WOLFSSL_CERT_MANAGER* cm, byte* current, int row)
{
    int     added  = 0;
    Signer* list   = cm->caTable[row];

    while (list) {
        XMEMCPY(current + added, &list->pubKeySize, sizeof(list->pubKeySize));
        added += (int)sizeof(list->pubKeySize);

        XMEMCPY(current + added, &list->keyOID,     sizeof(list->keyOID));
        added += (int)sizeof(list->keyOID);

        XMEMCPY(current + added, list->publicKey, list->pubKeySize);
        added += list->pubKeySize;

        XMEMCPY(current + added, &list->nameLen, sizeof(list->nameLen));
        added += (int)sizeof(list->nameLen);

        XMEMCPY(current + added, list->name, list->nameLen);
        added += list->nameLen;

        XMEMCPY(current + added, list->subjectNameHash, SIGNER_DIGEST_SIZE);
        added += SIGNER_DIGEST_SIZE;

        #ifndef NO_SKID
            XMEMCPY(current + added, list->subjectKeyIdHash,SIGNER_DIGEST_SIZE);
            added += SIGNER_DIGEST_SIZE;
        #endif

        list = list->next;
    }

    return added;
}


/* Persist cert cache to memory, have lock */
static WC_INLINE int DoMemSaveCertCache(WOLFSSL_CERT_MANAGER* cm,
                                     void* mem, int sz)
{
    int realSz;
    int ret = WOLFSSL_SUCCESS;
    int i;

    WOLFSSL_ENTER("DoMemSaveCertCache");

    realSz = GetCertCacheMemSize(cm);
    if (realSz > sz) {
        WOLFSSL_MSG("Mem output buffer too small");
        ret = BUFFER_E;
    }
    else {
        byte*           current;
        CertCacheHeader hdr;

        hdr.version  = WOLFSSL_CACHE_CERT_VERSION;
        hdr.rows     = CA_TABLE_SIZE;
        SetCertHeaderColumns(cm, hdr.columns);
        hdr.signerSz = (int)sizeof(Signer);

        XMEMCPY(mem, &hdr, sizeof(CertCacheHeader));
        current = (byte*)mem + sizeof(CertCacheHeader);

        for (i = 0; i < CA_TABLE_SIZE; ++i)
            current += StoreCertRow(cm, current, i);
    }

    return ret;
}


#if !defined(NO_FILESYSTEM)

/* Persist cert cache to file */
int CM_SaveCertCache(WOLFSSL_CERT_MANAGER* cm, const char* fname)
{
    XFILE file;
    int   rc = WOLFSSL_SUCCESS;
    int   memSz;
    byte* mem;

    WOLFSSL_ENTER("CM_SaveCertCache");

    file = XFOPEN(fname, "w+b");
    if (file == XBADFILE) {
       WOLFSSL_MSG("Couldn't open cert cache save file");
       return WOLFSSL_BAD_FILE;
    }

    if (wc_LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("wc_LockMutex on caLock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }

    memSz = GetCertCacheMemSize(cm);
    mem   = (byte*)XMALLOC(memSz, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Alloc for tmp buffer failed");
        rc = MEMORY_E;
    } else {
        rc = DoMemSaveCertCache(cm, mem, memSz);
        if (rc == WOLFSSL_SUCCESS) {
            int ret = (int)XFWRITE(mem, memSz, 1, file);
            if (ret != 1) {
                WOLFSSL_MSG("Cert cache file write failed");
                rc = FWRITE_ERROR;
            }
        }
        XFREE(mem, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wc_UnLockMutex(&cm->caLock);
    XFCLOSE(file);

    return rc;
}


/* Restore cert cache from file */
int CM_RestoreCertCache(WOLFSSL_CERT_MANAGER* cm, const char* fname)
{
    XFILE file;
    int   rc = WOLFSSL_SUCCESS;
    int   ret;
    int   memSz;
    byte* mem;

    WOLFSSL_ENTER("CM_RestoreCertCache");

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) {
       WOLFSSL_MSG("Couldn't open cert cache save file");
       return WOLFSSL_BAD_FILE;
    }

    if(XFSEEK(file, 0, XSEEK_END) != 0) {
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }
    memSz = (int)XFTELL(file);
    XREWIND(file);

    if (memSz > MAX_WOLFSSL_FILE_SIZE || memSz <= 0) {
        WOLFSSL_MSG("CM_RestoreCertCache file size error");
        XFCLOSE(file);
        return WOLFSSL_BAD_FILE;
    }

    mem = (byte*)XMALLOC(memSz, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Alloc for tmp buffer failed");
        XFCLOSE(file);
        return MEMORY_E;
    }

    ret = (int)XFREAD(mem, memSz, 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Cert file read error");
        rc = FREAD_ERROR;
    } else {
        rc = CM_MemRestoreCertCache(cm, mem, memSz);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Mem restore cert cache failed");
        }
    }

    XFREE(mem, cm->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFCLOSE(file);

    return rc;
}

#endif /* NO_FILESYSTEM */


/* Persist cert cache to memory */
int CM_MemSaveCertCache(WOLFSSL_CERT_MANAGER* cm, void* mem, int sz, int* used)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("CM_MemSaveCertCache");

    if (wc_LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("wc_LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    ret = DoMemSaveCertCache(cm, mem, sz);
    if (ret == WOLFSSL_SUCCESS)
        *used  = GetCertCacheMemSize(cm);

    wc_UnLockMutex(&cm->caLock);

    return ret;
}


/* Restore cert cache from memory */
int CM_MemRestoreCertCache(WOLFSSL_CERT_MANAGER* cm, const void* mem, int sz)
{
    int ret = WOLFSSL_SUCCESS;
    int i;
    CertCacheHeader* hdr = (CertCacheHeader*)mem;
    byte*            current = (byte*)mem + sizeof(CertCacheHeader);
    byte*            end     = (byte*)mem + sz;  /* don't go over */

    WOLFSSL_ENTER("CM_MemRestoreCertCache");

    if (current > end) {
        WOLFSSL_MSG("Cert Cache Memory buffer too small");
        return BUFFER_E;
    }

    if (hdr->version  != WOLFSSL_CACHE_CERT_VERSION ||
        hdr->rows     != CA_TABLE_SIZE ||
        hdr->signerSz != (int)sizeof(Signer)) {

        WOLFSSL_MSG("Cert Cache Memory header mismatch");
        return CACHE_MATCH_ERROR;
    }

    if (wc_LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("wc_LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    FreeSignerTable(cm->caTable, CA_TABLE_SIZE, cm->heap);

    for (i = 0; i < CA_TABLE_SIZE; ++i) {
        int added = RestoreCertRow(cm, current, i, hdr->columns[i], end);
        if (added < 0) {
            WOLFSSL_MSG("RestoreCertRow error");
            ret = added;
            break;
        }
        current += added;
    }

    wc_UnLockMutex(&cm->caLock);

    return ret;
}


/* get how big the the cert cache save buffer needs to be */
int CM_GetCertCacheMemSize(WOLFSSL_CERT_MANAGER* cm)
{
    int sz;

    WOLFSSL_ENTER("CM_GetCertCacheMemSize");

    if (wc_LockMutex(&cm->caLock) != 0) {
        WOLFSSL_MSG("wc_LockMutex on caLock failed");
        return BAD_MUTEX_E;
    }

    sz = GetCertCacheMemSize(cm);

    wc_UnLockMutex(&cm->caLock);

    return sz;
}

#endif /* PERSIST_CERT_CACHE */



int wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cipher_list");

    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    /* alloc/init on demand only */
    if (ctx->suites == NULL) {
        ctx->suites = (Suites*)XMALLOC(sizeof(Suites), ctx->heap,
                                       DYNAMIC_TYPE_SUITES);
        if (ctx->suites == NULL) {
            WOLFSSL_MSG("Memory alloc for Suites failed");
            return WOLFSSL_FAILURE;
        }
        XMEMSET(ctx->suites, 0, sizeof(Suites));
    }

    return (SetCipherList(ctx, ctx->suites, list)) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}


int wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list)
{
    WOLFSSL_ENTER("wolfSSL_set_cipher_list");

    return (SetCipherList(ssl->ctx, ssl->suites, list)) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

#ifdef HAVE_KEYING_MATERIAL

#define TLS_PRF_LABEL_CLIENT_FINISHED     "client finished"
#define TLS_PRF_LABEL_SERVER_FINISHED     "server finished"
#define TLS_PRF_LABEL_MASTER_SECRET       "master secret"
#define TLS_PRF_LABEL_EXT_MASTER_SECRET   "extended master secret"
#define TLS_PRF_LABEL_KEY_EXPANSION       "key expansion"

static const struct ForbiddenLabels {
    const char* label;
    size_t labelLen;
} forbiddenLabels[] = {
    {TLS_PRF_LABEL_CLIENT_FINISHED, XSTR_SIZEOF(TLS_PRF_LABEL_CLIENT_FINISHED)},
    {TLS_PRF_LABEL_SERVER_FINISHED, XSTR_SIZEOF(TLS_PRF_LABEL_SERVER_FINISHED)},
    {TLS_PRF_LABEL_MASTER_SECRET, XSTR_SIZEOF(TLS_PRF_LABEL_MASTER_SECRET)},
    {TLS_PRF_LABEL_EXT_MASTER_SECRET, XSTR_SIZEOF(TLS_PRF_LABEL_EXT_MASTER_SECRET)},
    {TLS_PRF_LABEL_KEY_EXPANSION, XSTR_SIZEOF(TLS_PRF_LABEL_KEY_EXPANSION)},
    {NULL, 0},
};

/**
 * Implement RFC 5705
 * TLS 1.3 uses a different exporter definition (section 7.5 of RFC 8446)
 * @return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on error
 */
int wolfSSL_export_keying_material(WOLFSSL *ssl,
        unsigned char *out, size_t outLen,
        const char *label, size_t labelLen,
        const unsigned char *context, size_t contextLen,
        int use_context)
{
    byte*  seed = NULL;
    word32 seedLen;
    const struct ForbiddenLabels* fl;

    WOLFSSL_ENTER("wolfSSL_export_keying_material");

    if (ssl == NULL || out == NULL || label == NULL ||
            (use_context && contextLen && context == NULL)) {
        WOLFSSL_MSG("Bad argument");
        return WOLFSSL_FAILURE;
    }

    /* clientRandom + serverRandom
     * OR
     * clientRandom + serverRandom + ctx len encoding + ctx */
    seedLen = !use_context ? (word32)SEED_LEN :
                             (word32)SEED_LEN + 2 + (word32)contextLen;

    if (ssl->options.saveArrays == 0 || ssl->arrays == NULL) {
        WOLFSSL_MSG("To export keying material wolfSSL needs to keep handshake "
                    "data. Call wolfSSL_KeepArrays before attempting to "
                    "export keyid material.");
        return WOLFSSL_FAILURE;
    }

    /* check forbidden labels */
    for (fl = &forbiddenLabels[0]; fl->label != NULL; fl++) {
        if (labelLen >= fl->labelLen &&
                XMEMCMP(label, fl->label, fl->labelLen) == 0) {
            WOLFSSL_MSG("Forbidden label");
            return WOLFSSL_FAILURE;
        }
    }


    /* Path for <=TLS 1.2 */
    seed = (byte*)XMALLOC(seedLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (seed == NULL) {
        WOLFSSL_MSG("malloc error");
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(seed,           ssl->arrays->clientRandom, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, ssl->arrays->serverRandom, RAN_LEN);

    if (use_context) {
        /* Encode len in big endian */
        seed[SEED_LEN    ] = (contextLen >> 8) & 0xFF;
        seed[SEED_LEN + 1] = (contextLen) & 0xFF;
        if (contextLen) {
            /* 0 length context is allowed */
            XMEMCPY(seed + SEED_LEN + 2, context, contextLen);
        }
    }

    PRIVATE_KEY_UNLOCK();
    if (wc_PRF_TLS(out, (word32)outLen, ssl->arrays->masterSecret, SECRET_LEN,
            (byte*)label, (word32)labelLen, seed, seedLen, IsAtLeastTLSv1_2(ssl),
            ssl->specs.mac_algorithm, ssl->heap, ssl->devId) != 0) {
        WOLFSSL_MSG("wc_PRF_TLS error");
        PRIVATE_KEY_LOCK();
        XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }
    PRIVATE_KEY_LOCK();

    XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_KEYING_MATERIAL */

int wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl)
{
    int useNb = 0;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_dtls_get_using_nonblock");
    if (ssl->options.dtls) {
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_get_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
    return useNb;
}


#ifndef WOLFSSL_LEANPSK

void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock)
{
    (void)nonblock;

    WOLFSSL_ENTER("wolfSSL_dtls_set_using_nonblock");

    if (ssl == NULL)
        return;

    if (ssl->options.dtls) {
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_set_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
}


#endif /* LEANPSK */




/* EITHER SIDE METHODS */

/* client only parts */


    #if defined(WOLFSSL_ALLOW_SSLV3)
    WOLFSSL_METHOD* wolfSSLv3_client_method(void)
    {
        return wolfSSLv3_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv3_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("SSLv3_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeSSLv3());
        return method;
    }
    #endif /* WOLFSSL_ALLOW_SSLV3 && !NO_OLD_TLS */


    WOLFSSL_METHOD* wolfSSLv23_client_method(void)
    {
        return wolfSSLv23_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfSSLv23_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("SSLv23_client_method_ex");
        if (method) {
            InitSSL_Method(method, MakeTLSv1_2());
            method->downgrade = 1;
        }
        return method;
    }

    /* please see note at top of README if you get an error from connect */
    WOLFSSL_ABI
    int wolfSSL_connect(WOLFSSL* ssl)
    {
        int neededState;

        WOLFSSL_ENTER("SSL_connect()");

            errno = 0;

        if (ssl == NULL)
            return BAD_FUNC_ARG;




        if (ssl->options.side != WOLFSSL_CLIENT_END) {
            WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
            return WOLFSSL_FATAL_ERROR;
        }


        if (ssl->buffers.outputBuffer.length > 0
        ) {
            if ( (ssl->error = SendBuffered(ssl)) == 0) {
                /* fragOffset is non-zero when sending fragments. On the last
                 * fragment, fragOffset is zero again, and the state can be
                 * advanced. */
                if (ssl->fragOffset == 0) {
                    if (ssl->options.connectState == CONNECT_BEGIN ||
                        ssl->options.connectState == HELLO_AGAIN ||
                       (ssl->options.connectState >= FIRST_REPLY_DONE &&
                        ssl->options.connectState <= FIRST_REPLY_FOURTH)) {
                        ssl->options.connectState++;
                        WOLFSSL_MSG("connect state: "
                                    "Advanced from last buffered fragment send");
                    }
                }
                else {
                    WOLFSSL_MSG("connect state: "
                                "Not advanced, more fragments to send");
                }
            }
            else {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }

        switch (ssl->options.connectState) {

        case CONNECT_BEGIN :
            /* always send client hello first */
            if ( (ssl->error = SendClientHello(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.connectState = CLIENT_HELLO_SENT;
            WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");
            FALL_THROUGH;

        case CLIENT_HELLO_SENT :
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                          SERVER_HELLODONE_COMPLETE;
            /* get response */
            while (ssl->options.serverState < neededState) {
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state */
                else if (neededState == SERVER_FINISHED_COMPLETE)
                    if (!ssl->options.resuming) {
                            neededState = SERVER_HELLODONE_COMPLETE;
                    }
            }

            ssl->options.connectState = HELLO_AGAIN;
            WOLFSSL_MSG("connect state: HELLO_AGAIN");
            FALL_THROUGH;

        case HELLO_AGAIN :
            if (ssl->options.certOnly)
                return WOLFSSL_SUCCESS;



            ssl->options.connectState = HELLO_AGAIN_REPLY;
            WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");
            FALL_THROUGH;

        case HELLO_AGAIN_REPLY :

            ssl->options.connectState = FIRST_REPLY_DONE;
            WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
            FALL_THROUGH;

        case FIRST_REPLY_DONE :
            ssl->options.connectState = FIRST_REPLY_FIRST;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");
            FALL_THROUGH;

        case FIRST_REPLY_FIRST :
            if (!ssl->options.resuming) {
                if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                WOLFSSL_MSG("sent: client key exchange");
            }

            ssl->options.connectState = FIRST_REPLY_SECOND;
            WOLFSSL_MSG("connect state: FIRST_REPLY_SECOND");
            FALL_THROUGH;

        case FIRST_REPLY_SECOND :
            /* CLIENT: Fail-safe for Server Authentication. */
            if (!ssl->options.peerAuthGood) {
                WOLFSSL_MSG("Server authentication did not happen");
                return WOLFSSL_FATAL_ERROR;
            }

            ssl->options.connectState = FIRST_REPLY_THIRD;
            WOLFSSL_MSG("connect state: FIRST_REPLY_THIRD");
            FALL_THROUGH;

        case FIRST_REPLY_THIRD :
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: change cipher spec");
            ssl->options.connectState = FIRST_REPLY_FOURTH;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FOURTH");
            FALL_THROUGH;

        case FIRST_REPLY_FOURTH :
            if ( (ssl->error = SendFinished(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: finished");
            ssl->options.connectState = FINISHED_DONE;
            WOLFSSL_MSG("connect state: FINISHED_DONE");
            FALL_THROUGH;

        case FINISHED_DONE :
            /* get response */
            while (ssl->options.serverState < SERVER_FINISHED_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }

            ssl->options.connectState = SECOND_REPLY_DONE;
            WOLFSSL_MSG("connect state: SECOND_REPLY_DONE");
            FALL_THROUGH;

        case SECOND_REPLY_DONE:
        #ifndef NO_HANDSHAKE_DONE_CB
            if (ssl->hsDoneCb) {
                int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
                if (cbret < 0) {
                    ssl->error = cbret;
                    WOLFSSL_MSG("HandShake Done Cb don't continue error");
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        #endif /* NO_HANDSHAKE_DONE_CB */

            if (!ssl->options.dtls) {
                if (!ssl->options.keepResources) {
                    FreeHandshakeResources(ssl);
                }
            }


            WOLFSSL_LEAVE("SSL_connect()", WOLFSSL_SUCCESS);
            return WOLFSSL_SUCCESS;

        default:
            WOLFSSL_MSG("Unknown connect state ERROR");
            return WOLFSSL_FATAL_ERROR; /* unknown connect state */
        }
    }



/* server only parts */


#ifndef NO_HANDSHAKE_DONE_CB

int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetHsDoneCb");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->hsDoneCb  = cb;
    ssl->hsDoneCtx = user_ctx;


    return WOLFSSL_SUCCESS;
}

#endif /* NO_HANDSHAKE_DONE_CB */

WOLFSSL_ABI
int wolfSSL_Cleanup(void)
{
    int ret = WOLFSSL_SUCCESS; /* Only the first error will be returned */
    int release = 0;

    WOLFSSL_ENTER("wolfSSL_Cleanup");

    if (initRefCount == 0)
        return ret;  /* possibly no init yet, but not failure either way */

    if ((count_mutex_valid == 1) && (wc_LockMutex(&count_mutex) != 0)) {
        WOLFSSL_MSG("Bad Lock Mutex count");
        ret = BAD_MUTEX_E;
    }

    release = initRefCount-- == 1;
    if (initRefCount < 0)
        initRefCount = 0;

    if (count_mutex_valid == 1) {
        wc_UnLockMutex(&count_mutex);
    }

    if (!release)
        return ret;



    if ((count_mutex_valid == 1) && (wc_FreeMutex(&count_mutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    count_mutex_valid = 0;


    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
        if (ret == WOLFSSL_SUCCESS)
            ret = WC_CLEANUP_E;
    }

#if FIPS_VERSION_GE(5,1)
    if (wolfCrypt_SetPrivateKeyReadEnable_fips(0, WC_KEYTYPE_ALL) < 0) {
        if (ret == WOLFSSL_SUCCESS)
            ret = WC_CLEANUP_E;
    }
#endif

#ifdef HAVE_GLOBAL_RNG
    if ((globalRNGMutex_valid == 1) && (wc_FreeMutex(&globalRNGMutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    globalRNGMutex_valid = 0;

#endif

    return ret;
}



WOLFSSL_SESSION* ClientSessionToSession(const WOLFSSL_SESSION* session)
{
    return (WOLFSSL_SESSION*)session;
}

/* No session cache version */
WOLFSSL_SESSION* wolfSSL_GetSession(WOLFSSL* ssl, byte* masterSecret,
        byte restoreSessionCerts)
{
    (void)ssl;
    (void)masterSecret;
    (void)restoreSessionCerts;

    return NULL;
}



/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
WOLFSSL_ABI
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn)
{
    WOLFSSL_ENTER("wolfSSL_check_domain_name");

    if (ssl == NULL || dn == NULL) {
        WOLFSSL_MSG("Bad function argument: NULL");
        return WOLFSSL_FAILURE;
    }

    if (ssl->buffers.domainName.buffer)
        XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    ssl->buffers.domainName.length = (word32)XSTRLEN(dn);
    ssl->buffers.domainName.buffer = (byte*)XMALLOC(
            ssl->buffers.domainName.length + 1, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    if (ssl->buffers.domainName.buffer) {
        unsigned char* domainName = ssl->buffers.domainName.buffer;
        XMEMCPY(domainName, dn, ssl->buffers.domainName.length);
        domainName[ssl->buffers.domainName.length] = '\0';
        return WOLFSSL_SUCCESS;
    }
    else {
        ssl->error = MEMORY_ERROR;
        return WOLFSSL_FAILURE;
    }
}


/* turn on wolfSSL zlib compression
   returns WOLFSSL_SUCCESS for success, else error (not built in)
*/
int wolfSSL_set_compression(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_set_compression");
    (void)ssl;
    return NOT_COMPILED_IN;
}


    #ifndef NO_WRITEV

        /* simulate writev semantics, doesn't actually do block at a time though
           because of SSL_write behavior and because front adds may be small */
        int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov, int iovcnt)
        {
            byte   staticBuffer[FILE_BUFFER_SIZE];
            byte* myBuffer  = staticBuffer;
            int   dynamic   = 0;
            int   sending   = 0;
            int   idx       = 0;
            int   i;
            int   ret;

            WOLFSSL_ENTER("wolfSSL_writev");

            for (i = 0; i < iovcnt; i++)
                sending += (int)iov[i].iov_len;

            if (sending > (int)sizeof(staticBuffer)) {
                myBuffer = (byte*)XMALLOC(sending, ssl->heap,
                                                           DYNAMIC_TYPE_WRITEV);
                if (!myBuffer)
                    return MEMORY_ERROR;

                dynamic = 1;
            }

            for (i = 0; i < iovcnt; i++) {
                XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
                idx += (int)iov[i].iov_len;
            }

           /* myBuffer may not be initialized fully, but the span up to the
            * sending length will be.
            */
            PRAGMA_GCC_DIAG_PUSH;
            PRAGMA_GCC("GCC diagnostic ignored \"-Wmaybe-uninitialized\"");
            ret = wolfSSL_write(ssl, myBuffer, sending);
            PRAGMA_GCC_DIAG_POP;

            if (dynamic)
                XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);

            return ret;
        }
    #endif








/* used to be defined on NO_FILESYSTEM only, but are generally useful */

    int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                         const unsigned char* in,
                                         long sz, int format, int userChain,
                                         word32 flags)
    {
        int verify;
        int ret = WOLFSSL_FAILURE;

        WOLFSSL_ENTER("wolfSSL_CTX_load_verify_buffer_ex");

        verify = GET_VERIFY_SETTING_CTX(ctx);
        if (flags & WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY)
            verify = VERIFY_SKIP_DATE;

        if (format == WOLFSSL_FILETYPE_PEM)
            ret = ProcessChainBuffer(ctx, in, sz, format, CA_TYPE, NULL,
                                      verify);
        else
            ret = ProcessBuffer(ctx, in, sz, format, CA_TYPE, NULL, NULL,
                                 userChain, verify);
#if defined(WOLFSSL_TRUST_PEER_CERT) && defined(OPENSSL_COMPATIBLE_DEFAULTS)
        if (ret == WOLFSSL_SUCCESS)
            ret = wolfSSL_CTX_trust_peer_buffer(ctx, in, sz, format);
#endif

        WOLFSSL_LEAVE("wolfSSL_CTX_load_verify_buffer_ex", ret);
        return ret;
    }

    /* wolfSSL extension allows DER files to be loaded from buffers as well */
    int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in,
                                       long sz, int format)
    {
        return wolfSSL_CTX_load_verify_buffer_ex(ctx, in, sz, format, 0,
            WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);
    }

    int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
                                       const unsigned char* in,
                                       long sz, int format)
    {
        return wolfSSL_CTX_load_verify_buffer_ex(ctx, in, sz, format, 1,
            WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS);
    }


#ifdef WOLFSSL_TRUST_PEER_CERT
    int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in,
                                       long sz, int format)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_trust_peer_buffer");

        /* sanity check on arguments */
        if (sz < 0 || in == NULL || ctx == NULL) {
            return BAD_FUNC_ARG;
        }

        if (format == WOLFSSL_FILETYPE_PEM)
            return ProcessChainBuffer(ctx, in, sz, format, TRUSTED_PEER_TYPE,
                                      NULL, GET_VERIFY_SETTING_CTX(ctx));
        else
            return ProcessBuffer(ctx, in, sz, format, TRUSTED_PEER_TYPE, NULL,
                                 NULL, 0, GET_VERIFY_SETTING_CTX(ctx));
    }
#endif /* WOLFSSL_TRUST_PEER_CERT */


    int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        int ret = WOLFSSL_FAILURE;

        WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_buffer");
        ret = ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 0,
                             GET_VERIFY_SETTING_CTX(ctx));
        WOLFSSL_LEAVE("wolfSSL_CTX_use_certificate_buffer", ret);
        return ret;
    }


    int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        int ret = WOLFSSL_FAILURE;

        WOLFSSL_ENTER("wolfSSL_CTX_use_PrivateKey_buffer");
        ret = ProcessBuffer(ctx, in, sz, format, PRIVATEKEY_TYPE, NULL, NULL,
                             0, GET_VERIFY_SETTING_CTX(ctx));
        WOLFSSL_LEAVE("wolfSSL_CTX_use_PrivateKey_buffer", ret);
        return ret;
    }


    int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_chain_buffer_format");
        return ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 1,
                             GET_VERIFY_SETTING_CTX(ctx));
    }

    int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                 const unsigned char* in, long sz)
    {
        return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, in, sz,
                                                            WOLFSSL_FILETYPE_PEM);
    }



    /* server wrapper for ctx or ssl Diffie-Hellman parameters */
    static int wolfSSL_SetTmpDH_buffer_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
                                               const unsigned char* buf,
                                               long sz, int format)
    {
        DerBuffer* der = NULL;
        int    ret      = 0;
        word32 pSz = MAX_DH_SIZE;
        word32 gSz = MAX_DH_SIZE;
        byte   p[MAX_DH_SIZE];
        byte   g[MAX_DH_SIZE];

        if (ctx == NULL || buf == NULL)
            return BAD_FUNC_ARG;

        ret = AllocDer(&der, 0, DH_PARAM_TYPE, ctx->heap);
        if (ret != 0) {
            return ret;
        }
        der->buffer = (byte*)buf;
        der->length = (word32)sz;


        if (format != WOLFSSL_FILETYPE_ASN1 && format != WOLFSSL_FILETYPE_PEM)
            ret = WOLFSSL_BAD_FILETYPE;
        else {
            if (format == WOLFSSL_FILETYPE_PEM) {
#ifdef WOLFSSL_PEM_TO_DER
                FreeDer(&der);
                ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap,
                               NULL, NULL);
                if (ret < 0) {
                    /* Also try X9.42 format */
                    ret = PemToDer(buf, sz, X942_PARAM_TYPE, &der, ctx->heap,
                               NULL, NULL);
                }
    #ifdef WOLFSSL_WPAS
    #endif /* WOLFSSL_WPAS */
#else
                ret = NOT_COMPILED_IN;
#endif /* WOLFSSL_PEM_TO_DER */
            }

            if (ret == 0) {
                if (wc_DhParamsLoad(der->buffer, der->length, p, &pSz, g, &gSz) < 0)
                    ret = WOLFSSL_BAD_FILETYPE;
                else if (ssl)
                    ret = wolfSSL_SetTmpDH(ssl, p, pSz, g, gSz);
                else
                    ret = wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);
            }
        }

        FreeDer(&der);


        return ret;
    }


    /* server Diffie-Hellman parameters, WOLFSSL_SUCCESS on ok */
    int wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* buf, long sz,
                               int format)
    {
        if (ssl == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_SetTmpDH_buffer_wrapper(ssl->ctx, ssl, buf, sz, format);
    }


    /* server ctx Diffie-Hellman parameters, WOLFSSL_SUCCESS on ok */
    int wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
                                   long sz, int format)
    {
        return wolfSSL_SetTmpDH_buffer_wrapper(ctx, NULL, buf, sz, format);
    }



    int wolfSSL_use_certificate_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        WOLFSSL_ENTER("wolfSSL_use_certificate_buffer");
        if (ssl == NULL)
            return BAD_FUNC_ARG;

        return ProcessBuffer(ssl->ctx, in, sz, format, CERT_TYPE, ssl, NULL, 0,
                             GET_VERIFY_SETTING_SSL(ssl));
    }


    int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        WOLFSSL_ENTER("wolfSSL_use_PrivateKey_buffer");
        if (ssl == NULL)
            return BAD_FUNC_ARG;

        return ProcessBuffer(ssl->ctx, in, sz, format, PRIVATEKEY_TYPE,
                             ssl, NULL, 0, GET_VERIFY_SETTING_SSL(ssl));
    }


    int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        WOLFSSL_ENTER("wolfSSL_use_certificate_chain_buffer_format");
        if (ssl == NULL)
            return BAD_FUNC_ARG;

        return ProcessBuffer(ssl->ctx, in, sz, format, CERT_TYPE,
                             ssl, NULL, 1, GET_VERIFY_SETTING_SSL(ssl));
    }

    int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                 const unsigned char* in, long sz)
    {
        return wolfSSL_use_certificate_chain_buffer_format(ssl, in, sz,
                                                            WOLFSSL_FILETYPE_PEM);
    }


    /* unload any certs or keys that SSL owns, leave CTX as is
       WOLFSSL_SUCCESS on ok */
    int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl)
    {
        if (ssl == NULL) {
            WOLFSSL_MSG("Null function arg");
            return BAD_FUNC_ARG;
        }

        if (ssl->buffers.weOwnCert && !ssl->keepCert) {
            WOLFSSL_MSG("Unloading cert");
            FreeDer(&ssl->buffers.certificate);
            #ifdef KEEP_OUR_CERT
            wolfSSL_X509_free(ssl->ourCert);
            ssl->ourCert = NULL;
            #endif
            ssl->buffers.weOwnCert = 0;
        }

        if (ssl->buffers.weOwnCertChain) {
            WOLFSSL_MSG("Unloading cert chain");
            FreeDer(&ssl->buffers.certChain);
            ssl->buffers.weOwnCertChain = 0;
        }

        if (ssl->buffers.weOwnKey) {
            WOLFSSL_MSG("Unloading key");
            FreeDer(&ssl->buffers.key);
            ssl->buffers.weOwnKey = 0;
        }

        return WOLFSSL_SUCCESS;
    }


    int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_UnloadCAs");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnloadCAs(ctx->cm);
    }


#ifdef WOLFSSL_TRUST_PEER_CERT
    int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnload_trust_peers(ctx->cm);
    }

#ifdef WOLFSSL_LOCAL_X509_STORE
    int wolfSSL_Unload_trust_peers(WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

        if (ssl == NULL)
            return BAD_FUNC_ARG;

        return wolfSSL_CertManagerUnload_trust_peers(SSL_CM(ssl));
    }
#endif /* WOLFSSL_LOCAL_X509_STORE */
#endif /* WOLFSSL_TRUST_PEER_CERT */
/* old NO_FILESYSTEM end */









    /* return true if connection established */
    int wolfSSL_is_init_finished(WOLFSSL* ssl)
    {
        if (ssl == NULL)
            return 0;

        if (ssl->options.handShakeState == HANDSHAKE_DONE)
            return 1;

        return 0;
    }


    static long wolf_set_options(long old_op, long op);
    long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt)
    {
        WOLFSSL_ENTER("SSL_CTX_set_options");

        if (ctx == NULL)
            return BAD_FUNC_ARG;

        ctx->mask = wolf_set_options(ctx->mask, opt);

        return ctx->mask;
    }



#ifdef WOLFSSL_ENCRYPTED_KEYS

    void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                   void* userdata)
    {
        WOLFSSL_ENTER("SSL_CTX_set_default_passwd_cb_userdata");
        if (ctx)
            ctx->passwd_userdata = userdata;
    }


    void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx, wc_pem_password_cb*
                                           cb)
    {
        WOLFSSL_ENTER("SSL_CTX_set_default_passwd_cb");
        if (ctx)
            ctx->passwd_cb = cb;
    }

    wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX *ctx)
    {
        if (ctx == NULL || ctx->passwd_cb == NULL) {
            return NULL;
        }

        return ctx->passwd_cb;
    }


    void* wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx)
    {
        if (ctx == NULL) {
            return NULL;
        }

        return ctx->passwd_userdata;
    }

#endif /* WOLFSSL_ENCRYPTED_KEYS */


















/* OPENSSL_EXTRA is needed for wolfSSL_X509_d21 function
   KEEP_OUR_CERT is to insure ability for returning ssl certificate */



#ifndef NO_ASN
#endif /* !NO_ASN */





int wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    int isShutdown = 0;

    WOLFSSL_ENTER("wolfSSL_get_shutdown");

    if (ssl) {
        {
            /* in OpenSSL, WOLFSSL_SENT_SHUTDOWN = 1, when closeNotifySent   *
             * WOLFSSL_RECEIVED_SHUTDOWN = 2, from close notify or fatal err */
            if (ssl->options.sentNotify)
                isShutdown |= WOLFSSL_SENT_SHUTDOWN;
            if (ssl->options.closeNotify||ssl->options.connReset)
                isShutdown |= WOLFSSL_RECEIVED_SHUTDOWN;
        }

    }
    return isShutdown;
}


int wolfSSL_session_reused(WOLFSSL* ssl)
{
    int resuming = 0;
    WOLFSSL_ENTER("wolfSSL_session_reused");
    if (ssl)
        resuming = ssl->options.resuming;
    WOLFSSL_LEAVE("wolfSSL_session_reused", resuming);
    return resuming;
}

/* return a new malloc'd session with default settings on success */
WOLFSSL_SESSION* wolfSSL_NewSession(void* heap)
{
    WOLFSSL_SESSION* ret = NULL;

    ret = (WOLFSSL_SESSION*)XMALLOC(sizeof(WOLFSSL_SESSION), heap,
            DYNAMIC_TYPE_SESSION);
    if (ret != NULL) {
        XMEMSET(ret, 0, sizeof(WOLFSSL_SESSION));
        if (wc_InitMutex(&ret->refMutex) != 0) {
            WOLFSSL_MSG("Error setting up session reference mutex");
            XFREE(ret, ret->heap, DYNAMIC_TYPE_SESSION);
            return NULL;
        }
        ret->refCount = 1;
        ret->type = WOLFSSL_SESSION_TYPE_HEAP;
        ret->heap = heap;
        ret->masterSecret = ret->_masterSecret;
    #ifndef NO_CLIENT_CACHE
        ret->serverID = ret->_serverID;
    #endif
#ifdef HAVE_STUNNEL
        /* stunnel has this funny mechanism of storing the "is_authenticated"
         * session info in the session ex data. This is basically their
         * default so let's just hard code it. */
        if (wolfSSL_SESSION_set_ex_data(ret, 0, (void *)(-1))
                != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error setting up ex data for stunnel");
            XFREE(ret, NULL, DYNAMIC_TYPE_OPENSSL);
            return NULL;
        }
#endif
#ifdef HAVE_EX_DATA
        ret->ownExData = 1;
#endif
    }
    return ret;
}


WOLFSSL_SESSION* wolfSSL_SESSION_new_ex(void* heap)
{
    return wolfSSL_NewSession(heap);
}

WOLFSSL_SESSION* wolfSSL_SESSION_new(void)
{
    return wolfSSL_SESSION_new_ex(NULL);
}

/* add one to session reference count
 * return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on error */
int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);

    if (session == NULL || session->type != WOLFSSL_SESSION_TYPE_HEAP)
        return WOLFSSL_FAILURE;

    if (wc_LockMutex(&session->refMutex) != 0) {
        WOLFSSL_MSG("Failed to lock session mutex");
        return WOLFSSL_FAILURE;
    }
    session->refCount++;
    wc_UnLockMutex(&session->refMutex);
    return WOLFSSL_SUCCESS;
}

/**
 * Deep copy the contents from input to output.
 * @param input         The source of the copy.
 * @param output        The destination of the copy.
 * @param avoidSysCalls If true, then system calls will be avoided or an error
 *                      will be returned if it is not possible to proceed
 *                      without a system call. This is useful for fetching
 *                      sessions from cache. When a cache row is locked, we
 *                      don't want to block other threads with long running
 *                      system calls.
 * @return              WOLFSSL_SUCCESS on success
 *                      WOLFSSL_FAILURE on failure
 */
int wolfSSL_DupSession(const WOLFSSL_SESSION* input, WOLFSSL_SESSION* output,
        int avoidSysCalls)
{
    const size_t copyOffset = OFFSETOF(WOLFSSL_SESSION, heap) + sizeof(input->heap);
    int ret = WOLFSSL_SUCCESS;

    (void)avoidSysCalls;

    input = ClientSessionToSession(input);
    output = ClientSessionToSession(output);

    if (input == NULL || output == NULL || input == output) {
        WOLFSSL_MSG("input or output are null or same");
        return WOLFSSL_FAILURE;
    }



    XMEMCPY((byte*)output + copyOffset, (byte*)input + copyOffset,
            sizeof(WOLFSSL_SESSION) - copyOffset);

    /* Set sane values for copy */
    if (output->type != WOLFSSL_SESSION_TYPE_CACHE)
    output->masterSecret = output->_masterSecret;
#ifndef NO_CLIENT_CACHE
    output->serverID = output->_serverID;
#endif
    return ret;
}

WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session)
{
#ifdef HAVE_EXT_CACHE
    WOLFSSL_SESSION* copy;

    WOLFSSL_ENTER("wolfSSL_SESSION_dup");

    session = ClientSessionToSession(session);
    if (session == NULL)
        return NULL;


    copy = wolfSSL_NewSession(session->heap);
    if (copy != NULL &&
            wolfSSL_DupSession(session, copy, 0) != WOLFSSL_SUCCESS) {
        wolfSSL_FreeSession(NULL, copy);
        copy = NULL;
    }
    return copy;
#else
    WOLFSSL_MSG("wolfSSL_SESSION_dup feature not compiled in");
    (void)session;
    return NULL;
#endif /* HAVE_EXT_CACHE */
}

void wolfSSL_FreeSession(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    if (session == NULL)
        return;

    (void)ctx;

    /* refCount will always be 1 or more if created externally.
     * Internal cache sessions don't initialize a refMutex. */
    if (session->refCount > 0) {
        if (wc_LockMutex(&session->refMutex) != 0) {
            WOLFSSL_MSG("Failed to lock session mutex");
            return;
        }
        if (session->refCount > 1) {
            session->refCount--;
            wc_UnLockMutex(&session->refMutex);
            return;
        }
        wc_UnLockMutex(&session->refMutex);
        wc_FreeMutex(&session->refMutex);
    }

#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
    if (ctx != NULL && ctx->rem_sess_cb
#ifdef HAVE_EX_DATA
            && session->ownExData /* This will be true if we are not using the
                                   * internal cache so it will get called for
                                   * externally cached sessions as well. */
#endif
    ) {
        ctx->rem_sess_cb(ctx, session);
    }
#endif





    if (session->type == WOLFSSL_SESSION_TYPE_HEAP) {
        XFREE(session, session->heap, DYNAMIC_TYPE_SESSION);
    }
}

void wolfSSL_SESSION_free(WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    wolfSSL_FreeSession(NULL, session);
}


#if defined(HAVE_EXT_CACHE)

/**
* set cipher to WOLFSSL_SESSION from WOLFSSL_CIPHER
* @param session  a pointer to WOLFSSL_SESSION structure
* @param cipher   a function pointer to WOLFSSL_CIPHER
* @return WOLFSSL_SUCCESS on success, otherwise WOLFSSL_FAILURE
*/
int wolfSSL_SESSION_set_cipher(WOLFSSL_SESSION* session,
                                            const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_set_cipher");

    session = ClientSessionToSession(session);
    /* sanity check */
    if (session == NULL || cipher == NULL) {
        WOLFSSL_MSG("bad argument");
        return WOLFSSL_FAILURE;
    }
    session->cipherSuite0 = cipher->cipherSuite0;
    session->cipherSuite  = cipher->cipherSuite;

    WOLFSSL_LEAVE("wolfSSL_SESSION_set_cipher", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA || HAVE_EXT_CACHE */


/* helper function that takes in a protocol version struct and returns string */
static const char* wolfSSL_internal_get_version(const ProtocolVersion* version)
{
    WOLFSSL_ENTER("wolfSSL_get_version");

    if (version == NULL) {
        return "Bad arg";
    }

    if (version->major == SSLv3_MAJOR) {
        switch (version->minor) {
            case SSLv3_MINOR :
                return "SSLv3";
            case TLSv1_MINOR :
                return "TLSv1";
            case TLSv1_1_MINOR :
                return "TLSv1.1";
            case TLSv1_2_MINOR :
                return "TLSv1.2";
            case TLSv1_3_MINOR :
                return "TLSv1.3";
            default:
                return "unknown";
        }
    }
    return "unknown";
}


const char* wolfSSL_get_version(const WOLFSSL* ssl)
{
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad argument");
        return "unknown";
    }

    return wolfSSL_internal_get_version(&ssl->version);
}


/* current library version */
const char* wolfSSL_lib_version(void)
{
    return LIBWOLFSSL_VERSION_STRING;
}



/* current library version in hex */
word32 wolfSSL_lib_version_hex(void)
{
    return LIBWOLFSSL_VERSION_HEX;
}


int wolfSSL_get_current_cipher_suite(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_get_current_cipher_suite");
    if (ssl)
        return (ssl->options.cipherSuite0 << 8) | ssl->options.cipherSuite;
    return 0;
}

WOLFSSL_CIPHER* wolfSSL_get_current_cipher(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_get_current_cipher");
    if (ssl) {
        ssl->cipher.cipherSuite0 = ssl->options.cipherSuite0;
        ssl->cipher.cipherSuite  = ssl->options.cipherSuite;
        return &ssl->cipher;
    }
    else
        return NULL;
}


const char* wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("wolfSSL_CIPHER_get_name");

    if (cipher == NULL) {
        return NULL;
    }

    #if !defined(WOLFSSL_CIPHER_INTERNALNAME)
        return GetCipherNameIana(cipher->cipherSuite0, cipher->cipherSuite);
    #else
        return wolfSSL_get_cipher_name_from_suite(cipher->cipherSuite0,
                cipher->cipherSuite);
    #endif
}

const char*  wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("SSL_CIPHER_get_version");

    if (cipher == NULL || cipher->ssl == NULL) {
        return NULL;
    }

    return wolfSSL_get_version(cipher->ssl);
}

const char* wolfSSL_SESSION_CIPHER_get_name(const WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    if (session == NULL) {
        return NULL;
    }

#if !defined(NO_RESUME_SUITE_CHECK)
    #if !defined(WOLFSSL_CIPHER_INTERNALNAME)
        return GetCipherNameIana(session->cipherSuite0, session->cipherSuite);
    #else
        return GetCipherNameInternal(session->cipherSuite0, session->cipherSuite);
    #endif
#else
    return NULL;
#endif
}

const char* wolfSSL_get_cipher(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_cipher");
    return wolfSSL_CIPHER_get_name(wolfSSL_get_current_cipher(ssl));
}

/* gets cipher name in the format DHE-RSA-... rather then TLS_DHE... */
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl)
{
    /* get access to cipher_name_idx in internal.c */
    return wolfSSL_get_cipher_name_internal(ssl);
}

const char* wolfSSL_get_cipher_name_from_suite(const byte cipherSuite0,
    const byte cipherSuite)
{
    return GetCipherNameInternal(cipherSuite0, cipherSuite);
}

const char* wolfSSL_get_cipher_name_iana_from_suite(const byte cipherSuite0,
        const byte cipherSuite)
{
    return GetCipherNameIana(cipherSuite0, cipherSuite);
}

int wolfSSL_get_cipher_suite_from_name(const char* name, byte* cipherSuite0,
                                       byte* cipherSuite, int *flags) {
    if ((name == NULL) ||
        (cipherSuite0 == NULL) ||
        (cipherSuite == NULL) ||
        (flags == NULL))
        return BAD_FUNC_ARG;
    return GetCipherSuiteFromName(name, cipherSuite0, cipherSuite, flags);
}



word32 wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher)
{
    word16 cipher_id = 0;

    WOLFSSL_ENTER("SSL_CIPHER_get_id");

    if (cipher && cipher->ssl) {
        cipher_id = (cipher->ssl->options.cipherSuite0 << 8) |
                     cipher->ssl->options.cipherSuite;
    }

    return cipher_id;
}

const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value)
{
    const WOLFSSL_CIPHER* cipher = NULL;
    byte cipherSuite0, cipherSuite;
    WOLFSSL_ENTER("SSL_get_cipher_by_value");

    /* extract cipher id information */
    cipherSuite =   (value       & 0xFF);
    cipherSuite0 = ((value >> 8) & 0xFF);

    /* TODO: lookup by cipherSuite0 / cipherSuite */
    (void)cipherSuite0;
    (void)cipherSuite;

    return cipher;
}



#ifdef HAVE_FFDHE
static const char* wolfssl_ffdhe_name(word16 group)
{
    const char* str = NULL;
    switch (group) {
        case WOLFSSL_FFDHE_2048:
            str = "FFDHE_2048";
            break;
        case WOLFSSL_FFDHE_3072:
            str = "FFDHE_3072";
            break;
        case WOLFSSL_FFDHE_4096:
            str = "FFDHE_4096";
            break;
        case WOLFSSL_FFDHE_6144:
            str = "FFDHE_6144";
            break;
        case WOLFSSL_FFDHE_8192:
            str = "FFDHE_8192";
            break;
        default:
            break;
    }
    return str;
}
#endif
/* Return the name of the curve used for key exchange as a printable string.
 *
 * ssl  The SSL/TLS object.
 * returns NULL if ECDH was not used, otherwise the name as a string.
 */
const char* wolfSSL_get_curve_name(WOLFSSL* ssl)
{
    const char* cName = NULL;

    if (ssl == NULL)
        return NULL;

#ifdef HAVE_FFDHE
    if (ssl->namedGroup != 0) {
        cName = wolfssl_ffdhe_name(ssl->namedGroup);
    }
#endif



    if (ssl->ecdhCurveOID != 0 && cName == NULL) {
        cName = wc_ecc_get_name(wc_ecc_get_oid(ssl->ecdhCurveOID, NULL,
                                NULL));
    }

    return cName;
}












#if defined(WOLFSSL_NGINX) ||  defined(WOLFSSL_HAPROXY)
#ifndef NO_ASN_TIME
#ifndef NO_BIO
int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_TIME* asnTime)
{
    char buf[MAX_TIME_STRING_SZ];
    int  ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_print");

    if (bio == NULL || asnTime == NULL) {
        WOLFSSL_MSG("NULL function argument");
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_ASN1_TIME_to_string((WOLFSSL_ASN1_TIME*)asnTime, buf,
                sizeof(buf)) == NULL) {
        XMEMSET(buf, 0, MAX_TIME_STRING_SZ);
        XSTRNCPY(buf, "Bad time value", sizeof(buf)-1);
        ret = WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, buf, (int)XSTRLEN(buf)) <= 0) {
        WOLFSSL_MSG("Unable to write to bio");
        return WOLFSSL_FAILURE;
    }

    return ret;
}
#endif /* !NO_BIO */

char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* t, char* buf, int len)
{
    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_to_string");

    if (t == NULL || buf == NULL || len < 5) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if (t->length > len) {
        WOLFSSL_MSG("Length of date is longer then buffer");
        return NULL;
    }

    if (!GetTimeString(t->data, t->type, buf, len)) {
        return NULL;
    }

    return buf;
}

/* Converts a WOLFSSL_ASN1_TIME to a struct tm. Returns WOLFSSL_SUCCESS on
 * success and WOLFSSL_FAILURE on failure. */
static int Asn1TimeToTm(WOLFSSL_ASN1_TIME* asnTime, struct tm* tm)
{
    unsigned char* asn1TimeBuf;
    int asn1TimeBufLen;
    int i = 0;
    int bytesNeeded = 11;

    if (asnTime == NULL) {
        WOLFSSL_MSG("asnTime is NULL");
        return WOLFSSL_FAILURE;
    }
    if (tm == NULL) {
        WOLFSSL_MSG("tm is NULL");
        return WOLFSSL_FAILURE;
    }

    asn1TimeBuf = wolfSSL_ASN1_TIME_get_data(asnTime);
    if (asn1TimeBuf == NULL) {
        WOLFSSL_MSG("Failed to get WOLFSSL_ASN1_TIME buffer.");
        return WOLFSSL_FAILURE;
    }
    asn1TimeBufLen = wolfSSL_ASN1_TIME_get_length(asnTime);
    if (asn1TimeBufLen <= 0) {
        WOLFSSL_MSG("Failed to get WOLFSSL_ASN1_TIME buffer length.");
        return WOLFSSL_FAILURE;
    }
    XMEMSET(tm, 0, sizeof(struct tm));

    /* Convert ASN1_time to struct tm */
    /* Check type */
    if (asnTime->type == ASN_UTC_TIME) {
        /* 2-digit year */
        bytesNeeded += 2;
        if (bytesNeeded > asn1TimeBufLen) {
            WOLFSSL_MSG("WOLFSSL_ASN1_TIME buffer length is invalid.");
            return WOLFSSL_FAILURE;
        }
        if (asn1TimeBuf[bytesNeeded-1] != 'Z') {
            WOLFSSL_MSG("Expecting UTC time.");
            return WOLFSSL_FAILURE;
        }

        tm->tm_year = (asn1TimeBuf[i] - '0') * 10; i++;
        tm->tm_year += asn1TimeBuf[i] - '0'; i++;
        if (tm->tm_year < 70) {
            tm->tm_year += 100;
        }
    }
    else if (asnTime->type == ASN_GENERALIZED_TIME) {
        /* 4-digit year */
        bytesNeeded += 4;
        if (bytesNeeded > asn1TimeBufLen) {
            WOLFSSL_MSG("WOLFSSL_ASN1_TIME buffer length is invalid.");
            return WOLFSSL_FAILURE;
        }
        if (asn1TimeBuf[bytesNeeded-1] != 'Z') {
            WOLFSSL_MSG("Expecting UTC time.");
            return WOLFSSL_FAILURE;
        }

        tm->tm_year = (asn1TimeBuf[i] - '0') * 1000; i++;
        tm->tm_year += (asn1TimeBuf[i] - '0') * 100; i++;
        tm->tm_year += (asn1TimeBuf[i] - '0') * 10; i++;
        tm->tm_year += asn1TimeBuf[i] - '0'; i++;
        tm->tm_year -= 1900;
    }
    else {
        WOLFSSL_MSG("asnTime->type is invalid.");
        return WOLFSSL_FAILURE;
    }

    tm->tm_mon = (asn1TimeBuf[i] - '0') * 10; i++;
    tm->tm_mon += (asn1TimeBuf[i] - '0') - 1; i++; /* January is 0 not 1 */
    tm->tm_mday = (asn1TimeBuf[i] - '0') * 10; i++;
    tm->tm_mday += (asn1TimeBuf[i] - '0'); i++;
    tm->tm_hour = (asn1TimeBuf[i] - '0') * 10; i++;
    tm->tm_hour += (asn1TimeBuf[i] - '0'); i++;
    tm->tm_min = (asn1TimeBuf[i] - '0') * 10; i++;
    tm->tm_min += (asn1TimeBuf[i] - '0'); i++;
    tm->tm_sec = (asn1TimeBuf[i] - '0') * 10; i++;
    tm->tm_sec += (asn1TimeBuf[i] - '0');

#ifdef XMKTIME
    /* Call XMKTIME on tm to get the tm_wday and tm_yday fields populated. */
    XMKTIME(tm);
#endif

    return WOLFSSL_SUCCESS;
}

int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME* asnTime, struct tm* tm)
{
    time_t currentTime;
    struct tm *tmpTs;
#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTs = &tmpTimeStorage;
#else
    tmpTs = NULL;
#endif
    (void)tmpTs;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_to_tm");

    /* If asnTime is NULL, then the current time is converted. */
    if (asnTime == NULL) {
        if (tm == NULL) {
            WOLFSSL_MSG("asnTime and tm are both NULL");
            return WOLFSSL_FAILURE;
        }

        currentTime = wc_Time(0);
        if (currentTime <= 0) {
            WOLFSSL_MSG("Failed to get current time.");
            return WOLFSSL_FAILURE;
        }

        tm = XGMTIME(&currentTime, tmpTs);
        if (tm == NULL) {
            WOLFSSL_MSG("Failed to convert current time to UTC.");
            return WOLFSSL_FAILURE;
        }

        return WOLFSSL_SUCCESS;
    }

    /* If tm is NULL this function performs a format check on asnTime only. */
    if (tm == NULL) {
        return wolfSSL_ASN1_TIME_check(asnTime);
    }

    return Asn1TimeToTm((WOLFSSL_ASN1_TIME*)asnTime, tm);
}
#endif /* !NO_ASN_TIME */
#endif /* WOLFSSL_MYSQL_COMPATIBLE || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA*/





static long wolf_set_options(long old_op, long op)
{
    /* if SSL_OP_ALL then turn all bug workarounds on */
    if ((op & WOLFSSL_OP_ALL) == WOLFSSL_OP_ALL) {
        WOLFSSL_MSG("\tSSL_OP_ALL");
    }

    /* by default cookie exchange is on with DTLS */
    if ((op & WOLFSSL_OP_COOKIE_EXCHANGE) == WOLFSSL_OP_COOKIE_EXCHANGE) {
        WOLFSSL_MSG("\tSSL_OP_COOKIE_EXCHANGE : on by default");
    }

    if ((op & WOLFSSL_OP_NO_SSLv2) == WOLFSSL_OP_NO_SSLv2) {
        WOLFSSL_MSG("\tWOLFSSL_OP_NO_SSLv2 : wolfSSL does not support SSLv2");
    }

#ifdef SSL_OP_NO_TLSv1_3
    if ((op & WOLFSSL_OP_NO_TLSv1_3) == WOLFSSL_OP_NO_TLSv1_3) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_3");
    }
#endif

    if ((op & WOLFSSL_OP_NO_TLSv1_2) == WOLFSSL_OP_NO_TLSv1_2) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_2");
    }

    if ((op & WOLFSSL_OP_NO_TLSv1_1) == WOLFSSL_OP_NO_TLSv1_1) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1_1");
    }

    if ((op & WOLFSSL_OP_NO_TLSv1) == WOLFSSL_OP_NO_TLSv1) {
        WOLFSSL_MSG("\tSSL_OP_NO_TLSv1");
    }

    if ((op & WOLFSSL_OP_NO_SSLv3) == WOLFSSL_OP_NO_SSLv3) {
        WOLFSSL_MSG("\tSSL_OP_NO_SSLv3");
    }

    if ((op & WOLFSSL_OP_CIPHER_SERVER_PREFERENCE) ==
            WOLFSSL_OP_CIPHER_SERVER_PREFERENCE) {
        WOLFSSL_MSG("\tWOLFSSL_OP_CIPHER_SERVER_PREFERENCE");
    }

    if ((op & WOLFSSL_OP_NO_COMPRESSION) == WOLFSSL_OP_NO_COMPRESSION) {
        WOLFSSL_MSG("SSL_OP_NO_COMPRESSION: compression not compiled in");
    }

    return old_op | op;
}


/* clears the counter for number of renegotiations done
 * returns the current count before it is cleared */
long wolfSSL_clear_num_renegotiations(WOLFSSL *s)
{
    long total;

    WOLFSSL_ENTER("wolfSSL_clear_num_renegotiations");
    if (s == NULL)
        return 0;

    total = s->secure_rene_count;
    s->secure_rene_count = 0;
    return total;
}


/* return the number of renegotiations since wolfSSL_new */
long wolfSSL_total_renegotiations(WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_total_renegotiations");
    return wolfSSL_num_renegotiations(s);
}


/* return the number of renegotiations since wolfSSL_new */
long wolfSSL_num_renegotiations(WOLFSSL* s)
{
    if (s == NULL) {
        return 0;
    }

    return s->secure_rene_count;
}


/* Is there a renegotiation currently in progress? */
int  wolfSSL_SSL_renegotiate_pending(WOLFSSL *s)
{
    return s && s->options.handShakeDone &&
            s->options.handShakeState != HANDSHAKE_DONE ? 1 : 0;
}


#ifdef WOLFSSL_HAVE_TLS_UNIQUE
WOLFSSL_API size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;

    WOLFSSL_ENTER("SSL_get_finished");

    if (!ssl || !buf || count < TLS_FINISHED_SZ) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        len = ssl->serverFinished_len;
        XMEMCPY(buf, ssl->serverFinished, len);
    }
    else {
        len = ssl->clientFinished_len;
        XMEMCPY(buf, ssl->clientFinished, len);
    }
    return len;
}

WOLFSSL_API size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count)
{
    byte len = 0;
    WOLFSSL_ENTER("SSL_get_peer_finished");

    if (!ssl || !buf || count < TLS_FINISHED_SZ) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        len = ssl->serverFinished_len;
        XMEMCPY(buf, ssl->serverFinished, len);
    }
    else {
        len = ssl->clientFinished_len;
        XMEMCPY(buf, ssl->clientFinished, len);
    }

    return len;
}
#endif /* WOLFSSL_HAVE_TLS_UNIQUE */



















#ifdef WOLFSSL_HAVE_WOLFSCEP
    /* Used by autoconf to see if wolfSCEP is available */
    void wolfSSL_wolfSCEP(void) {}
#endif


#ifdef WOLFSSL_HAVE_CERT_SERVICE
    /* Used by autoconf to see if cert service is available */
    void wolfSSL_cert_service(void) {}
#endif


#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) ||  defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) ||  defined(WOLFSSL_HAPROXY)

    char wolfSSL_CTX_use_certificate(WOLFSSL_CTX *ctx, WOLFSSL_X509 *x)
    {
        int ret;

        WOLFSSL_ENTER("wolfSSL_CTX_use_certificate");
        if (!ctx || !x || !x->derCert) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        FreeDer(&ctx->certificate); /* Make sure previous is free'd */
        ret = AllocDer(&ctx->certificate, x->derCert->length, CERT_TYPE,
                       ctx->heap);
        if (ret != 0)
            return WOLFSSL_FAILURE;

        XMEMCPY(ctx->certificate->buffer, x->derCert->buffer,
                x->derCert->length);
#ifdef KEEP_OUR_CERT
        if (ctx->ourCert != NULL && ctx->ownOurCert) {
            wolfSSL_X509_free(ctx->ourCert);
        }
        #ifndef WOLFSSL_X509_STORE_CERTS
        ctx->ourCert = x;
        if (wolfSSL_X509_up_ref(x) != 1) {
            return WOLFSSL_FAILURE;
        }
        #else
        ctx->ourCert = wolfSSL_X509_d2i(NULL, x->derCert->buffer,x->derCert->length);
        if(ctx->ourCert == NULL){
            return WOLFSSL_FAILURE;
        }
        #endif

        /* We own the cert because either we up its reference counter
         * or we create our own copy of the cert object. */
        ctx->ownOurCert = 1;
#endif

        /* Update the available options with public keys. */
        switch (x->pubKeyOID) {
            case RSAk:
                ctx->haveRSA = 1;
                break;
            case ECDSAk:
                ctx->haveECC = 1;
                ctx->pkCurveOID = x->pkCurveOID;
                break;
        }

        return WOLFSSL_SUCCESS;
    }

    static int PushCertToDerBuffer(DerBuffer** inOutDer, int weOwn,
            byte* cert, word32 certSz, void* heap)
    {
        int ret;
        DerBuffer* inChain = NULL;
        DerBuffer* der = NULL;
        word32 len = 0;
        if (inOutDer == NULL)
            return BAD_FUNC_ARG;
        inChain = *inOutDer;
        if (inChain != NULL)
            len = inChain->length;
        ret = AllocDer(&der, len + CERT_HEADER_SZ + certSz, CERT_TYPE,
                heap);
        if (ret != 0) {
            WOLFSSL_MSG("AllocDer error");
            return ret;
        }
        if (inChain != NULL)
            XMEMCPY(der->buffer, inChain->buffer, len);
        c32to24(certSz, der->buffer + len);
        XMEMCPY(der->buffer + len + CERT_HEADER_SZ, cert, certSz);
        if (weOwn)
            FreeDer(inOutDer);
        *inOutDer = der;
        return WOLFSSL_SUCCESS;
    }

    /**
     * wolfSSL_CTX_add1_chain_cert makes a copy of the cert so we free it
     * on success
     */
    int wolfSSL_CTX_add0_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_add0_chain_cert");
        if (wolfSSL_CTX_add1_chain_cert(ctx, x509) != WOLFSSL_SUCCESS) {
            return WOLFSSL_FAILURE;
        }
        wolfSSL_X509_free(x509);
        return WOLFSSL_SUCCESS;
    }

    int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
    {
        int ret;
        WOLFSSL_ENTER("wolfSSL_CTX_add1_chain_cert");
        if (ctx == NULL || x509 == NULL || x509->derCert == NULL) {
            return WOLFSSL_FAILURE;
        }

        if (ctx->certificate == NULL)
            ret = (int)wolfSSL_CTX_use_certificate(ctx, x509);
        else {
            if (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("wolfSSL_X509_up_ref error");
                return WOLFSSL_FAILURE;
            }
            ret = wolfSSL_CTX_load_verify_buffer(ctx, x509->derCert->buffer,
                x509->derCert->length, WOLFSSL_FILETYPE_ASN1);
            if (ret == WOLFSSL_SUCCESS) {
                /* push to ctx->certChain */
                ret = PushCertToDerBuffer(&ctx->certChain, 1,
                    x509->derCert->buffer, x509->derCert->length, ctx->heap);
            }
            /* Store cert to free it later */
            if (ret == WOLFSSL_SUCCESS && ctx->x509Chain == NULL) {
                ctx->x509Chain = wolfSSL_sk_X509_new();
                if (ctx->x509Chain == NULL) {
                    WOLFSSL_MSG("wolfSSL_sk_X509_new error");
                    ret =  WOLFSSL_FAILURE;
                }
            }
            if (ret == WOLFSSL_SUCCESS &&
                    wolfSSL_sk_X509_push(ctx->x509Chain, x509)
                        != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("wolfSSL_sk_X509_push error");
                ret = WOLFSSL_FAILURE;
            }
            if (ret != WOLFSSL_SUCCESS)
                wolfSSL_X509_free(x509); /* Decrease ref counter */
        }

        return (ret == WOLFSSL_SUCCESS) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
    }

#ifdef KEEP_OUR_CERT
    int wolfSSL_add0_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509)
    {
        int ret;

        WOLFSSL_ENTER("wolfSSL_add0_chain_cert");

        if (ssl == NULL || ssl->ctx == NULL || x509 == NULL ||
                x509->derCert == NULL)
            return WOLFSSL_FAILURE;

        if (ssl->buffers.certificate == NULL) {
            ret = wolfSSL_use_certificate(ssl, x509);
            /* Store cert to free it later */
            if (ret == WOLFSSL_SUCCESS) {
                if (ssl->buffers.weOwnCert)
                    wolfSSL_X509_free(ssl->ourCert);
                ssl->ourCert = x509;
                ssl->buffers.weOwnCert = 1;
            }
        }
        else {
            ret = PushCertToDerBuffer(&ssl->buffers.certChain,
                    ssl->buffers.weOwnCertChain, x509->derCert->buffer,
                    x509->derCert->length, ssl->heap);
            if (ret == WOLFSSL_SUCCESS) {
                ssl->buffers.weOwnCertChain = 1;
                /* Store cert to free it later */
                if (ssl->ourCertChain == NULL) {
                    ssl->ourCertChain = wolfSSL_sk_X509_new();
                    if (ssl->ourCertChain == NULL) {
                        WOLFSSL_MSG("wolfSSL_sk_X509_new error");
                        return WOLFSSL_FAILURE;
                    }
                }
                if (wolfSSL_sk_X509_push(ssl->ourCertChain, x509)
                        != WOLFSSL_SUCCESS) {
                    WOLFSSL_MSG("wolfSSL_sk_X509_push error");
                    return WOLFSSL_FAILURE;
                }
            }
        }
        return ret == WOLFSSL_SUCCESS ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
    }

    int wolfSSL_add1_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509)
    {
        int ret;

        WOLFSSL_ENTER("wolfSSL_add1_chain_cert");
        if (ssl == NULL || ssl->ctx == NULL || x509 == NULL ||
                x509->derCert == NULL)
            return WOLFSSL_FAILURE;

        if (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_up_ref error");
            return WOLFSSL_FAILURE;
        }
        ret = wolfSSL_add0_chain_cert(ssl, x509);
        /* Decrease ref counter on error */
        if (ret != WOLFSSL_SUCCESS)
            wolfSSL_X509_free(x509);
        return ret;
    }
#endif

    /* Return the corresponding short name for the nid <n>.
     * or NULL if short name can't be found.
     */
    const char * wolfSSL_OBJ_nid2sn(int n) {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2sn");

        if (n == NID_md5) {
            /* NID_surname == NID_md5 and NID_surname comes before NID_md5 in
             * wolfssl_object_info. As a result, the loop below will incorrectly
             * return "SN" instead of "MD5." NID_surname isn't the true OpenSSL
             * NID, but other functions rely on this table and modifying it to
             * conform with OpenSSL's NIDs isn't trivial. */
             return "MD5";
        }
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->sName;
            }
        }
        WOLFSSL_MSG("SN not found");
        return NULL;
    }


    size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o)
    {
        size_t ret = 0;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_length");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = len;
        }

        WOLFSSL_LEAVE("wolfSSL_OBJ_length", (int)ret);

        return ret;
    }

    const unsigned char* wolfSSL_OBJ_get0_data(const WOLFSSL_ASN1_OBJECT* o)
    {
        const unsigned char* ret = NULL;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_get0_data");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = o->obj + idx;
        }

        return ret;
    }


    /* Gets the NID value that corresponds with the ASN1 object.
     *
     * o ASN1 object to get NID of
     *
     * Return NID on success and a negative value on failure
     */
    int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o)
    {
        word32 oid = 0;
        word32 idx = 0;
        int ret;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_OBJ_obj2nid");
#endif

        if (o == NULL) {
            return -1;
        }


        if (o->nid > 0)
            return o->nid;
        if ((ret = GetObjectId(o->obj, &idx, &oid, o->grp, o->objSz)) < 0) {
            if (ret == ASN_OBJECT_ID_E) {
                /* Put ASN object tag in front and try again */
                int len = SetObjectId(o->objSz, NULL) + o->objSz;
                byte* buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (!buf) {
                    WOLFSSL_MSG("malloc error");
                    return -1;
                }
                idx = SetObjectId(o->objSz, buf);
                XMEMCPY(buf + idx, o->obj, o->objSz);
                idx = 0;
                ret = GetObjectId(buf, &idx, &oid, o->grp, len);
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret < 0) {
                    WOLFSSL_MSG("Issue getting OID of object");
                    return -1;
                }
            }
            else {
                WOLFSSL_MSG("Issue getting OID of object");
                return -1;
            }
        }

        return oid2nid(oid, o->grp);
    }

    /* Returns the long name that corresponds with an ASN1_OBJECT nid value.
     *  n : NID value of ASN1_OBJECT to search */
    const char* wolfSSL_OBJ_nid2ln(int n)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2ln");
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->lName;
            }
        }
        WOLFSSL_MSG("NID not found in table");
        return NULL;
    }

    /* Return the corresponding NID for the long name <ln>
     * or NID_undef if NID can't be found.
     */
    int wolfSSL_OBJ_ln2nid(const char *ln)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i, lnlen;
        WOLFSSL_ENTER("wolfSSL_OBJ_ln2nid");
        if (ln && (lnlen = XSTRLEN(ln)) > 0) {
            /* Accept input like "/commonName=" */
            if (ln[0] == '/') {
                ln++;
                lnlen--;
            }
            if (lnlen) {
                if (ln[lnlen-1] == '=') {
                    lnlen--;
                }
                for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++, obj_info++) {
                    if (lnlen == XSTRLEN(obj_info->lName) &&
                            XSTRNCMP(ln, obj_info->lName, lnlen) == 0) {
                        return obj_info->nid;
                    }
                }
            }
        }
        return NID_undef;
    }

    /* compares two objects, return 0 if equal */
    int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
                        const WOLFSSL_ASN1_OBJECT* b)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cmp");

        if (a && b && a->obj && b->obj) {
            if (a->objSz == b->objSz) {
                return XMEMCMP(a->obj, b->obj, a->objSz);
            }
            else if (a->type == EXT_KEY_USAGE_OID ||
                     b->type == EXT_KEY_USAGE_OID) {
                /* Special case for EXT_KEY_USAGE_OID so that
                 * cmp will be treated as a substring search */
                /* Used in libest to check for id-kp-cmcRA in
                 * EXT_KEY_USAGE extension */
                unsigned int idx;
                const byte* s; /* shorter */
                unsigned int sLen;
                const byte* l; /* longer */
                unsigned int lLen;
                if (a->objSz > b->objSz) {
                    s = b->obj; sLen = b->objSz;
                    l = a->obj; lLen = a->objSz;
                }
                else {
                    s = a->obj; sLen = a->objSz;
                    l = b->obj; lLen = b->objSz;
                }
                for (idx = 0; idx <= lLen - sLen; idx++) {
                    if (XMEMCMP(l + idx, s, sLen) == 0) {
                        /* Found substring */
                        return 0;
                    }
                }
            }
        }

        return WOLFSSL_FATAL_ERROR;
    }
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY */
#if  defined(HAVE_LIGHTY) ||  defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) ||  defined(HAVE_POCO_LIB) || defined(WOLFSSL_HAPROXY)
    /* Gets the NID value that is related to the OID string passed in. Example
     * string would be "2.5.29.14" for subject key ID.
     *
     * returns NID value on success and NID_undef on error
     */
    int wolfSSL_OBJ_txt2nid(const char* s)
    {
        unsigned int i;
    #ifdef WOLFSSL_CERT_EXT
        int ret;
        unsigned int sum = 0;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];
    #endif

        WOLFSSL_ENTER("OBJ_txt2nid");

        if (s == NULL) {
            return NID_undef;
        }

    #ifdef WOLFSSL_CERT_EXT
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0) {
            /* sum OID */
            for (i = 0; i < outSz; i++) {
                sum += out[i];
            }
        }
    #endif /* WOLFSSL_CERT_EXT */

        /* get the group that the OID's sum is in
         * @TODO possible conflict with multiples */
        for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++) {
            int len;
        #ifdef WOLFSSL_CERT_EXT
            if (ret == 0) {
                if (wolfssl_object_info[i].id == (int)sum) {
                    return wolfssl_object_info[i].nid;
                }
            }
        #endif

            /* try as a short name */
            len = (int)XSTRLEN(s);
            if ((int)XSTRLEN(wolfssl_object_info[i].sName) == len &&
                XSTRNCMP(wolfssl_object_info[i].sName, s, len) == 0) {
                return wolfssl_object_info[i].nid;
            }

            /* try as a long name */
            if ((int)XSTRLEN(wolfssl_object_info[i].lName) == len &&
                XSTRNCMP(wolfssl_object_info[i].lName, s, len) == 0) {
                return wolfssl_object_info[i].nid;
            }
        }

        return NID_undef;
    }
#endif
#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) ||  defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) ||  defined(WOLFSSL_HAPROXY)

    /* Creates new ASN1_OBJECT from short name, long name, or text
     * representation of oid. If no_name is 0, then short name, long name, and
     * numerical value of oid are interpreted. If no_name is 1, then only the
     * numerical value of the oid is interpreted.
     *
     * Returns pointer to ASN1_OBJECT on success, or NULL on error.
     */
#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name)
    {
        int i, ret;
        int nid = NID_undef;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];
        WOLFSSL_ASN1_OBJECT* obj;

        WOLFSSL_ENTER("wolfSSL_OBJ_txt2obj");

        if (s == NULL)
            return NULL;

        /* If s is numerical value, try to sum oid */
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0 && outSz > 0) {
            /* If numerical encode succeeded then just
             * create object from that because sums are
             * not unique and can cause confusion. */
            obj = wolfSSL_ASN1_OBJECT_new();
            if (obj == NULL) {
                WOLFSSL_MSG("Issue creating WOLFSSL_ASN1_OBJECT struct");
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC;
            obj->obj = (byte*)XMALLOC(1 + MAX_LENGTH_SZ + outSz, NULL,
                    DYNAMIC_TYPE_ASN1);
            if (obj->obj == NULL) {
                wolfSSL_ASN1_OBJECT_free(obj);
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA ;
            i = SetObjectId(outSz, (byte*)obj->obj);
            XMEMCPY((byte*)obj->obj + i, out, outSz);
            obj->objSz = i + outSz;
            return obj;
        }

        /* TODO: update short names in wolfssl_object_info and check OID sums
           are correct */
        for (i = 0; i < (int)WOLFSSL_OBJECT_INFO_SZ; i++) {
            /* Short name, long name, and numerical value are interpreted */
            if (no_name == 0 &&
                ((XSTRCMP(s, wolfssl_object_info[i].sName) == 0) ||
                 (XSTRCMP(s, wolfssl_object_info[i].lName) == 0)))
            {
                    nid = wolfssl_object_info[i].nid;
            }
        }

        if (nid != NID_undef)
            return wolfSSL_OBJ_nid2obj(nid);

        return NULL;
    }
#endif

    /* compatibility function. Its intended use is to remove OID's from an
     * internal table that have been added with OBJ_create. wolfSSL manages its
     * own internal OID values and does not currently support OBJ_create. */
    void wolfSSL_OBJ_cleanup(void)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cleanup()");
    }

    #ifndef NO_WOLFSSL_STUB
    int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln)
    {
        (void)oid;
        (void)sn;
        (void)ln;
        WOLFSSL_STUB("wolfSSL_OBJ_create");
        return WOLFSSL_FAILURE;
    }
    #endif

    void wolfSSL_set_verify_depth(WOLFSSL *ssl, int depth)
    {
    }

#endif /* OPENSSL_ALL || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
    HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */
#if  defined(HAVE_LIGHTY) ||  defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) ||  defined(HAVE_POCO_LIB) || defined(WOLFSSL_HAPROXY)
    WOLFSSL_ASN1_OBJECT * wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne)
    {
        WOLFSSL_ASN1_OBJECT* obj = NULL;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_X509_NAME_ENTRY_get_object");
#endif
        if (ne == NULL) return NULL;
        obj = wolfSSL_OBJ_nid2obj_ex(ne->nid, ne->object);
        if (obj != NULL) {
            obj->nid = ne->nid;
            return obj;
        }
        return NULL;
    }


#endif /* OPENSSL_ALL || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
    HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */


#if defined(HAVE_EX_DATA) &&  ( defined(WOLFSSL_NGINX) ||  defined(WOLFSSL_HAPROXY) ||  defined(HAVE_LIGHTY)) || defined(HAVE_EX_DATA)
/**
 * get_ex_new_index is a helper function for the following
 * xx_get_ex_new_index functions:
 *  - wolfSSL_CRYPTO_get_ex_new_index
 *  - wolfSSL_CTX_get_ex_new_index
 *  - wolfSSL_get_ex_new_index
 * Issues a unique index number for the specified class-index.
 * Returns an index number greater or equal to zero on success,
 * -1 on failure.
 */
int wolfssl_get_ex_new_index(int class_index)
{
    /* index counter for each class index*/
    static int ctx_idx = 0;
    static int ssl_idx = 0;
    static int ssl_session_idx = 0;
    static int x509_idx = 0;

    int idx = -1;

    switch(class_index) {
        case WOLF_CRYPTO_EX_INDEX_SSL:
            idx = ssl_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_SSL_CTX:
            idx = ctx_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_X509:
            idx = x509_idx++;
            break;
        case WOLF_CRYPTO_EX_INDEX_SSL_SESSION:
            idx = ssl_session_idx++;
            break;

        /* following class indexes are not supoprted */
        case WOLF_CRYPTO_EX_INDEX_X509_STORE:
        case WOLF_CRYPTO_EX_INDEX_X509_STORE_CTX:
        case WOLF_CRYPTO_EX_INDEX_DH:
        case WOLF_CRYPTO_EX_INDEX_DSA:
        case WOLF_CRYPTO_EX_INDEX_EC_KEY:
        case WOLF_CRYPTO_EX_INDEX_RSA:
        case WOLF_CRYPTO_EX_INDEX_ENGINE:
        case WOLF_CRYPTO_EX_INDEX_UI:
        case WOLF_CRYPTO_EX_INDEX_BIO:
        case WOLF_CRYPTO_EX_INDEX_APP:
        case WOLF_CRYPTO_EX_INDEX_UI_METHOD:
        case WOLF_CRYPTO_EX_INDEX_DRBG:
        default:
            break;
    }
    return idx;
}
#endif /* HAVE_EX_DATA || WOLFSSL_WPAS_SMALL */

#if defined(HAVE_EX_DATA)
void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int idx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_ex_data");
#ifdef HAVE_EX_DATA
    if(ctx != NULL) {
        return wolfSSL_CRYPTO_get_ex_data(&ctx->ex_data, idx);
    }
#else
    (void)ctx;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_CTX_get_ex_new_index(long idx, void* arg, void* a, void* b,
                                void* c)
{

    WOLFSSL_ENTER("wolfSSL_CTX_get_ex_new_index");
    (void)idx;
    (void)arg;
    (void)a;
    (void)b;
    (void)c;

    return wolfssl_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_CTX);
}

/* Return the index that can be used for the WOLFSSL structure to store
 * application data.
 *
 */
int wolfSSL_get_ex_new_index(long argValue, void* arg,
        WOLFSSL_CRYPTO_EX_new* cb1, WOLFSSL_CRYPTO_EX_dup* cb2,
        WOLFSSL_CRYPTO_EX_free* cb3)
{

    WOLFSSL_ENTER("wolfSSL_get_ex_new_index");

    (void)argValue;
    (void)arg;
    (void)cb1;
    (void)cb2;
    (void)cb3;

    return wolfssl_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL);
}


int wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int idx, void* data)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_ex_data");
    #ifdef HAVE_EX_DATA
    if (ctx != NULL)
    {
        return wolfSSL_CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
    }
    #else
    (void)ctx;
    (void)idx;
    (void)data;
    #endif
    return WOLFSSL_FAILURE;
}


#endif /* defined(HAVE_EX_DATA) || defined(WOLFSSL_WPAS_SMALL) */


#if defined(HAVE_EX_DATA)

int wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data)
{
    WOLFSSL_ENTER("wolfSSL_set_ex_data");
#ifdef HAVE_EX_DATA
    if (ssl != NULL)
    {
        return wolfSSL_CRYPTO_set_ex_data(&ssl->ex_data, idx, data);
    }
#else
    WOLFSSL_MSG("HAVE_EX_DATA macro is not defined");
    (void)ssl;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}


void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx)
{
    WOLFSSL_ENTER("wolfSSL_get_ex_data");
#ifdef HAVE_EX_DATA
    if (ssl != NULL) {
        return wolfSSL_CRYPTO_get_ex_data(&ssl->ex_data, idx);
    }
#else
    WOLFSSL_MSG("HAVE_EX_DATA macro is not defined");
    (void)ssl;
    (void)idx;
#endif
    return 0;
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL || WOLFSSL_WPAS_SMALL */

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL)



/* returns the enum value associated with handshake state
 *
 * ssl the WOLFSSL structure to get state of
 */
int wolfSSL_get_state(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_state");

    if (ssl == NULL) {
        WOLFSSL_MSG("Null argument passed in");
        return SSL_FAILURE;
    }

    return ssl->options.handShakeState;
}
#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE */


#if defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY)  || defined(WOLFSSL_NGINX)

long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt)
{
    WOLFSSL_ENTER("wolfSSL_ctrl");
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (cmd) {
        #if defined(WOLFSSL_NGINX)
        case SSL_CTRL_SET_TLSEXT_HOSTNAME:
            WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TLSEXT_HOSTNAME.");
            if (pt == NULL) {
                WOLFSSL_MSG("Passed in NULL Host Name.");
                break;
            }
            return wolfSSL_set_tlsext_host_name(ssl, (const char*) pt);
        #endif /* WOLFSSL_NGINX || WOLFSSL_QT || OPENSSL_ALL */
        default:
            WOLFSSL_MSG("Case not implemented.");
    }
    (void)opt;
    (void)pt;
    return WOLFSSL_FAILURE;
}

long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt, void* pt)
{
    long ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_CTX_ctrl");
    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    switch (cmd) {
    case SSL_CTRL_CHAIN:
        WOLFSSL_MSG("Session certificates not compiled in");
        ret = WOLFSSL_FAILURE;
        break;

    case SSL_CTRL_EXTRA_CHAIN_CERT:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_EXTRA_CHAIN_CERT.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in x509 pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_CTX_add_extra_chain_cert(ctx, (WOLFSSL_X509*)pt);

    case SSL_CTRL_SET_TMP_DH:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TMP_DH.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in DH pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_CTX_set_tmp_dh(ctx, (WOLFSSL_DH*)pt);

    case SSL_CTRL_SET_TMP_ECDH:
        WOLFSSL_MSG("Entering Case: SSL_CTRL_SET_TMP_ECDH.");
        if (pt == NULL) {
            WOLFSSL_MSG("Passed in ECDH pointer NULL.");
            ret = WOLFSSL_FAILURE;
            break;
        }
        return wolfSSL_SSL_CTX_set_tmp_ecdh(ctx, (WOLFSSL_EC_KEY*)pt);
    case SSL_CTRL_MODE:
        wolfSSL_CTX_set_mode(ctx,opt);
        break;
    case SSL_CTRL_SET_MIN_PROTO_VERSION:
        WOLFSSL_MSG("set min proto version");
        return wolfSSL_CTX_set_min_proto_version(ctx, (int)opt);
    case SSL_CTRL_SET_MAX_PROTO_VERSION:
        WOLFSSL_MSG("set max proto version");
        return wolfSSL_CTX_set_max_proto_version(ctx, (int)opt);
    case SSL_CTRL_GET_MIN_PROTO_VERSION:
        WOLFSSL_MSG("get min proto version");
        return wolfSSL_CTX_get_min_proto_version(ctx);
    case SSL_CTRL_GET_MAX_PROTO_VERSION:
        WOLFSSL_MSG("get max proto version");
        return wolfSSL_CTX_get_max_proto_version(ctx);
    default:
        WOLFSSL_MSG("CTX_ctrl cmd not implemented");
        ret = WOLFSSL_FAILURE;
        break;
    }

    (void)ctx;
    (void)cmd;
    (void)opt;
    (void)pt;
    WOLFSSL_LEAVE("wolfSSL_CTX_ctrl", (int)ret);
    return ret;
}

#ifndef WOLFSSL_NO_STUB
long wolfSSL_CTX_callback_ctrl(WOLFSSL_CTX* ctx, int cmd, void (*fp)(void))
{
    (void) ctx;
    (void) cmd;
    (void) fp;
    WOLFSSL_STUB("wolfSSL_CTX_callback_ctrl");
    return WOLFSSL_FAILURE;

}
#endif /* WOLFSSL_NO_STUB */

#ifndef NO_WOLFSSL_STUB
long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx)
{
    return wolfSSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0L, NULL);
}
#endif

/* Returns the verifyCallback from the ssl structure if successful.
Returns NULL otherwise. */
VerifyCallback wolfSSL_get_verify_callback(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_verify_callback()");
    if (ssl) {
        return ssl->verifyCallback;
    }
    return NULL;
}

/* Adds the ASN1 certificate to the user ctx.
Returns WOLFSSL_SUCCESS if no error, returns WOLFSSL_FAILURE otherwise.*/
int wolfSSL_CTX_use_certificate_ASN1(WOLFSSL_CTX *ctx, int derSz,
                                                       const unsigned char *der)
{
    WOLFSSL_ENTER("wolfSSL_CTX_use_certificate_ASN1()");
    if (der != NULL && ctx != NULL) {
        if (wolfSSL_CTX_use_certificate_buffer(ctx, der, derSz,
                                      WOLFSSL_FILETYPE_ASN1) == WOLFSSL_SUCCESS) {
            return WOLFSSL_SUCCESS;
        }

    }
    return WOLFSSL_FAILURE;
}


#if !defined(HAVE_FAST_RSA) && defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)
/* Adds the rsa private key to the user ctx.
Returns WOLFSSL_SUCCESS if no error, returns WOLFSSL_FAILURE otherwise.*/
int wolfSSL_CTX_use_RSAPrivateKey(WOLFSSL_CTX* ctx, WOLFSSL_RSA* rsa)
{
    int ret;
    int derSize;
    unsigned char *maxDerBuf;
    unsigned char* key = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_use_RSAPrivateKey()");

    if (ctx == NULL || rsa == NULL) {
        WOLFSSL_MSG("one or more inputs were NULL");
        return BAD_FUNC_ARG;
    }
    maxDerBuf = (unsigned char*)XMALLOC(4096, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (maxDerBuf == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return MEMORY_E;
    }
    key = maxDerBuf;
    /* convert RSA struct to der encoded buffer and get the size */
    if ((derSize = wolfSSL_i2d_RSAPrivateKey(rsa, &key)) <= 0) {
        WOLFSSL_MSG("wolfSSL_i2d_RSAPrivateKey() failure");
        XFREE(maxDerBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, (const unsigned char*)maxDerBuf,
                                                    derSize, SSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_CTX_USE_PrivateKey_buffer() failure");
        XFREE(maxDerBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }
    XFREE(maxDerBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* NO_RSA && !HAVE_FAST_RSA */


#ifndef NO_BIO
/* Converts EVP_PKEY data from a bio buffer to a WOLFSSL_EVP_PKEY structure.
Returns pointer to private EVP_PKEY struct upon success, NULL if there
is a failure.*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO* bio,
                                                         WOLFSSL_EVP_PKEY** out)
{
    unsigned char* mem = NULL;
    int memSz = 0;
    WOLFSSL_EVP_PKEY* key = NULL;
    int i = 0, j = 0;
    unsigned char* extraBioMem = NULL;
    int extraBioMemSz = 0;
    int derLength = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_bio()");

    if (bio == NULL) {
        return NULL;
    }
    (void)out;

    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_get_len() failure");
        return NULL;
    }

    mem = (unsigned char*)XMALLOC(memSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return NULL;
    }

    if (wolfSSL_BIO_read(bio, (unsigned char*)mem, memSz) == memSz) {
        /* Determines key type and returns the new private EVP_PKEY object */
        if ((key = wolfSSL_d2i_PrivateKey_EVP(NULL, &mem, (long)memSz)) == NULL) {
            WOLFSSL_MSG("wolfSSL_d2i_PrivateKey_EVP() failure");
            XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* Write extra data back into bio object if necessary. */
        derLength = key->pkey_sz;
        extraBioMemSz = (memSz - derLength);
        if (extraBioMemSz > 0) {
            extraBioMem = (unsigned char *)XMALLOC(extraBioMemSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (extraBioMem == NULL) {
                WOLFSSL_MSG("Malloc failure");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }

            for (i = derLength; i < memSz; i++) {
                *(extraBioMem + j) = *(mem + i);
                j++;
            }

            wolfSSL_BIO_write(bio, extraBioMem, extraBioMemSz);
            if (wolfSSL_BIO_get_len(bio) <= 0) {
                WOLFSSL_MSG("Failed to write memory to bio");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
            XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        }

        if (out != NULL) {
            *out = key;
        }
    }
    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */


#if defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) ||  defined(WOLFSSL_NGINX)

/* Converts a DER encoded private key to a WOLFSSL_EVP_PKEY structure.
 * returns a pointer to a new WOLFSSL_EVP_PKEY structure on success and NULL
 * on fail */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** out,
                                                  unsigned char** in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_EVP");
    return d2iGenericKey(out, (const unsigned char**)in, inSz, 1);
}

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT || WOLFSSL_WPAS_SMALL*/


/* stunnel compatibility functions*/


#if  defined(HAVE_EX_DATA)


int wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION* session, int idx, void* data)
{
    int ret = WOLFSSL_FAILURE;
    WOLFSSL_ENTER("wolfSSL_SESSION_set_ex_data");
#ifdef HAVE_EX_DATA
    session = ClientSessionToSession(session);
    if (session != NULL) {
        {
            ret = wolfSSL_CRYPTO_set_ex_data(&session->ex_data, idx, data);
        }
    }
#else
    (void)session;
    (void)idx;
    (void)data;
#endif
    return ret;
}


void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION* session, int idx)
{
    void* ret = NULL;
    WOLFSSL_ENTER("wolfSSL_SESSION_get_ex_data");
#ifdef HAVE_EX_DATA
    session = ClientSessionToSession(session);
    if (session != NULL) {
        {
            ret = wolfSSL_CRYPTO_get_ex_data(&session->ex_data, idx);
        }
    }
#else
    (void)session;
    (void)idx;
#endif
    return ret;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || HAVE_EX_DATA */

/* Note: This is a huge section of API's - through
 *       wolfSSL_X509_OBJECT_get0_X509_CRL */



int wolfSSL_version(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_version");
    if (ssl->version.major == SSLv3_MAJOR) {
        switch (ssl->version.minor) {
            case SSLv3_MINOR :
                return SSL3_VERSION;
            case TLSv1_MINOR :
                return TLS1_VERSION;
            case TLSv1_1_MINOR :
                return TLS1_1_VERSION;
            case TLSv1_2_MINOR :
                return TLS1_2_VERSION;
            case TLSv1_3_MINOR :
                return TLS1_3_VERSION;
            default:
                return WOLFSSL_FAILURE;
        }
    }
    else if (ssl->version.major == DTLS_MAJOR) {
        switch (ssl->version.minor) {
            case DTLS_MINOR :
                return DTLS1_VERSION;
            case DTLSv1_2_MINOR :
                return DTLS1_2_VERSION;
            default:
                return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_FAILURE;
}

WOLFSSL_CTX* wolfSSL_get_SSL_CTX(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_SSL_CTX");
    return ssl->ctx;
}

#if defined(HAVE_STUNNEL) ||  defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

const byte* wolfSSL_SESSION_get_id(const WOLFSSL_SESSION* sess,
        unsigned int* idLen)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_get_id");
    sess = ClientSessionToSession(sess);
    if (sess == NULL || idLen == NULL) {
        WOLFSSL_MSG("Bad func args. Please provide idLen");
        return NULL;
    }
    *idLen = sess->sessionIDSz;
    return sess->sessionID;
}


#endif /* OPENSSL_ALL || OPENSSL_EXTRA || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#if defined(WOLFSSL_NGINX)

/* TODO: Doesn't currently track SSL_VERIFY_CLIENT_ONCE */
int wolfSSL_get_verify_mode(const WOLFSSL* ssl) {
    int mode = 0;
    WOLFSSL_ENTER("wolfSSL_get_verify_mode");

    if (!ssl) {
        return WOLFSSL_FAILURE;
    }

    if (ssl->options.verifyNone) {
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        if (ssl->options.verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ssl->options.failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ssl->options.failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_get_verify_mode", mode);
    return mode;
}

int wolfSSL_CTX_get_verify_mode(const WOLFSSL_CTX* ctx)
{
    int mode = 0;
    WOLFSSL_ENTER("wolfSSL_CTX_get_verify_mode");

    if (!ctx) {
        return WOLFSSL_FAILURE;
    }

    if (ctx->verifyNone) {
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        if (ctx->verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ctx->failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ctx->failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_get_verify_mode", mode);
    return mode;
}

#endif




#ifdef WOLFSSL_JNI

int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr)
{
    WOLFSSL_ENTER("wolfSSL_set_jobject");
    if (ssl != NULL)
    {
        ssl->jObjectRef = objPtr;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

void* wolfSSL_get_jobject(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_jobject");
    if (ssl != NULL)
        return ssl->jObjectRef;
    return NULL;
}

#endif /* WOLFSSL_JNI */




#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

/* converts an IPv6 or IPv4 address into an octet string for use with rfc3280
 * example input would be "127.0.0.1" and the returned value would be 7F000001
 */
WOLFSSL_ASN1_STRING* wolfSSL_a2i_IPADDRESS(const char* ipa)
{
    int ipaSz = WOLFSSL_IP4_ADDR_LEN;
    char buf[WOLFSSL_IP6_ADDR_LEN + 1]; /* plus 1 for terminator */
    int  af = WOLFSSL_IP4;
    WOLFSSL_ASN1_STRING *ret = NULL;

    if (ipa == NULL)
        return NULL;

    if (XSTRSTR(ipa, ":") != NULL) {
        af = WOLFSSL_IP6;
        ipaSz = WOLFSSL_IP6_ADDR_LEN;
    }

    buf[WOLFSSL_IP6_ADDR_LEN] = '\0';
    if (XINET_PTON(af, ipa, (void*)buf) != 1) {
        WOLFSSL_MSG("Error parsing IP address");
        return NULL;
    }

    ret = wolfSSL_ASN1_STRING_new();
    if (ret != NULL) {
        if (wolfSSL_ASN1_STRING_set(ret, buf, ipaSz) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error setting the string");
            wolfSSL_ASN1_STRING_free(ret);
            ret = NULL;
        }
    }

    return ret;
}

/* Is the specified cipher suite a fake one used an an extension proxy? */
static WC_INLINE int SCSV_Check(byte suite0, byte suite)
{
    (void)suite0;
    (void)suite;
#ifdef HAVE_RENEGOTIATION_INDICATION
    if (suite0 == CIPHER_BYTE && suite == TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        return 1;
#endif
    return 0;
}

static WC_INLINE int sslCipherMinMaxCheck(const WOLFSSL *ssl, byte suite0,
        byte suite)
{
    const CipherSuiteInfo* cipher_names = GetCipherNames();
    int cipherSz = GetCipherNamesSize();
    int i;
    for (i = 0; i < cipherSz; i++)
        if (cipher_names[i].cipherSuite0 == suite0 &&
                cipher_names[i].cipherSuite == suite)
            break;
    if (i == cipherSz)
        return 1;
    /* Check min version */
    if (cipher_names[i].minor < ssl->options.minDowngrade) {
        if (ssl->options.minDowngrade <= TLSv1_2_MINOR &&
                cipher_names[i].minor >= TLSv1_MINOR)
            /* 1.0 ciphersuites are in general available in 1.1 and
             * 1.1 ciphersuites are in general available in 1.2 */
            return 0;
        return 1;
    }
    /* Check max version */
    switch (cipher_names[i].minor) {
    case SSLv3_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_SSLv3;
    case TLSv1_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1;
    case TLSv1_1_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_1;
    case TLSv1_2_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2;
    case TLSv1_3_MINOR :
        return ssl->options.mask & WOLFSSL_OP_NO_TLSv1_3;
    default:
        WOLFSSL_MSG("Unrecognized minor version");
        return 1;
    }
}

/* returns a pointer to internal cipher suite list. Should not be free'd by
 * caller.
 */
WOLF_STACK_OF(WOLFSSL_CIPHER) *wolfSSL_get_ciphers_compat(const WOLFSSL *ssl)
{
    WOLF_STACK_OF(WOLFSSL_CIPHER)* ret = NULL;
    Suites* suites;

    WOLFSSL_ENTER("wolfSSL_get_ciphers_compat");
    if (ssl == NULL || (ssl->suites == NULL && ssl->ctx->suites == NULL)) {
        return NULL;
    }

    if (ssl->suites != NULL) {
        if (ssl->suites->suiteSz == 0 &&
                InitSSL_Suites((WOLFSSL*)ssl) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Suite initialization failure");
            return NULL;
        }
        suites = ssl->suites;
    }
    else {
        suites = ssl->ctx->suites;
    }

    /* check if stack needs populated */
    if (suites->stack == NULL) {
        int i;
        for (i = 0; i < suites->suiteSz; i+=2) {
            WOLFSSL_STACK* add;

            /* A couple of suites are placeholders for special options,
             * skip those. */
            if (SCSV_Check(suites->suites[i], suites->suites[i+1])
                    || sslCipherMinMaxCheck(ssl, suites->suites[i],
                                            suites->suites[i+1])) {
                continue;
            }

            add = wolfSSL_sk_new_node(ssl->heap);
            if (add != NULL) {
                add->type = STACK_TYPE_CIPHER;
                add->data.cipher.cipherSuite0 = suites->suites[i];
                add->data.cipher.cipherSuite  = suites->suites[i+1];
                add->data.cipher.ssl          = ssl;

                add->next = ret;
                if (ret != NULL) {
                    add->num = ret->num + 1;
                }
                else {
                    add->num = 1;
                }
                ret = add;
            }
        }
        suites->stack = ret;
    }
    return suites->stack;
}
#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_LIGHTY)
long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx)
{
    WOLFSSL_ENTER("wolfSSL_SSL_CTX_get_timeout");

    if (ctx == NULL)
        return 0;

    return ctx->timeout;
}


/* returns the time in seconds of the current timeout */
long wolfSSL_get_timeout(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_timeout");

    if (ssl == NULL)
        return 0;
    return ssl->timeout;
}
#endif

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_LIGHTY)

int wolfSSL_SSL_CTX_set_tmp_ecdh(WOLFSSL_CTX *ctx, WOLFSSL_EC_KEY *ecdh)
{
    WOLFSSL_ENTER("wolfSSL_SSL_CTX_set_tmp_ecdh");

    if (ctx == NULL || ecdh == NULL)
        return BAD_FUNC_ARG;

    ctx->ecdhCurveOID = ecdh->group->curve_oid;

    return WOLFSSL_SUCCESS;
}

/* Assumes that the session passed in is from the cache. */
int wolfSSL_SSL_CTX_remove_session(WOLFSSL_CTX *ctx, WOLFSSL_SESSION *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_CTX_remove_session");

    s = ClientSessionToSession(s);
    if (ctx == NULL || s == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_EXT_CACHE
    if (!ctx->internalCacheOff)
#endif
    {
        /* Don't remove session just timeout session. */
        s->timeout = 0;
    }

#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
    if (ctx->rem_sess_cb != NULL) {
        ctx->rem_sess_cb(ctx, s);
    }
#endif

    return 0;
}

#ifndef NO_BIO
BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_rbio");
    /* Nginx sets the buffer size if the read BIO is different to write BIO.
     * The setting buffer size doesn't do anything so return NULL for both.
     */
    if (s == NULL)
        return NULL;

    return s->biord;
}
BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_wbio");
    (void)s;
    /* Nginx sets the buffer size if the read BIO is different to write BIO.
     * The setting buffer size doesn't do anything so return NULL for both.
     */
    if (s == NULL)
        return NULL;

    return s->biowr;
}
#endif /* !NO_BIO */

int wolfSSL_SSL_do_handshake(WOLFSSL *s)
{
    WOLFSSL_ENTER("wolfSSL_SSL_do_handshake");

    if (s == NULL)
        return WOLFSSL_FAILURE;

    if (s->options.side == WOLFSSL_CLIENT_END) {
        return wolfSSL_connect(s);
    }

    WOLFSSL_MSG("Server not compiled in");
    return WOLFSSL_FAILURE;
}

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
int wolfSSL_SSL_in_init(const WOLFSSL *ssl)
#else
int wolfSSL_SSL_in_init(WOLFSSL *ssl)
#endif
{
    WOLFSSL_ENTER("SSL_in_init");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        return ssl->options.connectState < SECOND_REPLY_DONE;
    }
    return ssl->options.acceptState < ACCEPT_THIRD_REPLY_DONE;
}

int wolfSSL_SSL_in_connect_init(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("SSL_connect_init");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        return ssl->options.connectState > CONNECT_BEGIN &&
            ssl->options.connectState < SECOND_REPLY_DONE;
    }

    return ssl->options.acceptState > ACCEPT_BEGIN &&
        ssl->options.acceptState < ACCEPT_THIRD_REPLY_DONE;
}


#ifndef NO_BIO
int wolfSSL_a2i_ASN1_INTEGER(WOLFSSL_BIO *bio, WOLFSSL_ASN1_INTEGER *asn1,
        char *buf, int size)
{
    int readNextLine;
    int lineLen;
    int len;
    byte isNumCheck;
    word32 outLen;
    const int extraTagSz = MAX_LENGTH_SZ + 1;
    byte intTag[MAX_LENGTH_SZ + 1];
    int idx = 0;

    WOLFSSL_ENTER("wolfSSL_a2i_ASN1_INTEGER");

    if (!bio || !asn1 || !buf || size <= 0) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    /* Reset asn1 */
    if (asn1->isDynamic && asn1->data) {
        XFREE(asn1->data, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    XMEMSET(asn1->intData, 0, WOLFSSL_ASN1_INTEGER_MAX);
    asn1->data = asn1->intData;
    asn1->isDynamic = 0;
    asn1->length = 0;
    asn1->negative = 0;
    asn1->type = V_ASN1_INTEGER;

    lineLen = wolfSSL_BIO_gets(bio, buf, size);
    do {
        readNextLine = 0;
        if (lineLen <= 0) {
            WOLFSSL_MSG("wolfSSL_BIO_gets error");
            return WOLFSSL_FAILURE;
        }
        while (lineLen && (buf[lineLen-1] == '\n' || buf[lineLen-1] == '\r'))
            lineLen--;
        if (buf[lineLen-1] == '\\')
            readNextLine = 1;
        /* Ignore none-hex chars at the end of the line */
        outLen = 1;
        while (lineLen && Base16_Decode((byte*)buf + lineLen - 1, 1,
                &isNumCheck, &outLen) == ASN_INPUT_E)
            lineLen--;
        if (!lineLen || lineLen % 2) {
            WOLFSSL_MSG("Invalid line length");
            return WOLFSSL_FAILURE;
        }
        len = asn1->length + (lineLen/2);
        /* Check if it will fit in static memory and
         * save space for the ASN tag in front */
        if (len > (int)(WOLFSSL_ASN1_INTEGER_MAX - extraTagSz)) {
            /* Allocate mem for data */
            if (asn1->isDynamic) {
                byte* tmp = (byte*)XREALLOC(asn1->data, len + extraTagSz, NULL,
                        DYNAMIC_TYPE_OPENSSL);
                if (!tmp) {
                    WOLFSSL_MSG("realloc error");
                    return WOLFSSL_FAILURE;
                }
                asn1->data = tmp;
            }
            else {
                /* Up to this point asn1->data pointed to asn1->intData.
                 * Now that the size has grown larger than intData can handle
                 * the asn1 structure moves to a dynamic type with isDynamic
                 * flag being set and asn1->data being malloc'd. */
                asn1->data = (byte*)XMALLOC(len + extraTagSz, NULL,
                        DYNAMIC_TYPE_OPENSSL);
                if (!asn1->data) {
                    WOLFSSL_MSG("malloc error");
                    return WOLFSSL_FAILURE;
                }
                asn1->isDynamic = 1;
                XMEMCPY(asn1->data, asn1->intData, asn1->length);
            }
        }
        len = lineLen/2;
        if (Base16_Decode((byte*)buf, lineLen, asn1->data + asn1->length,
                (word32*)&len) != 0) {
            WOLFSSL_MSG("Base16_Decode error");
            return WOLFSSL_FAILURE;
        }
        asn1->length += len;
    } while (readNextLine);

    /* Write ASN tag */
    idx = SetASNInt(asn1->length, asn1->data[0], intTag);
    XMEMMOVE(asn1->data + idx, asn1->data, asn1->length);
    XMEMCPY(asn1->data, intTag, idx);
    asn1->dataMax = asn1->length += idx;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_i2a_ASN1_INTEGER(BIO *bp, const WOLFSSL_ASN1_INTEGER *a)
{
    word32 idx = 1;
    int len = 0;
    byte buf[512];
    word32 bufLen = 512;

    WOLFSSL_ENTER("wolfSSL_i2a_ASN1_INTEGER");

    if (bp == NULL || a == NULL)
        return WOLFSSL_FAILURE;

    /* Skip ASN.1 INTEGER (type) byte. */
    if (a->data[idx] == 0x80 || /* Indefinite length, can't determine length */
            GetLength(a->data, &idx, &len, a->length) < 0) {
        return 0;
    }

    /* Zero length integer is the value zero. */
    if (len == 0) {
        return wolfSSL_BIO_write(bp, "00", 2);
    }

    if (Base16_Encode(a->data + idx, len, buf, &bufLen) != 0 ||
            bufLen == 0) {
        return 0;
    }

    return wolfSSL_BIO_write(bp, buf, bufLen - 1); /* Don't write out NULL char */
}
#endif /* !NO_BIO */



#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
#endif /* OPENSSL_ALL || WOLFSSL_NGINX  || WOLFSSL_HAPROXY */



#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx, WOLF_STACK_OF(X509)** chain)
{
    word32         idx;
    word32         length;
    WOLFSSL_STACK* node;
    WOLFSSL_STACK* last = NULL;

    if (ctx == NULL || chain == NULL) {
        chain = NULL;
        return WOLFSSL_FAILURE;
    }
    if (ctx->x509Chain != NULL) {
        *chain = ctx->x509Chain;
        return WOLFSSL_SUCCESS;
    }

    /* If there are no chains then success! */
    *chain = NULL;
    if (ctx->certChain == NULL || ctx->certChain->length == 0) {
        return WOLFSSL_SUCCESS;
    }

    /* Create a new stack of WOLFSSL_X509 object from chain buffer. */
    for (idx = 0; idx < ctx->certChain->length; ) {
        node = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
                                       DYNAMIC_TYPE_OPENSSL);
        if (node == NULL)
            return WOLFSSL_FAILURE;
        node->next = NULL;

        /* 3 byte length | X509 DER data */
        ato24(ctx->certChain->buffer + idx, &length);
        idx += 3;

        /* Create a new X509 from DER encoded data. */
        node->data.x509 = wolfSSL_X509_d2i(NULL, ctx->certChain->buffer + idx,
            length);
        if (node->data.x509 == NULL) {
            XFREE(node, NULL, DYNAMIC_TYPE_OPENSSL);
            /* Return as much of the chain as we created. */
            ctx->x509Chain = *chain;
            return WOLFSSL_FAILURE;
        }
        idx += length;

        /* Add object to the end of the stack. */
        if (last == NULL) {
            node->num = 1;
            *chain = node;
        }
        else {
            (*chain)->num++;
            last->next = node;
        }

        last = node;
    }

    ctx->x509Chain = *chain;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb)
{
    if (ctx == NULL || ctx->cm == NULL || cb == NULL)
        return WOLFSSL_FAILURE;

    (void)cb;
    *cb = NULL;

    return WOLFSSL_SUCCESS;

}

int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb)
{
    if (ctx == NULL || ctx->cm == NULL)
        return WOLFSSL_FAILURE;

    (void)cb;

    return WOLFSSL_SUCCESS;
}

int wolfSSL_CTX_get0_chain_certs(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get0_chain_certs");
    if (ctx == NULL || sk == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }
    *sk = ctx->x509Chain;
    return WOLFSSL_SUCCESS;
}

#ifdef KEEP_OUR_CERT
int wolfSSL_get0_chain_certs(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    WOLFSSL_ENTER("wolfSSL_get0_chain_certs");
    if (ssl == NULL || sk == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }
    *sk = ssl->ourCertChain;
    return WOLFSSL_SUCCESS;
}
#endif

WOLF_STACK_OF(WOLFSSL_STRING)* wolfSSL_sk_WOLFSSL_STRING_new(void)
{
    WOLF_STACK_OF(WOLFSSL_STRING)* ret = wolfSSL_sk_new_node(NULL);

    if (ret) {
        ret->type = STACK_TYPE_STRING;
    }

    return ret;
}

void wolfSSL_WOLFSSL_STRING_free(WOLFSSL_STRING s)
{
    WOLFSSL_ENTER("wolfSSL_WOLFSSL_STRING_free");

    if (s != NULL)
        XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);
}

void wolfSSL_sk_WOLFSSL_STRING_free(WOLF_STACK_OF(WOLFSSL_STRING)* sk)
{
    WOLFSSL_STACK* tmp;
    WOLFSSL_ENTER("wolfSSL_sk_WOLFSSL_STRING_free");

    if (sk == NULL)
        return;

    /* parse through stack freeing each node */
    while (sk) {
        tmp = sk->next;
        XFREE(sk->data.string, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
        sk = tmp;
    }
}

WOLFSSL_STRING wolfSSL_sk_WOLFSSL_STRING_value(WOLF_STACK_OF(WOLFSSL_STRING)* strings,
    int idx)
{
    for (; idx > 0 && strings != NULL; idx--)
        strings = strings->next;
    if (strings == NULL)
        return NULL;
    return strings->data.string;
}

int wolfSSL_sk_WOLFSSL_STRING_num(WOLF_STACK_OF(WOLFSSL_STRING)* strings)
{
    if (strings)
        return (int)strings->num;
    return 0;
}

#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

#if defined(WOLFSSL_NGINX) ||  defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY)
#ifdef HAVE_ALPN
void wolfSSL_get0_alpn_selected(const WOLFSSL *ssl, const unsigned char **data,
                                unsigned int *len)
{
    word16 nameLen;

    if (ssl != NULL && data != NULL && len != NULL) {
        TLSX_ALPN_GetRequest(ssl->extensions, (void **)data, &nameLen);
        *len = nameLen;
    }
}

int wolfSSL_select_next_proto(unsigned char **out, unsigned char *outLen,
                              const unsigned char *in, unsigned int inLen,
                              const unsigned char *clientNames,
                              unsigned int clientLen)
{
    unsigned int i, j;
    byte lenIn, lenClient;

    if (out == NULL || outLen == NULL || in == NULL || clientNames == NULL)
        return OPENSSL_NPN_UNSUPPORTED;

    for (i = 0; i < inLen; i += lenIn) {
        lenIn = in[i++];
        for (j = 0; j < clientLen; j += lenClient) {
            lenClient = clientNames[j++];

            if (lenIn != lenClient)
                continue;

            if (XMEMCMP(in + i, clientNames + j, lenIn) == 0) {
                *out = (unsigned char *)(in + i);
                *outLen = lenIn;
                return OPENSSL_NPN_NEGOTIATED;
            }
        }
    }

    *out = (unsigned char *)clientNames + 1;
    *outLen = clientNames[0];
    return OPENSSL_NPN_NO_OVERLAP;
}

void wolfSSL_CTX_set_alpn_select_cb(WOLFSSL_CTX *ctx,
                                    int (*cb) (WOLFSSL *ssl,
                                               const unsigned char **out,
                                               unsigned char *outlen,
                                               const unsigned char *in,
                                               unsigned int inlen,
                                               void *arg), void *arg)
{
    if (ctx != NULL) {
        ctx->alpnSelect = cb;
        ctx->alpnSelectArg = arg;
    }
}

void wolfSSL_CTX_set_next_protos_advertised_cb(WOLFSSL_CTX *s,
                                           int (*cb) (WOLFSSL *ssl,
                                                      const unsigned char
                                                      **out,
                                                      unsigned int *outlen,
                                                      void *arg), void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_protos_advertised_cb");
}

void wolfSSL_CTX_set_next_proto_select_cb(WOLFSSL_CTX *s,
                                      int (*cb) (WOLFSSL *ssl,
                                                 unsigned char **out,
                                                 unsigned char *outlen,
                                                 const unsigned char *in,
                                                 unsigned int inlen,
                                                 void *arg), void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_proto_select_cb");
}

void wolfSSL_get0_next_proto_negotiated(const WOLFSSL *s, const unsigned char **data,
                                    unsigned *len)
{
    (void)s;
    (void)data;
    (void)len;
    WOLFSSL_STUB("wolfSSL_get0_next_proto_negotiated");
}
#endif /* HAVE_ALPN */

#endif /* WOLFSSL_NGINX  / WOLFSSL_HAPROXY */









#ifndef NO_CERT
#define WOLFSSL_X509_INCLUDED
#include "src/x509.c"
#endif

/*******************************************************************************
 * START OF standard C library wrapping APIs
 ******************************************************************************/


/*******************************************************************************
 * END OF standard C library wrapping APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF EX_DATA APIs
 ******************************************************************************/

#ifdef HAVE_EX_DATA
void* wolfSSL_CRYPTO_get_ex_data(const WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_get_ex_data");
#ifdef MAX_EX_DATA
    if(ex_data && idx < MAX_EX_DATA && idx >= 0) {
        return ex_data->ex_data[idx];
    }
#else
    (void)ex_data;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_CRYPTO_set_ex_data(WOLFSSL_CRYPTO_EX_DATA* ex_data, int idx, void *data)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_set_ex_data");
#ifdef MAX_EX_DATA
    if (ex_data && idx < MAX_EX_DATA && idx >= 0) {
        ex_data->ex_data[idx] = data;
        return WOLFSSL_SUCCESS;
    }
#else
    (void)ex_data;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}


/**
 * Issues unique index for the class specified by class_index.
 * Other parameter except class_index are ignored.
 * Currently, following class_index are accepted:
 *  - WOLF_CRYPTO_EX_INDEX_SSL
 *  - WOLF_CRYPTO_EX_INDEX_SSL_CTX
 *  - WOLF_CRYPTO_EX_INDEX_X509
 * @param class_index index one of CRYPTO_EX_INDEX_xxx
 * @param argp  parameters to be saved
 * @param argl  parameters to be saved
 * @param new_func a pointer to WOLFSSL_CRYPTO_EX_new
 * @param dup_func a pointer to WOLFSSL_CRYPTO_EX_dup
 * @param free_func a pointer to WOLFSSL_CRYPTO_EX_free
 * @return index value grater or equal to zero on success, -1 on failure.
 */
int wolfSSL_CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                                           WOLFSSL_CRYPTO_EX_new* new_func,
                                           WOLFSSL_CRYPTO_EX_dup* dup_func,
                                           WOLFSSL_CRYPTO_EX_free* free_func)
{
    WOLFSSL_ENTER("wolfSSL_CRYPTO_get_ex_new_index");
    (void)argl;
    (void)argp;
    (void)new_func;
    (void)dup_func;
    (void)free_func;

    return wolfssl_get_ex_new_index(class_index);
}
#endif /* HAVE_EX_DATA */

/*******************************************************************************
 * END OF EX_DATA APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF BUF_MEM API
 ******************************************************************************/


/*******************************************************************************
 * END OF BUF_MEM API
 ******************************************************************************/

#define WOLFSSL_CONF_INCLUDED
#include <src/conf.c>

/*******************************************************************************
 * START OF RAND API
 ******************************************************************************/



/*******************************************************************************
 * END OF RAND API
 ******************************************************************************/

/*******************************************************************************
 * START OF EVP_CIPHER API
 ******************************************************************************/


/*******************************************************************************
 * END OF EVP_CIPHER API
 ******************************************************************************/


#define WOLFSSL_X509_STORE_INCLUDED
#include <src/x509_str.c>

/*******************************************************************************
 * START OF PKCS7 APIs
 ******************************************************************************/
#ifdef HAVE_PKCS7


#endif /* HAVE_PKCS7 */
/*******************************************************************************
 * END OF PKCS7 APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF PKCS12 APIs
 ******************************************************************************/

#if defined(HAVE_PKCS12)


#endif /* HAVE_PKCS12 */
/*******************************************************************************
 * END OF PKCS12 APIs
 ******************************************************************************/



/*******************************************************************************
 * BEGIN OPENSSL FIPS DRBG APIs
 ******************************************************************************/
/*******************************************************************************
 * END OF OPENSSL FIPS DRBG APIs
 ******************************************************************************/


#endif /* !WOLFCRYPT_ONLY */

/*******************************************************************************
 * START OF CRYPTO-ONLY APIs
 ******************************************************************************/

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) ||  defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) ||  defined(WOLFSSL_HAPROXY)

    /* One shot SHA1 hash of message.
     *
     * d  message to hash
     * n  size of d buffer
     * md buffer to hold digest. Should be SHA_DIGEST_SIZE.
     *
     * Note: if md is null then a static buffer of SHA_DIGEST_SIZE is used.
     *       When the static buffer is used this function is not thread safe.
     *
     * Returns a pointer to the message digest on success and NULL on failure.
     */
    unsigned char *wolfSSL_SHA1(const unsigned char *d, size_t n,
            unsigned char *md)
    {
        static byte dig[WC_SHA_DIGEST_SIZE];
        byte* ret = md;
        wc_Sha sha;

        WOLFSSL_ENTER("wolfSSL_SHA1");

        if (wc_InitSha_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WOLFSSL_MSG("SHA1 Init failed");
            return NULL;
        }

        if (wc_ShaUpdate(&sha, (const byte*)d, (word32)n) != 0) {
            WOLFSSL_MSG("SHA1 Update failed");
            return NULL;
        }

        if (md == NULL) {
            WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA1 IS NOT "
                        "THREAD SAFE WHEN md == NULL");
            ret = dig;
        }
        if (wc_ShaFinal(&sha, ret) != 0) {
            WOLFSSL_MSG("SHA1 Final failed");
            wc_ShaFree(&sha);
            return NULL;
        }
        wc_ShaFree(&sha);

        return ret;
    }

    /* One shot SHA224 hash of message.
     *
     * d  message to hash
     * n  size of d buffer
     * md buffer to hold digest. Should be WC_SHA224_DIGEST_SIZE.
     *
     * Note: if md is null then a static buffer of WC_SHA256_DIGEST_SIZE is used.
     *       When the static buffer is used this function is not thread safe.
     *
     * Returns a pointer to the message digest on success and NULL on failure.
     */
      unsigned char *wolfSSL_SHA224(const unsigned char *d, size_t n,
            unsigned char *md)
     {
        static byte dig[WC_SHA224_DIGEST_SIZE];
        byte* ret = md;
        wc_Sha256 sha;

        WOLFSSL_ENTER("wolfSSL_SHA224");

        if (wc_InitSha224_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WOLFSSL_MSG("SHA224 Init failed");
            return NULL;
        }

        if (wc_Sha224Update(&sha, (const byte*)d, (word32)n) != 0) {
            WOLFSSL_MSG("SHA224 Update failed");
            return NULL;
        }

        if (md == NULL) {
            WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA224 IS NOT "
                        "THREAD SAFE WHEN md == NULL");
            ret = dig;
        }
        if (wc_Sha224Final(&sha, ret) != 0) {
            WOLFSSL_MSG("SHA224 Final failed");
            wc_Sha224Free(&sha);
            return NULL;
        }
        wc_Sha224Free(&sha);

        return ret;
    }

    /* One shot SHA256 hash of message.
     *
     * d  message to hash
     * n  size of d buffer
     * md buffer to hold digest. Should be WC_SHA256_DIGEST_SIZE.
     *
     * Note: if md is null then a static buffer of WC_SHA256_DIGEST_SIZE is used.
     *       When the static buffer is used this function is not thread safe.
     *
     * Returns a pointer to the message digest on success and NULL on failure.
     */
    unsigned char *wolfSSL_SHA256(const unsigned char *d, size_t n,
            unsigned char *md)
    {
        static byte dig[WC_SHA256_DIGEST_SIZE];
        byte* ret = md;
        wc_Sha256 sha;

        WOLFSSL_ENTER("wolfSSL_SHA256");

        if (wc_InitSha256_ex(&sha, NULL, INVALID_DEVID) != 0) {
            WOLFSSL_MSG("SHA256 Init failed");
            return NULL;
        }

        if (wc_Sha256Update(&sha, (const byte*)d, (word32)n) != 0) {
            WOLFSSL_MSG("SHA256 Update failed");
            return NULL;
        }

        if (md == NULL) {
            WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA256 IS NOT "
                        "THREAD SAFE WHEN md == NULL");
            ret = dig;
        }
        if (wc_Sha256Final(&sha, ret) != 0) {
            WOLFSSL_MSG("SHA256 Final failed");
            wc_Sha256Free(&sha);
            return NULL;
        }
        wc_Sha256Free(&sha);

        return ret;
    }

     /* One shot SHA384 hash of message.
      *
      * d  message to hash
      * n  size of d buffer
      * md buffer to hold digest. Should be WC_SHA256_DIGEST_SIZE.
      *
      * Note: if md is null then a static buffer of WC_SHA256_DIGEST_SIZE is used.
      *       When the static buffer is used this function is not thread safe.
      *
      * Returns a pointer to the message digest on success and NULL on failure.
      */
     unsigned char *wolfSSL_SHA384(const unsigned char *d, size_t n,
             unsigned char *md)
     {
         static byte dig[WC_SHA384_DIGEST_SIZE];
         byte* ret = md;
         wc_Sha384 sha;

         WOLFSSL_ENTER("wolfSSL_SHA384");

         if (wc_InitSha384_ex(&sha, NULL, INVALID_DEVID) != 0) {
             WOLFSSL_MSG("SHA384 Init failed");
             return NULL;
         }

         if (wc_Sha384Update(&sha, (const byte*)d, (word32)n) != 0) {
             WOLFSSL_MSG("SHA384 Update failed");
             return NULL;
         }

         if (md == NULL) {
             WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA384 IS NOT "
                         "THREAD SAFE WHEN md == NULL");
             ret = dig;
         }
         if (wc_Sha384Final(&sha, ret) != 0) {
             WOLFSSL_MSG("SHA384 Final failed");
             wc_Sha384Free(&sha);
             return NULL;
         }
         wc_Sha384Free(&sha);

         return ret;
     }

     /* One shot SHA512 hash of message.
      *
      * d  message to hash
      * n  size of d buffer
      * md buffer to hold digest. Should be WC_SHA256_DIGEST_SIZE.
      *
      * Note: if md is null then a static buffer of WC_SHA256_DIGEST_SIZE is used.
      *       When the static buffer is used this function is not thread safe.
      *
      * Returns a pointer to the message digest on success and NULL on failure.
      */
     unsigned char *wolfSSL_SHA512(const unsigned char *d, size_t n,
             unsigned char *md)
     {
         static byte dig[WC_SHA512_DIGEST_SIZE];
         byte* ret = md;
         wc_Sha512 sha;

         WOLFSSL_ENTER("wolfSSL_SHA512");

         if (wc_InitSha512_ex(&sha, NULL, INVALID_DEVID) != 0) {
             WOLFSSL_MSG("SHA512 Init failed");
             return NULL;
         }

         if (wc_Sha512Update(&sha, (const byte*)d, (word32)n) != 0) {
             WOLFSSL_MSG("SHA512 Update failed");
             return NULL;
         }

         if (md == NULL) {
             WOLFSSL_MSG("STATIC BUFFER BEING USED. wolfSSL_SHA512 IS NOT "
                         "THREAD SAFE WHEN md == NULL");
             ret = dig;
         }
         if (wc_Sha512Final(&sha, ret) != 0) {
             WOLFSSL_MSG("SHA512 Final failed");
             wc_Sha512Free(&sha);
             return NULL;
         }
         wc_Sha512Free(&sha);

         return ret;
     }
#endif /* OPENSSL_EXTRA || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
        * HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */

/*******************************************************************************
 * END OF CRYPTO-ONLY APIs
 ******************************************************************************/
