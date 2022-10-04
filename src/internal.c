/* internal.c
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

int const WOLFSSL_GENERAL_ALIGNMENT = 16; // Fabio: For intel instructions, coan

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
 * WOLFSSL_SMALL_CERT_VERIFY:
 *     Verify the certificate signature without using DecodedCert. Doubles up
 *     on some code but allows smaller peak heap memory usage.
 *     Cannot be used with WOLFSSL_NONBLOCK_OCSP.
 * WOLFSSL_ALT_CERT_CHAINS:
 *     Allows CA's to be presented by peer, but not part of a valid chain.
 *     Default wolfSSL behavior is to require validation of all presented peer
 *     certificates. This also allows loading intermediate CA's as trusted
 *     and ignoring no signer failures for CA's up the chain to root.
 * WOLFSSL_DTLS_RESEND_ONLY_TIMEOUT:
 *     Enable resending the previous DTLS handshake flight only on a network
 *     read timeout. By default we resend in two more cases, when we receive:
 *     - an out of order last msg of the peer's flight
 *     - a duplicate of the first msg from the peer's flight
 * WOLFSSL_NO_DEF_TICKET_ENC_CB:
 *     No default ticket encryption callback.
 *     Server only.
 *     Application must set its own callback to use session tickets.
 * WOLFSSL_TICKET_ENC_CHACHA20_POLY1305
 *     Use ChaCha20-Poly1305 to encrypt/decrypt session tickets in default
 *     callback. Default algorithm if none defined and algorithms compiled in.
 *     Server only.
 * WOLFSSL_TICKET_ENC_AES128_GCM
 *     Use AES128-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only. Default algorithm if ChaCha20/Poly1305 not compiled in.
 * WOLFSSL_TICKET_ENC_AES256_GCM
 *     Use AES256-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only.
 * WOLFSSL_TICKET_DECRYPT_NO_CREATE
 *     Default callback will not request creation of new ticket on successful
 *     decryption.
 *     Server only.
 * WOLFSSL_TLS13_NO_PEEK_HANDSHAKE_DONE
 *     Once a normal TLS 1.3 handshake is complete, a session ticket message
 *     may be received by a client. To support detecting this, peek will
 *     return WOLFSSL_ERROR_WANT_READ.
 *     This define turns off this behaviour.
 */


#ifdef EXTERNAL_OPTS_OPENVPN
#error EXTERNAL_OPTS_OPENVPN should not be defined\
    when building wolfSSL
#endif

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>



    #ifndef NO_STDIO_FILESYSTEM
            #include <stdio.h>
    #endif



#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }





    static int DoHelloVerifyRequest(WOLFSSL* ssl, const byte* input,
                                    word32* inOutIdx, word32 size);
    static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                                   word32* inOutIdx, word32 size);
        static int DoCertificateRequest(WOLFSSL* ssl, const byte* input,
                                        word32* inOutIdx, word32 size);





    static int cipherExtraData(WOLFSSL* ssl);

enum processReply {
    doProcessInit = 0,
    getRecordLayerHeader,
    getData,
    verifyEncryptedMessage,
    decryptMessage,
    verifyMessage,
    runProcessingOneMessage
};



/* Server random bytes for TLS v1.3 described downgrade protection mechanism. */
static const byte tls13Downgrade[7] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44
};
#define TLS13_DOWNGRADE_SZ  sizeof(tls13Downgrade)


static int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
                    int padLen, int content, int verify, int epochOrder);




#if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif


int IsTLS(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINOR)
        return 1;

    return 0;
}

int IsAtLeastTLSv1_3(const ProtocolVersion pv)
{
    return (pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_3_MINOR);
}

static WC_INLINE int IsEncryptionOn(WOLFSSL* ssl, int isSend)
{

    return ssl->keys.encryptionOn &&
        (isSend ? ssl->encrypt.setup : ssl->decrypt.setup);
}








void InitSSL_Method(WOLFSSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = WOLFSSL_CLIENT_END;
    method->downgrade  = 0;
}


/* Initialize SSL context, return 0 on success */
int InitSSL_Ctx(WOLFSSL_CTX* ctx, WOLFSSL_METHOD* method, void* heap)
{
    int ret = 0;

    XMEMSET(ctx, 0, sizeof(WOLFSSL_CTX));

    ctx->method   = method;
    ctx->refCount = 1;          /* so either CTX_free or SSL_free can release */
    ctx->heap     = ctx;        /* defaults to self */
    ctx->timeout  = WOLFSSL_SESSION_TIMEOUT;
    ctx->minDowngrade = WOLFSSL_MIN_DOWNGRADE; /* current default: TLSv1_MINOR */

    if (wc_InitMutex(&ctx->countMutex) < 0) {
        WOLFSSL_MSG("Mutex error on CTX init");
        ctx->err = CTX_INIT_MUTEX_E;
        return BAD_MUTEX_E;
    }

    ctx->privateKeyDevId = INVALID_DEVID;

    ctx->minDhKeySz  = MIN_DHKEY_SZ;
    ctx->maxDhKeySz  = MAX_DHKEY_SZ;
    ctx->minRsaKeySz = MIN_RSAKEY_SZ;
    ctx->minEccKeySz  = MIN_ECCKEY_SZ;
    ctx->eccTempKeySz = ECDHE_SIZE;
    ctx->verifyDepth = MAX_CHAIN_DEPTH;

#ifdef HAVE_NETX
    ctx->CBIORecv = NetX_Receive;
    ctx->CBIOSend = NetX_Send;
#elif defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    ctx->CBIORecv = Mynewt_Receive;
    ctx->CBIOSend = Mynewt_Send;
#elif defined WOLFSSL_LWIP_NATIVE
    ctx->CBIORecv = LwIPNativeReceive;
    ctx->CBIOSend = LwIPNativeSend;
#elif defined(WOLFSSL_GNRC)
    ctx->CBIORecv = GNRC_ReceiveFrom;
    ctx->CBIOSend = GNRC_SendTo;
#elif defined WOLFSSL_ISOTP
    ctx->CBIORecv = ISOTP_Receive;
    ctx->CBIOSend = ISOTP_Send;
#else
    #ifdef MICRIUM
        ctx->CBIORecv = MicriumReceive;
        ctx->CBIOSend = MicriumSend;
    #else
        ctx->CBIORecv = EmbedReceive;
        ctx->CBIOSend = EmbedSend;
    #endif /* MICRIUM */
#endif /* WOLFSSL_USER_IO */

    if (method->side == WOLFSSL_CLIENT_END) {
        ctx->haveECDSAsig  = 1;        /* always on client side */
        ctx->haveECC  = 1;             /* server turns on with ECC key cert */
        ctx->haveStaticECC = 1;        /* server can turn on by loading key */
    }

    ctx->devId = INVALID_DEVID;


    ctx->cm = wolfSSL_CertManagerNew_ex(heap);
    if (ctx->cm == NULL) {
        WOLFSSL_MSG("Bad Cert Manager New");
        return BAD_CERT_MANAGER_ERROR;
    }

    if (method->side == WOLFSSL_CLIENT_END) {
        if ((method->version.major == SSLv3_MAJOR) &&
             (method->version.minor >= TLSv1_MINOR)) {

            ctx->haveEMS = 1;
        }
    }




    ctx->heap = heap; /* wolfSSL_CTX_load_static_memory sets */


    return ret;
}



/* In case contexts are held in array and don't want to free actual ctx. */

/* The allocations done in InitSSL_Ctx must be free'd with ctx->onHeapHint
 * logic. A WOLFSSL_CTX can be assigned a static memory heap hint using
 * wolfSSL_CTX_load_static_memory after CTX creation, which means variables
 * allocated in InitSSL_Ctx were allocated from heap and should be free'd with
 * a NULL heap hint. */
void SSL_CtxResourceFree(WOLFSSL_CTX* ctx)
{
    void* heapAtCTXInit = ctx->heap;



    XFREE(ctx->method, heapAtCTXInit, DYNAMIC_TYPE_METHOD);
    ctx->method = NULL;

    if (ctx->suites) {
        XFREE(ctx->suites, ctx->heap, DYNAMIC_TYPE_SUITES);
        ctx->suites = NULL;
    }

    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_G.buffer = NULL;
    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_P.buffer = NULL;


    FreeDer(&ctx->privateKey);
    FreeDer(&ctx->certificate);
    #ifdef KEEP_OUR_CERT
        if (ctx->ourCert && ctx->ownOurCert) {
            wolfSSL_X509_free(ctx->ourCert);
            ctx->ourCert = NULL;
        }
    #endif /* KEEP_OUR_CERT */
    FreeDer(&ctx->certChain);
    wolfSSL_CertManagerFree(ctx->cm);
    ctx->cm = NULL;
    #if defined(HAVE_LIGHTY)
        wolfSSL_sk_X509_NAME_pop_free(ctx->ca_names, NULL);
        ctx->ca_names = NULL;
    #endif

    TLSX_FreeAll(ctx->extensions, ctx->heap);


    (void)heapAtCTXInit;
}


void FreeSSL_Ctx(WOLFSSL_CTX* ctx)
{
    int refCount;
    void* heap = ctx->heap;

    /* decrement CTX reference count */
    if ((refCount = SSL_CTX_RefCount(ctx, -1)) < 0) {
        /* check error state, if mutex error code then mutex init failed but
         * CTX was still malloc'd */
        if (ctx->err == CTX_INIT_MUTEX_E) {
            SSL_CtxResourceFree(ctx);
            XFREE(ctx, heap, DYNAMIC_TYPE_CTX);
        }
        return;
    }

    if (refCount == 0) {
        WOLFSSL_MSG("CTX ref count down to 0, doing full free");

        SSL_CtxResourceFree(ctx);
        wc_FreeMutex(&ctx->countMutex);
        XFREE(ctx, heap, DYNAMIC_TYPE_CTX);
    }
    else {
        WOLFSSL_MSG("CTX ref count not 0 yet, no free");
    }
    (void)heap; /* not used in some builds */
}


/* Set cipher pointers to null */
void InitCiphers(WOLFSSL* ssl)
{
    ssl->encrypt.aes = NULL;
    ssl->decrypt.aes = NULL;
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
    ssl->auth.poly1305 = NULL;
    ssl->encrypt.setup = 0;
    ssl->decrypt.setup = 0;
    ssl->auth.setup    = 0;
}


/* Free ciphers */
void FreeCiphers(WOLFSSL* ssl)
{
    (void)ssl;
    wc_AesFree(ssl->encrypt.aes);
    wc_AesFree(ssl->decrypt.aes);
        XFREE(ssl->decrypt.additional, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
        XFREE(ssl->encrypt.additional, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
    XFREE(ssl->encrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.nonce, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
    XFREE(ssl->encrypt.nonce, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
    XFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->auth.poly1305, ssl->heap, DYNAMIC_TYPE_CIPHER);
}


void InitCipherSpecs(CipherSpecs* cs)
{
    XMEMSET(cs, 0, sizeof(CipherSpecs));

    cs->bulk_cipher_algorithm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea                   = INVALID_BYTE;
    cs->sig_algo              = INVALID_BYTE;
}

static int GetMacDigestSize(byte macAlgo)
{
    switch (macAlgo) {
        case sha_mac:
            return WC_SHA_DIGEST_SIZE;
        case sha256_mac:
            return WC_SHA256_DIGEST_SIZE;
        case sha384_mac:
            return WC_SHA384_DIGEST_SIZE;
        case sha512_mac:
            return WC_SHA512_DIGEST_SIZE;
        default:
            break;
    }
    return NOT_COMPILED_IN;
}

static WC_INLINE void AddSuiteHashSigAlgo(Suites* suites, byte macAlgo,
    byte sigAlgo, int keySz, word16* inOutIdx)
{
    int addSigAlgo = 1;

    if (sigAlgo == ecc_dsa_sa_algo) {
        int digestSz = GetMacDigestSize(macAlgo);
        /* do not add sig/algos with digest size larger than key size */
        if (digestSz <= 0 || (keySz > 0 && digestSz > keySz)) {
            addSigAlgo = 0;
        }
    }

    if (addSigAlgo) {
        {
            suites->hashSigAlgo[*inOutIdx] = macAlgo;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = sigAlgo;
            *inOutIdx += 1;
        }
    }
}

void InitSuitesHashSigAlgo(Suites* suites, int haveECDSAsig, int haveRSAsig,
                           int haveFalconSig, int haveAnon, int tls1_2,
                           int keySz)
{
    word16 idx = 0;

    (void)tls1_2;
    (void)keySz;

    if (haveECDSAsig) {
        AddSuiteHashSigAlgo(suites, sha512_mac, ecc_dsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha384_mac, ecc_dsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha256_mac, ecc_dsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha_mac, ecc_dsa_sa_algo, keySz, &idx);
    }
    if (haveFalconSig) {
    }
    if (haveRSAsig) {
        AddSuiteHashSigAlgo(suites, sha512_mac, rsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha384_mac, rsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha256_mac, rsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha224_mac, rsa_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, sha_mac, rsa_sa_algo, keySz, &idx);
    }


    (void)haveAnon;
    (void)haveECDSAsig;
    suites->hashSigAlgoSz = idx;
}

void InitSuites(Suites* suites, ProtocolVersion pv, int keySz, word16 haveRSA,
                word16 havePSK, word16 haveDH, word16 haveECDSAsig,
                word16 haveECC, word16 haveStaticECC,  word16 haveFalconSig,
                word16 haveAnon, int side)
{
    word16 idx = 0;
    int    tls    = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
    int    dtls   = 0;
    int    haveRSAsig = 1;

    (void)tls;  /* shut up compiler */
    (void)tls1_2;
    (void)dtls;
    (void)haveDH;
    (void)havePSK;
    (void)haveStaticECC;
    (void)haveECC;
    (void)side;
    (void)haveRSA;    /* some builds won't read */
    (void)haveRSAsig; /* non ecc builds won't read */
    (void)haveAnon;   /* anon ciphers optional */
    (void)haveFalconSig;

    if (suites == NULL) {
        WOLFSSL_MSG("InitSuites pointer error");
        return;
    }

    if (suites->setSuites)
        return;      /* trust user settings, don't override */





#ifdef HAVE_RENEGOTIATION_INDICATION
    if (side == WOLFSSL_CLIENT_END) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    }
#endif




    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }


















/* Place as higher priority for MYSQL */



















    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    }













/* Place as higher priority for MYSQL testing */





































#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    if (!dtls && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_MD5;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    if (haveRSA ) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif










    suites->suiteSz = idx;

    if (suites->hashSigAlgoSz == 0) {
        InitSuitesHashSigAlgo(suites, haveECDSAsig | haveECC,
                              haveRSAsig | haveRSA, haveFalconSig,
                              0, tls1_2, keySz);
    }
}


/* Decode the signature algorithm.
 *
 * input     The encoded signature algorithm.
 * hashalgo  The hash algorithm.
 * hsType    The signature type.
 */
static WC_INLINE void DecodeSigAlg(const byte* input, byte* hashAlgo, byte* hsType)
{
    *hsType = invalid_sa_algo;
    switch (input[0]) {
        case NEW_SA_MAJOR:
            {
                *hsType   = input[0];
                *hashAlgo = input[1];
            }
            break;
        default:
            *hashAlgo = input[0];
            *hsType   = input[1];
            break;
    }
}


static enum wc_HashType HashAlgoToType(int hashAlgo)
{
    switch (hashAlgo) {
        case sha512_mac:
            return WC_HASH_TYPE_SHA512;
        case sha384_mac:
            return WC_HASH_TYPE_SHA384;
        case sha256_mac:
            return WC_HASH_TYPE_SHA256;
        case sha224_mac:
            return WC_HASH_TYPE_SHA224;
        case sha_mac:
            return WC_HASH_TYPE_SHA;
        default:
            WOLFSSL_MSG("Bad hash sig algo");
            break;
    }

    return WC_HASH_TYPE_NONE;
}


void InitX509Name(WOLFSSL_X509_NAME* name, int dynamicFlag, void* heap)
{
    (void)dynamicFlag;

    if (name != NULL) {
        XMEMSET(name, 0, sizeof(WOLFSSL_X509_NAME));
        name->name        = name->staticName;
        name->heap = heap;
        name->dynamicName = 0;
    }
}


void FreeX509Name(WOLFSSL_X509_NAME* name)
{
    if (name != NULL) {
        if (name->dynamicName) {
            XFREE(name->name, name->heap, DYNAMIC_TYPE_SUBJECT_CN);
            name->name = NULL;
        }
    }
}


/* Initialize wolfSSL X509 type */
void InitX509(WOLFSSL_X509* x509, int dynamicFlag, void* heap)
{
    if (x509 == NULL) {
        WOLFSSL_MSG("Null parameter passed in!");
        return;
    }

    XMEMSET(x509, 0, sizeof(WOLFSSL_X509));

    x509->heap = heap;
    InitX509Name(&x509->issuer, 0, heap);
    InitX509Name(&x509->subject, 0, heap);
    x509->dynamicMemory  = (byte)dynamicFlag;
}


/* Free wolfSSL X509 type */
void FreeX509(WOLFSSL_X509* x509)
{
    if (x509 == NULL)
        return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&x509->subject);
    if (x509->pubKey.buffer) {
        XFREE(x509->pubKey.buffer, x509->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        x509->pubKey.buffer = NULL;
    }
    FreeDer(&x509->derCert);
    XFREE(x509->sig.buffer, x509->heap, DYNAMIC_TYPE_SIGNATURE);
    x509->sig.buffer = NULL;
    if (x509->altNames) {
        FreeAltNames(x509->altNames, x509->heap);
        x509->altNames = NULL;
    }

}


/* Encode the signature algorithm into buffer.
 *
 * hashalgo  The hash algorithm.
 * hsType   The signature type.
 * output    The buffer to encode into.
 */
static WC_INLINE void EncodeSigAlg(byte hashAlgo, byte hsType, byte* output)
{
    switch (hsType) {
        case ecc_dsa_sa_algo:
            output[0] = hashAlgo;
            output[1] = ecc_dsa_sa_algo;
            break;
        case rsa_sa_algo:
            output[0] = hashAlgo;
            output[1] = rsa_sa_algo;
            break;
        default:
            break;
    }
    (void)hashAlgo;
    (void)output;
}


static word32 MacSize(WOLFSSL* ssl)
{
    word32 digestSz = ssl->specs.hash_size;

    return digestSz;
}

static int TypeHash(int hashAlgo)
{
    switch (hashAlgo) {
        case sha512_mac:
            return SHA512h;
        case sha384_mac:
            return SHA384h;
        case sha256_mac:
            return SHA256h;
        case sha224_mac:
            return SHA224h;
        case sha_mac:
            return SHAh;
        default:
            break;
    }

    return 0;
}



int RsaVerify(WOLFSSL* ssl, byte* in, word32 inSz, byte** out, int sigAlgo,
              int hashAlgo, RsaKey* key, buffer* keyBufInfo)
{
    int ret = SIG_VERIFY_E;


    (void)ssl;
    (void)keyBufInfo;
    (void)sigAlgo;
    (void)hashAlgo;

    WOLFSSL_ENTER("RsaVerify");


    {
        ret = wc_RsaSSL_VerifyInline(in, inSz, out, key);
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("RsaVerify", ret);

    return ret;
}

/* Verify RSA signature, 0 on success */
/* This function is used to check the sign result */
int VerifyRsaSign(WOLFSSL* ssl, byte* verifySig, word32 sigSz,
    const byte* plain, word32 plainSz, int sigAlgo, int hashAlgo, RsaKey* key,
    DerBuffer* keyBufInfo)
{
    byte* out = NULL;  /* inline result */
    int   ret;

    (void)ssl;
    (void)keyBufInfo;
    (void)sigAlgo;
    (void)hashAlgo;

    WOLFSSL_ENTER("VerifyRsaSign");

    if (verifySig == NULL || plain == NULL) {
        return BAD_FUNC_ARG;
    }

    if (sigSz > ENCRYPT_LEN) {
        WOLFSSL_MSG("Signature buffer too big");
        return BUFFER_E;
    }


    {
        {
            ret = wc_RsaSSL_VerifyInline(verifySig, sigSz, &out, key);
        }

        if (ret > 0) {
            if (ret != (int)plainSz || !out ||
                                            XMEMCMP(plain, out, plainSz) != 0) {
                WOLFSSL_MSG("RSA Signature verification failed");
                ret = RSA_SIGN_FAULT;
            } else {
                ret = 0;  /* RSA reset */
            }
        }
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("VerifyRsaSign", ret);

    return ret;
}



int RsaEnc(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out, word32* outSz,
    RsaKey* key, buffer* keyBufInfo)
{
    int ret = BAD_FUNC_ARG;

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("RsaEnc");


    {
        ret = wc_RsaPublicEncrypt(in, inSz, out, *outSz, key, ssl->rng);
    }

    /* Handle async pending response */

    /* For positive response return in outSz */
    if (ret > 0) {
        *outSz = ret;
        ret = 0;
    }

    WOLFSSL_LEAVE("RsaEnc", ret);

    return ret;
}




int EccSign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
    word32* outSz, ecc_key* key, DerBuffer* keyBufInfo)
{
    int ret;

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("EccSign");


    {
        ret = wc_ecc_sign_hash(in, inSz, out, outSz, ssl->rng, key);
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("EccSign", ret);

    return ret;
}

int EccVerify(WOLFSSL* ssl, const byte* in, word32 inSz, const byte* out,
    word32 outSz, ecc_key* key, buffer* keyBufInfo)
{
    int ret = SIG_VERIFY_E;

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("EccVerify");


    {
        ret = wc_ecc_verify_hash(in, inSz, out, outSz, &ssl->eccVerifyRes, key);
    }

    /* Handle async pending response */
    {
        ret = (ret != 0 || ssl->eccVerifyRes == 0) ? VERIFY_SIGN_ERROR : 0;
    }

    WOLFSSL_LEAVE("EccVerify", ret);

    return ret;
}

int EccSharedSecret(WOLFSSL* ssl, ecc_key* priv_key, ecc_key* pub_key,
        byte* pubKeyDer, word32* pubKeySz, byte* out, word32* outlen,
        int side)
{
    int ret;

    (void)ssl;
    (void)pubKeyDer;
    (void)pubKeySz;
    (void)side;

    WOLFSSL_ENTER("EccSharedSecret");


    {
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_shared_secret(priv_key, pub_key, out, outlen);
            PRIVATE_KEY_LOCK();
            sparky_tls_log(12, "ssl->arrays->preMasterSecret", out, *outlen);
        }
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("EccSharedSecret", ret);

    return ret;
}

int EccMakeKey(WOLFSSL* ssl, ecc_key* key, ecc_key* peer)
{
    int ret = 0;
    int keySz = 0;
    int ecc_curve = ECC_CURVE_DEF;

    WOLFSSL_ENTER("EccMakeKey");


    /* get key size */
    if (peer == NULL || peer->dp == NULL) {
        keySz = ssl->eccTempKeySz;
        /* get curve type */
        if (ssl->ecdhCurveOID > 0) {
            ecc_curve = wc_ecc_get_oid(ssl->ecdhCurveOID, NULL, NULL);
        }
    }
    else {
        keySz = peer->dp->size;
        ecc_curve = peer->dp->id;
    }

    {
        ret = wc_ecc_make_key_ex(ssl->rng, keySz, key, ecc_curve);
        sparky_tls_log(9, "ssl->hsKey", key, keySz);
    }

    /* make sure the curve is set for TLS */
    if (ret == 0 && key->dp) {
        ssl->ecdhCurveOID = key->dp->oidSum;
        ssl->namedGroup = 0;
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("EccMakeKey", ret);

    return ret;
}










int DhGenKeyPair(WOLFSSL* ssl, DhKey* dhKey,
    byte* priv, word32* privSz,
    byte* pub, word32* pubSz)
{
    int ret;

    WOLFSSL_ENTER("DhGenKeyPair");


    PRIVATE_KEY_UNLOCK();
    ret = wc_DhGenerateKeyPair(dhKey, ssl->rng, priv, privSz, pub, pubSz);
    PRIVATE_KEY_LOCK();

    /* Handle async pending response */

    WOLFSSL_LEAVE("DhGenKeyPair", ret);

    return ret;
}

int DhAgree(WOLFSSL* ssl, DhKey* dhKey,
    const byte* priv, word32 privSz,
    const byte* otherPub, word32 otherPubSz,
    byte* agree, word32* agreeSz,
    const byte* prime, word32 primeSz)
{
    int ret;

    (void)ssl;

    WOLFSSL_ENTER("DhAgree");


    {
        /* check the public key has valid number */
        if (dhKey != NULL && (prime == NULL || primeSz == 0)) {
            /* wc_DhCheckPubKey does not do exponentiation */
            ret = wc_DhCheckPubKey(dhKey, otherPub, otherPubSz);
        }
        else {
            ret = wc_DhCheckPubValue(prime, primeSz, otherPub, otherPubSz);
        }
        if (ret != 0) {
            /* translate to valid error (wc_DhCheckPubValue returns MP_VAL -1) */
            ret = PEER_KEY_ERROR;

        }
        else
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_DhAgree(dhKey, agree, agreeSz, priv, privSz, otherPub,
                    otherPubSz);
            PRIVATE_KEY_LOCK();
        }
    }

    /* Handle async pending response */

    WOLFSSL_LEAVE("DhAgree", ret);

    (void)prime;
    (void)primeSz;

    return ret;
}




int InitSSL_Suites(WOLFSSL* ssl)
{
    int keySz = 0;
    byte havePSK = 0;
    byte haveAnon = 0;
    byte haveRSA = 0;
    byte haveMcast = 0;

    (void)haveAnon; /* Squash unused var warnings */
    (void)haveMcast;

    if (!ssl)
        return BAD_FUNC_ARG;

    haveRSA = 1;


    keySz = ssl->buffers.keySz;

    /* make sure server has DH parms, and add PSK if there */
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, ssl->options.haveStaticECC,
                   ssl->options.haveFalconSig, ssl->options.haveAnon,
                   ssl->options.side);
    }
    else {
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK, TRUE,
                   ssl->options.haveECDSAsig, ssl->options.haveECC,
                   ssl->options.haveStaticECC, ssl->options.haveFalconSig,
                   ssl->options.haveAnon, ssl->options.side);
    }

    /* make sure server has cert and key unless using PSK, Anon, or
     * Multicast. This should be true even if just switching ssl ctx */
    if (ssl->options.side == WOLFSSL_SERVER_END &&
            !havePSK && !haveAnon && !haveMcast) {

        /* server certificate must be loaded */
        if (!ssl->buffers.certificate || !ssl->buffers.certificate->buffer) {
            WOLFSSL_MSG("Server missing certificate");
            return NO_PRIVATE_KEY;
        }

        if (!ssl->buffers.key || !ssl->buffers.key->buffer) {
            /* allow no private key if using existing key */
            {
                WOLFSSL_MSG("Server missing private key");
                return NO_PRIVATE_KEY;
            }
        }
    }

    return WOLFSSL_SUCCESS;
}

/* returns new reference count. Arg incr positive=up or negative=down */
int SSL_CTX_RefCount(WOLFSSL_CTX* ctx, int incr)
{
    int refCount;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wc_LockMutex(&ctx->countMutex) != 0) {
        WOLFSSL_MSG("Couldn't lock CTX count mutex");
        return BAD_MUTEX_E;
    }

    ctx->refCount += incr;
    /* make sure refCount is never negative */
    if (ctx->refCount < 0) {
        ctx->refCount = 0;
    }
    refCount = ctx->refCount;

    wc_UnLockMutex(&ctx->countMutex);

    return refCount;
}

/* This function inherits a WOLFSSL_CTX's fields into an SSL object.
   It is used during initialization and to switch an ssl's CTX with
   wolfSSL_Set_SSL_CTX.  Requires ssl->suites alloc and ssl-arrays with PSK
   unless writeDup is on.

   ssl      object to initialize
   ctx      parent factory
   writeDup flag indicating this is a write dup only

   WOLFSSL_SUCCESS return value on success */
int SetSSL_CTX(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
{
    int ret;
    byte newSSL;

    if (!ssl || !ctx)
        return BAD_FUNC_ARG;

    if (ssl->suites == NULL && !writeDup)
        return BAD_FUNC_ARG;

    newSSL = ssl->ctx == NULL; /* Assign after null check */


    /* decrement previous CTX reference count if exists.
     * This should only happen if switching ctxs!*/
    if (!newSSL) {
        WOLFSSL_MSG("freeing old ctx to decrement reference count. Switching ctx.");
        wolfSSL_CTX_free(ssl->ctx);
    }

    /* increment CTX reference count */
    if ((ret = SSL_CTX_RefCount(ctx, 1)) < 0) {
        return ret;
    }
    ret = WOLFSSL_SUCCESS; /* set default ret */

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    /* Don't change version on a SSL object that has already started a
     * handshake */
    if (!ssl->msgsReceived.got_client_hello &&
            !ssl->msgsReceived.got_server_hello)
        ssl->version = ctx->method->version;

    ssl->eccTempKeySz = ctx->eccTempKeySz;
    ssl->ecdhCurveOID = ctx->ecdhCurveOID;
    ssl->pkCurveOID = ctx->pkCurveOID;

    ssl->timeout = ctx->timeout;
    ssl->verifyCallback    = ctx->verifyCallback;
    /* If we are setting the ctx on an already initialized SSL object
     * then we possibly already have a side defined. Don't overwrite unless
     * the context has a well defined role. */
    if (newSSL || ctx->method->side != WOLFSSL_NEITHER_END)
        ssl->options.side      = ctx->method->side;
    ssl->options.downgrade    = ctx->method->downgrade;
    ssl->options.minDowngrade = ctx->minDowngrade;

    ssl->options.haveRSA       = ctx->haveRSA;
    ssl->options.haveDH        = ctx->haveDH;
    ssl->options.haveECDSAsig  = ctx->haveECDSAsig;
    ssl->options.haveECC       = ctx->haveECC;
    ssl->options.haveStaticECC = ctx->haveStaticECC;
    ssl->options.haveFalconSig = ctx->haveFalconSig;


    ssl->options.minDhKeySz = ctx->minDhKeySz;
    ssl->options.maxDhKeySz = ctx->maxDhKeySz;
    ssl->options.minRsaKeySz = ctx->minRsaKeySz;
    ssl->options.minEccKeySz = ctx->minEccKeySz;

    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;
#ifdef HAVE_EXT_CACHE
    ssl->options.internalCacheOff     = ctx->internalCacheOff;
    ssl->options.internalCacheLookupOff = ctx->internalCacheLookupOff;
#endif

    ssl->options.verifyPeer     = ctx->verifyPeer;
    ssl->options.verifyNone     = ctx->verifyNone;
    ssl->options.failNoCert     = ctx->failNoCert;
    ssl->options.failNoCertxPSK = ctx->failNoCertxPSK;
    ssl->options.sendVerify     = ctx->sendVerify;

    ssl->options.partialWrite  = ctx->partialWrite;
    ssl->options.quietShutdown = ctx->quietShutdown;
    ssl->options.groupMessages = ctx->groupMessages;

        ssl->options.dhKeyTested = ctx->dhKeyTested;
    ssl->buffers.serverDH_P = ctx->serverDH_P;
    ssl->buffers.serverDH_G = ctx->serverDH_G;

    /* ctx still owns certificate, certChain, key, dh, and cm */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.certChain = ctx->certChain;
    ssl->buffers.key      = ctx->privateKey;
    ssl->buffers.keyType  = ctx->privateKeyType;
    ssl->buffers.keyId    = ctx->privateKeyId;
    ssl->buffers.keyLabel = ctx->privateKeyLabel;
    ssl->buffers.keySz    = ctx->privateKeySz;
    ssl->buffers.keyDevId = ctx->privateKeyDevId;



    if (writeDup == 0) {

        if (ctx->suites) {
            *ssl->suites = *ctx->suites;
        }
        else {
            XMEMSET(ssl->suites, 0, sizeof(Suites));
        }

        if (ssl->options.side != WOLFSSL_NEITHER_END) {
            /* Defer initializing suites until accept or connect */
            ret = InitSSL_Suites(ssl);
        }
    }  /* writeDup check */




        ssl->CBIORecv = ctx->CBIORecv;
        ssl->CBIOSend = ctx->CBIOSend;
    ssl->verifyDepth = ctx->verifyDepth;

    return ret;
}

int InitHandshakeHashes(WOLFSSL* ssl)
{
    int ret;

    /* make sure existing handshake hashes are free'd */
    if (ssl->hsHashes != NULL) {
        FreeHandshakeHashes(ssl);
    }

    /* allocate handshake hashes */
    ssl->hsHashes = (HS_Hashes*)XMALLOC(sizeof(HS_Hashes), ssl->heap,
                                                           DYNAMIC_TYPE_HASHES);
    if (ssl->hsHashes == NULL) {
        WOLFSSL_MSG("HS_Hashes Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->hsHashes, 0, sizeof(HS_Hashes));

#ifndef NO_MD5
    ret = wc_InitMd5_ex(&ssl->hsHashes->hashMd5, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
#endif
    ret = wc_InitSha_ex(&ssl->hsHashes->hashSha, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    ret = wc_InitSha256_ex(&ssl->hsHashes->hashSha256, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    ret = wc_InitSha384_ex(&ssl->hsHashes->hashSha384, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    ret = wc_InitSha512_ex(&ssl->hsHashes->hashSha512, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;

    return ret;
}

void FreeHandshakeHashes(WOLFSSL* ssl)
{
    if (ssl->hsHashes) {
    #ifndef NO_MD5
        wc_Md5Free(&ssl->hsHashes->hashMd5);
    #endif
        wc_ShaFree(&ssl->hsHashes->hashSha);
        wc_Sha256Free(&ssl->hsHashes->hashSha256);
        wc_Sha384Free(&ssl->hsHashes->hashSha384);
        wc_Sha512Free(&ssl->hsHashes->hashSha512);

        XFREE(ssl->hsHashes, ssl->heap, DYNAMIC_TYPE_HASHES);
        ssl->hsHashes = NULL;
    }
}


/* init everything to 0, NULL, default values before calling anything that may
   fail so that destructor has a "good" state to cleanup

   ssl      object to initialize
   ctx      parent factory
   writeDup flag indicating this is a write dup only

   0 on success */
int InitSSL(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
{
    int  ret;

    XMEMSET(ssl, 0, sizeof(WOLFSSL));

    ssl->heap = ctx->heap; /* carry over user heap without static memory */

    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;

    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;


    ssl->rfd = -1;   /* set to invalid descriptor */
    ssl->wfd = -1;
    ssl->devId = ctx->devId; /* device for async HW (from wolfAsync_DevOpen) */

    /* initialize states */
    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN;
    ssl->options.handShakeState  = NULL_STATE;
    ssl->options.processReply = doProcessInit;
    ssl->options.asyncState = TLS_ASYNC_BEGIN;
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;
    ssl->encrypt.state = CIPHER_STATE_BEGIN;
    ssl->decrypt.state = CIPHER_STATE_BEGIN;
        ssl->options.dhDoKeyTest = 1;

#ifdef HAVE_NETX
    ssl->IOCB_ReadCtx  = &ssl->nxCtx;  /* default NetX IO ctx, same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and write */
#elif defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    ssl->mnCtx = mynewt_ctx_new();
    if(!ssl->mnCtx) {
        return MEMORY_E;
    }
    ssl->IOCB_ReadCtx  = ssl->mnCtx;  /* default Mynewt IO ctx, same for read */
    ssl->IOCB_WriteCtx = ssl->mnCtx;  /* and write */
#elif defined (WOLFSSL_GNRC)
    ssl->IOCB_ReadCtx = ssl->gnrcCtx;
    ssl->IOCB_WriteCtx = ssl->gnrcCtx;
#else
    ssl->IOCB_ReadCtx  = &ssl->rfd;  /* prevent invalid pointer access if not */
    ssl->IOCB_WriteCtx = &ssl->wfd;  /* correctly set */
#endif


        ssl->hmac = SSL_hmac; /* default to SSLv3 */

#if defined(WOLFSSL_OPENVPN) && defined(HAVE_KEYING_MATERIAL)
    /* Save arrays by default for OpenVPN */
    ssl->options.saveArrays = 1;
#endif

    ssl->cipher.ssl = ssl;

    ssl->options.haveEMS = ctx->haveEMS;
    ssl->options.useClientOrder = ctx->useClientOrder;
    ssl->options.mutualAuth = ctx->mutualAuth;


#ifdef HAVE_ALPN
    ssl->alpn_client_list = NULL;
    #if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
        ssl->alpnSelect    = ctx->alpnSelect;
        ssl->alpnSelectArg = ctx->alpnSelectArg;
    #endif
#endif
    ssl->options.userCurves = ctx->userCurves;

    ssl->options.disallowEncThenMac = ctx->disallowEncThenMac;

    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_history.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;


    InitCiphers(ssl);
    InitCipherSpecs(&ssl->specs);

    /* all done with init, now can return errors, call other stuff */

    if (!writeDup) {
        /* arrays */
        ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
        if (ssl->arrays == NULL) {
            WOLFSSL_MSG("Arrays Memory error");
            return MEMORY_E;
        }
        XMEMSET(ssl->arrays, 0, sizeof(Arrays));


        {
            /* suites */
            ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                       DYNAMIC_TYPE_SUITES);
            if (ssl->suites == NULL) {
                WOLFSSL_MSG("Suites Memory error");
                return MEMORY_E;
            }
        }
    }

    /* Initialize SSL with the appropriate fields from it's ctx */
    /* requires valid arrays and suites unless writeDup ing */
    if ((ret =  SetSSL_CTX(ssl, ctx, writeDup)) != WOLFSSL_SUCCESS)
        return ret;

    ssl->options.dtls = ssl->version.major == DTLS_MAJOR;


    if (ssl->rng == NULL) {
        /* RNG */
        ssl->rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), ssl->heap,DYNAMIC_TYPE_RNG);
        if (ssl->rng == NULL) {
            WOLFSSL_MSG("RNG Memory error");
            return MEMORY_E;
        }
        XMEMSET(ssl->rng, 0, sizeof(WC_RNG));
        ssl->options.weOwnRng = 1;

        /* FIPS RNG API does not accept a heap hint */
        if ( (ret = wc_InitRng_ex(ssl->rng, ssl->heap, ssl->devId)) != 0) {
            WOLFSSL_MSG("RNG Init error");
            return ret;
        }
    }


    /* hsHashes */
    ret = InitHandshakeHashes(ssl);
    if (ret != 0)
        return ret;



    ssl->session = wolfSSL_NewSession(ssl->heap);
    if (ssl->session == NULL) {
        WOLFSSL_MSG("SSL Session Memory error");
        return MEMORY_E;
    }




    return 0;
}


/* free use of temporary arrays */
void FreeArrays(WOLFSSL* ssl, int keep)
{
    if (ssl->arrays) {
        if (keep && !IsAtLeastTLSv1_3(ssl->version)) {
            /* keeps session id for user retrieval */
            XMEMCPY(ssl->session->sessionID, ssl->arrays->sessionID, ID_LEN);
            ssl->session->sessionIDSz = ssl->arrays->sessionIDSz;
        }
        if (ssl->arrays->preMasterSecret) {
            ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
            XFREE(ssl->arrays->preMasterSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
            ssl->arrays->preMasterSecret = NULL;
        }
        XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
        ssl->arrays->pendingMsg = NULL;
        ForceZero(ssl->arrays, sizeof(Arrays)); /* clear arrays struct */
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}

void FreeKey(WOLFSSL* ssl, int type, void** pKey)
{
    if (ssl && pKey && *pKey) {
        switch (type) {
            case DYNAMIC_TYPE_RSA:
                wc_FreeRsaKey((RsaKey*)*pKey);
                break;
            case DYNAMIC_TYPE_ECC:
                wc_ecc_free((ecc_key*)*pKey);
                break;
            case DYNAMIC_TYPE_DH:
                wc_FreeDhKey((DhKey*)*pKey);
                break;
            default:
                break;
        }
        XFREE(*pKey, ssl->heap, type);

        /* Reset pointer */
        *pKey = NULL;
    }
}

int AllocKey(WOLFSSL* ssl, int type, void** pKey)
{
    int ret = BAD_FUNC_ARG;
    int sz = 0;

    if (ssl == NULL || pKey == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Sanity check key destination */
    if (*pKey != NULL) {
        WOLFSSL_MSG("Key already present!");
        return BAD_STATE_E;
    }

    /* Determine size */
    switch (type) {
        case DYNAMIC_TYPE_RSA:
            sz = sizeof(RsaKey);
            break;
        case DYNAMIC_TYPE_ECC:
            sz = sizeof(ecc_key);
            break;
        case DYNAMIC_TYPE_DH:
            sz = sizeof(DhKey);
            break;
        default:
            return BAD_FUNC_ARG;
    }

    /* Allocate memory for key */
    *pKey = (void *)XMALLOC(sz, ssl->heap, type);
    if (*pKey == NULL) {
        return MEMORY_E;
    }

    /* Initialize key */
    switch (type) {
        case DYNAMIC_TYPE_RSA:
            ret = wc_InitRsaKey_ex((RsaKey*)*pKey, ssl->heap, ssl->devId);
            break;
        case DYNAMIC_TYPE_ECC:
            ret = wc_ecc_init_ex((ecc_key*)*pKey, ssl->heap, ssl->devId);
            break;
        case DYNAMIC_TYPE_DH:
            ret = wc_InitDhKey_ex((DhKey*)*pKey, ssl->heap, ssl->devId);
            break;
        default:
            return BAD_FUNC_ARG;
    }

    /* On error free handshake key */
    if (ret != 0) {
        FreeKey(ssl, type, pKey);
    }

    return ret;
}

static int ReuseKey(WOLFSSL* ssl, int type, void* pKey)
{
    int ret = 0;

    (void)ssl;

    switch (type) {
        case DYNAMIC_TYPE_RSA:
            wc_FreeRsaKey((RsaKey*)pKey);
            ret = wc_InitRsaKey_ex((RsaKey*)pKey, ssl->heap, ssl->devId);
            break;
        case DYNAMIC_TYPE_ECC:
            wc_ecc_free((ecc_key*)pKey);
            ret = wc_ecc_init_ex((ecc_key*)pKey, ssl->heap, ssl->devId);
            break;
        case DYNAMIC_TYPE_DH:
            wc_FreeDhKey((DhKey*)pKey);
            ret = wc_InitDhKey_ex((DhKey*)pKey, ssl->heap, ssl->devId);
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return ret;
}

void FreeKeyExchange(WOLFSSL* ssl)
{
    /* Cleanup signature buffer */
    if (ssl->buffers.sig.buffer) {
        XFREE(ssl->buffers.sig.buffer, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        ssl->buffers.sig.buffer = NULL;
        ssl->buffers.sig.length = 0;
    }

    /* Cleanup digest buffer */
    if (ssl->buffers.digest.buffer) {
        XFREE(ssl->buffers.digest.buffer, ssl->heap, DYNAMIC_TYPE_DIGEST);
        ssl->buffers.digest.buffer = NULL;
        ssl->buffers.digest.length = 0;
    }

    /* Free handshake key */
    FreeKey(ssl, ssl->hsType, &ssl->hsKey);

    /* Free temp DH key */
    FreeKey(ssl, DYNAMIC_TYPE_DH, (void**)&ssl->buffers.serverDH_Key);

    /* Cleanup async */
}


/* Free up all memory used by Suites structure from WOLFSSL */
void FreeSuites(WOLFSSL* ssl)
{
    {
        XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    }
    ssl->suites = NULL;
}


/* In case holding SSL object in array and don't want to free actual ssl */
void SSL_ResourceFree(WOLFSSL* ssl)
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which may optionally be kept for the whole session. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        WOLFSSL_MSG("Free'ing server ssl");
    }
    else {
        WOLFSSL_MSG("Free'ing client ssl");
    }


    FreeCiphers(ssl);
    FreeArrays(ssl, 0);
    FreeKeyExchange(ssl);
    if (ssl->options.weOwnRng) {
        wc_FreeRng(ssl->rng);
        XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
    }
    FreeSuites(ssl);
    FreeHandshakeHashes(ssl);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    /* clear keys struct after session */
    ForceZero(&ssl->keys, sizeof(Keys));

    if (ssl->buffers.serverDH_Priv.buffer) {
        ForceZero(ssl->buffers.serverDH_Priv.buffer,
                                             ssl->buffers.serverDH_Priv.length);
    }
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    ssl->keepCert = 0; /* make sure certificate is free'd */
    wolfSSL_UnloadCertsKeys(ssl);
    FreeKey(ssl, DYNAMIC_TYPE_RSA, (void**)&ssl->peerRsaKey);
    ssl->peerRsaKeyPresent = 0;
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    XFREE(ssl->peerSceTsipEncRsaKeyIndex, ssl->heap, DYNAMIC_TYPE_RSA);
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccKey);
    ssl->peerEccKeyPresent = 0;
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccDsaKey);
    ssl->peerEccDsaKeyPresent = 0;
    {
        int dtype = 0;
        dtype = DYNAMIC_TYPE_ECC;
        FreeKey(ssl, dtype, (void**)&ssl->eccTempKey);
        ssl->eccTempKeyPresent = 0;
    }
    TLSX_FreeAll(ssl->extensions, ssl->heap);

#ifdef HAVE_ALPN
    if (ssl->alpn_client_list != NULL) {
        XFREE(ssl->alpn_client_list, ssl->heap, DYNAMIC_TYPE_ALPN);
        ssl->alpn_client_list = NULL;
    }
#endif
#if defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    if (ssl->mnCtx) {
        mynewt_ctx_clear(ssl->mnCtx);
        ssl->mnCtx = NULL;
    }
#endif
#ifdef HAVE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPacket);
#endif

    if (ssl->session != NULL)
        wolfSSL_FreeSession(ssl->ctx, ssl->session);

#if defined(HAVE_LIGHTY)
    wolfSSL_sk_X509_NAME_pop_free(ssl->ca_names, NULL);
    ssl->ca_names = NULL;
#endif
}

/* Free any handshake resources no longer needed */
void FreeHandshakeResources(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("FreeHandshakeResources");



    /* input buffer */
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    {
        /* free suites unless using compatibility layer */
        FreeSuites(ssl);
        /* hsHashes */
        FreeHandshakeHashes(ssl);
    }

    /* RNG */
    if (ssl->options.tls1_1 == 0
        || ssl->specs.cipher_type == stream
    ) {
        if (ssl->options.weOwnRng) {
            wc_FreeRng(ssl->rng);
            XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
            ssl->rng = NULL;
            ssl->options.weOwnRng = 0;
        }
    }

        /* arrays */
        if (ssl->options.saveArrays == 0)
            FreeArrays(ssl, 1);

    {
        /* peerRsaKey */
        FreeKey(ssl, DYNAMIC_TYPE_RSA, (void**)&ssl->peerRsaKey);
        ssl->peerRsaKeyPresent = 0;
        FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccDsaKey);
        ssl->peerEccDsaKeyPresent = 0;
    }

    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccKey);
    ssl->peerEccKeyPresent = 0;
    {
        int dtype;
        dtype = DYNAMIC_TYPE_ECC;
        FreeKey(ssl, dtype, (void**)&ssl->eccTempKey);
        ssl->eccTempKeyPresent = 0;
    }

    if (ssl->buffers.serverDH_Priv.buffer) {
        ForceZero(ssl->buffers.serverDH_Priv.buffer,
                                             ssl->buffers.serverDH_Priv.length);
    }
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
    ssl->buffers.serverDH_Priv.buffer = NULL;
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ssl->buffers.serverDH_Pub.buffer = NULL;
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
    }

    wolfSSL_UnloadCertsKeys(ssl);


}


/* heap argument is the heap hint used when creating SSL */
void FreeSSL(WOLFSSL* ssl, void* heap)
{
    WOLFSSL_CTX* ctx = ssl->ctx;
    SSL_ResourceFree(ssl);
    XFREE(ssl, heap, DYNAMIC_TYPE_SSL);
    if (ctx)
        FreeSSL_Ctx(ctx); /* will decrement and free underlying CTX if 0 */
    (void)heap;
}


static WC_INLINE void GetSEQIncrement(WOLFSSL* ssl, int verify, word32 seq[2])
{
    if (verify) {
        seq[0] = ssl->keys.peer_sequence_number_hi;
        seq[1] = ssl->keys.peer_sequence_number_lo++;
        if (seq[1] > ssl->keys.peer_sequence_number_lo) {
            /* handle rollover */
            ssl->keys.peer_sequence_number_hi++;
        }
    }
    else {
        seq[0] = ssl->keys.sequence_number_hi;
        seq[1] = ssl->keys.sequence_number_lo++;
        if (seq[1] > ssl->keys.sequence_number_lo) {
            /* handle rollover */
            ssl->keys.sequence_number_hi++;
        }
    }
}



void WriteSEQ(WOLFSSL* ssl, int verifyOrder, byte* out)
{
    word32 seq[2] = {0, 0};

    if (!ssl->options.dtls) {
        GetSEQIncrement(ssl, verifyOrder, seq);
    }
    else {
    }

    c32toa(seq[0], out);
    c32toa(seq[1], out + OPAQUE32_LEN);
}


#if defined(WOLFSSL_ALLOW_SSLV3)

ProtocolVersion MakeSSLv3(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = SSLv3_MINOR;

    return pv;
}

#endif /* WOLFSSL_ALLOW_SSLV3 && !NO_OLD_TLS */




#ifndef NO_ASN_TIME
#if defined(USER_TICKS)
#if 0
    word32 LowResTimer(void)
    {
        /*
        write your own clock tick function if don't want time(0)
        needs second accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif

#elif defined(TIME_OVERRIDES)
#if !defined(NO_ASN_TIME)
    /* use same asn time overrides unless user wants tick override above */

    word32 LowResTimer(void)
    {
        return (word32) wc_Time(0);
    }
#else
    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t * timer);

    word32 LowResTimer(void)
    {
        return (word32) XTIME(0);
    }
#endif

#elif defined(HAVE_RTP_SYS)

    #include "rtptime.h"

    word32 LowResTimer(void)
    {
        return (word32)rtp_get_system_sec();
    }

#elif defined(WOLFSSL_DEOS)

    word32 LowResTimer(void)
    {
        const word32 systemTickTimeInHz = 1000000 / systemTickInMicroseconds();
        const volatile word32 *systemTickPtr = systemTickPointer();

        return (word32) *systemTickPtr/systemTickTimeInHz;
    }

#elif defined(MICRIUM)

    word32 LowResTimer(void)
    {
        OS_TICK ticks = 0;
        OS_ERR  err;

        ticks = OSTimeGet(&err);

        return (word32) (ticks / OSCfg_TickRate_Hz);
    }


#elif defined(MICROCHIP_TCPIP_V5)

    word32 LowResTimer(void)
    {
        return (word32) (TickGet() / TICKS_PER_SECOND);
    }


#elif defined(MICROCHIP_TCPIP)

    #if defined(MICROCHIP_MPLAB_HARMONY)

        #include <system/tmr/sys_tmr.h>

        word32 LowResTimer(void)
        {
            return (word32) (SYS_TMR_TickCountGet() /
                             SYS_TMR_TickCounterFrequencyGet());
        }

    #else

        word32 LowResTimer(void)
        {
            return (word32) (SYS_TICK_Get() / SYS_TICK_TicksPerSecondGet());
        }

    #endif

#elif defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)

    #include "include/task.h"

    unsigned int LowResTimer(void)
    {
        return (unsigned int)(((float)xTaskGetTickCount())/configTICK_RATE_HZ);
    }

#elif defined(FREERTOS)

    #include "task.h"

    unsigned int LowResTimer(void)
    {
        return (unsigned int)(((float)xTaskGetTickCount())/configTICK_RATE_HZ);
    }

#elif defined(FREESCALE_KSDK_BM)

    #include "lwip/sys.h" /* lwIP */
    word32 LowResTimer(void)
    {
        return sys_now()/1000;
    }

#elif defined(WOLFSSL_TIRTOS)

    word32 LowResTimer(void)
    {
        return (word32) Seconds_get();
    }
#elif defined(WOLFSSL_XILINX)
    #include "xrtcpsu.h"

    word32 LowResTimer(void)
    {
        XRtcPsu_Config* con;
        XRtcPsu         rtc;

        con = XRtcPsu_LookupConfig(XPAR_XRTCPSU_0_DEVICE_ID);
        if (con != NULL) {
            if (XRtcPsu_CfgInitialize(&rtc, con, con->BaseAddr)
                    == XST_SUCCESS) {
                return (word32)XRtcPsu_GetCurrentTime(&rtc);
            }
            else {
                WOLFSSL_MSG("Unable to initialize RTC");
            }
        }

        return 0;
    }

#elif defined(WOLFSSL_UTASKER)

    word32 LowResTimer(void)
    {
        return (word32)(uTaskerSystemTick / TICK_RESOLUTION);
    }

#elif defined(WOLFSSL_NUCLEUS_1_2)

    #define NU_TICKS_PER_SECOND 100

    word32 LowResTimer(void)
    {
        /* returns number of 10ms ticks, so 100 ticks/sec */
        return NU_Retrieve_Clock() / NU_TICKS_PER_SECOND;
    }
#elif defined(WOLFSSL_APACHE_MYNEWT)

    #include "os/os_time.h"
    word32 LowResTimer(void)
    {
        word32 now;
        struct os_timeval tv;
        os_gettimeofday(&tv, NULL);
        now = (word32)tv.tv_sec;
        return now;
    }

#elif defined(WOLFSSL_ZEPHYR)

    word32 LowResTimer(void)
    {
        return k_uptime_get() / 1000;
    }

#else
    /* Posix style time */
    #if !defined(USER_TIME) && !defined(USE_WOLF_TM)
    #include <time.h>
    #endif

    word32 LowResTimer(void)
    {
    #if !defined(NO_ASN_TIME)
        return (word32)wc_Time(0);
    #else
        return (word32)XTIME(0);
    #endif
    }
#endif
#else
    /* user must supply timer function to return elapsed seconds:
     *   word32 LowResTimer(void);
     */
#endif /* !NO_ASN_TIME */


int HashRaw(WOLFSSL* ssl, const byte* data, int sz)
{
    int ret = 0;

    (void)data;
    (void)sz;

    if (ssl->hsHashes == NULL) {
        return BAD_FUNC_ARG;
    }

        wc_ShaUpdate(&ssl->hsHashes->hashSha, data, sz);
    #ifndef NO_MD5
        wc_Md5Update(&ssl->hsHashes->hashMd5, data, sz);
    #endif

    if (IsAtLeastTLSv1_2(ssl)) {
        ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, data, sz);
        if (ret != 0)
            return ret;
        ret = wc_Sha384Update(&ssl->hsHashes->hashSha384, data, sz);
        if (ret != 0)
            return ret;
        ret = wc_Sha512Update(&ssl->hsHashes->hashSha512, data, sz);
        if (ret != 0)
            return ret;
    }

    {
        int const type = (data[0]);
        int star_no = -1;
        char const* msg_name = "UnknownMessage";
        switch(type)
        {
        case client_hello       :msg_name="H1.ClientHello    "; star_no = 2; break;
        case server_hello       :msg_name="H2.ServerHello    "; star_no = 3; break;
        case certificate        :msg_name="H3.ServerCert     "; star_no = 4; break;
        case server_key_exchange:msg_name="H4.ServerKeyExch  "; star_no = 6; break;
        case server_hello_done  :msg_name="H5.ServerHelloDone"; star_no = 7; break;
        case client_key_exchange:msg_name="H6.ClientKeyExch  "; star_no = 15; break;
        case finished           :msg_name="Hx.Finished       "; star_no = 0; break;
        }
        wc_Sha256 const* hashes_state = &ssl->hsHashes->hashSha256;
        size_t const hashes_len = sizeof(*hashes_state); // WC_SHA256_DIGEST_SIZE + WC_SHA256_BLOCK_SIZE + sizeof(word32) + 3;
        sparky_tls_log(0, "HASH-INPUT", data, sz);
        sparky_tls_log(star_no, msg_name, hashes_state, hashes_len);
    }
    return ret;
}

/* add output to md5 and sha handshake hashes, exclude record header */
int HashOutput(WOLFSSL* ssl, const byte* output, int sz, int ivSz)
{
    const byte* adj;

    if (ssl->hsHashes == NULL)
        return BAD_FUNC_ARG;

    adj = output + RECORD_HEADER_SZ + ivSz;
    sz -= RECORD_HEADER_SZ;

    char dbg_buf[256];
    snprintf(dbg_buf, sizeof(dbg_buf), "### HASH_OUTPUT: %d bytes to hash", sz);
    WOLFSSL_MSG(dbg_buf);

    return HashRaw(ssl, adj, sz);
}


/* add input to md5 and sha handshake hashes, include handshake header */
int HashInput(WOLFSSL* ssl, const byte* input, int sz)
{
    const byte* adj;

    if (ssl->hsHashes == NULL) {
        return BAD_FUNC_ARG;
    }

    adj = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

    char dbg_buf[256];
    snprintf(dbg_buf, sizeof(dbg_buf), "### HASH_INPUT: %d bytes to hash", sz);
    WOLFSSL_MSG(dbg_buf);

    return HashRaw(ssl, adj, sz);
}


/* add record layer header for message */
static void AddRecordHeader(byte* output, word32 length, byte type, WOLFSSL* ssl, int epochOrder)
{
    RecordLayerHeader* rl;

    (void)epochOrder;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    if (rl == NULL) {
        return;
    }
    rl->type    = type;
    rl->pvMajor = ssl->version.major;       /* type and version same in each */
        rl->pvMinor = ssl->version.minor;


    if (!ssl->options.dtls) {
        c16toa((word16)length, rl->length);
    }
    else {
    }
}


/* add handshake header for message */
static void AddHandShakeHeader(byte* output, word32 length,
                               word32 fragOffset, word32 fragLength,
                               byte type, WOLFSSL* ssl)
{
    HandShakeHeader* hs;
    (void)fragOffset;
    (void)fragLength;
    (void)ssl;

    /* handshake header */
    hs = (HandShakeHeader*)output;
    if (hs == NULL)
        return;

    hs->type = type;
    c32to24(length, hs->length);         /* type and length same for each */
}

/* add both headers for handshake message */
static void AddHeaders(byte* output, word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;


    AddRecordHeader(output, length + lengthAdj, handshake, ssl, CUR_ORDER);
    AddHandShakeHeader(output + outputAdj, length, 0, length, type, ssl);
}






/* return bytes received, -1 on error */
static int wolfSSLReceive(WOLFSSL* ssl, byte* buf, word32 sz)
{
    int recvd;
    int retryLimit = WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS;

    if (ssl->CBIORecv == NULL) {
        WOLFSSL_MSG("Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssl->CBIORecv(ssl, (char *)buf, (int)sz, ssl->IOCB_ReadCtx);
    if (recvd < 0) {
        switch (recvd) {
            case WOLFSSL_CBIO_ERR_GENERAL:        /* general/unknown error */
                return -1;

            case WOLFSSL_CBIO_ERR_WANT_READ:      /* want read, would block */
                if (retryLimit > 0 && ssl->ctx->autoRetry &&
                        !ssl->options.handShakeDone && !ssl->options.dtls) {
                    retryLimit--;
                    goto retry;
                }
                return WANT_READ;

            case WOLFSSL_CBIO_ERR_CONN_RST:       /* connection reset */
                ssl->options.connReset = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_ISR:            /* interrupt */
                /* see if we got our timeout */
                goto retry;

            case WOLFSSL_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssl->options.isClosed = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_TIMEOUT:
                return -1;

            default:
                WOLFSSL_MSG("Unexpected recv return code");
                return recvd;
        }
    }

    return recvd;
}


/* Switch dynamic output buffer back to static, buffer is assumed clear */
void ShrinkOutputBuffer(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Shrinking output buffer");
    XFREE(ssl->buffers.outputBuffer.buffer - ssl->buffers.outputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
}


/* Switch dynamic input buffer back to static, keep any remaining input */
/* forced free means cleaning up */
void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree)
{
    int usedLength = ssl->buffers.inputBuffer.length -
                     ssl->buffers.inputBuffer.idx;
    if (!forcedFree && usedLength > STATIC_BUFFER_LEN)
        return;

    WOLFSSL_MSG("Shrinking input buffer");

    if (!forcedFree && usedLength > 0)
        XMEMCPY(ssl->buffers.inputBuffer.staticBuffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
               usedLength);

    XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset      = 0;
    ssl->buffers.inputBuffer.idx = 0;
    ssl->buffers.inputBuffer.length = usedLength;
}

int SendBuffered(WOLFSSL* ssl)
{
    if (ssl->CBIOSend == NULL) {
        WOLFSSL_MSG("Your IO Send callback is null, please set");
        return SOCKET_ERROR_E;
    }


    while (ssl->buffers.outputBuffer.length > 0) {
        int sent = ssl->CBIOSend(ssl,
                                      (char*)ssl->buffers.outputBuffer.buffer +
                                      ssl->buffers.outputBuffer.idx,
                                      (int)ssl->buffers.outputBuffer.length,
                                      ssl->IOCB_WriteCtx);
        if (sent < 0) {
            switch (sent) {

                case WOLFSSL_CBIO_ERR_WANT_WRITE:        /* would block */
                    return WANT_WRITE;

                case WOLFSSL_CBIO_ERR_CONN_RST:          /* connection reset */
                    ssl->options.connReset = 1;
                    break;

                case WOLFSSL_CBIO_ERR_ISR:               /* interrupt */
                    /* see if we got our timeout */
                    continue;

                case WOLFSSL_CBIO_ERR_CONN_CLOSE: /* epipe / conn closed */
                    ssl->options.connReset = 1;  /* treat same as reset */
                    break;

                default:
                    return SOCKET_ERROR_E;
            }

            return SOCKET_ERROR_E;
        }

        if (sent > (int)ssl->buffers.outputBuffer.length) {
            WOLFSSL_MSG("SendBuffered() out of bounds read");
            return SEND_OOB_READ_E;
        }

        ssl->buffers.outputBuffer.idx += sent;
        ssl->buffers.outputBuffer.length -= sent;
    }

    ssl->buffers.outputBuffer.idx = 0;

    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);

    return 0;
}


/* Grow the output buffer */
static WC_INLINE int GrowOutputBuffer(WOLFSSL* ssl, int size)
{
    byte* tmp;
    byte  hdrSz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ :
                                      RECORD_HEADER_SZ;
    byte align = WOLFSSL_GENERAL_ALIGNMENT;

    /* the encrypted data will be offset from the front of the buffer by
       the header, if the user wants encrypted alignment they need
       to define their alignment requirement */

    while (align < hdrSz)
        align *= 2;

    tmp = (byte*)XMALLOC(size + ssl->buffers.outputBuffer.length + align,
                             ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    WOLFSSL_MSG("growing output buffer");

    if (tmp == NULL)
        return MEMORY_E;

    if (align)
        tmp += align - hdrSz;


    if (ssl->buffers.outputBuffer.length)
        XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
               ssl->buffers.outputBuffer.length);

    if (ssl->buffers.outputBuffer.dynamicFlag)
        XFREE(ssl->buffers.outputBuffer.buffer -
              ssl->buffers.outputBuffer.offset, ssl->heap,
              DYNAMIC_TYPE_OUT_BUFFER);
    ssl->buffers.outputBuffer.dynamicFlag = 1;

    if (align)
        ssl->buffers.outputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.outputBuffer.offset = 0;

    ssl->buffers.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffer.bufferSize = size +
                                           ssl->buffers.outputBuffer.length;
    return 0;
}


/* Grow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength)
{
    byte* tmp;
    byte  align = ssl->options.dtls ? WOLFSSL_GENERAL_ALIGNMENT : 0;
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;

    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }

    if (usedLength < 0 || size < 0) {
        WOLFSSL_MSG("GrowInputBuffer() called with negative number");
        return BAD_FUNC_ARG;
    }

    tmp = (byte*)XMALLOC(size + usedLength + align,
                             ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    WOLFSSL_MSG("growing input buffer");

    if (tmp == NULL)
        return MEMORY_E;

    if (align)
        tmp += align - hdrSz;


    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag)
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap,DYNAMIC_TYPE_IN_BUFFER);

    ssl->buffers.inputBuffer.dynamicFlag = 1;
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
        ssl->buffers.inputBuffer.offset = 0;

    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    return 0;
}


/* Check available size into output buffer, make room if needed.
 * This function needs to be called before anything gets put
 * into the output buffers since it flushes pending data if it
 * predicts that the msg will exceed MTU. */
int CheckAvailableSize(WOLFSSL *ssl, int size)
{
    if (size < 0) {
        WOLFSSL_MSG("CheckAvailableSize() called with negative number");
        return BAD_FUNC_ARG;
    }


    if (ssl->buffers.outputBuffer.bufferSize - ssl->buffers.outputBuffer.length
                                             < (word32)size) {
        if (GrowOutputBuffer(ssl, size) < 0)
            return MEMORY_E;
    }

    return 0;
}


/* do all verify and sanity checks on record header */
static int GetRecordHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    if (!ssl->options.dtls) {
        XMEMCPY(rh, input + *inOutIdx, RECORD_HEADER_SZ);
        *inOutIdx += RECORD_HEADER_SZ;
        ato16(rh->length, size);
    }
    else {
    }


    /* catch version mismatch */
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor)
    {
        if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->options.acceptState < ACCEPT_FIRST_REPLY_DONE)

            WOLFSSL_MSG("Client attempting to connect with different version");
        else if (ssl->options.side == WOLFSSL_CLIENT_END &&
                                 ssl->options.downgrade &&
                                 ssl->options.connectState < FIRST_REPLY_DONE)
            WOLFSSL_MSG("Server attempting to accept with different version");
        else if (ssl->options.dtls && rh->type == handshake)
            /* Check the DTLS handshake message RH version later. */
            WOLFSSL_MSG("DTLS handshake, skip RH version number check");
        else {
            WOLFSSL_MSG("SSL version error");
            /* send alert per RFC5246 Appendix E. Backward Compatibility */
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                SendAlert(ssl, alert_fatal, protocol_version);
            }
            return VERSION_ERROR;              /* only use requested version */
        }
    }

    /* record layer length check */
    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA))
        return LENGTH_ERROR;

    if (*size == 0 && rh->type != application_data) {
        WOLFSSL_MSG("0 length, non-app data record.");
        return LENGTH_ERROR;
    }

    /* verify record type here as well */
    switch (rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
            break;
        case no_type:
        default:
            WOLFSSL_MSG("Unknown Record Type");
            return UNKNOWN_RECORD_TYPE;
    }

    /* haven't decrypted this record yet */
    ssl->keys.decryptedCur = 0;

    return 0;
}

static int GetHandShakeHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              byte *type, word32 *size, word32 totalSz)
{
    const byte *ptr = input + *inOutIdx;
    (void)ssl;

    *inOutIdx += HANDSHAKE_HEADER_SZ;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = ptr[0];
    c24to32(&ptr[1], size);

    return 0;
}



/* fill with MD5 pad size since biggest required */
static const byte PAD1[PAD_MD5] =
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
static const byte PAD2[PAD_MD5] =
                              { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };


/* calculate MD5 hash for finished */
#ifdef WOLFSSL_TI_HASH
#include <wolfssl/wolfcrypt/hash.h>
#endif

static int BuildMD5(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret;
    byte md5_result[WC_MD5_DIGEST_SIZE];
    wc_Md5  md5[1];

    /* make md5 inner */
    ret = wc_Md5Copy(&ssl->hsHashes->hashMd5, md5);
    if (ret == 0)
        ret = wc_Md5Update(md5, sender, SIZEOF_SENDER);
    if (ret == 0)
        ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_Md5Update(md5, PAD1, PAD_MD5);
    if (ret == 0)
        ret = wc_Md5Final(md5, md5_result);

    /* make md5 outer */
    if (ret == 0) {
        ret = wc_InitMd5_ex(md5, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_Md5Update(md5, PAD2, PAD_MD5);
            if (ret == 0)
                ret = wc_Md5Update(md5, md5_result, WC_MD5_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_Md5Final(md5, hashes->md5);
            wc_Md5Free(md5);
        }
    }


    return ret;
}


/* calculate SHA hash for finished */
static int BuildSHA(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret;
    byte sha_result[WC_SHA_DIGEST_SIZE];
    wc_Sha  sha[1];
    /* make sha inner */
    ret = wc_ShaCopy(&ssl->hsHashes->hashSha, sha); /* Save current position */
    if (ret == 0)
        ret = wc_ShaUpdate(sha, sender, SIZEOF_SENDER);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, PAD1, PAD_SHA);
    if (ret == 0)
        ret = wc_ShaFinal(sha, sha_result);

    /* make sha outer */
    if (ret == 0) {
        ret = wc_InitSha_ex(sha, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, PAD2, PAD_SHA);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, sha_result, WC_SHA_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_ShaFinal(sha, hashes->sha);
            wc_ShaFree(sha);
        }
    }


    return ret;
}


/* Finished doesn't support SHA512, not SHA512 cipher suites yet */
static int BuildFinished(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.tls) {
        ret = BuildTlsFinished(ssl, hashes, sender);
    }
    if (!ssl->options.tls) {
        ret = BuildMD5(ssl, hashes, sender);
        if (ret == 0) {
            ret = BuildSHA(ssl, hashes, sender);
        }
    }

    return ret;
}


    /* cipher requirements */
    enum {
        REQUIRES_RSA,
        REQUIRES_DHE,
        REQUIRES_ECC,
        REQUIRES_ECC_STATIC,
        REQUIRES_PSK,
        REQUIRES_RSA_SIG,
        REQUIRES_AEAD
    };



    /* Does this cipher suite (first, second) have the requirement
       an ephemeral key exchange will still require the key for signing
       the key exchange so ECDHE_RSA requires an rsa key thus rsa_kea */
    static int CipherRequires(byte first, byte second, int requirement)
    {

        (void)requirement;


        if (first == CHACHA_BYTE) {

        switch (second) {
            case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                break;

            case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_ECC)
                    return 1;
                break;

            case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;

            case TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                break;

            case TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_ECC)
                    return 1;
                break;

            case TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;


            case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                break;

            case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                break;

            case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;
        }

        if (requirement == REQUIRES_AEAD)
            return 1;
        }

        /* ECC extensions */
        if (first == ECC_BYTE) {

        switch (second) {
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;



        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM :
        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :
        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_NULL_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDHE_PSK_WITH_NULL_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;

        case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;


        default:
            WOLFSSL_MSG("Unsupported cipher suite, CipherRequires ECC");
            return 0;
        }   /* switch */
        }   /* if     */


        /* Distinct TLS v1.3 cipher suites with cipher and digest only. */
        if (first == TLS13_BYTE) {

            switch (second) {

            default:
                WOLFSSL_MSG("Unsupported cipher suite, CipherRequires "
                            "TLS v1.3");
                return 0;
            }
        }


        if (first != ECC_BYTE && first != CHACHA_BYTE &&
            first != TLS13_BYTE) {   /* normal suites */
        switch (second) {


        case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_NULL_MD5 :
        case TLS_RSA_WITH_NULL_SHA :
        case TLS_RSA_WITH_NULL_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;



        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_GCM_SHA256 :
        case TLS_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :
        case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;


        case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        default:
            WOLFSSL_MSG("Unsupported cipher suite, CipherRequires");
            return 0;
        }  /* switch */
        }  /* if ECC / Normal suites else */


        return 0;
    }





/* Match names with wildcards, each wildcard can represent a single name
   component or fragment but not multiple names, i.e.,
   *.z.com matches y.z.com but not x.y.z.com

   return 1 on success */
int MatchDomainName(const char* pattern, int len, const char* str)
{
    int ret = 0;
    char p, s;

    if (pattern == NULL || str == NULL || len <= 0)
        return 0;

    while (len > 0) {

        p = (char)XTOLOWER((unsigned char)*pattern++);
        if (p == '\0')
            break;

        if (p == '*') {
            while (--len > 0 &&
                (p = (char)XTOLOWER((unsigned char)*pattern++)) == '*') {
            }

            if (len == 0)
                p = '\0';

            while ( (s = (char)XTOLOWER((unsigned char) *str)) != '\0') {
                if (s == p)
                    break;
                if (s == '.')
                    return 0;
                str++;
            }
        }
        else {
            if (p != (char)XTOLOWER((unsigned char) *str))
                return 0;
        }


        if (len > 0) {
            str++;
            len--;
        }
    }

    if (*str == '\0' && len == 0) {
        ret = 1; /* success */
    }

    return ret;
}


/* Check that alternative names, if they exists, match the domain.
 * Fail if there are wild patterns and they didn't match.
 * Check the common name if no alternative names matched.
 *
 * dCert    Decoded cert to get the alternative names from.
 * domain   Domain name to compare against.
 * checkCN  Whether to check the common name.
 * returns  1 : match was found.
 *          0 : no match found.
 *         -1 : No matches and wild pattern match failed.
 */
int CheckForAltNames(DecodedCert* dCert, const char* domain, int* checkCN)
{
    int match = 0;
    DNS_entry* altName = NULL;
    char *buf;
    word32 len;

    WOLFSSL_MSG("Checking AltNames");

    if (dCert)
        altName = dCert->altNames;

    if (checkCN != NULL) {
        *checkCN = (altName == NULL) ? 1 : 0;
    }

    while (altName) {
        WOLFSSL_MSG("\tindividual AltName check");

#if defined(WOLFSSL_IP_ALT_NAME)
        if (altName->type == ASN_IP_TYPE) {
            buf = altName->ipString;
            len = (word32)XSTRLEN(buf);
        }
        else
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
        {
            buf = altName->name;
            len = altName->len;
        }

        if (MatchDomainName(buf, len, domain)) {
            match = 1;
            if (checkCN != NULL) {
                *checkCN = 0;
            }
            WOLFSSL_MSG("\tmatch found");
            break;
        }
        /* No matches and wild pattern match failed. */
        else if (buf && (len >=1) && (buf[0] == '*')) {
            match = -1;
            WOLFSSL_MSG("\twildcard match failed");
        }

        altName = altName->next;
    }

    return match;
}


/* Check the domain name matches the subject alternative name or the subject
 * name.
 *
 * dcert          Decoded certificate.
 * domainName     The domain name.
 * domainNameLen  The length of the domain name.
 * returns DOMAIN_NAME_MISMATCH when no match found and 0 on success.
 */
int CheckHostName(DecodedCert* dCert, const char *domainName, size_t domainNameLen)
{
    int checkCN;
    int ret = DOMAIN_NAME_MISMATCH;

    /* Assume name is NUL terminated. */
    (void)domainNameLen;

    if (CheckForAltNames(dCert, domainName, &checkCN) != 1) {
        WOLFSSL_MSG("DomainName match on alt names failed");
    }
    else {
        ret = 0;
    }

    if (checkCN == 1) {
        if (MatchDomainName(dCert->subjectCN, dCert->subjectCNLen,
                            domainName) == 1) {
            ret = 0;
        }
        else {
            WOLFSSL_MSG("DomainName match on common name failed");
        }
    }

    return ret;
}

int CheckIPAddr(DecodedCert* dCert, const char* ipasc)
{
    WOLFSSL_MSG("Checking IPAddr");

    return CheckHostName(dCert, ipasc, (size_t)XSTRLEN(ipasc));
}









void DoCertFatalAlert(WOLFSSL* ssl, int ret)
{
    int alertWhy;
    if (ssl == NULL || ret == 0) {
        return;
    }
    WOLFSSL_ERROR(ret);

    /* Determine alert reason */
    alertWhy = bad_certificate;
    if (ret == ASN_AFTER_DATE_E || ret == ASN_BEFORE_DATE_E) {
        alertWhy = certificate_expired;
    } else if (ret == ASN_NO_SIGNER_E) {
        alertWhy = unknown_ca;
    }
    else if (ret == NO_PEER_CERT) {
        {
            alertWhy = handshake_failure;
        }
    }

    /* send fatal alert and mark connection closed */
    SendAlert(ssl, alert_fatal, alertWhy); /* try to send */
    ssl->options.isClosed = 1;
}

/* WOLFSSL_ALWAYS_VERIFY_CB: Use verify callback for success or failure cases */
/* WOLFSSL_VERIFY_CB_ALL_CERTS: Issue callback for all intermediate certificates */

/* Callback is issued for certificate presented in TLS Certificate (11) packet.
 * The intermediates are done first then peer leaf cert last. Use the
 * store->error_depth member to determine index (0=peer, >1 intermediates)
 */

int DoVerifyCallback(WOLFSSL_CERT_MANAGER* cm, WOLFSSL* ssl, int ret,
                                                        ProcPeerCertArgs* args)
{
    int verify_ok = 0, use_cb = 0;
    void *heap;

    if (cm == NULL) {
        return BAD_FUNC_ARG;
    }

    heap = (ssl != NULL) ? ssl->heap : cm->heap;

    /* Determine if verify was okay */
    if (ret == 0) {
        verify_ok = 1;
    }

    /* Determine if verify callback should be used */
    if (ret != 0) {
        if ((ssl != NULL) && (!ssl->options.verifyNone)) {
            use_cb = 1; /* always report errors */
        }
    }
    /* if verify callback has been set */
    if ((use_cb && (ssl != NULL) && ((ssl->verifyCallback != NULL)
        ))
    #ifndef NO_WOLFSSL_CM_VERIFY
        || (cm->verifyCallback != NULL)
    #endif
        ) {
        int verifyFail = 0;
        WOLFSSL_X509_STORE_CTX store[1];
        char domain[ASN_NAME_MAX];


        XMEMSET(store, 0, sizeof(WOLFSSL_X509_STORE_CTX));
        domain[0] = '\0';

        /* build subject CN as string to return in store */
        if (args->dCertInit && args->dCert && args->dCert->subjectCN) {
            int subjectCNLen = args->dCert->subjectCNLen;
            if (subjectCNLen > ASN_NAME_MAX-1)
                subjectCNLen = ASN_NAME_MAX-1;
            if (subjectCNLen > 0) {
                XMEMCPY(domain, args->dCert->subjectCN, subjectCNLen);
                domain[subjectCNLen] = '\0';
            }
        }

        store->error = ret;
        store->error_depth = args->certIdx;
        store->discardSessionCerts = 0;
        store->domain = domain;
        if (ssl != NULL) {
            if (ssl->verifyCbCtx != NULL) {
                /* Use the WOLFSSL user context if set */
                store->userCtx = ssl->verifyCbCtx;
            }
            else {
                /* Else use the WOLFSSL_CTX user context */
                store->userCtx = ssl->ctx->verifyCbCtx;
            }
        }
        else {
            store->userCtx = cm;
        }
        store->certs = args->certs;
        store->totalCerts = args->totalCerts;

        if (ssl != NULL) {
        }
    #ifndef NO_WOLFSSL_CM_VERIFY
        /* non-zero return code indicates failure override */
        if (cm->verifyCallback != NULL) {
            store->userCtx = cm;
            if (cm->verifyCallback(verify_ok, store)) {
                if (ret != 0) {
                    WOLFSSL_MSG("Verify CM callback overriding error!");
                    ret = 0;
                }
            }
            else {
                verifyFail = 1;
            }
        }
    #endif

        if (ssl != NULL) {

            /* non-zero return code indicates failure override */
            if (ssl->verifyCallback) {
                if (ssl->verifyCallback(verify_ok, store)) {
                    if (ret != 0) {
                        WOLFSSL_MSG("Verify callback overriding error!");
                        ret = 0;
                    }
                }
                else {
                    verifyFail = 1;
                }
            }
        }

        if (verifyFail) {
            /* induce error if one not present */
            if (ret == 0) {
                ret = VERIFY_CERT_ERROR;
            }

            /* mark as verify error */
            args->verifyErr = 1;
        }
    }

    (void)heap;

    return ret;
}

static void FreeProcPeerCertArgs(WOLFSSL* ssl, void* pArgs)
{
    ProcPeerCertArgs* args = (ProcPeerCertArgs*)pArgs;

    (void)ssl;

    if (args->certs) {
        XFREE(args->certs, ssl->heap, DYNAMIC_TYPE_DER);
        args->certs = NULL;
    }
    if (args->dCert) {
        if (args->dCertInit) {
            FreeDecodedCert(args->dCert);
            args->dCertInit = 0;
        }
        XFREE(args->dCert, ssl->heap, DYNAMIC_TYPE_DCERT);
        args->dCert = NULL;
    }
}


static int ProcessPeerCertParse(WOLFSSL* ssl, ProcPeerCertArgs* args,
    int certType, int verify, byte** pSubjectHash, int* pAlreadySigner)
{
    int ret = 0;
    buffer* cert;
    byte* subjectHash = NULL;
    int alreadySigner = 0;
#ifdef WOLFSSL_SMALL_CERT_VERIFY
    int sigRet = 0;
#endif

    if (ssl == NULL || args == NULL
    #ifndef WOLFSSL_SMALL_CERT_VERIFY
        || args->dCert == NULL
    #endif
    ) {
        return BAD_FUNC_ARG;
    }

    /* check to make sure certificate index is valid */
    if (args->certIdx > args->count)
        return BUFFER_E;

    /* check if returning from non-blocking OCSP */
    /* skip this section because cert is already initialized and parsed */

#ifdef WOLFSSL_TRUST_PEER_CERT
    /* we have trusted peer */
    if (args->haveTrustPeer) {
        return 0;
    }
#endif

    /* get certificate buffer */
    cert = &args->certs[args->certIdx];

#ifdef WOLFSSL_SMALL_CERT_VERIFY
    if (verify == VERIFY) {
        /* for small cert verify, release decoded cert during signature check to
            reduce peak memory usage */
        if (args->dCert != NULL) {
            if (args->dCertInit) {
                FreeDecodedCert(args->dCert);
                args->dCertInit = 0;
            }
            XFREE(args->dCert, ssl->heap, DYNAMIC_TYPE_DCERT);
            args->dCert = NULL;
        }

        /* perform cert parsing and signature check */
        sigRet = CheckCertSignature(cert->buffer, cert->length,
                                         ssl->heap, SSL_CM(ssl));
        /* fail on errors here after the ParseCertRelative call, so dCert is populated */

        /* verify name only in ParseCertRelative below, signature check done */
        verify = VERIFY_NAME;
    }
#endif /* WOLFSSL_SMALL_CERT_VERIFY */

    /* make sure the decoded cert structure is allocated and initialized */
    if (!args->dCertInit
    #ifdef WOLFSSL_SMALL_CERT_VERIFY
        || args->dCert == NULL
    #endif
    ) {
    #ifdef WOLFSSL_SMALL_CERT_VERIFY
        if (args->dCert == NULL) {
            args->dCert = (DecodedCert*)XMALLOC(
                                 sizeof(DecodedCert), ssl->heap,
                                 DYNAMIC_TYPE_DCERT);
            if (args->dCert == NULL) {
                return MEMORY_E;
            }
        }
    #endif

        InitDecodedCert(args->dCert, cert->buffer, cert->length, ssl->heap);

        args->dCertInit = 1;
        args->dCert->sigCtx.devId = ssl->devId;

    }

    /* Parse Certificate */
    ret = ParseCertRelative(args->dCert, certType, verify, SSL_CM(ssl));
    /* perform below checks for date failure cases */
    if (ret == 0 || ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E) {
        /* get subject and determine if already loaded */
    #ifndef NO_SKID
        if (args->dCert->extAuthKeyIdSet)
            subjectHash = args->dCert->extSubjKeyId;
        else
    #endif
            subjectHash = args->dCert->subjectHash;
        alreadySigner = AlreadySigner(SSL_CM(ssl), subjectHash);
    }

#ifdef WOLFSSL_SMALL_CERT_VERIFY
    /* get signature check failures from above */
    if (ret == 0)
        ret = sigRet;
#endif

    if (pSubjectHash)
        *pSubjectHash = subjectHash;
    if (pAlreadySigner)
        *pAlreadySigner = alreadySigner;


    return ret;
}

/* Check key sizes for certs. Is redundant check since
   ProcessBuffer also performs this check. */
static int ProcessPeerCertCheckKey(WOLFSSL* ssl, ProcPeerCertArgs* args)
{
    int ret = 0;

    if (ssl->options.verifyNone) {
        return ret;
    }

    switch (args->dCert->keyOID) {
        case RSAk:
            if (ssl->options.minRsaKeySz < 0 ||
                    args->dCert->pubKeySize <
                     (word16)ssl->options.minRsaKeySz) {
                WOLFSSL_MSG(
                    "RSA key size in cert chain error");
                ret = RSA_KEY_SIZE_E;
            }
            break;
        case ECDSAk:
            if (ssl->options.minEccKeySz < 0 ||
                    args->dCert->pubKeySize <
                     (word16)ssl->options.minEccKeySz) {
                WOLFSSL_MSG(
                    "ECC key size in cert chain error");
                ret = ECC_KEY_SIZE_E;
            }
            break;
        default:
            WOLFSSL_MSG("Key size not checked");
            /* key not being checked for size if not in
               switch */
            break;
    }

    return ret;
}

int ProcessPeerCerts(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                     word32 totalSz)
{
    int ret = 0;
    ProcPeerCertArgs  args[1];
    byte* subjectHash = NULL;
    int alreadySigner = 0;

    WOLFSSL_ENTER("ProcessPeerCerts");

    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(ProcPeerCertArgs));
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
    }

    switch (ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            word32 listSz;



            /* allocate buffer for certs */
            args->certs = (buffer*)XMALLOC(sizeof(buffer) * MAX_CHAIN_DEPTH,
                                            ssl->heap, DYNAMIC_TYPE_DER);
            if (args->certs == NULL) {
                ERROR_OUT(MEMORY_E, exit_ppc);
            }
            XMEMSET(args->certs, 0, sizeof(buffer) * MAX_CHAIN_DEPTH);

            /* Certificate List */
            if ((args->idx - args->begin) + OPAQUE24_LEN > totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }
            c24to32(input + args->idx, &listSz);
            args->idx += OPAQUE24_LEN;
            if (listSz > MAX_CERTIFICATE_SZ) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }
            if ((args->idx - args->begin) + listSz != totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }

            WOLFSSL_MSG("Loading peer's cert chain");
            /* first put cert chain into buffer so can verify top down
               we're sent bottom up */
            while (listSz) {
                word32 certSz;


                if (args->totalCerts >= ssl->verifyDepth ||
                        args->totalCerts >= MAX_CHAIN_DEPTH) {
                    ERROR_OUT(MAX_CHAIN_ERROR, exit_ppc);
                }

                if ((args->idx - args->begin) + OPAQUE24_LEN > totalSz) {
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
                }

                c24to32(input + args->idx, &certSz);
                args->idx += OPAQUE24_LEN;

                if ((args->idx - args->begin) + certSz > totalSz) {
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
                }

                args->certs[args->totalCerts].length = certSz;
                args->certs[args->totalCerts].buffer = input + args->idx;


                args->idx += certSz;
                listSz -= certSz + CERT_HEADER_SZ;


                args->totalCerts++;
                WOLFSSL_MSG("\tPut another cert into chain");
            } /* while (listSz) */

            args->count = args->totalCerts;
            args->certIdx = 0; /* select peer cert (first one) */

            if (args->count == 0) {
                /* Empty certificate message. */
                if ((ssl->options.side == WOLFSSL_SERVER_END) &&
                    (ssl->options.mutualAuth || (ssl->options.failNoCert &&
                                             IsAtLeastTLSv1_3(ssl->version)))) {
                    WOLFSSL_MSG("No peer cert from Client");
                    ret = NO_PEER_CERT;
                    DoCertFatalAlert(ssl, ret);
                }
                else if ((ssl->options.side == WOLFSSL_CLIENT_END) &&
                         IsAtLeastTLSv1_3(ssl->version)) {
                    WOLFSSL_MSG("No peer cert from Server");
                    ret = NO_PEER_CERT;
                    SendAlert(ssl, alert_fatal, decode_error);
                }
            }

            args->dCertInit = 0;
        #ifndef WOLFSSL_SMALL_CERT_VERIFY
            args->dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), ssl->heap,
                                                       DYNAMIC_TYPE_DCERT);
            if (args->dCert == NULL) {
                ERROR_OUT(MEMORY_E, exit_ppc);
            }
            XMEMSET(args->dCert, 0, sizeof(DecodedCert));
        #endif

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            if (args->count > 0) {

                /* check for trusted peer and get untrustedDepth */
            #if defined(WOLFSSL_TRUST_PEER_CERT)
                if (args->certIdx == 0) {
                #ifdef WOLFSSL_TRUST_PEER_CERT
                    TrustedPeerCert* tp;
                #endif

                    ret = ProcessPeerCertParse(ssl, args, CERT_TYPE, NO_VERIFY,
                        &subjectHash, &alreadySigner);
                    if (ret != 0)
                        goto exit_ppc;


                #ifdef WOLFSSL_TRUST_PEER_CERT
                    tp = GetTrustedPeer(SSL_CM(ssl), args->dCert);
                    WOLFSSL_MSG("Checking for trusted peer cert");

                    if (tp && MatchTrustedPeer(tp, args->dCert)) {
                        WOLFSSL_MSG("Found matching trusted peer cert");
                        args->haveTrustPeer = 1;
                    }
                    else if (tp == NULL) {
                        /* no trusted peer cert */
                        WOLFSSL_MSG("No matching trusted peer cert. Checking CAs");
                    }
                    else {
                        WOLFSSL_MSG("Trusted peer cert did not match!");
                    }
                    if (!args->haveTrustPeer)
                #endif
                    {
                        /* free cert if not trusted peer */
                        FreeDecodedCert(args->dCert);
                        args->dCertInit = 0;
                    }
                }
            #endif /* WOLFSSL_TRUST_PEER_CERT || OPENSSL_EXTRA */

                /* check certificate up to peer's first */
                /* do not verify chain if trusted peer cert found */
                while (args->count > 1
                #ifdef WOLFSSL_TRUST_PEER_CERT
                    && !args->haveTrustPeer
                #endif /* WOLFSSL_TRUST_PEER_CERT */
                ) {
                    int skipAddCA = 0;

                    /* select last certificate */
                    args->certIdx = args->count - 1;

                    ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                        !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                        &subjectHash, &alreadySigner);
                    if (ret == 0) {
                        ret = ProcessPeerCertCheckKey(ssl, args);
                    }

                    if (ret == 0 && args->dCert->isCA == 0) {
                        WOLFSSL_MSG("Chain cert is not a CA, not adding as one");
                    }
                    else if (ret == 0 && ssl->options.verifyNone) {
                        WOLFSSL_MSG("Chain cert not verified by option, "
                            "not adding as CA");
                    }
                    else if (ret == 0) {

                        if (alreadySigner) {
                            WOLFSSL_MSG("Verified CA from chain and already had it");
                        }
                    }
                    else {
                        WOLFSSL_MSG("Failed to verify CA from chain");
                    }


                    /* Do verify callback */
                    ret = DoVerifyCallback(SSL_CM(ssl), ssl, ret, args);
                    if (ssl->options.verifyNone &&
                              (ret == CRL_MISSING || ret == CRL_CERT_REVOKED ||
                               ret == CRL_CERT_DATE_ERR)) {
                        WOLFSSL_MSG("Ignoring CRL problem based on verify setting");
                        ret = ssl->error = 0;
                    }



                    /* If valid CA then add to Certificate Manager */
                    if (ret == 0 && args->dCert->isCA &&
                            !ssl->options.verifyNone && !skipAddCA) {
                        buffer* cert = &args->certs[args->certIdx];

                        /* Is valid CA */
                        if (!alreadySigner) {
                            DerBuffer* add = NULL;
                            ret = AllocDer(&add, cert->length, CA_TYPE, ssl->heap);
                            if (ret < 0)
                                goto exit_ppc;

                            XMEMCPY(add->buffer, cert->buffer, cert->length);

                            /* CA already verified above in ParseCertRelative */
                            WOLFSSL_MSG("Adding CA from chain");
                            ret = AddCA(SSL_CM(ssl), &add, WOLFSSL_CHAIN_CA,
                                NO_VERIFY);
                            if (ret == WOLFSSL_SUCCESS) {
                                ret = 0;
                            }
                        }
                    }

                    /* Handle error codes */
                    if (ret != 0) {
                        if (!ssl->options.verifyNone) {
                            DoCertFatalAlert(ssl, ret);
                        }
                        ssl->error = ret; /* Report SSL error */

                        if (args->lastErr == 0) {
                            args->lastErr = ret; /* save error from last time */
                            ret = 0; /* reset error */
                        }
                    }

                    FreeDecodedCert(args->dCert);
                    args->dCertInit = 0;
                    args->count--;
                } /* while (count > 0 && !args->haveTrustPeer) */
            } /* if (count > 0) */

            /* Check for error */
            if (ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            /* peer's, may not have one if blank client cert sent by TLSv1.2 */
            if (args->count > 0) {
                WOLFSSL_MSG("Verifying Peer's cert");

                /* select peer cert (first one) */
                args->certIdx = 0;

                ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                        !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                        &subjectHash, &alreadySigner);
                if (ret == 0) {
                    WOLFSSL_MSG("Verified Peer's cert");

                #ifndef OPENSSL_COMPATIBLE_DEFAULTS
                    /* Check peer's certificate version number. TLS 1.2 / 1.3
                     * requires the clients certificate be version 3 unless a
                     * different version has been negotiated using RFC 7250.
                     * OpenSSL doesn't appear to be performing this check.
                     * For TLS 1.3 see RFC8446 Section 4.4.2.3 */
                    if (ssl->options.side == WOLFSSL_SERVER_END) {
                        if (args->dCert->version != WOLFSSL_X509_V3) {
                            WOLFSSL_MSG("Peers certificate was not version 3!");
                            args->lastErr = ASN_VERSION_E;
                            /* setting last error but not considering it fatal
                             * giving the user a chance to override */
                        }
                    }
                #endif

                    /* check if fatal error */
                    if (args->verifyErr) {
                        args->fatal = 1;
                        ret = args->lastErr;
                    }
                    else {
                        args->fatal = 0;
                    }
                }
                else if (ret == ASN_PARSE_E || ret == BUFFER_E) {
                    WOLFSSL_MSG("Got Peer cert ASN PARSE or BUFFER ERROR");
                    args->fatal = 1;
                }
                else {
                    WOLFSSL_MSG("Failed to verify Peer's cert");
                    if (ssl->verifyCallback) {
                        WOLFSSL_MSG(
                            "\tCallback override available, will continue");
                        /* check if fatal error */
                        args->fatal = (args->verifyErr) ? 1 : 0;
                        if (args->fatal)
                            DoCertFatalAlert(ssl, ret);
                    }
                    else {
                        WOLFSSL_MSG("\tNo callback override available, fatal");
                        args->fatal = 1;
                        DoCertFatalAlert(ssl, ret);
                    }
                }

            } /* if (count > 0) */

            /* Check for error */
            if (args->fatal && ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            if (args->count > 0) {


            #ifndef IGNORE_KEY_EXTENSIONS
                if (args->dCert->extKeyUsageSet) {
                    if ((ssl->specs.kea == rsa_kea) &&
                        (ssl->options.side == WOLFSSL_CLIENT_END) &&
                        (args->dCert->extKeyUsage & KEYUSE_KEY_ENCIPHER) == 0) {
                        ret = KEYUSE_ENCIPHER_E;
                    }
                    if ((ssl->specs.sig_algo == rsa_sa_algo ||
                            (ssl->specs.sig_algo == ecc_dsa_sa_algo &&
                                 !ssl->specs.static_ecdh)) &&
                        (args->dCert->extKeyUsage & KEYUSE_DIGITAL_SIG) == 0) {
                        WOLFSSL_MSG("KeyUse Digital Sig not set");
                        ret = KEYUSE_SIGNATURE_E;
                    }
                }

                if (args->dCert->extExtKeyUsageSet) {
                    if (ssl->options.side == WOLFSSL_CLIENT_END) {
                        if ((args->dCert->extExtKeyUsage &
                                (EXTKEYUSE_ANY | EXTKEYUSE_SERVER_AUTH)) == 0) {
                            WOLFSSL_MSG("ExtKeyUse Server Auth not set");
                            ret = EXTKEYUSE_AUTH_E;
                        }
                    }
                    else {
                        if ((args->dCert->extExtKeyUsage &
                                (EXTKEYUSE_ANY | EXTKEYUSE_CLIENT_AUTH)) == 0) {
                            WOLFSSL_MSG("ExtKeyUse Client Auth not set");
                            ret = EXTKEYUSE_AUTH_E;
                        }
                    }
                }
            #endif /* IGNORE_KEY_EXTENSIONS */

                if (args->fatal) {
                    ssl->error = ret;
                    goto exit_ppc;
                }

                /* Certificate validated and stored. */
                ssl->options.havePeerCert = 1;
                if (ssl->options.side == WOLFSSL_CLIENT_END &&
                    ssl->specs.sig_algo == rsa_kea) {
                    /* CLIENT: No ServerKeyExchange message sent by server. */
                    ssl->options.peerAuthGood = 1;
                }
                if (ssl->options.side == WOLFSSL_CLIENT_END &&
                    ssl->specs.static_ecdh) {
                    /* CLIENT: No ServerKeyExchange message sent by server. */
                    ssl->options.peerAuthGood = 1;
                }


                if (!ssl->options.verifyNone && ssl->buffers.domainName.buffer) {
                #ifndef WOLFSSL_ALLOW_NO_CN_IN_SAN
                    /* Per RFC 5280 section 4.2.1.6, "Whenever such identities
                     * are to be bound into a certificate, the subject
                     * alternative name extension MUST be used." */
                    if (args->dCert->altNames) {
                        if (CheckForAltNames(args->dCert,
                                (char*)ssl->buffers.domainName.buffer,
                                NULL) != 1) {
                            WOLFSSL_MSG("DomainName match on alt names failed");
                            /* try to get peer key still */
                            ret = DOMAIN_NAME_MISMATCH;
                        }
                    }
                    else {
                        if (MatchDomainName(
                                 args->dCert->subjectCN,
                                 args->dCert->subjectCNLen,
                                 (char*)ssl->buffers.domainName.buffer) == 0) {
                            WOLFSSL_MSG("DomainName match on common name failed");
                            ret = DOMAIN_NAME_MISMATCH;
                        }
                    }
                #else /* WOLFSSL_ALL_NO_CN_IN_SAN */
                    /* Old behavior. */
                    if (MatchDomainName(args->dCert->subjectCN,
                                args->dCert->subjectCNLen,
                                (char*)ssl->buffers.domainName.buffer) == 0) {
                        WOLFSSL_MSG("DomainName match on common name failed");
                        if (CheckForAltNames(args->dCert,
                                 (char*)ssl->buffers.domainName.buffer,
                                 NULL) != 1) {
                            WOLFSSL_MSG(
                                "DomainName match on alt names failed too");
                            /* try to get peer key still */
                            ret = DOMAIN_NAME_MISMATCH;
                        }
                    }
                #endif /* WOLFSSL_ALL_NO_CN_IN_SAN */
                }

                /* decode peer key */
                switch (args->dCert->keyOID) {
                    case RSAk:
                    {
                        word32 keyIdx = 0;
                        int keyRet = 0;

                        if (ssl->peerRsaKey == NULL) {
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_RSA,
                                                (void**)&ssl->peerRsaKey);
                        } else if (ssl->peerRsaKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_RSA,
                                              ssl->peerRsaKey);
                            ssl->peerRsaKeyPresent = 0;
                        }

                        if (keyRet != 0 || wc_RsaPublicKeyDecode(
                               args->dCert->publicKey, &keyIdx, ssl->peerRsaKey,
                                                args->dCert->pubKeySize) != 0) {
                            ret = PEER_KEY_ERROR;
                        }
                        else {
                            ssl->peerRsaKeyPresent = 1;
                    #if defined(WOLFSSL_RENESAS_TSIP_TLS) || \
                                             defined(WOLFSSL_RENESAS_SCEPROTECT)
                        /* copy encrypted tsip key index into ssl object */
                        if (args->dCert->sce_tsip_encRsaKeyIdx) {
                            if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                ssl->peerSceTsipEncRsaKeyIndex = (byte*)XMALLOC(
                                    TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY,
                                    ssl->heap, DYNAMIC_TYPE_RSA);
                                if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                    args->lastErr = MEMORY_E;
                                    goto exit_ppc;
                                }
                            }

                            XMEMCPY(ssl->peerSceTsipEncRsaKeyIndex,
                                        args->dCert->sce_tsip_encRsaKeyIdx,
                                        TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY);
                         }
                    #endif
                        }

                        /* check size of peer RSA key */
                        if (ret == 0 && ssl->peerRsaKeyPresent &&
                                          !ssl->options.verifyNone &&
                                          wc_RsaEncryptSize(ssl->peerRsaKey)
                                              < ssl->options.minRsaKeySz) {
                            ret = RSA_KEY_SIZE_E;
                            WOLFSSL_MSG("Peer RSA key is too small");
                        }
                        break;
                    }
                    case ECDSAk:
                    {
                        int keyRet = 0;
                        word32 idx = 0;
                    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || \
                        defined(WOLFSSL_RENESAS_TSIP_TLS)
                        /* copy encrypted tsip/sce key index into ssl object */
                        if (args->dCert->sce_tsip_encRsaKeyIdx) {
                            if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                ssl->peerSceTsipEncRsaKeyIndex = (byte*)XMALLOC(
                                    TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY,
                                    ssl->heap, DYNAMIC_TYPE_RSA);
                                if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                    args->lastErr = MEMORY_E;
                                    ERROR_OUT(MEMORY_ERROR, exit_ppc);
                                }
                            }

                            XMEMCPY(ssl->peerSceTsipEncRsaKeyIndex,
                                        args->dCert->sce_tsip_encRsaKeyIdx,
                                        TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY);
                         }
                    #endif
                        if (ssl->peerEccDsaKey == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                    (void**)&ssl->peerEccDsaKey);
                        } else if (ssl->peerEccDsaKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_ECC,
                                              ssl->peerEccDsaKey);
                            ssl->peerEccDsaKeyPresent = 0;
                        }

                        if (keyRet != 0 ||
                            wc_EccPublicKeyDecode(args->dCert->publicKey, &idx,
                                                ssl->peerEccDsaKey,
                                                args->dCert->pubKeySize) != 0) {
                            ret = PEER_KEY_ERROR;
                        }
                        else {
                            ssl->peerEccDsaKeyPresent = 1;

                        }

                        /* check size of peer ECC key */
                        if (ret == 0 && ssl->peerEccDsaKeyPresent &&
                                              !ssl->options.verifyNone &&
                                              wc_ecc_size(ssl->peerEccDsaKey)
                                              < ssl->options.minEccKeySz) {
                            ret = ECC_KEY_SIZE_E;
                            WOLFSSL_MSG("Peer ECC key is too small");
                        }

                        /* populate curve oid - if missing */
                        if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->ecdhCurveOID == 0)
                            ssl->ecdhCurveOID = args->dCert->pkCurveOID;
                        break;
                    }
                    default:
                        break;
                }

                /* args->dCert free'd in function cleanup after callback */
            } /* if (count > 0) */

            /* Check for error */
            if (args->fatal && ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            /* load last error */
            if (args->lastErr != 0 && ret == 0) {
                ret = args->lastErr;
            }


            /* Do verify callback */
            ret = DoVerifyCallback(SSL_CM(ssl), ssl, ret, args);

            if (ssl->options.verifyNone &&
                              (ret == CRL_MISSING || ret == CRL_CERT_REVOKED ||
                               ret == CRL_CERT_DATE_ERR)) {
                WOLFSSL_MSG("Ignoring CRL problem based on verify setting");
                ret = ssl->error = 0;
            }

            if (ret != 0) {
                if (!ssl->options.verifyNone) {
                    DoCertFatalAlert(ssl, ret);
                }
                ssl->error = ret; /* Report SSL error */
            }

            if (ret == 0 && ssl->options.side == WOLFSSL_CLIENT_END) {
                ssl->options.serverState = SERVER_CERT_COMPLETE;
            }

            if (IsEncryptionOn(ssl, 0)) {
                args->idx += ssl->keys.padSz;
                if (ssl->options.startedETMRead)
                    args->idx += MacSize(ssl);
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            /* Set final index */
            *inOutIdx = args->idx;

            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
            break;
    } /* switch(ssl->options.asyncState) */

exit_ppc:

    WOLFSSL_LEAVE("ProcessPeerCerts", ret);



    FreeProcPeerCertArgs(ssl, args);


    FreeKeyExchange(ssl);

    return ret;
}


/* handle processing of certificate (11) */
static int DoCertificate(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                                                                word32 size)
{
    int ret;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_DO);
    WOLFSSL_ENTER("DoCertificate");


    ret = ProcessPeerCerts(ssl, input, inOutIdx, size);


    WOLFSSL_LEAVE("DoCertificate", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_DO);

    return ret;
}

/* handle processing of certificate_status (22) */
static int DoCertificateStatus(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                                                                    word32 size)
{
    int    ret = 0;
    byte   status_type;
    word32 status_length;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_STATUS_DO);
    WOLFSSL_ENTER("DoCertificateStatus");

    if (size < ENUM_LEN + OPAQUE24_LEN)
        return BUFFER_ERROR;

    status_type = input[(*inOutIdx)++];

    c24to32(input + *inOutIdx, &status_length);
    *inOutIdx += OPAQUE24_LEN;

    if (size != ENUM_LEN + OPAQUE24_LEN + status_length)
        return BUFFER_ERROR;

    switch (status_type) {



        default:
            ret = BUFFER_ERROR;
    }

    if (ret != 0)
        SendAlert(ssl, alert_fatal, bad_certificate_status_response);

    if (IsEncryptionOn(ssl, 0)) {
        if (ssl->options.startedETMRead) {
            word32 digestSz = MacSize(ssl);
            if (*inOutIdx + ssl->keys.padSz + digestSz > size)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz + digestSz;
        }
        else
        {
            if (*inOutIdx + ssl->keys.padSz > size)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz;
        }
    }

    WOLFSSL_LEAVE("DoCertificateStatus", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_STATUS_DO);

    return ret;
}





static int DoHelloRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                                                    word32 size, word32 totalSz)
{
    (void)input;

    WOLFSSL_START(WC_FUNC_HELLO_REQUEST_DO);
    WOLFSSL_ENTER("DoHelloRequest");

    if (size) /* must be 0 */
        return BUFFER_ERROR;

    if (IsEncryptionOn(ssl, 0)) {
        /* If size == totalSz then we are in DtlsMsgDrain so no need to worry
         * about padding */
        if (ssl->options.startedETMRead) {
            word32 digestSz = MacSize(ssl);
            if (size != totalSz &&
                    *inOutIdx + ssl->keys.padSz + digestSz > totalSz)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz + digestSz;
        }
        else
        {
            /* access beyond input + size should be checked against totalSz */
            if (size != totalSz &&
                    *inOutIdx + ssl->keys.padSz > totalSz)
                return BUFFER_E;

            *inOutIdx += ssl->keys.padSz;
        }
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        SendAlert(ssl, alert_fatal, unexpected_message); /* try */
        return FATAL_ERROR;
    }
    else {
        return SendAlert(ssl, alert_warning, no_renegotiation);
    }
}


int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size,
                                                      word32 totalSz, int sniff)
{
    word32 finishedSz = (ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ);

    WOLFSSL_START(WC_FUNC_FINISHED_DO);
    WOLFSSL_ENTER("DoFinished");

    if (finishedSz != size)
        return BUFFER_ERROR;

    /* check against totalSz
     * If size == totalSz then we are in DtlsMsgDrain so no need to worry about
     * padding */
    if (size != totalSz) {
        if (ssl->options.startedETMRead) {
            if (*inOutIdx + size + ssl->keys.padSz + MacSize(ssl) > totalSz)
                return BUFFER_E;
        }
        else
        {
            if (*inOutIdx + size + ssl->keys.padSz > totalSz)
                return BUFFER_E;
        }
    }


    if (sniff == NO_SNIFF) {
        if (XMEMCMP(input + *inOutIdx, &ssl->hsHashes->verifyHashes,size) != 0){
            WOLFSSL_MSG("Verify finished error on hashes");
            return VERIFY_FINISHED_ERROR;
        }
    }


    /* force input exhaustion at ProcessReply consuming padSz */
    *inOutIdx += size + ssl->keys.padSz;
    if (ssl->options.startedETMRead)
        *inOutIdx += MacSize(ssl);

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        if (ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }

    WOLFSSL_LEAVE("DoFinished", 0);
    WOLFSSL_END(WC_FUNC_FINISHED_DO);

    return 0;
}


/* Make sure no duplicates, no fast forward, or other problems; 0 on success */
static int SanityCheckMsgReceived(WOLFSSL* ssl, byte type)
{
    /* verify not a duplicate, mark received, check state */
    switch (type) {

        case hello_request:
            if (ssl->msgsReceived.got_hello_request) {
                WOLFSSL_MSG("Duplicate HelloRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_request = 1;

            break;


        case server_hello:
            if (ssl->msgsReceived.got_server_hello) {
                WOLFSSL_MSG("Duplicate ServerHello received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello = 1;

            break;

        case hello_verify_request:
            if (ssl->msgsReceived.got_hello_verify_request) {
                WOLFSSL_MSG("Duplicate HelloVerifyRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_verify_request = 1;

            break;

        case session_ticket:
            if (ssl->msgsReceived.got_session_ticket) {
                WOLFSSL_MSG("Duplicate SessionTicket received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_session_ticket = 1;

            break;

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
            break;

        case certificate_status:
            if (ssl->msgsReceived.got_certificate_status) {
                WOLFSSL_MSG("Duplicate CertificateStatus received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_status = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Certificate before CertificateStatus");
                return OUT_OF_ORDER_E;
            }
            if (ssl->msgsReceived.got_server_key_exchange != 0) {
                WOLFSSL_MSG("CertificateStatus after ServerKeyExchange");
                return OUT_OF_ORDER_E;
            }

            break;

        case server_key_exchange:
            if (ssl->msgsReceived.got_server_key_exchange) {
                WOLFSSL_MSG("Duplicate ServerKeyExchange received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_key_exchange = 1;

            if (ssl->msgsReceived.got_server_hello == 0) {
                WOLFSSL_MSG("No ServerHello before ServerKeyExchange");
                return OUT_OF_ORDER_E;
            }
            if (ssl->msgsReceived.got_certificate_status == 0) {
            }

            break;

        case certificate_request:
            if (ssl->msgsReceived.got_certificate_request) {
                WOLFSSL_MSG("Duplicate CertificateRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_request = 1;

            break;

        case server_hello_done:
            if (ssl->msgsReceived.got_server_hello_done) {
                WOLFSSL_MSG("Duplicate ServerHelloDone received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello_done = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                if (ssl->specs.kea == psk_kea ||
                    ssl->specs.kea == dhe_psk_kea ||
                    ssl->specs.kea == ecdhe_psk_kea ||
                    ssl->options.usingAnon_cipher) {
                    WOLFSSL_MSG("No Cert required");
                } else {
                    WOLFSSL_MSG("No Certificate before ServerHelloDone");
                    return OUT_OF_ORDER_E;
                }
            }
            if (ssl->msgsReceived.got_server_key_exchange == 0) {
                int pskNoServerHint = 0;  /* not required in this case */

                if (ssl->specs.static_ecdh == 1 ||
                    ssl->specs.kea == rsa_kea ||
                    pskNoServerHint) {
                    WOLFSSL_MSG("No KeyExchange required");
                } else {
                    WOLFSSL_MSG("No ServerKeyExchange before ServerDone");
                    return OUT_OF_ORDER_E;
                }
            }
            break;



        case finished:
            if (ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("Duplicate Finished received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_finished = 1;

            if (ssl->msgsReceived.got_change_cipher == 0) {
                WOLFSSL_MSG("Finished received before ChangeCipher");
                return NO_CHANGE_CIPHER_E;
            }
            break;

        case change_cipher_hs:
            if (ssl->msgsReceived.got_change_cipher) {
                WOLFSSL_MSG("Duplicate ChangeCipher received");
                return DUPLICATE_MSG_E;
            }
            /* DTLS is going to ignore the CCS message if the client key
             * exchange message wasn't received yet. */
            if (!ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;

            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if (!ssl->options.resuming) {
                   if (ssl->msgsReceived.got_server_hello_done == 0) {
                        WOLFSSL_MSG("No ServerHelloDone before ChangeCipher");
                        return OUT_OF_ORDER_E;
                   }
                }
                else {
                    if (ssl->msgsReceived.got_server_hello == 0) {
                        WOLFSSL_MSG("No ServerHello before ChangeCipher on Resume");
                        return OUT_OF_ORDER_E;
                    }
                }
            }
            if (ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;
            break;

        default:
            WOLFSSL_MSG("Unknown message type");
            return SANITY_MSG_E;
    }

    return 0;
}


static int DoHandShakeMsgType(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          byte type, word32 size, word32 totalSz)
{
    int ret = 0;
    word32 expectedIdx;

    WOLFSSL_ENTER("DoHandShakeMsgType");


    /* make sure can read the message */
    if (*inOutIdx + size > totalSz) {
        WOLFSSL_MSG("Incomplete Data");
        return INCOMPLETE_DATA;
    }

    expectedIdx = *inOutIdx + size +
                  (ssl->keys.encryptionOn ? ssl->keys.padSz : 0);
    if (ssl->options.startedETMRead && ssl->keys.encryptionOn)
        expectedIdx += MacSize(ssl);


    /* sanity check msg received */
    if ( (ret = SanityCheckMsgReceived(ssl, type)) != 0) {
        WOLFSSL_MSG("Sanity Check on handshake message type received failed");
        return ret;
    }


    if (ssl->options.handShakeState == HANDSHAKE_DONE && type != hello_request){
        WOLFSSL_MSG("HandShake message after handshake complete");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls == 0 &&
               ssl->options.serverState == NULL_STATE && type != server_hello) {
        WOLFSSL_MSG("First server message not server hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls &&
            type == server_hello_done &&
            ssl->options.serverState < SERVER_HELLO_COMPLETE) {
        WOLFSSL_MSG("Server hello done received before server hello in DTLS");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END &&
               ssl->options.clientState == NULL_STATE && type != client_hello) {
        WOLFSSL_MSG("First client message not client hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    /* above checks handshake state */
    /* hello_request not hashed */
    /* Also, skip hashing the client_hello message here for DTLS. It will be
     * hashed later if the DTLS cookie is correct. */
    if (type != hello_request
    ) {
        ret = HashInput(ssl, input + *inOutIdx, size);
        if (ret != 0) {
            WOLFSSL_MSG("Incomplete handshake hashes");
            return ret;
        }
    }


    switch (type) {

    case hello_request:
        WOLFSSL_MSG("processing hello request");
        ret = DoHelloRequest(ssl, input, inOutIdx, size, totalSz);
        break;

    case hello_verify_request:
        WOLFSSL_MSG("processing hello verify request");
        ret = DoHelloVerifyRequest(ssl, input,inOutIdx, size);
        if (IsEncryptionOn(ssl, 0)) {
            if (ssl->options.startedETMRead) {
                word32 digestSz = MacSize(ssl);
                if (*inOutIdx + ssl->keys.padSz + digestSz > totalSz)
                    return BUFFER_E;
                *inOutIdx += ssl->keys.padSz + digestSz;
            }
            else
            {
                /* access beyond input + size should be checked against totalSz
                 */
                if (*inOutIdx + ssl->keys.padSz > totalSz)
                    return BUFFER_E;

                *inOutIdx += ssl->keys.padSz;
            }
        }
        break;

    case server_hello:
        WOLFSSL_MSG("processing server hello");
        ret = DoServerHello(ssl, input, inOutIdx, size);
        break;

    case certificate_request:
        WOLFSSL_MSG("processing certificate request");
        ret = DoCertificateRequest(ssl, input, inOutIdx, size);
        break;

    case server_key_exchange:
        WOLFSSL_MSG("processing server key exchange");
        ret = DoServerKeyExchange(ssl, input, inOutIdx, size);
        break;


    case certificate:
        WOLFSSL_MSG("processing certificate");
        ret = DoCertificate(ssl, input, inOutIdx, size);
        break;

    case certificate_status:
        WOLFSSL_MSG("processing certificate status");
        ret = DoCertificateStatus(ssl, input, inOutIdx, size);
        break;

    case server_hello_done:
        WOLFSSL_MSG("processing server hello done");
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
            if (ssl->options.startedETMRead)
                *inOutIdx += MacSize(ssl);
        }
        if (ssl->options.resuming) {
            WOLFSSL_MSG("Not resuming as thought");
            ssl->options.resuming = 0;
            /* CLIENT: No longer resuming, reset peer authentication state. */
            ssl->options.peerAuthGood = 0;
        }
        break;

    case finished:
        WOLFSSL_MSG("processing finished");
        ret = DoFinished(ssl, input, inOutIdx, size, totalSz, NO_SNIFF);
        break;


    default:
        WOLFSSL_MSG("Unknown handshake message type");
        ret = UNKNOWN_HANDSHAKE_TYPE;
        break;
    }
    if (ret == 0 && expectedIdx != *inOutIdx) {
        WOLFSSL_MSG("Extra data in handshake message");
        if (!ssl->options.dtls)
            SendAlert(ssl, alert_fatal, decode_error);
        ret = DECODE_E;
    }

    if (ret == 0 && ssl->buffers.inputBuffer.dynamicFlag
    ) {
        if (IsEncryptionOn(ssl, 0)) {
            word32 extra = ssl->keys.padSz;

            if (ssl->options.startedETMRead)
                extra += MacSize(ssl);

            if (extra > ssl->buffers.inputBuffer.idx)
                return BUFFER_E;

            ssl->buffers.inputBuffer.idx -= extra;
            ShrinkInputBuffer(ssl, NO_FORCED_FREE);
            ssl->buffers.inputBuffer.idx += extra;
        }
        else {
            ShrinkInputBuffer(ssl, NO_FORCED_FREE);
        }
    }



    WOLFSSL_LEAVE("DoHandShakeMsgType()", ret);
    return ret;
}


static int DoHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    int    ret = 0;
    word32 inputLength;

    WOLFSSL_ENTER("DoHandShakeMsg()");

    if (ssl->arrays == NULL) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl,input,inOutIdx,&type, &size, totalSz) != 0)
            return PARSE_ERROR;

        return DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }

    inputLength = ssl->buffers.inputBuffer.length - *inOutIdx;

    /* If there is a pending fragmented handshake message,
     * pending message size will be non-zero. */
    if (ssl->arrays->pendingMsgSz == 0) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl,input, inOutIdx, &type, &size, totalSz) != 0)
            return PARSE_ERROR;

        /* Cap the maximum size of a handshake message to something reasonable.
         * By default is the maximum size of a certificate message assuming
         * nine 2048-bit RSA certificates in the chain. */
        if (size > MAX_HANDSHAKE_SZ) {
            WOLFSSL_MSG("Handshake message too large");
            return HANDSHAKE_SIZE_ERROR;
        }

        /* size is the size of the certificate message payload */
        if (inputLength - HANDSHAKE_HEADER_SZ < size) {
            ssl->arrays->pendingMsgType = type;
            ssl->arrays->pendingMsgSz = size + HANDSHAKE_HEADER_SZ;
            ssl->arrays->pendingMsg = (byte*)XMALLOC(size + HANDSHAKE_HEADER_SZ,
                                                     ssl->heap,
                                                     DYNAMIC_TYPE_ARRAYS);
            if (ssl->arrays->pendingMsg == NULL)
                return MEMORY_E;
            XMEMCPY(ssl->arrays->pendingMsg,
                    input + *inOutIdx - HANDSHAKE_HEADER_SZ,
                    inputLength);
            ssl->arrays->pendingMsgOffset = inputLength;
            *inOutIdx += inputLength - HANDSHAKE_HEADER_SZ;
            return 0;
        }

        ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }
    else {
        word32 pendSz =
            ssl->arrays->pendingMsgSz - ssl->arrays->pendingMsgOffset;

        /* Catch the case where there may be the remainder of a fragmented
         * handshake message and the next handshake message in the same
         * record. */
        if (inputLength > pendSz)
            inputLength = pendSz;

        {
            /* for async this copy was already done, do not replace, since
             * contents may have been changed for inline operations */
            XMEMCPY(ssl->arrays->pendingMsg + ssl->arrays->pendingMsgOffset,
                    input + *inOutIdx, inputLength);
        }
        ssl->arrays->pendingMsgOffset += inputLength;
        *inOutIdx += inputLength;

        if (ssl->arrays->pendingMsgOffset == ssl->arrays->pendingMsgSz)
        {
            word32 idx = HANDSHAKE_HEADER_SZ;
            ret = DoHandShakeMsgType(ssl,
                                     ssl->arrays->pendingMsg,
                                     &idx, ssl->arrays->pendingMsgType,
                                     ssl->arrays->pendingMsgSz - idx,
                                     ssl->arrays->pendingMsgSz);
            {
                XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
                ssl->arrays->pendingMsg = NULL;
                ssl->arrays->pendingMsgSz = 0;
            }
        }
    }

    WOLFSSL_LEAVE("DoHandShakeMsg()", ret);
    return ret;
}





static WC_INLINE void AeadIncrementExpIV(WOLFSSL* ssl)
{
    int i;
    for (i = AEAD_MAX_EXP_SZ-1; i >= 0; i--) {
        if (++ssl->keys.aead_exp_IV[i]) return;
    }
}





#if !defined(NO_GCM_ENCRYPT_EXTRA)
/* The following type is used to share code between AES-GCM and AES-CCM. */
    typedef int (*AesAuthEncryptFunc)(Aes* aes, byte* out,
                                       const byte* in, word32 sz,
                                       byte* iv, word32 ivSz,
                                       byte* authTag, word32 authTagSz,
                                       const byte* authIn, word32 authInSz);
    #define AES_AUTH_ENCRYPT_FUNC AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt_ex
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt_ex
#else
    #define AES_AUTH_ENCRYPT_FUNC wc_AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt
#endif



static WC_INLINE int EncryptDo(WOLFSSL* ssl, byte* out, const byte* input,
    word16 sz, int asyncOkay)
{
    int ret = 0;
    (void)asyncOkay;

    (void)out;
    (void)input;
    (void)sz;

    if (input == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (ssl->specs.bulk_cipher_algorithm) {


        case wolfssl_aes:
            ret = wc_AesCbcEncrypt(ssl->encrypt.aes, out, input, sz);
            break;

        case wolfssl_aes_gcm:
        case wolfssl_aes_ccm:/* GCM AEAD macros use same size as CCM */
        {
            AES_AUTH_ENCRYPT_FUNC aes_auth_fn;
            const byte* additionalSrc;


            aes_auth_fn = AES_GCM_ENCRYPT;
            additionalSrc = input - 5;

            XMEMSET(ssl->encrypt.additional, 0, AEAD_AUTH_DATA_SZ);

            /* sequence number field is 64-bits */
            WriteSEQ(ssl, CUR_ORDER, ssl->encrypt.additional);

            /* Store the type, version. Unfortunately, they are in
             * the input buffer ahead of the plaintext. */
            XMEMCPY(ssl->encrypt.additional + AEAD_TYPE_OFFSET,
                                                        additionalSrc, 3);

            /* Store the length of the plain text minus the explicit
             * IV length minus the authentication tag size. */
            c16toa(sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                ssl->encrypt.additional + AEAD_LEN_OFFSET);
            ret = aes_auth_fn(ssl->encrypt.aes,
                    out + AESGCM_EXP_IV_SZ, input + AESGCM_EXP_IV_SZ,
                    sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                    ssl->encrypt.nonce, AESGCM_NONCE_SZ,
                    out + sz - ssl->specs.aead_mac_size,
                    ssl->specs.aead_mac_size,
                    ssl->encrypt.additional, AEAD_AUTH_DATA_SZ);
#if !defined(NO_PUBLIC_GCM_SET_IV)
            XMEMCPY(out,
                    ssl->encrypt.nonce + AESGCM_IMP_IV_SZ, AESGCM_EXP_IV_SZ);
#endif
        }
        break;




        default:
            WOLFSSL_MSG("wolfSSL Encrypt programming error");
            ret = ENCRYPT_ERROR;
    }


    return ret;
}

static WC_INLINE int Encrypt(WOLFSSL* ssl, byte* out, const byte* input,
    word16 sz, int asyncOkay)
{
    int ret = 0;


    sparky_tls_log(0, "Input for Encrypt", input, sz);

    switch (ssl->encrypt.state) {
        case CIPHER_STATE_BEGIN:
        {
            if (ssl->encrypt.setup == 0) {
                WOLFSSL_MSG("Encrypt ciphers not setup");
                return ENCRYPT_ERROR;
            }


            /* make sure AES GCM/CCM memory is allocated */
            /* free for these happens in FreeCiphers */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                /* make sure auth iv and auth are allocated */
                if (ssl->encrypt.additional == NULL)
                    ssl->encrypt.additional = (byte*)XMALLOC(AEAD_AUTH_DATA_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->encrypt.nonce == NULL)
                    ssl->encrypt.nonce = (byte*)XMALLOC(AESGCM_NONCE_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->encrypt.additional == NULL ||
                         ssl->encrypt.nonce == NULL) {
                    return MEMORY_E;
                }
            }

            /* Advance state and proceed */
            ssl->encrypt.state = CIPHER_STATE_DO;
        }
        FALL_THROUGH;

        case CIPHER_STATE_DO:
        {
            ret = EncryptDo(ssl, out, input, sz, asyncOkay);

            sparky_tls_log(31, "EncryptedMsg", out, sz);

            /* Advance state */
            ssl->encrypt.state = CIPHER_STATE_END;

        }
        FALL_THROUGH;

        case CIPHER_STATE_END:
        {
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm)
            {
                /* finalize authentication cipher */
                if (ssl->encrypt.nonce)
                    ForceZero(ssl->encrypt.nonce, AESGCM_NONCE_SZ);
            }
            break;
        }

        default:
            break;
    }

    /* Reset state */
    ssl->encrypt.state = CIPHER_STATE_BEGIN;

    return ret;
}


static WC_INLINE int DecryptDo(WOLFSSL* ssl, byte* plain, const byte* input,
                           word16 sz)
{
    int ret = 0;

    (void)plain;
    (void)input;
    (void)sz;

    switch (ssl->specs.bulk_cipher_algorithm)
    {


        case wolfssl_aes:
            ret = wc_AesCbcDecrypt(ssl->decrypt.aes, plain, input, sz);
            break;

        case wolfssl_aes_gcm:
        case wolfssl_aes_ccm: /* GCM AEAD macros use same size as CCM */
        {
            wc_AesAuthDecryptFunc aes_auth_fn;


            aes_auth_fn = wc_AesGcmDecrypt;

            XMEMSET(ssl->decrypt.additional, 0, AEAD_AUTH_DATA_SZ);

            /* sequence number field is 64-bits */
            WriteSEQ(ssl, PEER_ORDER, ssl->decrypt.additional);

            ssl->decrypt.additional[AEAD_TYPE_OFFSET] = ssl->curRL.type;
            ssl->decrypt.additional[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
            ssl->decrypt.additional[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

            c16toa(sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                    ssl->decrypt.additional + AEAD_LEN_OFFSET);

                XMEMCPY(ssl->decrypt.nonce, ssl->keys.aead_dec_imp_IV,
                        AESGCM_IMP_IV_SZ);
            XMEMCPY(ssl->decrypt.nonce + AESGCM_IMP_IV_SZ, input,
                                                            AESGCM_EXP_IV_SZ);
            if ((ret = aes_auth_fn(ssl->decrypt.aes,
                        plain + AESGCM_EXP_IV_SZ,
                        input + AESGCM_EXP_IV_SZ,
                           sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                        ssl->decrypt.nonce, AESGCM_NONCE_SZ,
                        input + sz - ssl->specs.aead_mac_size,
                        ssl->specs.aead_mac_size,
                        ssl->decrypt.additional, AEAD_AUTH_DATA_SZ)) < 0) {
            }
        }
        break;




        default:
            WOLFSSL_MSG("wolfSSL Decrypt programming error");
            ret = DECRYPT_ERROR;
    }

    return ret;
}

static int DecryptTls(WOLFSSL* ssl, byte* plain, const byte* input, word16 sz)
{
    int ret = 0;

    {
        /* Reset state */
        ret = 0;
        ssl->decrypt.state = CIPHER_STATE_BEGIN;
    }

    switch (ssl->decrypt.state) {
        case CIPHER_STATE_BEGIN:
        {
            if (ssl->decrypt.setup == 0) {
                WOLFSSL_MSG("Decrypt ciphers not setup");
                return DECRYPT_ERROR;
            }

            /* make sure AES GCM/CCM memory is allocated */
            /* free for these happens in FreeCiphers */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                /* make sure auth iv and auth are allocated */
                if (ssl->decrypt.additional == NULL)
                    ssl->decrypt.additional = (byte*)XMALLOC(AEAD_AUTH_DATA_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->decrypt.nonce == NULL)
                    ssl->decrypt.nonce = (byte*)XMALLOC(AESGCM_NONCE_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->decrypt.additional == NULL ||
                         ssl->decrypt.nonce == NULL) {
                    return MEMORY_E;
                }
            }

            /* Advance state and proceed */
            ssl->decrypt.state = CIPHER_STATE_DO;
        }
        FALL_THROUGH;
        case CIPHER_STATE_DO:
        {

            ret = DecryptDo(ssl, plain, input, sz);

            /* Advance state */
            ssl->decrypt.state = CIPHER_STATE_END;

        }
        FALL_THROUGH;
        case CIPHER_STATE_END:
        {
            /* make sure AES GCM/CCM nonce is cleared */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                if (ssl->decrypt.nonce)
                    ForceZero(ssl->decrypt.nonce, AESGCM_NONCE_SZ);

                if (ret < 0)
                    ret = VERIFY_MAC_ERROR;
            }
            break;
        }

        default:
            break;
    }

    /* Reset state */
    ssl->decrypt.state = CIPHER_STATE_BEGIN;

    /* handle mac error case */
    if (ret == VERIFY_MAC_ERROR) {
        if (!ssl->options.dtls) {
            SendAlert(ssl, alert_fatal, bad_record_mac);
        }
    #ifdef WOLFSSL_DTLS_DROP_STATS
        if (ssl->options.dtls)
            ssl->macDropCount++;
    #endif /* WOLFSSL_DTLS_DROP_STATS */
    }

    return ret;
}


/* Check conditions for a cipher to have an explicit IV.
 *
 * ssl  The SSL/TLS object.
 * returns 1 if the cipher in use has an explicit IV and 0 otherwise.
 */
static WC_INLINE int CipherHasExpIV(WOLFSSL *ssl)
{
    return (ssl->specs.cipher_type == aead) &&
            (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha);
}

/* check cipher text size for sanity */
static int SanityCheckCipherText(WOLFSSL* ssl, word32 encryptSz)
{
    word32 minLength = ssl->specs.hash_size; /* covers stream */

    if (ssl->specs.cipher_type == block) {
        if (ssl->options.startedETMRead) {
            if ((encryptSz - MacSize(ssl)) % ssl->specs.block_size) {
                WOLFSSL_MSG("Block ciphertext not block size");
                return SANITY_CIPHER_E;
            }
        }
        else
        if (encryptSz % ssl->specs.block_size) {
            WOLFSSL_MSG("Block ciphertext not block size");
            return SANITY_CIPHER_E;
        }

        minLength++;  /* pad byte */

        if (ssl->specs.block_size > minLength)
            minLength = ssl->specs.block_size;

        if (ssl->options.tls1_1)
            minLength += ssl->specs.block_size;  /* explicit IV */
    }
    else
    if (ssl->specs.cipher_type == aead) {
        minLength = ssl->specs.aead_mac_size;    /* authTag size */
        if (CipherHasExpIV(ssl))
            minLength += AESGCM_EXP_IV_SZ;       /* explicit IV  */
    }

    if (encryptSz < minLength) {
        WOLFSSL_MSG("Ciphertext not minimum size");
        return SANITY_CIPHER_E;
    }

    return 0;
}


/* check all length bytes for the pad value, return 0 on success */
static int PadCheck(const byte* a, byte pad, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ pad;
    }

    return compareSum;
}


/* Mask the padding bytes with the expected values.
 * Constant time implementation - does maximum pad size possible.
 *
 * data   Message data.
 * sz     Size of the message including MAC and padding and padding length.
 * macSz  Size of the MAC.
 * returns 0 on success, otherwise failure.
 */
static byte MaskPadding(const byte* data, int sz, int macSz)
{
    int i;
    int checkSz = sz - 1;
    byte paddingSz = data[sz - 1];
    byte mask;
    byte good = ctMaskGT(paddingSz, sz - 1 - macSz);

    if (checkSz > TLS_MAX_PAD_SZ)
        checkSz = TLS_MAX_PAD_SZ;

    for (i = 0; i < checkSz; i++) {
        mask = ctMaskLTE(i, paddingSz);
        good |= mask & (data[sz - 1 - i] ^ paddingSz);
    }

    return good;
}

/* Mask the MAC in the message with the MAC calculated.
 * Constant time implementation - starts looking for MAC where maximum padding
 * size has it.
 *
 * data    Message data.
 * sz      Size of the message including MAC and padding and padding length.
 * macSz   Size of the MAC data.
 * expMac  Expected MAC value.
 * returns 0 on success, otherwise failure.
 */
static byte MaskMac(const byte* data, int sz, int macSz, byte* expMac)
{
    int i, j;
    unsigned char mac[WC_MAX_DIGEST_SIZE];
    int scanStart = sz - 1 - TLS_MAX_PAD_SZ - macSz;
    int macEnd = sz - 1 - data[sz - 1];
    int macStart = macEnd - macSz;
    int r = 0;
    unsigned char started, notEnded;
    unsigned char good = 0;

    scanStart &= ctMaskIntGTE(scanStart, 0);
    macStart &= ctMaskIntGTE(macStart, 0);

    /* Div on Intel has different speeds depending on value.
     * Use a bitwise AND or mod a specific value (converted to mul). */
    if ((macSz & (macSz - 1)) == 0)
        r = (macSz - (scanStart - macStart)) & (macSz - 1);
    else if (macSz == WC_SHA_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA_DIGEST_SIZE;
    else if (macSz == WC_SHA384_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA384_DIGEST_SIZE;

    XMEMSET(mac, 0, macSz);
    for (i = scanStart; i < sz; i += macSz) {
        for (j = 0; j < macSz && j + i < sz; j++) {
            started = ctMaskGTE(i + j, macStart);
            notEnded = ctMaskLT(i + j, macEnd);
            mac[j] |= started & notEnded & data[i + j];
        }
    }

    if ((macSz & (macSz - 1)) == 0) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) & (macSz - 1)];
    }
    else if (macSz == WC_SHA_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA_DIGEST_SIZE];
    }
    else if (macSz == WC_SHA384_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA384_DIGEST_SIZE];
    }

    return good;
}

/* timing resistant pad/verify check, return 0 on success */
int TimingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int macSz,
                    int pLen, int content)
{
    byte verify[WC_MAX_DIGEST_SIZE];
    byte good;
    int  ret = 0;

    good = MaskPadding(input, pLen, macSz);
    /* 4th argument has potential to underflow, ssl->hmac function should
     * either increment the size by (macSz + padLen + 1) before use or check on
     * the size to make sure is valid. */
    ret = ssl->hmac(ssl, verify, input, pLen - macSz - padLen - 1, padLen,
                                                        content, 1, PEER_ORDER);
    good |= MaskMac(input, pLen, ssl->specs.hash_size, verify);

    /* Non-zero on failure. */
    good = (byte)~(word32)good;
    good &= good >> 4;
    good &= good >> 2;
    good &= good >> 1;
    /* Make ret negative on masking failure. */
    ret -= 1 - good;

    /* Treat any failure as verify MAC error. */
    if (ret != 0)
        ret = VERIFY_MAC_ERROR;

    return ret;
}


int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx, int sniff)
{
    word32 msgSz   = ssl->keys.encryptSz;
    word32 idx     = *inOutIdx;
    int    dataSz;
    int    ivExtra = 0;
    byte*  rawData = input + idx;  /* keep current  for hmac */

    if (ssl->options.handShakeDone == 0) {
        WOLFSSL_MSG("Received App data before a handshake completed");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        return OUT_OF_ORDER_E;
    }

    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
    }
    else
    if (ssl->specs.cipher_type == aead) {
        if (CipherHasExpIV(ssl))
            ivExtra = AESGCM_EXP_IV_SZ;
    }

    dataSz = msgSz - ivExtra - ssl->keys.padSz;
    if (ssl->options.startedETMRead)
        dataSz -= MacSize(ssl);
    if (dataSz < 0) {
        WOLFSSL_MSG("App data buffer error, malicious input?");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        return BUFFER_ERROR;
    }

    /* read data */
    if (dataSz) {
        int rawSz = dataSz;       /* keep raw size for idx adjustment */

        idx += rawSz;

        ssl->buffers.clearOutputBuffer.buffer = rawData;
        ssl->buffers.clearOutputBuffer.length = dataSz;
    }

    idx += ssl->keys.padSz;
    if (ssl->options.startedETMRead)
        idx += MacSize(ssl);


    *inOutIdx = idx;
    return 0;
}

const char* AlertTypeToString(int type)
{
    switch (type) {
        case close_notify:
            {
                static const char close_notify_str[] =
                    "close_notify";
                return close_notify_str;
            }

        case unexpected_message:
            {
                static const char unexpected_message_str[] =
                    "unexpected_message";
                return unexpected_message_str;
            }

        case bad_record_mac:
            {
                static const char bad_record_mac_str[] =
                    "bad_record_mac";
                return bad_record_mac_str;
            }

        case record_overflow:
            {
                static const char record_overflow_str[] =
                    "record_overflow";
                return record_overflow_str;
            }

        case decompression_failure:
            {
                static const char decompression_failure_str[] =
                    "decompression_failure";
                return decompression_failure_str;
            }

        case handshake_failure:
            {
                static const char handshake_failure_str[] =
                    "handshake_failure";
                return handshake_failure_str;
            }

        case no_certificate:
            {
                static const char no_certificate_str[] =
                    "no_certificate";
                return no_certificate_str;
            }

        case bad_certificate:
            {
                static const char bad_certificate_str[] =
                    "bad_certificate";
                return bad_certificate_str;
            }

        case unsupported_certificate:
            {
                static const char unsupported_certificate_str[] =
                    "unsupported_certificate";
                return unsupported_certificate_str;
            }

        case certificate_revoked:
            {
                static const char certificate_revoked_str[] =
                    "certificate_revoked";
                return certificate_revoked_str;
            }

        case certificate_expired:
            {
                static const char certificate_expired_str[] =
                    "certificate_expired";
                return certificate_expired_str;
            }

        case certificate_unknown:
            {
                static const char certificate_unknown_str[] =
                    "certificate_unknown";
                return certificate_unknown_str;
            }

        case illegal_parameter:
            {
                static const char illegal_parameter_str[] =
                    "illegal_parameter";
                return illegal_parameter_str;
            }

        case unknown_ca:
            {
                static const char unknown_ca_str[] =
                    "unknown_ca";
                return unknown_ca_str;
            }

        case access_denied:
            {
                static const char access_denied_str[] =
                    "access_denied";
                return access_denied_str;
            }

        case decode_error:
            {
                static const char decode_error_str[] =
                    "decode_error";
                return decode_error_str;
            }

        case decrypt_error:
            {
                static const char decrypt_error_str[] =
                    "decrypt_error";
                return decrypt_error_str;
            }

        case protocol_version:
            {
                static const char protocol_version_str[] =
                    "protocol_version";
                return protocol_version_str;
            }

        case insufficient_security:
            {
                static const char insufficient_security_str[] =
                    "insufficient_security";
                return insufficient_security_str;
            }

        case internal_error:
            {
                static const char internal_error_str[] =
                    "internal_error";
                return internal_error_str;
            }

        case user_canceled:
            {
                static const char user_canceled_str[] =
                    "user_canceled";
                return user_canceled_str;
            }

        case no_renegotiation:
            {
                static const char no_renegotiation_str[] =
                    "no_renegotiation";
                return no_renegotiation_str;
            }

        case unrecognized_name:
            {
                static const char unrecognized_name_str[] =
                    "unrecognized_name";
                return unrecognized_name_str;
            }

        case bad_certificate_status_response:
            {
                static const char bad_certificate_status_response_str[] =
                    "bad_certificate_status_response";
                return bad_certificate_status_response_str;
            }

        case no_application_protocol:
            {
                static const char no_application_protocol_str[] =
                    "no_application_protocol";
                return no_application_protocol_str;
            }

        default:
            WOLFSSL_MSG("Unknown Alert");
            return NULL;
    }
}

static void LogAlert(int type)
{
    const char* typeStr;
    char buff[60];

    typeStr = AlertTypeToString(type);
    if (typeStr != NULL) {
        XSNPRINTF(buff, sizeof(buff), "Alert type: %s", typeStr);
        WOLFSSL_MSG(buff);
    }
}

/* process alert, return level */
static int DoAlert(WOLFSSL* ssl, byte* input, word32* inOutIdx, int* type)
{
    byte level;
    byte code;
    word32 dataSz = (word32)ssl->curSize;
    int ivExtra = 0;


    if (IsEncryptionOn(ssl, 0)) {
        if (ssl->specs.cipher_type == block) {
            if (ssl->options.tls1_1)
                ivExtra = ssl->specs.block_size;
        }
        else
        if (ssl->specs.cipher_type == aead) {
            if (CipherHasExpIV(ssl))
                ivExtra = AESGCM_EXP_IV_SZ;
        }
        dataSz -= ivExtra;
        dataSz -= ssl->keys.padSz;
        if (ssl->options.startedETMRead)
            dataSz -= MacSize(ssl);
    }

    /* make sure can read the message */
    if (dataSz != ALERT_SIZE) {
        return BUFFER_E;
    }

    level = input[(*inOutIdx)++];
    code  = input[(*inOutIdx)++];
    ssl->alert_history.last_rx.code = code;
    ssl->alert_history.last_rx.level = level;
    *type = code;
    if (level == alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    if (++ssl->options.alertCount >= WOLFSSL_ALERT_COUNT_MAX) {
        WOLFSSL_MSG("Alert count exceeded");
        return ALERT_COUNT_E;
    }

    LogAlert(*type);
    if (*type == close_notify) {
        ssl->options.closeNotify = 1;
    }
    WOLFSSL_ERROR(*type);

    if (IsEncryptionOn(ssl, 0)) {
        *inOutIdx += ssl->keys.padSz;
        if (ssl->options.startedETMRead)
            *inOutIdx += MacSize(ssl);
    }

    return level;
}

static int GetInputData(WOLFSSL *ssl, word32 size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;
    int dtlsExtra = 0;


    /* check max input length */
    usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
    maxLength  = ssl->buffers.inputBuffer.bufferSize - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */


    /* check that no lengths or size values are negative */
    if (usedLength < 0 || maxLength < 0 || inSz <= 0) {
        return BUFFER_ERROR;
    }

    if (inSz > maxLength) {
        if (GrowInputBuffer(ssl, size + dtlsExtra, usedLength) < 0)
            return MEMORY_E;
    }

    /* Put buffer data at start if not there */
    if (usedLength > 0 && ssl->buffers.inputBuffer.idx != 0)
        XMEMMOVE(ssl->buffers.inputBuffer.buffer,
                ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
                usedLength);

    /* remove processed data */
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    /* read data from network */
    do {
        in = wolfSSLReceive(ssl,
                     ssl->buffers.inputBuffer.buffer +
                     ssl->buffers.inputBuffer.length,
                     inSz);
        if (in == WANT_READ)
            return WANT_READ;

        if (in < 0)
            return SOCKET_ERROR_E;

        if (in > inSz)
            return RECV_OVERFLOW_E;

        ssl->buffers.inputBuffer.length += in;
        inSz -= in;

    } while (ssl->buffers.inputBuffer.length < size);


    return 0;
}

static WC_INLINE int VerifyMacEnc(WOLFSSL* ssl, const byte* input, word32 msgSz,
                                  int content)
{
    int    ret;
    word32 digestSz = ssl->specs.hash_size;
    byte   verify[WC_MAX_DIGEST_SIZE];

    WOLFSSL_MSG("Verify MAC of Encrypted Data");

    if (msgSz < digestSz) {
        return VERIFY_MAC_ERROR;
    }

    ret  = ssl->hmac(ssl, verify, input, msgSz - digestSz, -1, content, 1, PEER_ORDER);
    ret |= ConstantCompare(verify, input + msgSz - digestSz, digestSz);
    if (ret != 0) {
        return VERIFY_MAC_ERROR;
    }

    return 0;
}

static WC_INLINE int VerifyMac(WOLFSSL* ssl, const byte* input, word32 msgSz,
                            int content, word32* padSz)
{
    int    ivExtra = 0;
    int    ret;
    word32 pad     = 0;
    word32 padByte = 0;
    word32 digestSz = ssl->specs.hash_size;
    byte   verify[WC_MAX_DIGEST_SIZE];


    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
        pad = *(input + msgSz - ivExtra - 1);
        padByte = 1;

        if (ssl->options.tls) {
            ret = TimingPadVerify(ssl, input, pad, digestSz, msgSz - ivExtra,
                                  content);
            if (ret != 0)
                return ret;
        }
        else {  /* sslv3, some implementations have bad padding, but don't
                 * allow bad read */
            int  badPadLen = 0;
            byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE] = {0};
            byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;

            (void)dmy;

            if (pad > (msgSz - digestSz - 1)) {
                WOLFSSL_MSG("Plain Len not long enough for pad/mac");
                pad       = 0;  /* no bad read */
                badPadLen = 1;
            }
            (void)PadCheck(dummy, (byte)pad, MAX_PAD_SIZE);  /* timing only */
            ret = ssl->hmac(ssl, verify, input, msgSz - digestSz - pad - 1,
                            pad, content, 1, PEER_ORDER);
            if (ConstantCompare(verify, input + msgSz - digestSz - pad - 1,
                                digestSz) != 0)
                return VERIFY_MAC_ERROR;
            if (ret != 0 || badPadLen)
                return VERIFY_MAC_ERROR;
        }
    }
    else if (ssl->specs.cipher_type == stream) {
        ret = ssl->hmac(ssl, verify, input, msgSz - digestSz, -1, content, 1,
                        PEER_ORDER);
        if (ConstantCompare(verify, input + msgSz - digestSz, digestSz) != 0){
            return VERIFY_MAC_ERROR;
        }
        if (ret != 0)
            return VERIFY_MAC_ERROR;
    }

    if (ssl->specs.cipher_type == aead) {
        *padSz = ssl->specs.aead_mac_size;
    }
    else {
        *padSz = digestSz + pad + padByte;
    }

    (void)input;
    (void)msgSz;
    (void)content;

    return 0;
}

int ProcessReply(WOLFSSL* ssl)
{
    return ProcessReplyEx(ssl, 0);
}

/* Process input requests. Return 0 is done, 1 is call again to complete, and
   negative number is error. If allowSocketErr is set, SOCKET_ERROR_E in
   ssl->error will be whitelisted. This is useful when the connection has been
   closed and the endpoint wants to check for an alert sent by the other end. */
int ProcessReplyEx(WOLFSSL* ssl, int allowSocketErr)
{
    int    ret = 0, type, readSz;
    int    atomicUser = 0;
    word32 startIdx = 0;


    if (ssl->error != 0 && ssl->error != WANT_READ && ssl->error != WANT_WRITE
        && (allowSocketErr != 1 || ssl->error != SOCKET_ERROR_E)
    ) {
        WOLFSSL_MSG("ProcessReply retry in error state, not allowed");
        return ssl->error;
    }


    for (;;) {
        switch (ssl->options.processReply) {

        /* in the WOLFSSL_SERVER case, get the first byte for detecting
         * old client hello */
        case doProcessInit:

            readSz = RECORD_HEADER_SZ;


            /* get header or return error */
            if (!ssl->options.dtls) {
                if ((ret = GetInputData(ssl, readSz)) < 0)
                    return ret;
            } else {
            }

            FALL_THROUGH;

        /* get the record layer header */
        case getRecordLayerHeader:

            ret = GetRecordHeader(ssl, ssl->buffers.inputBuffer.buffer,
                                       &ssl->buffers.inputBuffer.idx,
                                       &ssl->curRL, &ssl->curSize);

            if (ret != 0)
                return ret;


            ssl->options.processReply = getData;
            FALL_THROUGH;

        /* retrieve record layer data */
        case getData:

            /* get sz bytes or return error */
            if (!ssl->options.dtls) {
                if ((ret = GetInputData(ssl, ssl->curSize)) < 0) {
                    return ret;
                }
            }
            else {
            }

            if (IsEncryptionOn(ssl, 0)) {

            }
            ssl->keys.padSz = 0;

            ssl->options.processReply = verifyEncryptedMessage;
            startIdx = ssl->buffers.inputBuffer.idx;  /* in case > 1 msg per */
            FALL_THROUGH;

        /* verify digest of encrypted message */
        case verifyEncryptedMessage:
            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                   !atomicUser && ssl->options.startedETMRead) {
                ret = VerifyMacEnc(ssl, ssl->buffers.inputBuffer.buffer +
                                   ssl->buffers.inputBuffer.idx,
                                   ssl->curSize, ssl->curRL.type);
                if (ret < 0) {
                    WOLFSSL_MSG("VerifyMacEnc failed");
                    WOLFSSL_ERROR(ret);
                    return DECRYPT_ERROR;
                }
                ssl->keys.encryptSz    = ssl->curSize;
            }
            ssl->options.processReply = decryptMessage;
            FALL_THROUGH;

        /* decrypt message */
        case decryptMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != change_cipher_spec))
            {
                bufferStatic* in = &ssl->buffers.inputBuffer;

                ret = SanityCheckCipherText(ssl, ssl->curSize);
                if (ret < 0) {
                    return ret;
                }

                if (atomicUser) {
                }
                else {
                    if (!ssl->options.tls1_3) {
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        ret = DecryptTls(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize - (word16)digestSz);
                        if (ret == 0) {
                            byte invalid = 0;
                            byte padding = (byte)-1;
                            word32 i;
                            word32 off = in->idx + ssl->curSize - digestSz - 1;

                            /* Last of padding bytes - indicates length. */
                            ssl->keys.padSz = in->buffer[off];
                            /* Constant time checking of padding - don't leak
                             * the length of the data.
                             */
                            /* Compare max pad bytes or at most data + pad. */
                            for (i = 1; i < MAX_PAD_SIZE && off >= i; i++) {
                                /* Mask on indicates this is expected to be a
                                 * padding byte.
                                 */
                                padding &= ctMaskLTE(i, ssl->keys.padSz);
                                /* When this is a padding byte and not equal
                                 * to length then mask is set.
                                 */
                                invalid |= padding &
                                           ctMaskNotEq(in->buffer[off - i],
                                                       ssl->keys.padSz);
                            }
                            /* If mask is set then there was an error. */
                            if (invalid) {
                                ret = DECRYPT_ERROR;
                            }
                            ssl->keys.padSz += 1;
                            ssl->keys.decryptedCur = 1;
                        }
                    }
                    else
                    {
                        ret = DecryptTls(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize);
                    }
                    }
                    else
                    {
                        ret = DECRYPT_ERROR;
                    }
                }


                if (ret >= 0) {
                    /* handle success */
                    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
                        ssl->buffers.inputBuffer.idx += ssl->specs.block_size;
                    /* go past TLSv1.1 IV */
                    if (CipherHasExpIV(ssl))
                        ssl->buffers.inputBuffer.idx += AESGCM_EXP_IV_SZ;
                }
                else {
                    WOLFSSL_MSG("Decrypt failed");
                    WOLFSSL_ERROR(ret);
                    return DECRYPT_ERROR;
                }
            }

            ssl->options.processReply = verifyMessage;
            FALL_THROUGH;

        /* verify digest of message */
        case verifyMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != change_cipher_spec))
            {
                if (!atomicUser
                                && !ssl->options.startedETMRead
                    ) {
                    ret = VerifyMac(ssl, ssl->buffers.inputBuffer.buffer +
                                    ssl->buffers.inputBuffer.idx,
                                    ssl->curSize, ssl->curRL.type,
                                    &ssl->keys.padSz);
                    if (ret < 0) {
                        WOLFSSL_MSG("VerifyMac failed");
                        WOLFSSL_ERROR(ret);
                        return DECRYPT_ERROR;
                    }
                }

                ssl->keys.encryptSz    = ssl->curSize;
                ssl->keys.decryptedCur = 1;
            }

            ssl->options.processReply = runProcessingOneMessage;
            FALL_THROUGH;

        /* the record layer is here */
        case runProcessingOneMessage:
            /* can't process a message if we have no data.  */
            if (ssl->buffers.inputBuffer.idx
                >= ssl->buffers.inputBuffer.length)
                return BUFFER_ERROR;

            if (IsEncryptionOn(ssl, 0) && ssl->options.startedETMRead) {
                if ((ssl->curSize -
                        ssl->keys.padSz -
                        MacSize(ssl) > MAX_PLAINTEXT_SZ)
                                ) {
                    WOLFSSL_MSG("Plaintext too long - Encrypt-Then-MAC");
                    return BUFFER_ERROR;
                }
            }
            else
                /* TLS13 plaintext limit is checked earlier before decryption */
                if (!IsAtLeastTLSv1_3(ssl->version)
                        && ssl->curSize - ssl->keys.padSz > MAX_PLAINTEXT_SZ
                                ) {
                WOLFSSL_MSG("Plaintext too long");
                return BUFFER_ERROR;
            }


            WOLFSSL_MSG("received record layer msg");

            switch (ssl->curRL.type) {
                case handshake :
                    WOLFSSL_MSG("got HANDSHAKE");
                    /* debugging in DoHandShakeMsg */
                    if (ssl->options.dtls) {
                    }
                    else if (!IsAtLeastTLSv1_3(ssl->version)
                            ) {
                        ret = DoHandShakeMsg(ssl,
                                            ssl->buffers.inputBuffer.buffer,
                                            &ssl->buffers.inputBuffer.idx,
                                            ssl->buffers.inputBuffer.length);
                    }
                    else {
                        ret = BUFFER_ERROR;
                    }
                    if (ret != 0
                            /* DoDtlsHandShakeMsg can return a WANT_WRITE when
                             * calling DtlsMsgPoolSend. This msg is done
                             * processing so let's move on. */
                        && (!ssl->options.dtls
                            || ret != WANT_WRITE)
                    ) {
                        WOLFSSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case change_cipher_spec:
                    WOLFSSL_MSG("got CHANGE CIPHER SPEC");


                    if (ssl->buffers.inputBuffer.idx >=
                            ssl->buffers.inputBuffer.length ||
                            ssl->curSize < 1) {
                        WOLFSSL_MSG("ChangeCipher msg too short");
                        return LENGTH_ERROR;
                    }
                    if (ssl->buffers.inputBuffer.buffer[
                            ssl->buffers.inputBuffer.idx] != 1) {
                        WOLFSSL_MSG("ChangeCipher msg wrong value");
                        return LENGTH_ERROR;
                    }

                    if (IsEncryptionOn(ssl, 0) && ssl->options.handShakeDone) {
                        if (ssl->specs.cipher_type == aead) {
                            if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                                ssl->curSize -= AESGCM_EXP_IV_SZ;
                            ssl->buffers.inputBuffer.idx += ssl->specs.aead_mac_size;
                            ssl->curSize -= ssl->specs.aead_mac_size;
                        }
                        else
                        {
                            ssl->buffers.inputBuffer.idx += ssl->keys.padSz;
                            ssl->curSize -= (word16)ssl->keys.padSz;
                            ssl->curSize -= ssl->specs.iv_size;
                        }

                        if (ssl->options.startedETMRead) {
                            word32 digestSz = MacSize(ssl);
                            ssl->buffers.inputBuffer.idx += digestSz;
                            ssl->curSize -= (word16)digestSz;
                        }
                    }

                    if (ssl->curSize != 1) {
                        WOLFSSL_MSG("Malicious or corrupted ChangeCipher msg");
                        return LENGTH_ERROR;
                    }

                    ssl->buffers.inputBuffer.idx++;

                    ret = SanityCheckMsgReceived(ssl, change_cipher_hs);
                    if (ret != 0) {
                        if (!ssl->options.dtls) {
                            return ret;
                        }
                        else {
                        }
                    }

                    ssl->keys.encryptionOn = 1;

                    /* setup decrypt keys for following messages */
                    /* XXX This might not be what we want to do when
                     * receiving a CCS with multicast. We update the
                     * key when the application updates them. */
                    if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                        return ret;

                    ssl->options.startedETMRead = ssl->options.encThenMac;


                    ret = BuildFinished(ssl, &ssl->hsHashes->verifyHashes,
                                       ssl->options.side == WOLFSSL_CLIENT_END ?
                                       server : client);
                    if (ret != 0)
                        return ret;
                    break;

                case application_data:
                    WOLFSSL_MSG("got app DATA");
                    if ((ret = DoApplicationData(ssl,
                                                ssl->buffers.inputBuffer.buffer,
                                                &ssl->buffers.inputBuffer.idx,
                                                              NO_SNIFF)) != 0) {
                        WOLFSSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case alert:
                    WOLFSSL_MSG("got ALERT!");
                    ret = DoAlert(ssl, ssl->buffers.inputBuffer.buffer,
                                  &ssl->buffers.inputBuffer.idx, &type);
                    if (ret == alert_fatal)
                        return FATAL_ERROR;
                    else if (ret < 0)
                        return ret;

                    /* catch warnings that are handled as errors */
                    if (type == close_notify) {
                        ssl->buffers.inputBuffer.idx =
                            ssl->buffers.inputBuffer.length;
                        ssl->options.processReply = doProcessInit;
                        return ssl->error = ZERO_RETURN;
                    }

                    if (type == decrypt_error)
                        return FATAL_ERROR;

                    /* Reset error if we got an alert level in ret */
                    if (ret > 0)
                        ret = 0;
                    break;

                default:
                    WOLFSSL_ERROR(UNKNOWN_RECORD_TYPE);
                    return UNKNOWN_RECORD_TYPE;
            }

            ssl->options.processReply = doProcessInit;

            /* input exhausted */
            if (ssl->buffers.inputBuffer.idx >= ssl->buffers.inputBuffer.length
                )
                return ret;

            /* more messages per record */
            else if ((ssl->buffers.inputBuffer.idx - startIdx) < ssl->curSize) {
                WOLFSSL_MSG("More messages in record");

                ssl->options.processReply = runProcessingOneMessage;

                if (IsEncryptionOn(ssl, 0)) {
                    WOLFSSL_MSG("Bundled encrypted messages, remove middle pad");
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        if (ssl->buffers.inputBuffer.idx >=
                                                   ssl->keys.padSz + digestSz) {
                            ssl->buffers.inputBuffer.idx -=
                                                     ssl->keys.padSz + digestSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            return FATAL_ERROR;
                        }
                    }
                    else
                    {
                        if (ssl->buffers.inputBuffer.idx >= ssl->keys.padSz) {
                            ssl->buffers.inputBuffer.idx -= ssl->keys.padSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            return FATAL_ERROR;
                        }
                    }
                }
            }
            /* more records */
            else {
                WOLFSSL_MSG("More records in input");
            }
            continue;
        default:
            WOLFSSL_MSG("Bad process input state, programming error");
            return INPUT_CASE_ERROR;
        }
    }
}

int SendChangeCipher(WOLFSSL* ssl)
{
    byte              *output;
    int                sendSz = RECORD_HEADER_SZ + ENUM_LEN;
    int                idx    = RECORD_HEADER_SZ;
    int                ret;



    /* are we in scr */
    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        sendSz += MAX_MSG_EXTRA;
    }

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddRecordHeader(output, 1, change_cipher_spec, ssl, CUR_ORDER);

    output[idx] = 1;             /* turn it on */

    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        byte input[ENUM_LEN];
        int  inputSz = ENUM_LEN;

        input[0] = 1;  /* turn it on */
        sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                              change_cipher_spec, 0, 0, 0, CUR_ORDER);
        if (sendSz < 0) {
            return sendSz;
        }
    }
    ssl->buffers.outputBuffer.length += sendSz;

    {
        /* setup encrypt keys */
        if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
            return ret;

        ssl->options.startedETMWrite = ssl->options.encThenMac;
    }

    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}


static int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
                    int padLen, int content, int verify, int epochOrder)
{
    byte   result[WC_MAX_DIGEST_SIZE];
    word32 digestSz = ssl->specs.hash_size;            /* actual sizes */
    word32 padSz    = ssl->specs.pad_size;
    int    ret      = 0;

    wc_Md5 md5;
    wc_Sha sha;

    /* data */
    byte seq[SEQ_SZ];
    byte conLen[ENUM_LEN + LENGTH_SZ];     /* content & length */
    const byte* macSecret = NULL;

    (void)padLen;


    macSecret = wolfSSL_GetMacSecret(ssl, verify);

    XMEMSET(seq, 0, SEQ_SZ);
    conLen[0] = (byte)content;
    c16toa((word16)sz, &conLen[ENUM_LEN]);
    WriteSEQ(ssl, epochOrder, seq);

    if (ssl->specs.mac_algorithm == md5_mac) {
        ret =  wc_InitMd5_ex(&md5, ssl->heap, ssl->devId);
        if (ret != 0)
            return ret;

        /* inner */
        ret =  wc_Md5Update(&md5, macSecret, digestSz);
        ret |= wc_Md5Update(&md5, PAD1, padSz);
        ret |= wc_Md5Update(&md5, seq, SEQ_SZ);
        ret |= wc_Md5Update(&md5, conLen, sizeof(conLen));
        /* in buffer */
        ret |= wc_Md5Update(&md5, in, sz);
        if (ret != 0)
            return VERIFY_MAC_ERROR;
        ret = wc_Md5Final(&md5, result);
        if (ret != 0)
            return VERIFY_MAC_ERROR;

        /* outer */
        ret =  wc_Md5Update(&md5, macSecret, digestSz);
        ret |= wc_Md5Update(&md5, PAD2, padSz);
        ret |= wc_Md5Update(&md5, result, digestSz);
        if (ret != 0)
            return VERIFY_MAC_ERROR;
        ret =  wc_Md5Final(&md5, digest);
        if (ret != 0)
            return VERIFY_MAC_ERROR;

        wc_Md5Free(&md5);
    }
    else {
        ret =  wc_InitSha_ex(&sha, ssl->heap, ssl->devId);
        if (ret != 0)
            return ret;

        /* inner */
        ret =  wc_ShaUpdate(&sha, macSecret, digestSz);
        ret |= wc_ShaUpdate(&sha, PAD1, padSz);
        ret |= wc_ShaUpdate(&sha, seq, SEQ_SZ);
        ret |= wc_ShaUpdate(&sha, conLen, sizeof(conLen));
        /* in buffer */
        ret |= wc_ShaUpdate(&sha, in, sz);
        if (ret != 0)
            return VERIFY_MAC_ERROR;
        ret = wc_ShaFinal(&sha, result);
        if (ret != 0)
            return VERIFY_MAC_ERROR;

        /* outer */
        ret =  wc_ShaUpdate(&sha, macSecret, digestSz);
        ret |= wc_ShaUpdate(&sha, PAD2, padSz);
        ret |= wc_ShaUpdate(&sha, result, digestSz);
        if (ret != 0)
            return VERIFY_MAC_ERROR;
        ret =  wc_ShaFinal(&sha, digest);
        if (ret != 0)
            return VERIFY_MAC_ERROR;

        wc_ShaFree(&sha);
    }
    return 0;
}

#if !defined(NO_MD5)
static int BuildMD5_CertVerify(WOLFSSL* ssl, byte* digest)
{
    int ret;
    byte md5_result[WC_MD5_DIGEST_SIZE];
    wc_Md5  md5[1];

    /* make md5 inner */
    ret = wc_Md5Copy(&ssl->hsHashes->hashMd5, md5); /* Save current position */
    if (ret == 0)
        ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_Md5Update(md5, PAD1, PAD_MD5);
    if (ret == 0)
        ret = wc_Md5Final(md5, md5_result);

    /* make md5 outer */
    if (ret == 0) {
        ret = wc_InitMd5_ex(md5, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_Md5Update(md5, ssl->arrays->masterSecret, SECRET_LEN);
            if (ret == 0)
                ret = wc_Md5Update(md5, PAD2, PAD_MD5);
            if (ret == 0)
                ret = wc_Md5Update(md5, md5_result, WC_MD5_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_Md5Final(md5, digest);
            wc_Md5Free(md5);
        }
    }


    return ret;
}
#endif /* !NO_MD5 && !NO_OLD_TLS */

static int BuildSHA_CertVerify(WOLFSSL* ssl, byte* digest)
{
    int ret;
    byte sha_result[WC_SHA_DIGEST_SIZE];
    wc_Sha  sha[1];

    /* make sha inner */
    ret = wc_ShaCopy(&ssl->hsHashes->hashSha, sha); /* Save current position */
    if (ret == 0)
        ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, PAD1, PAD_SHA);
    if (ret == 0)
        ret = wc_ShaFinal(sha, sha_result);

    /* make sha outer */
    if (ret == 0) {
        ret = wc_InitSha_ex(sha, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, PAD2, PAD_SHA);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, sha_result, WC_SHA_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_ShaFinal(sha, digest);
            wc_ShaFree(sha);
        }
    }


    return ret;
}

int BuildCertHashes(WOLFSSL* ssl, Hashes* hashes)
{
    int ret = 0;

    (void)hashes;

    if (ssl->options.tls) {
    #if !defined(NO_MD5)
        ret = wc_Md5GetHash(&ssl->hsHashes->hashMd5, hashes->md5);
        if (ret != 0)
            return ret;
    #endif
        ret = wc_ShaGetHash(&ssl->hsHashes->hashSha, hashes->sha);
        if (ret != 0)
            return ret;
        if (IsAtLeastTLSv1_2(ssl)) {
                ret = wc_Sha256GetHash(&ssl->hsHashes->hashSha256,
                                       hashes->sha256);
                if (ret != 0)
                    return ret;
                ret = wc_Sha384GetHash(&ssl->hsHashes->hashSha384,
                                       hashes->sha384);
                if (ret != 0)
                    return ret;
                ret = wc_Sha512GetHash(&ssl->hsHashes->hashSha512,
                                       hashes->sha512);
                if (ret != 0)
                    return ret;
        }
    }
    else {
    #if !defined(NO_MD5)
        ret = BuildMD5_CertVerify(ssl, hashes->md5);
        if (ret != 0)
            return ret;
    #endif
        ret = BuildSHA_CertVerify(ssl, hashes->sha);
        if (ret != 0)
            return ret;
    }

    return ret;
}

void FreeBuildMsgArgs(WOLFSSL* ssl, BuildMsgArgs* args)
{
    if (args) {
        /* only free the IV if it was dynamically allocated */
        if (ssl && args->iv && (args->iv != args->staticIvBuffer)) {
            XFREE(args->iv, ssl->heap, DYNAMIC_TYPE_SALT);
        }
        XMEMSET(args, 0, sizeof(BuildMsgArgs));
    }
}

/* Build SSL Message, encrypted */
int BuildMessage(WOLFSSL* ssl, byte* output, int outSz, const byte* input,
             int inSz, int type, int hashOutput, int sizeOnly, int asyncOkay,
             int epochOrder)
{
    int ret;
    BuildMsgArgs* args;
    BuildMsgArgs  lcl_args;

    WOLFSSL_ENTER("BuildMessage");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    /* catch mistaken sizeOnly parameter */
    if (!sizeOnly && (output == NULL || input == NULL) ) {
        return BAD_FUNC_ARG;
    }
    if (sizeOnly && (output || input) ) {
        return BAD_FUNC_ARG;
    }

    (void)epochOrder;


    {
        args = &lcl_args;
    }

    /* Reset state */
    {
        ret = 0;
        ssl->options.buildMsgState = BUILD_MSG_BEGIN;
        XMEMSET(args, 0, sizeof(BuildMsgArgs));

        args->sz = RECORD_HEADER_SZ + inSz;
        args->idx  = RECORD_HEADER_SZ;
        args->headerSz = RECORD_HEADER_SZ;
    }

    switch (ssl->options.buildMsgState) {
        case BUILD_MSG_BEGIN:
        {

            ssl->options.buildMsgState = BUILD_MSG_SIZE;
        }
        FALL_THROUGH;
        case BUILD_MSG_SIZE:
        {
            args->digestSz = ssl->specs.hash_size;
            args->sz += args->digestSz;


            if (ssl->specs.cipher_type == block) {
                word32 blockSz = ssl->specs.block_size;

                if (blockSz == 0) {
                    WOLFSSL_MSG("Invalid block size with block cipher type");
                    ERROR_OUT(BAD_STATE_E, exit_buildmsg);
                }

                if (ssl->options.tls1_1) {
                    args->ivSz = blockSz;
                    args->sz  += args->ivSz;

                    if (args->ivSz > MAX_IV_SZ)
                        ERROR_OUT(BUFFER_E, exit_buildmsg);
                }
                args->sz += 1;       /* pad byte */
                if (ssl->options.startedETMWrite) {
                    args->pad = (args->sz - args->headerSz -
                                                      args->digestSz) % blockSz;
                }
                else
                {
                    args->pad = (args->sz - args->headerSz) % blockSz;
                }
                if (args->pad != 0)
                    args->pad = blockSz - args->pad;
                args->sz += args->pad;
            }

            if (ssl->specs.cipher_type == aead) {
                if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                    args->ivSz = AESGCM_EXP_IV_SZ;

                args->sz += (args->ivSz + ssl->specs.aead_mac_size - args->digestSz);
            }

            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (args->sz > (word32)outSz) {
                WOLFSSL_MSG("Oops, want to write past output buffer size");
                ERROR_OUT(BUFFER_E, exit_buildmsg);
            }

            if (args->ivSz > 0) {
                if (args->ivSz > sizeof(args->staticIvBuffer)) {
                    args->iv = (byte*)XMALLOC(args->ivSz, ssl->heap,
                                              DYNAMIC_TYPE_SALT);
                    if (args->iv == NULL) {
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                    }
                }
                else {
                    args->iv = args->staticIvBuffer;
                }

                ret = wc_RNG_GenerateBlock(ssl->rng, args->iv, args->ivSz);

                // Fabio: zero out the IV for the first encrypted outbound msg: HS fin
                memset(args->iv, 0, args->ivSz);
                sparky_tls_log(32, "args->iv", args->iv, args->ivSz);

                if (ret != 0)
                    goto exit_buildmsg;
            }

            args->size = (word16)(args->sz - args->headerSz);    /* include mac and digest */
            AddRecordHeader(output, args->size, (byte)type, ssl, epochOrder);

            /* write to output */
            if (args->ivSz > 0) {
                XMEMCPY(output + args->idx, args->iv,
                                        min(args->ivSz, MAX_IV_SZ));
                args->idx += args->ivSz;
            }
            XMEMCPY(output + args->idx, input, inSz);
            args->idx += inSz;

            ssl->options.buildMsgState = BUILD_MSG_HASH;
        }
        FALL_THROUGH;
        case BUILD_MSG_HASH:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (type == handshake && hashOutput) {
                ret = HashOutput(ssl, output, args->headerSz + inSz, args->ivSz);
                if (ret != 0)
                    goto exit_buildmsg;
            }
            if (ssl->specs.cipher_type == block) {
                word32 tmpIdx;
                word32 i;

                if (ssl->options.startedETMWrite)
                    tmpIdx = args->idx;
                else
                    tmpIdx = args->idx + args->digestSz;

                for (i = 0; i <= args->pad; i++)
                    output[tmpIdx++] = (byte)args->pad; /* pad byte gets pad value */
            }

            ssl->options.buildMsgState = BUILD_MSG_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            /* User Record Layer Callback handling */

            if (ssl->specs.cipher_type != aead
                                               && !ssl->options.startedETMWrite
                ) {
                {
                    ret = ssl->hmac(ssl, output + args->idx, output +
                                args->headerSz + args->ivSz, inSz, -1, type, 0, epochOrder);
                }
            }
            if (ret != 0)
                goto exit_buildmsg;

            ssl->options.buildMsgState = BUILD_MSG_ENCRYPT;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPT:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (ssl->options.startedETMWrite) {
                ret = Encrypt(ssl, output + args->headerSz,
                                          output + args->headerSz,
                                          (word16)(args->size - args->digestSz),
                                          asyncOkay);
            }
            else
            {
                ret = Encrypt(ssl, output + args->headerSz,
                                output + args->headerSz, args->size, asyncOkay);
            }
            if (ret != 0)
                goto exit_buildmsg;
            ssl->options.buildMsgState = BUILD_MSG_ENCRYPTED_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPTED_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (ssl->options.startedETMWrite) {
                WOLFSSL_MSG("Calculate MAC of Encrypted Data");

                {
                    ret = ssl->hmac(ssl, output + args->idx + args->pad + 1,
                                    output + args->headerSz,
                                    args->ivSz + inSz + args->pad + 1, -1, type,
                                    0, epochOrder);
                }
            }
        }
        FALL_THROUGH;
        default:
            break;
    }

exit_buildmsg:

    WOLFSSL_LEAVE("BuildMessage", ret);


    /* make sure build message state is reset */
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;


    /* return sz on success */
    if (ret == 0)
        ret = args->sz;

    /* Final cleanup */
    FreeBuildMsgArgs(ssl, args);

    return ret;
}


int SendFinished(WOLFSSL* ssl)
{
    int              sendSz,
                     finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                     FINISHED_SZ;
    byte             input[FINISHED_SZ + DTLS_HANDSHAKE_HEADER_SZ];  /* max */
    byte            *output;
    Hashes*          hashes;
    int              ret;
    int              headerSz = HANDSHAKE_HEADER_SZ;
    int              outputSz;

    WOLFSSL_START(WC_FUNC_FINISHED_SEND);
    WOLFSSL_ENTER("SendFinished");

    /* check for available size */
    outputSz = sizeof(input) + MAX_MSG_EXTRA;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;


    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHandShakeHeader(input, finishedSz, 0, finishedSz, finished, ssl);

    /* make finished hashes */
    hashes = (Hashes*)&input[headerSz];
    ret = BuildFinished(ssl, hashes,
                     ssl->options.side == WOLFSSL_CLIENT_END ? client : server);
    if (ret != 0) return ret;



    sendSz = BuildMessage(ssl, output, outputSz, input, headerSz + finishedSz,
                                                          handshake, 1, 0, 0, CUR_ORDER);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    if (!ssl->options.resuming) {
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }


    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);


    WOLFSSL_LEAVE("SendFinished", ret);
    WOLFSSL_END(WC_FUNC_FINISHED_SEND);

    return ret;
}


static int cipherExtraData(WOLFSSL* ssl)
{
    int cipherExtra;
    /* Cipher data that may be added by BuildMessage */
    /* There is always an IV (expect for chacha). For AEAD ciphers,
     * there is the authentication tag (aead_mac_size). For block
     * ciphers we have the hash_size MAC on the message, and one
     * block size for possible padding. */
    if (ssl->specs.cipher_type == aead) {
        cipherExtra = ssl->specs.aead_mac_size;
        /* CHACHA does not have an explicit IV. */
        if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha) {
            cipherExtra += AESGCM_EXP_IV_SZ;
        }
    }
    else {
        cipherExtra = ssl->specs.iv_size + ssl->specs.block_size +
            ssl->specs.hash_size;
    }
    /* Sanity check so we don't ever return negative. */
    return cipherExtra > 0 ? cipherExtra : 0;
}



/* handle generation of certificate_request (13) */
int SendCertificateRequest(WOLFSSL* ssl)
{
    byte   *output;
    int    ret;
    int    sendSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    word32 dnLen = 0;
#if defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names;
#endif

    int  typeTotal = 1;  /* only 1 for now */
    int  reqSz = ENUM_LEN + typeTotal + REQ_HEADER_SZ;  /* add auth later */

    WOLFSSL_START(WC_FUNC_CERTIFICATE_REQUEST_SEND);
    WOLFSSL_ENTER("SendCertificateRequest");

    if (IsAtLeastTLSv1_2(ssl))
        reqSz += LENGTH_SZ + ssl->suites->hashSigAlgoSz;

#if defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    /* Certificate Authorities */
    names = SSL_CA_NAMES(ssl);
    while (names != NULL) {
        byte seq[MAX_SEQ_SZ];
        WOLFSSL_X509_NAME* name = names->data.name;

        if (name != NULL) {
            /* 16-bit length | SEQ | Len | DER of name */
            dnLen += OPAQUE16_LEN + SetSequence(name->rawLen, seq) +
                        name->rawLen;
        }
        names = names->next;
    }
    reqSz += dnLen;
#endif

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher)
        return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;

    if (!ssl->options.dtls) {
        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;
    }
    else {
    }

    if (IsEncryptionOn(ssl, 1))
        sendSz += cipherExtraData(ssl);

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHeaders(output, reqSz, certificate_request, ssl);

    /* write to output */
    output[i++] = (byte)typeTotal;  /* # of types */
    if ((ssl->options.cipherSuite0 == ECC_BYTE ||
         ssl->options.cipherSuite0 == CHACHA_BYTE) &&
                     ssl->specs.sig_algo == ecc_dsa_sa_algo) {
        output[i++] = ecdsa_sign;
    } else
    {
        output[i++] = rsa_sign;
    }

    /* supported hash/sig */
    if (IsAtLeastTLSv1_2(ssl)) {
        c16toa(ssl->suites->hashSigAlgoSz, &output[i]);
        i += OPAQUE16_LEN;

        XMEMCPY(&output[i],
                         ssl->suites->hashSigAlgo, ssl->suites->hashSigAlgoSz);
        i += ssl->suites->hashSigAlgoSz;
    }

    /* Certificate Authorities */
    c16toa((word16)dnLen, &output[i]);  /* auth's */
    i += REQ_HEADER_SZ;
#if defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    names = SSL_CA_NAMES(ssl);
    while (names != NULL) {
        byte seq[MAX_SEQ_SZ];
        WOLFSSL_X509_NAME* name = names->data.name;

        if (name != NULL) {
            c16toa((word16)name->rawLen +
                   (word16)SetSequence(name->rawLen, seq), &output[i]);
            i += OPAQUE16_LEN;
            i += SetSequence(name->rawLen, output + i);
            XMEMCPY(output + i, name->raw, name->rawLen);
            i += name->rawLen;
        }
        names = names->next;
    }
#endif
    (void)i;

        if (IsEncryptionOn(ssl, 1)) {
            byte* input = NULL;
            int   inputSz = i; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;

            if (inputSz <= 0) {
                WOLFSSL_MSG("Send Cert Req bad inputSz");
                return BUFFER_E;
            }

            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            sendSz = i;
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages)
        ret = 0;
    else
        ret = SendBuffered(ssl);

    WOLFSSL_LEAVE("SendCertificateRequest", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_REQUEST_SEND);

    return ret;
}


/* handle generation of certificate_status (22) */
int SendCertificateStatus(WOLFSSL* ssl)
{
    int ret = 0;
    byte status_type = 0;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_STATUS_SEND);
    WOLFSSL_ENTER("SendCertificateStatus");

    (void) ssl;



    switch (status_type) {


        default:
            break;
    }

    WOLFSSL_LEAVE("SendCertificateStatus", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_STATUS_SEND);

    return ret;
}






/* If secure renegotiation is disabled, this will always return false.
 * Otherwise it checks to see if we are currently renegotiating. */
int IsSCR(WOLFSSL* ssl)
{
    (void)ssl;
    return 0;
}




int SendData(WOLFSSL* ssl, const void* data, int sz)
{
    int sent = 0,  /* plainText size */
        sendSz,
        ret;

    if (ssl->error == WANT_WRITE
    ) {
        ssl->error = 0;
    }

    /* don't allow write after decrypt or mac error */
    if (ssl->error == VERIFY_MAC_ERROR || ssl->error == DECRYPT_ERROR) {
        /* For DTLS allow these possible errors and allow the session
            to continue despite them */
        if (ssl->options.dtls) {
            ssl->error = 0;
        }
        else {
            WOLFSSL_MSG("Not allowing write after decrypt or mac error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (ssl->options.handShakeState != HANDSHAKE_DONE && !IsSCR(ssl)) {
        int err;
        WOLFSSL_MSG("handshake not complete, trying to finish");
        if ( (err = wolfSSL_negotiate(ssl)) != WOLFSSL_SUCCESS) {
            return  err;
        }
    }

    /* last time system socket output buffer was full, try again to send */
    if (ssl->buffers.outputBuffer.length > 0
        ) {
        WOLFSSL_MSG("output buffer was full, trying to send again");
        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }
        else {
            /* advance sent to previous sent + plain size just sent */
            sent = ssl->buffers.prevSent + ssl->buffers.plainSz;
            WOLFSSL_MSG("sent write buffered data");

            if (sent > sz) {
                WOLFSSL_MSG("error: write() after WANT_WRITE with short size");
                return ssl->error = BAD_FUNC_ARG;
            }
        }
    }

    for (;;) {
        byte* out;
        byte* sendBuffer = (byte*)data + sent;  /* may switch on comp */
        int   buffSz;                           /* may switch on comp */
        int   outputSz;

        {
            buffSz = wolfSSL_GetMaxFragSize(ssl, sz - sent);

        }

        if (sent == sz) break;

        outputSz = buffSz + COMP_EXTRA + DTLS_RECORD_HEADER_SZ;
        if (IsEncryptionOn(ssl, 1) || ssl->options.tls1_3)
            outputSz += cipherExtraData(ssl);

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
            return ssl->error = ret;

        /* get output buffer */
        out = ssl->buffers.outputBuffer.buffer +
              ssl->buffers.outputBuffer.length;

        if (!ssl->options.tls1_3) {
            sendSz = BuildMessage(ssl, out, outputSz, sendBuffer, buffSz,
                                  application_data, 0, 0, 1, CUR_ORDER);
        }
        else {
            sendSz = BUFFER_ERROR;
        }
        if (sendSz < 0) {
            return BUILD_MSG_ERROR;
        }

        ssl->buffers.outputBuffer.length += sendSz;

        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            /* store for next call if WANT_WRITE or user embedSend() that
               doesn't present like WANT_WRITE */
            ssl->buffers.plainSz  = buffSz;
            ssl->buffers.prevSent = sent;
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }

        sent += buffSz;

        /* only one message per attempt */
        if (ssl->options.partialWrite == 1) {
            WOLFSSL_MSG("Partial Write on, only sending one record");
            break;
        }
    }

    return sent;
}

/* process input data */
int ReceiveData(WOLFSSL* ssl, byte* output, int sz, int peek)
{
    int size;

    WOLFSSL_ENTER("ReceiveData()");

    /* reset error state */
    if (ssl->error == WANT_READ || ssl->error == WOLFSSL_ERROR_WANT_READ) {
        ssl->error = 0;
    }


    if (ssl->error != 0 && ssl->error != WANT_WRITE
    ) {
        WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
        return ssl->error;
    }

    {
        int negotiate = 0;
        if (ssl->options.handShakeState != HANDSHAKE_DONE)
            negotiate = 1;

        if (negotiate) {
            int err;
            WOLFSSL_MSG("Handshake not complete, trying to finish");
            if ( (err = wolfSSL_negotiate(ssl)) != WOLFSSL_SUCCESS) {
                return err;
            }
        }
    }


    while (ssl->buffers.clearOutputBuffer.length == 0) {
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            if (ssl->error == ZERO_RETURN) {
                WOLFSSL_MSG("Zero return, no more data coming");
                return 0; /* no more data coming */
            }
            if (ssl->error == SOCKET_ERROR_E) {
                if (ssl->options.connReset || ssl->options.isClosed) {
                    WOLFSSL_MSG("Peer reset or closed, connection done");
                    ssl->error = SOCKET_PEER_CLOSED_E;
                    WOLFSSL_ERROR(ssl->error);
                    return 0; /* peer reset or closed */
                }
            }
            return ssl->error;
        }
#ifndef WOLFSSL_TLS13_NO_PEEK_HANDSHAKE_DONE
#endif
    }

    size = min(sz, (int)ssl->buffers.clearOutputBuffer.length);

    XMEMCPY(output, ssl->buffers.clearOutputBuffer.buffer, size);

    if (peek == 0) {
        ssl->buffers.clearOutputBuffer.length -= size;
        ssl->buffers.clearOutputBuffer.buffer += size;
    }

    if (ssl->buffers.clearOutputBuffer.length == 0 &&
                                           ssl->buffers.inputBuffer.dynamicFlag)
       ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    WOLFSSL_LEAVE("ReceiveData()", size);
    return size;
}


/* send alert message */
int SendAlert(WOLFSSL* ssl, int severity, int type)
{
    byte input[ALERT_SIZE];
    byte *output;
    int  sendSz;
    int  ret;
    int  outputSz;
    int  dtlsExtra = 0;

    WOLFSSL_ENTER("SendAlert");


    /* if sendalert is called again for nonblocking */
    if (ssl->options.sendAlertState != 0) {
        ret = SendBuffered(ssl);
        if (ret == 0)
            ssl->options.sendAlertState = 0;
        return ret;
    }


    /* check for available size */
    outputSz = ALERT_SIZE + MAX_MSG_EXTRA + dtlsExtra;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    /* Check output buffer */
    if (ssl->buffers.outputBuffer.buffer == NULL)
        return BUFFER_E;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    input[0] = (byte)severity;
    input[1] = (byte)type;
    ssl->alert_history.last_tx.code = type;
    ssl->alert_history.last_tx.level = severity;
    if (severity == alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    /* send encrypted alert if encryption is on - can be a rehandshake over
     * an existing encrypted channel.
     * TLS 1.3 encrypts handshake packets after the ServerHello
     */
    if (IsEncryptionOn(ssl, 1)) {
        sendSz = BuildMessage(ssl, output, outputSz, input, ALERT_SIZE, alert,
                                                                       0, 0, 0, CUR_ORDER);
    }
    else {

        AddRecordHeader(output, ALERT_SIZE, alert, ssl, CUR_ORDER);
        output += RECORD_HEADER_SZ;
        XMEMCPY(output, input, ALERT_SIZE);

        sendSz = RECORD_HEADER_SZ + ALERT_SIZE;
    }
    if (sendSz < 0)
        return BUILD_MSG_ERROR;


    ssl->buffers.outputBuffer.length += sendSz;
    ssl->options.sendAlertState = 1;

    ret = SendBuffered(ssl);

    WOLFSSL_LEAVE("SendAlert", ret);

    return ret;
}

const char* wolfSSL_ERR_reason_error_string(unsigned long e)
{

    int error = (int)e;

    /* pass to wolfCrypt */
    if (error < MAX_CODE_E && error > MIN_CODE_E) {
        return wc_GetErrorString(error);
    }

    switch (error) {


    case UNSUPPORTED_SUITE :
        return "unsupported cipher suite";

    case INPUT_CASE_ERROR :
        return "input state error";

    case PREFIX_ERROR :
        return "bad index to key rounds";

    case MEMORY_ERROR :
        return "out of memory";

    case VERIFY_FINISHED_ERROR :
        return "verify problem on finished";

    case VERIFY_MAC_ERROR :
        return "verify mac problem";

    case PARSE_ERROR :
        return "parse error on header";

    case SIDE_ERROR :
        return "wrong client/server type";

    case NO_PEER_CERT : /* OpenSSL compatibility expects this exact text */
        return "peer did not return a certificate";

    case UNKNOWN_HANDSHAKE_TYPE :
        return "weird handshake type";

    case SOCKET_ERROR_E :
        return "error state on socket";

    case SOCKET_NODATA :
        return "expected data, not there";

    case INCOMPLETE_DATA :
        return "don't have enough data to complete task";

    case UNKNOWN_RECORD_TYPE :
        return "unknown type in record hdr";

    case DECRYPT_ERROR :
        return "error during decryption";

    case FATAL_ERROR :
        return "received alert fatal error";

    case ENCRYPT_ERROR :
        return "error during encryption";

    case FREAD_ERROR :
        return "fread problem";

    case NO_PEER_KEY :
        return "need peer's key";

    case NO_PRIVATE_KEY :
        return "need the private key";

    case NO_DH_PARAMS :
        return "server missing DH params";

    case RSA_PRIVATE_ERROR :
        return "error during rsa priv op";

    case MATCH_SUITE_ERROR :
        return "can't match cipher suite";

    case COMPRESSION_ERROR :
        return "compression mismatch error";

    case BUILD_MSG_ERROR :
        return "build message failure";

    case BAD_HELLO :
        return "client hello malformed";

    case DOMAIN_NAME_MISMATCH :
        return "peer subject name mismatch";

    case IPADDR_MISMATCH :
        return "peer ip address mismatch";

    case WANT_READ :
    case WOLFSSL_ERROR_WANT_READ :
        return "non-blocking socket wants data to be read";

    case NOT_READY_ERROR :
        return "handshake layer not ready yet, complete first";

    case VERSION_ERROR :
        return "record layer version error";

    case WANT_WRITE :
    case WOLFSSL_ERROR_WANT_WRITE :
        return "non-blocking socket write buffer full";

    case BUFFER_ERROR :
        return "malformed buffer input error";

    case VERIFY_CERT_ERROR :
        return "verify problem on certificate";

    case VERIFY_SIGN_ERROR :
        return "verify problem based on signature";

    case CLIENT_ID_ERROR :
        return "psk client identity error";

    case SERVER_HINT_ERROR:
        return "psk server hint error";

    case PSK_KEY_ERROR:
        return "psk key callback error";

    case GETTIME_ERROR:
        return "gettimeofday() error";

    case GETITIMER_ERROR:
        return "getitimer() error";

    case SIGACT_ERROR:
        return "sigaction() error";

    case SETITIMER_ERROR:
        return "setitimer() error";

    case LENGTH_ERROR:
        return "record layer length error";

    case PEER_KEY_ERROR:
        return "cant decode peer key";

    case ZERO_RETURN:
    case WOLFSSL_ERROR_ZERO_RETURN:
        return "peer sent close notify alert";

    case ECC_CURVETYPE_ERROR:
        return "Bad ECC Curve Type or unsupported";

    case ECC_CURVE_ERROR:
        return "Bad ECC Curve or unsupported";

    case ECC_PEERKEY_ERROR:
        return "Bad ECC Peer Key";

    case ECC_MAKEKEY_ERROR:
        return "ECC Make Key failure";

    case ECC_EXPORT_ERROR:
        return "ECC Export Key failure";

    case ECC_SHARED_ERROR:
        return "ECC DHE shared failure";

    case NOT_CA_ERROR:
        return "Not a CA by basic constraint error";

    case BAD_CERT_MANAGER_ERROR:
        return "Bad Cert Manager error";

    case OCSP_CERT_REVOKED:
        return "OCSP Cert revoked";

    case CRL_CERT_REVOKED:
        return "CRL Cert revoked";

    case CRL_MISSING:
        return "CRL missing, not loaded";

    case MONITOR_SETUP_E:
        return "CRL monitor setup error";

    case THREAD_CREATE_E:
        return "Thread creation problem";

    case OCSP_NEED_URL:
        return "OCSP need URL";

    case OCSP_CERT_UNKNOWN:
        return "OCSP Cert unknown";

    case OCSP_LOOKUP_FAIL:
        return "OCSP Responder lookup fail";

    case MAX_CHAIN_ERROR:
        return "Maximum Chain Depth Exceeded";

    case COOKIE_ERROR:
        return "DTLS Cookie Error";

    case SEQUENCE_ERROR:
        return "DTLS Sequence Error";

    case SUITES_ERROR:
        return "Suites Pointer Error";

    case OUT_OF_ORDER_E:
        return "Out of order message, fatal";

    case BAD_KEA_TYPE_E:
        return "Bad KEA type found";

    case SANITY_CIPHER_E:
        return "Sanity check on ciphertext failed";

    case RECV_OVERFLOW_E:
        return "Receive callback returned more than requested";

    case GEN_COOKIE_E:
        return "Generate Cookie Error";

    case NO_PEER_VERIFY:
        return "Need peer certificate verify Error";

    case FWRITE_ERROR:
        return "fwrite Error";

    case CACHE_MATCH_ERROR:
        return "Cache restore header match Error";

    case UNKNOWN_SNI_HOST_NAME_E:
        return "Unrecognized host name Error";

    case UNKNOWN_MAX_FRAG_LEN_E:
        return "Unrecognized max frag len Error";

    case KEYUSE_SIGNATURE_E:
        return "Key Use digitalSignature not set Error";

    case KEYUSE_ENCIPHER_E:
        return "Key Use keyEncipherment not set Error";

    case EXTKEYUSE_AUTH_E:
        return "Ext Key Use server/client auth not set Error";

    case SEND_OOB_READ_E:
        return "Send Callback Out of Bounds Read Error";

    case SECURE_RENEGOTIATION_E:
        return "Invalid Renegotiation Error";

    case SESSION_TICKET_LEN_E:
        return "Session Ticket Too Long Error";

    case SESSION_TICKET_EXPECT_E:
        return "Session Ticket Error";

    case SESSION_SECRET_CB_E:
        return "Session Secret Callback Error";

    case NO_CHANGE_CIPHER_E:
        return "Finished received from peer before Change Cipher Error";

    case SANITY_MSG_E:
        return "Sanity Check on message order Error";

    case DUPLICATE_MSG_E:
        return "Duplicate HandShake message Error";

    case SNI_UNSUPPORTED:
        return "Protocol version does not support SNI Error";

    case SOCKET_PEER_CLOSED_E:
        return "Peer closed underlying transport Error";

    case BAD_TICKET_KEY_CB_SZ:
        return "Bad user session ticket key callback Size Error";

    case BAD_TICKET_MSG_SZ:
        return "Bad session ticket message Size Error";

    case BAD_TICKET_ENCRYPT:
        return "Bad user ticket callback encrypt Error";

    case DH_KEY_SIZE_E:
        return "DH key too small Error";

    case SNI_ABSENT_ERROR:
        return "No Server Name Indication extension Error";

    case RSA_SIGN_FAULT:
        return "RSA Signature Fault Error";

    case HANDSHAKE_SIZE_ERROR:
        return "Handshake message too large Error";

    case UNKNOWN_ALPN_PROTOCOL_NAME_E:
        return "Unrecognized protocol name Error";

    case BAD_CERTIFICATE_STATUS_ERROR:
        return "Bad Certificate Status Message Error";

    case OCSP_INVALID_STATUS:
        return "Invalid OCSP Status Error";

    case OCSP_WANT_READ:
        return "OCSP nonblock wants read";

    case RSA_KEY_SIZE_E:
        return "RSA key too small";

    case ECC_KEY_SIZE_E:
        return "ECC key too small";

    case DTLS_EXPORT_VER_E:
        return "Version needs updated after code change or version mismatch";

    case INPUT_SIZE_E:
        return "Input size too large Error";

    case CTX_INIT_MUTEX_E:
        return "Initialize ctx mutex error";

    case EXT_MASTER_SECRET_NEEDED_E:
        return "Extended Master Secret must be enabled to resume EMS session";

    case DTLS_POOL_SZ_E:
        return "Maximum DTLS pool size exceeded";

    case DECODE_E:
        return "Decode handshake message error";

    case WRITE_DUP_READ_E:
        return "Write dup write side can't read error";

    case WRITE_DUP_WRITE_E:
        return "Write dup read side can't write error";

    case INVALID_CERT_CTX_E:
        return "Certificate context does not match request or not empty";

    case BAD_KEY_SHARE_DATA:
        return "The Key Share data contains group that wasn't in Client Hello";

    case MISSING_HANDSHAKE_DATA:
        return "The handshake message is missing required data";

    case BAD_BINDER: /* OpenSSL compatibility expects this exact text */
        return "binder does not verify";

    case EXT_NOT_ALLOWED:
        return "Extension type not allowed in handshake message type";

    case INVALID_PARAMETER:
        return "The security parameter is invalid";

    case UNSUPPORTED_EXTENSION:
        return "TLS Extension not requested by the client";

    case PRF_MISSING:
        return "Pseudo-random function is not enabled";

    case KEY_SHARE_ERROR:
        return "Key share extension did not contain a valid named group";

    case POST_HAND_AUTH_ERROR:
        return "Client will not do post handshake authentication";

    case HRR_COOKIE_ERROR:
        return "Cookie does not match one sent in HelloRetryRequest";

    case MCAST_HIGHWATER_CB_E:
        return "Multicast highwater callback returned error";

    case ALERT_COUNT_E:
        return "Alert Count exceeded error";

    case EXT_MISSING:
        return "Required TLS extension missing";

    case DTLS_RETX_OVER_TX:
        return "DTLS interrupting flight transmit with retransmit";

    case DH_PARAMS_NOT_FFDHE_E:
        return "Server DH parameters were not from the FFDHE set as required";

    case TCA_INVALID_ID_TYPE:
        return "TLS Extension Trusted CA ID type invalid";

    case TCA_ABSENT_ERROR:
        return "TLS Extension Trusted CA ID response absent";

    case TSIP_MAC_DIGSZ_E:
        return "TSIP MAC size invalid, must be sized for SHA-1 or SHA-256";

    case CLIENT_CERT_CB_ERROR:
        return "Error importing client cert or key from callback";

    case SSL_SHUTDOWN_ALREADY_DONE_E:
        return "Shutdown has already occurred";

    case TLS13_SECRET_CB_E:
        return "TLS1.3 Secret Callback Error";

    case DTLS_SIZE_ERROR:
        return "DTLS trying to send too much in single datagram error";

    case NO_CERT_ERROR:
        return "TLS1.3 No Certificate Set Error";

    case APP_DATA_READY:
        return "Application data is available for reading";

    case TOO_MUCH_EARLY_DATA:
        return "Too much early data";

    case SOCKET_FILTERED_E:
        return "Session stopped by network filter";

    case UNSUPPORTED_PROTO_VERSION:
        return "bad/unsupported protocol version";

    case FALCON_KEY_SIZE_E:
        return "Wrong key size for Falcon.";

    default :
        return "unknown error number";
    }

}

const char* wolfSSL_ERR_func_error_string(unsigned long e)
{
    (void)e;
    WOLFSSL_MSG("wolfSSL_ERR_func_error_string does not return the name of "
                "the function that failed. Please inspect the wolfSSL debug "
                "logs to determine where the error occurred.");
    return "";
}

/* return library name
 * @param e error code
 * @return text library name,
 *    if there is no suitable library found, returns empty string
 */
const char* wolfSSL_ERR_lib_error_string(unsigned long e)
{
    int libe = 0;

    (void)libe;
    (void)e;

    return "";
}

void SetErrorString(int error, char* str)
{
    XSTRNCPY(str, wolfSSL_ERR_reason_error_string(error), WOLFSSL_MAX_ERROR_SZ);
    str[WOLFSSL_MAX_ERROR_SZ-1] = 0;
}


    /* note that the comma is included at the end of the SUITE_ALIAS() macro
     * definitions, to allow aliases to be gated out by the above null macros
     * in the NO_CIPHER_SUITE_ALIASES section.
     */

        #if  defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),"",(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #else
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),"",(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #endif

static const CipherSuiteInfo cipher_names[] =
{










#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    SUITE_INFO("RC4-MD5","SSL_RSA_WITH_RC4_128_MD5",CIPHER_BYTE,SSL_RSA_WITH_RC4_128_MD5,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("DES-CBC3-SHA","SSL_RSA_WITH_3DES_EDE_CBC_SHA",CIPHER_BYTE,SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif


































    SUITE_INFO("ECDHE-RSA-AES128-SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
























    SUITE_INFO("ECDHE-RSA-AES128-GCM-SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
































#ifdef HAVE_RENEGOTIATION_INDICATION
    SUITE_INFO("RENEGOTIATION-INFO","TLS_EMPTY_RENEGOTIATION_INFO_SCSV",CIPHER_BYTE,TLS_EMPTY_RENEGOTIATION_INFO_SCSV,SSLv3_MINOR,SSLv3_MAJOR),
#endif








#ifdef BUILD_WDM_WITH_NULL_SHA256
    SUITE_INFO("WDM-NULL-SHA256","WDM_WITH_NULL_SHA256",CIPHER_BYTE,WDM_WITH_NULL_SHA256, TLSv1_3_MINOR, SSLv3_MAJOR)
#endif

};


/* returns the cipher_names array */
const CipherSuiteInfo* GetCipherNames(void)
{
    return cipher_names;
}


/* returns the number of elements in the cipher_names array */
int GetCipherNamesSize(void)
{
    return (int)(sizeof(cipher_names) / sizeof(CipherSuiteInfo));
}


const char* GetCipherNameInternal(const byte cipherSuite0, const byte cipherSuite)
{
    int i;
    const char* nameInternal = "None";

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((cipher_names[i].cipherSuite0 == cipherSuite0) &&
            (cipher_names[i].cipherSuite  == cipherSuite)
            && (! (cipher_names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS))
            ) {
            nameInternal = cipher_names[i].name;
            break;
        }
    }
    return nameInternal;
}


const char* GetCipherNameIana(const byte cipherSuite0, const byte cipherSuite)
{
    int i;
    const char* nameIana = "NONE";

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((cipher_names[i].cipherSuite0 == cipherSuite0) &&
            (cipher_names[i].cipherSuite  == cipherSuite)
            && (! (cipher_names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS))
            ) {
            nameIana = cipher_names[i].name_iana;
            break;
        }
    }
    return nameIana;
}

const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }

    return GetCipherNameInternal(ssl->options.cipherSuite0, ssl->options.cipherSuite);
}

const char* wolfSSL_get_cipher_name_iana(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }

    return GetCipherNameIana(ssl->options.cipherSuite0, ssl->options.cipherSuite);
}

int GetCipherSuiteFromName(const char* name, byte* cipherSuite0,
                           byte* cipherSuite, int* flags)
{
    int           ret = BAD_FUNC_ARG;
    int           i;
    unsigned long len;
    const char*   nameDelim;

    /* Support trailing : */
    nameDelim = XSTRSTR(name, ":");
    if (nameDelim)
        len = (unsigned long)(nameDelim - name);
    else
        len = (unsigned long)XSTRLEN(name);

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((XSTRNCMP(name, cipher_names[i].name, len) == 0) &&
            (cipher_names[i].name[len] == 0)) {
            *cipherSuite0 = cipher_names[i].cipherSuite0;
            *cipherSuite  = cipher_names[i].cipherSuite;
            *flags = cipher_names[i].flags;
            ret = 0;
            break;
        }
    }

    return ret;
}

/**
Set the enabled cipher suites.

@param [out] suites Suites structure.
@param [in]  list   List of cipher suites, only supports full name from
                    cipher_names[] delimited by ':'.

@return true on success, else false.
*/
int SetCipherList(WOLFSSL_CTX* ctx, Suites* suites, const char* list)
{
    int       ret           = 0;
    int       idx           = 0;
    int       haveRSAsig    = 0;
    int       haveECDSAsig  = 0;
    int       haveFalconSig = 0;
    int       haveAnon      = 0;
    const int suiteSz       = GetCipherNamesSize();
    const char* next        = list;

    if (suites == NULL || list == NULL) {
        WOLFSSL_MSG("SetCipherList parameter error");
        return 0;
    }

    if (next[0] == 0 || XSTRCMP(next, "ALL") == 0 ||
        XSTRCMP(next, "DEFAULT") == 0 || XSTRCMP(next, "HIGH") == 0)
        return 1; /* wolfSSL default */

    do {
        const char* current = next;
        char   name[MAX_SUITE_NAME + 1];
        int    i;
        word32 length;

        next = XSTRSTR(next, ":");
        length = MAX_SUITE_NAME;
        if (next != NULL) {
            word32 currLen = (word32)(next - current);
            if (length > currLen) {
                length = currLen;
            }
        }

        XSTRNCPY(name, current, length);
        name[(length == sizeof(name)) ? length - 1 : length] = 0;

        for (i = 0; i < suiteSz; i++) {
            if (XSTRNCMP(name, cipher_names[i].name, sizeof(name)) == 0
                || XSTRNCMP(name, cipher_names[i].name_iana, sizeof(name)) == 0
             ) {

                if (idx + 1 >= WOLFSSL_MAX_SUITE_SZ) {
                    WOLFSSL_MSG("WOLFSSL_MAX_SUITE_SZ set too low");
                    return 0; /* suites buffer not large enough, error out */
                }

                suites->suites[idx++] = cipher_names[i].cipherSuite0;
                suites->suites[idx++] = cipher_names[i].cipherSuite;
                /* The suites are either ECDSA, RSA, PSK, or Anon. The RSA
                 * suites don't necessarily have RSA in the name. */
                if ((haveECDSAsig == 0) && XSTRSTR(name, "ECDSA"))
                    haveECDSAsig = 1;
                else
                if (haveRSAsig == 0
                   ) {
                    haveRSAsig = 1;
                }

                ret = 1; /* found at least one */
                break;
            }
        }
    }
    while (next++); /* ++ needed to skip ':' */

    if (ret) {
        int keySz = 0;
        keySz = ctx->privateKeySz;
        suites->setSuites = 1;
        suites->suiteSz   = (word16)idx;
        InitSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig, haveFalconSig,
                              haveAnon, 1, keySz);
    }

    (void)ctx;

    return ret;
}


static int MatchSigAlgo(WOLFSSL* ssl, int sigAlgo)
{
    /* Signature algorithm matches certificate. */
    return sigAlgo == ssl->suites->sigAlgo;
}

static int CmpEccStrength(int hashAlgo, int curveSz)
{
    int dgstSz = GetMacDigestSize((byte)hashAlgo);
    if (dgstSz <= 0)
        return -1;
    return dgstSz - (curveSz & (~0x3));
}

static byte MinHashAlgo(WOLFSSL* ssl)
{
#if !defined(WOLFSSL_ALLOW_TLS_SHA1)
    if (IsAtLeastTLSv1_2(ssl)) {
        return sha256_mac;
    }
#endif /* WOLFSSL_NO_TLS12 */
    (void)ssl;
    return sha_mac;
}

int PickHashSigAlgo(WOLFSSL* ssl, const byte* hashSigAlgo, word32 hashSigAlgoSz)
{
    word32 i;
    int ret = MATCH_SUITE_ERROR;
    byte minHash;

    /* set defaults */
    if (IsAtLeastTLSv1_3(ssl->version)) {
        /* TLS 1.3 cipher suites don't have public key algorithms in them.
         * Using the one in the certificate - if any.
         */
        ssl->suites->sigAlgo = ssl->buffers.keyType;
    }
    else {
        ssl->suites->sigAlgo = ssl->specs.sig_algo;
    }
    if (ssl->suites->sigAlgo == anonymous_sa_algo) {
        /* PSK ciphersuite - get digest to use from cipher suite */
        ssl->suites->hashAlgo = ssl->specs.mac_algorithm;
        return 0;
    }
    ssl->suites->hashAlgo = minHash = MinHashAlgo(ssl);

    /* No list means go with the defaults. */
    if (hashSigAlgoSz == 0)
        return 0;

    /* i+1 since two bytes used to describe hash and signature algorithm */
    for (i = 0; (i+1) < hashSigAlgoSz; i += HELLO_EXT_SIGALGO_SZ) {
        byte hashAlgo = 0, sigAlgo = 0;

        DecodeSigAlg(&hashSigAlgo[i], &hashAlgo, &sigAlgo);
        /* Keep looking if hash algorithm not strong enough. */
        if (hashAlgo < minHash)
            continue;
        /* Keep looking if signature algorithm isn't supported by cert. */
        if (!MatchSigAlgo(ssl, sigAlgo))
            continue;


    #if defined(WOLFSSL_ECDSA_MATCH_HASH)
        #error "WOLFSSL_ECDSA_MATCH_HASH and USE_ECDSA_KEYSZ_HASH_ALGO cannot "
               "be used together"
    #endif

    #if  defined(WOLFSSL_ECDSA_MATCH_HASH)
        if (sigAlgo == ecc_dsa_sa_algo
        #ifndef WOLFSSL_ECDSA_MATCH_HASH
            && IsAtLeastTLSv1_3(ssl->version)
        #endif
            ) {
            /* Must be exact match. */
            if (CmpEccStrength(hashAlgo, ssl->buffers.keySz) != 0)
                continue;

            /* Matched ECDSA exaclty - set chosen and finished. */
            ssl->suites->hashAlgo = hashAlgo;
            ssl->suites->sigAlgo = sigAlgo;
            ret = 0;
            break;
        }
    #endif

    /* For ECDSA the `USE_ECDSA_KEYSZ_HASH_ALGO` build option will choose a hash
     * algorithm that matches the ephemeral ECDHE key size or the next highest
     * available. This workaround resolves issue with some peer's that do not
     * properly support scenarios such as a P-256 key hashed with SHA512.
     */
        if (sigAlgo == ecc_dsa_sa_algo) {
            int cmp = CmpEccStrength(hashAlgo, ssl->eccTempKeySz);

            /* Keep looking if digest not strong enough. */
            if (cmp < 0)
                continue;

            /* Looking for exact match or next highest. */
            if (ret != 0 || hashAlgo <= ssl->suites->hashAlgo) {
                ssl->suites->hashAlgo = hashAlgo;
                ssl->suites->sigAlgo = sigAlgo;
                ssl->namedGroup = 0;
                ret = 0;
            }

            /* Continue looking if not the same strength. */
            if (cmp > 0)
                continue;
            /* Exact match - finished. */
            break;
        }

        switch (hashAlgo) {
            case sha_mac:
            case sha224_mac:
            case sha256_mac:
            case sha384_mac:
            case sha512_mac:
            #ifdef WOLFSSL_STRONGEST_HASH_SIG
                /* Is hash algorithm weaker than chosen/min? */
                if (hashAlgo < ssl->suites->hashAlgo)
                    break;
            #else
                /* Is hash algorithm stonger than last chosen? */
                if (ret == 0 && hashAlgo > ssl->suites->hashAlgo)
                    break;
            #endif
                /* The chosen one - but keep looking. */
                ssl->suites->hashAlgo = hashAlgo;
                ssl->suites->sigAlgo = sigAlgo;
                ret = 0;
                break;
            default:
                /* Support for hash algorithm not compiled in. */
                break;
        }
    }

    return ret;
}




/* Decode the private key - RSA/ECC/Ed25519/Ed448/Falcon - and creates a key
 * object.
 *
 * The signature type is set as well.
 * The maximum length of a signature is returned.
 *
 * ssl     The SSL/TLS object.
 * length  The length of a signature.
 * returns 0 on success, otherwise failure.
 */
int DecodePrivateKey(WOLFSSL *ssl, word16* length)
{
    int      ret = BAD_FUNC_ARG;
    int      keySz;
    word32   idx;

    /* make sure private key exists */
    if (ssl->buffers.key == NULL || ssl->buffers.key->buffer == NULL) {
        /* allow no private key if using external */
        {
            WOLFSSL_MSG("Private key missing!");
            ERROR_OUT(NO_PRIVATE_KEY, exit_dpk);
        }
    }


    if (ssl->buffers.keyType == rsa_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_RSA;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        WOLFSSL_MSG("Trying RSA private key");

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an RSA private key. */
        ret = wc_RsaPrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                    (RsaKey*)ssl->hsKey, ssl->buffers.key->length);
        if (ret == 0) {
            WOLFSSL_MSG("Using RSA private key");

            /* It worked so check it meets minimum key size requirements. */
            keySz = wc_RsaEncryptSize((RsaKey*)ssl->hsKey);
            if (keySz < 0) { /* check if keySz has error case */
                ERROR_OUT(keySz, exit_dpk);
            }

            if (keySz < ssl->options.minRsaKeySz) {
                WOLFSSL_MSG("RSA key size too small");
                ERROR_OUT(RSA_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = (word16)keySz;

            goto exit_dpk;
        }
    }

    FreeKey(ssl, ssl->hsType, (void**)&ssl->hsKey);

    if (ssl->buffers.keyType == ecc_dsa_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_ECC;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        WOLFSSL_MSG("Trying ECC private key, RSA didn't work");

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an ECC private key. */
        ret = wc_EccPrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                                     (ecc_key*)ssl->hsKey,
                                     ssl->buffers.key->length);
        if (ret == 0) {
            WOLFSSL_MSG("Using ECC private key");

            /* Check it meets the minimum ECC key size requirements. */
            keySz = wc_ecc_size((ecc_key*)ssl->hsKey);
            if (keySz < ssl->options.minEccKeySz) {
                WOLFSSL_MSG("ECC key size too small");
                ERROR_OUT(ECC_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = (word16)wc_ecc_sig_size((ecc_key*)ssl->hsKey);

            goto exit_dpk;
        }
    }

    (void)idx;
    (void)keySz;
    (void)length;
exit_dpk:
    return ret;
}



/* client only parts */


    /* handle generation of client_hello (1) */
    int SendClientHello(WOLFSSL* ssl)
    {
        byte              *output;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                idSz;
        int                ret;
        word16             extSz = 0;

        if (ssl == NULL) {
            return BAD_FUNC_ARG;
        }

        idSz = ssl->options.resuming ? ssl->session->sessionIDSz : 0;


        WOLFSSL_START(WC_FUNC_CLIENT_HELLO_SEND);
        WOLFSSL_ENTER("SendClientHello");

        if (ssl->suites == NULL) {
            WOLFSSL_MSG("Bad suites pointer in SendClientHello");
            return SUITES_ERROR;
        }

        length = VERSION_SZ + RAN_LEN
               + idSz + ENUM_LEN
               + ssl->suites->suiteSz + SUITE_LEN
               + COMP_LEN + ENUM_LEN;

        /* auto populate extensions supported unless user defined */
        if ((ret = TLSX_PopulateExtensions(ssl, 0)) != 0)
            return ret;
        extSz = 0;
        ret = TLSX_GetRequestSize(ssl, client_hello, &extSz);
        if (ret != 0)
            return ret;
        length += extSz;
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        if (ssl->arrays == NULL) {
            return BAD_FUNC_ARG;
        }


        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, client_hello, ssl);

        /* client hello, first version */
        output[idx++] = ssl->version.major;
        output[idx++] = ssl->version.minor;
        ssl->chVersion = ssl->version;  /* store in case changed */

        /* then random */
        if (ssl->options.connectState == CONNECT_BEGIN) {
            ret = wc_RNG_GenerateBlock(ssl->rng, output + idx, RAN_LEN);
            memset(output + idx, 0, RAN_LEN);  // Fabio: HFT websockets
            if (ret != 0)
                return ret;
            sparky_tls_log(1, "CLIENT RANDOM", output + idx, RAN_LEN);

            /* store random */
            XMEMCPY(ssl->arrays->clientRandom, output + idx, RAN_LEN);
        } else {
        }
        idx += RAN_LEN;

        /* then session id */
        output[idx++] = (byte)idSz;
        if (idSz) {
            XMEMCPY(output + idx, ssl->session->sessionID,
                                                      ssl->session->sessionIDSz);
            idx += ssl->session->sessionIDSz;
        }

        /* then DTLS cookie */
        /* then cipher suites */
        c16toa(ssl->suites->suiteSz, output + idx);
        idx += OPAQUE16_LEN;
        XMEMCPY(output + idx, &ssl->suites->suites, ssl->suites->suiteSz);
        idx += ssl->suites->suiteSz;

        /* last, compression */
        output[idx++] = COMP_LEN;
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;

        extSz = 0;
        ret = TLSX_WriteRequest(ssl, output + idx, client_hello, &extSz);
        if (ret != 0)
            return ret;
        idx += extSz;

        (void)idx; /* suppress analyzer warning, keep idx current */

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;


        ssl->buffers.outputBuffer.length += sendSz;

        ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendClientHello", ret);
        WOLFSSL_END(WC_FUNC_CLIENT_HELLO_SEND);

        return ret;
    }


    /* handle processing of DTLS hello_verify_request (3) */
    static int DoHelloVerifyRequest(WOLFSSL* ssl, const byte* input,
                                    word32* inOutIdx, word32 size)
    {
        ProtocolVersion pv;
        byte            cookieSz;
        word32          begin = *inOutIdx;



        if (OPAQUE16_LEN + OPAQUE8_LEN > size)
            return BUFFER_ERROR;

        XMEMCPY(&pv, input + *inOutIdx, OPAQUE16_LEN);
        *inOutIdx += OPAQUE16_LEN;

        if (pv.major != DTLS_MAJOR ||
                         (pv.minor != DTLS_MINOR && pv.minor != DTLSv1_2_MINOR))
            return VERSION_ERROR;

        cookieSz = input[(*inOutIdx)++];

        if (cookieSz) {
            if ((*inOutIdx - begin) + cookieSz > size)
                return BUFFER_ERROR;

            *inOutIdx += cookieSz;
        }

        ssl->options.serverState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
        return 0;
    }


    static WC_INLINE int DSH_CheckSessionId(WOLFSSL* ssl)
    {
        int ret = 0;



        ret = ret ||
              (ssl->options.haveSessionId && XMEMCMP(ssl->arrays->sessionID,
                                          ssl->session->sessionID, ID_LEN) == 0);

        return ret;
    }

    /* Check the version in the received message is valid and set protocol
     * version to use.
     *
     * ssl  The SSL/TLS object.
     * pv   The protocol version from the packet.
     * returns 0 on success, otherwise failure.
     */
    int CheckVersion(WOLFSSL *ssl, ProtocolVersion pv)
    {


        if (pv.minor > ssl->version.minor) {
            WOLFSSL_MSG("Server using higher version, fatal error");
            return VERSION_ERROR;
        }
        if (pv.minor < ssl->version.minor) {
            WOLFSSL_MSG("server using lower version");

            /* Check for downgrade attack. */
            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("\tno downgrade allowed, fatal error");
                return VERSION_ERROR;
            }
            if (pv.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                return VERSION_ERROR;
            }


            /* Checks made - OK to downgrade. */
            if (pv.minor == SSLv3_MINOR) {
                /* turn off tls */
                WOLFSSL_MSG("\tdowngrading to SSLv3");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = SSLv3_MINOR;
            }
            else if (pv.minor == TLSv1_MINOR) {
                /* turn off tls 1.1+ */
                WOLFSSL_MSG("\tdowngrading to TLSv1");
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = TLSv1_MINOR;
            }
            else if (pv.minor == TLSv1_1_MINOR) {
                WOLFSSL_MSG("\tdowngrading to TLSv1.1");
                ssl->version.minor  = TLSv1_1_MINOR;
            }
            else if (pv.minor == TLSv1_2_MINOR) {
                WOLFSSL_MSG("    downgrading to TLSv1.2");
                ssl->version.minor  = TLSv1_2_MINOR;
            }
        }


        return 0;
    }

    /* handle processing of server_hello (2) */
    int DoServerHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                      word32 helloSz)
    {
        byte            cs0;   /* cipher suite bytes 0, 1 */
        byte            cs1;
        ProtocolVersion pv;
        byte            compression;
        word32          i = *inOutIdx;
        word32          begin = i;
        int             ret;

        WOLFSSL_START(WC_FUNC_SERVER_HELLO_DO);
        WOLFSSL_ENTER("DoServerHello");


        /* protocol version, random and session id length check */
        if (OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        /* protocol version */
        XMEMCPY(&pv, input + i, OPAQUE16_LEN);
        i += OPAQUE16_LEN;

        ret = CheckVersion(ssl, pv);
        if (ret != 0)
            return ret;


        /* random */
        XMEMCPY(ssl->arrays->serverRandom, input + i, RAN_LEN);
        i += RAN_LEN;
        sparky_tls_log(5, "SERVER_RANDOM", ssl->arrays->serverRandom, RAN_LEN);

        /* session id */
        ssl->arrays->sessionIDSz = input[i++];

        if (ssl->arrays->sessionIDSz > ID_LEN) {
            WOLFSSL_MSG("Invalid session ID size");
            ssl->arrays->sessionIDSz = 0;
            return BUFFER_ERROR;
        }
        else if (ssl->arrays->sessionIDSz) {
            if ((i - begin) + ssl->arrays->sessionIDSz > helloSz)
                return BUFFER_ERROR;

            XMEMCPY(ssl->arrays->sessionID, input + i,
                                                      ssl->arrays->sessionIDSz);
            i += ssl->arrays->sessionIDSz;
            ssl->options.haveSessionId = 1;
        }


        /* suite and compression */
        if ((i - begin) + OPAQUE16_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        cs0 = input[i++];
        cs1 = input[i++];


        ssl->options.cipherSuite0 = cs0;
        ssl->options.cipherSuite  = cs1;

        compression = input[i++];

#ifndef WOLFSSL_NO_STRICT_CIPHER_SUITE
        {
            word32 idx, found = 0;
            /* confirm server_hello cipher suite is one sent in client_hello */
            for (idx = 0; idx < ssl->suites->suiteSz; idx += 2) {
                if (ssl->suites->suites[idx]   == cs0 &&
                    ssl->suites->suites[idx+1] == cs1) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                WOLFSSL_MSG("ServerHello did not use cipher suite from ClientHello");
                return MATCH_SUITE_ERROR;
            }
        }
#endif /* !WOLFSSL_NO_STRICT_CIPHER_SUITE */

        if (compression != NO_COMPRESSION && !ssl->options.usingCompression) {
            WOLFSSL_MSG("Server forcing compression w/o support");
            return COMPRESSION_ERROR;
        }

        if (compression != ZLIB_COMPRESSION && ssl->options.usingCompression) {
            WOLFSSL_MSG("Server refused compression, turning off");
            ssl->options.usingCompression = 0;  /* turn off if server refused */
        }

        *inOutIdx = i;

        if ( (i - begin) < helloSz) {
            if (TLSX_SupportExtensions(ssl)) {
                word16 totalExtSz;

                if ((i - begin) + OPAQUE16_LEN > helloSz)
                    return BUFFER_ERROR;

                ato16(&input[i], &totalExtSz);
                i += OPAQUE16_LEN;

                if ((i - begin) + totalExtSz > helloSz)
                    return BUFFER_ERROR;

                if ((ret = TLSX_Parse(ssl, (byte *) input + i, totalExtSz,
                                                           server_hello, NULL)))
                    return ret;

                i += totalExtSz;
                *inOutIdx = i;
            }
            else
                *inOutIdx = begin + helloSz; /* skip extensions */
        }
        else
            ssl->options.haveEMS = 0; /* If no extensions, no EMS */

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
            if (ssl->options.startedETMWrite &&
                                              ssl->specs.cipher_type == block) {
                *inOutIdx += MacSize(ssl);
            }
        }


        ret = CompleteServerHello(ssl);

        WOLFSSL_LEAVE("DoServerHello", ret);
        WOLFSSL_END(WC_FUNC_SERVER_HELLO_DO);

        return ret;
    }

    int CompleteServerHello(WOLFSSL* ssl)
    {
        int ret;

        if (!ssl->options.resuming) {
            byte* down = ssl->arrays->serverRandom + RAN_LEN -
                                                         TLS13_DOWNGRADE_SZ - 1;
            byte  vers = ssl->arrays->serverRandom[RAN_LEN - 1];
            if (ssl->ctx->method->version.major == SSLv3_MAJOR &&
                                ssl->ctx->method->version.minor == TLSv1_2_MINOR
            ) {
                /* TLS v1.2 capable client not allowed to downgrade when
                 * connecting to TLS v1.2 capable server.
                 */
                if (XMEMCMP(down, tls13Downgrade, TLS13_DOWNGRADE_SZ) == 0 &&
                                                                    vers == 0) {
                    SendAlert(ssl, alert_fatal, illegal_parameter);
                    return VERSION_ERROR;
                }
            }
        }
        else {
            if (DSH_CheckSessionId(ssl)) {
                if (SetCipherSpecs(ssl) == 0) {

                    XMEMCPY(ssl->arrays->masterSecret,
                            ssl->session->masterSecret, SECRET_LEN);
                    ret = -1; /* default value */
                    if (ssl->options.tls)
                        ret = DeriveTlsKeys(ssl);
                    if (!ssl->options.tls)
                        ret = DeriveKeys(ssl);
                    /* SERVER: peer auth based on session secret. */
                    ssl->options.peerAuthGood = (ret == 0);
                    ssl->options.serverState = SERVER_HELLODONE_COMPLETE;

                    return ret;
                }
                else {
                    WOLFSSL_MSG("Unsupported cipher suite, DoServerHello");
                    return UNSUPPORTED_SUITE;
                }
            }
            else {
                WOLFSSL_MSG("Server denied resumption attempt");
                ssl->options.resuming = 0; /* server denied resumption try */
            }
        }
        return SetCipherSpecs(ssl);
    }



    /* Make sure client setup is valid for this suite, true on success */
    int VerifyClientSuite(WOLFSSL* ssl)
    {
        byte first   = ssl->options.cipherSuite0;
        byte second  = ssl->options.cipherSuite;

        WOLFSSL_ENTER("VerifyClientSuite");

        if (CipherRequires(first, second, REQUIRES_PSK)) {
            WOLFSSL_MSG("Requires PSK");
            {
                WOLFSSL_MSG("Don't have PSK");
                return 0;
            }
        }

        return 1;  /* success */
    }


    /* handle processing of certificate_request (13) */
    static int DoCertificateRequest(WOLFSSL* ssl, const byte* input, word32*
                                    inOutIdx, word32 size)
    {
        word16 len;
        word32 begin = *inOutIdx;
    #if  defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
        int ret;
    #endif

        WOLFSSL_START(WC_FUNC_CERTIFICATE_REQUEST_DO);
        WOLFSSL_ENTER("DoCertificateRequest");


        if (OPAQUE8_LEN > size)
            return BUFFER_ERROR;

        len = input[(*inOutIdx)++];

        if ((*inOutIdx - begin) + len > size)
            return BUFFER_ERROR;

        /* types, read in here */
        *inOutIdx += len;

        /* signature and hash signature algorithm */
        if (IsAtLeastTLSv1_2(ssl)) {
            if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
                return BUFFER_ERROR;

            ato16(input + *inOutIdx, &len);
            *inOutIdx += OPAQUE16_LEN;

            if ((len > size) || ((*inOutIdx - begin) + len > size))
                return BUFFER_ERROR;

            if (PickHashSigAlgo(ssl, input + *inOutIdx, len) != 0 &&
                                             ssl->buffers.certificate &&
                                             ssl->buffers.certificate->buffer) {
                if (ssl->buffers.key && ssl->buffers.key->buffer) {
                    return INVALID_PARAMETER;
                }
            }
            *inOutIdx += len;
        }

        /* authorities */
        if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
            return BUFFER_ERROR;

        /* DN seq length */
        ato16(input + *inOutIdx, &len);
        *inOutIdx += OPAQUE16_LEN;

        if ((*inOutIdx - begin) + len > size)
            return BUFFER_ERROR;

    #if defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
        if (ssl->ca_names != ssl->ctx->ca_names)
            wolfSSL_sk_X509_NAME_pop_free(ssl->ca_names, NULL);
        ssl->ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ssl->ca_names == NULL) {
            return MEMORY_ERROR;
        }
    #endif

        while (len) {
            word16 dnSz;

            if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
                return BUFFER_ERROR;

            ato16(input + *inOutIdx, &dnSz);
            *inOutIdx += OPAQUE16_LEN;

            if ((*inOutIdx - begin) + dnSz > size)
                return BUFFER_ERROR;

        #if defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
            {
                /* Use a DecodedCert struct to get access to GetName to
                 * parse DN name */
                DecodedCert cert;
                WOLFSSL_X509_NAME* name;

                InitDecodedCert(&cert, input + *inOutIdx, dnSz, ssl->heap);

                if ((ret = GetName(&cert, SUBJECT, dnSz)) != 0) {
                    FreeDecodedCert(&cert);
                    return ret;
                }

                if ((name = wolfSSL_X509_NAME_new()) == NULL) {
                    FreeDecodedCert(&cert);
                    return MEMORY_ERROR;
                }

                CopyDecodedName(name, &cert, SUBJECT);

                if (wolfSSL_sk_X509_NAME_push(ssl->ca_names, name)
                        == WOLFSSL_FAILURE) {
                    FreeDecodedCert(&cert);
                    wolfSSL_X509_NAME_free(name);
                    return MEMORY_ERROR;
                }

                FreeDecodedCert(&cert);
            }
        #endif

            *inOutIdx += dnSz;
            len -= OPAQUE16_LEN + dnSz;
        }


        /* don't send client cert or cert verify if user hasn't provided
           cert and private key */
        if (ssl->buffers.certificate && ssl->buffers.certificate->buffer) {
            if (ssl->buffers.key && ssl->buffers.key->buffer) {
                ssl->options.sendVerify = SEND_CERT;
            }
        }
        else if (IsTLS(ssl))
        {
            ssl->options.sendVerify = SEND_BLANK_CERT;
        }

        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
            if (ssl->options.startedETMRead)
                *inOutIdx += MacSize(ssl);
        }

        WOLFSSL_LEAVE("DoCertificateRequest", 0);
        WOLFSSL_END(WC_FUNC_CERTIFICATE_REQUEST_DO);

        return 0;
    }



    static int CheckCurveId(int tlsCurveId)
    {
        int ret = ECC_CURVE_ERROR;

        switch (tlsCurveId) {
    #if ECC_MIN_KEY_SZ <= 224
            case WOLFSSL_ECC_SECP224R1: return ECC_SECP224R1_OID;
    #endif
    #if ECC_MIN_KEY_SZ <= 256
            case WOLFSSL_ECC_SECP256R1: return ECC_SECP256R1_OID;
    #endif
    #if ECC_MIN_KEY_SZ <= 384
            case WOLFSSL_ECC_SECP384R1: return ECC_SECP384R1_OID;
    #endif
    #if ECC_MIN_KEY_SZ <= 521
            case WOLFSSL_ECC_SECP521R1: return ECC_SECP521R1_OID;
    #endif
            default: break;
        }

        return ret;
    }


/* Persistable DoServerKeyExchange arguments */
typedef struct DskeArgs {
    byte*  output; /* not allocated */
    byte*  verifySig;
    word32 idx;
    word32 begin;
    word16 verifySigSz;
    word16 sigSz;
    byte   sigAlgo;
    byte   hashAlgo;
} DskeArgs;

static void FreeDskeArgs(WOLFSSL* ssl, void* pArgs)
{
    DskeArgs* args = (DskeArgs*)pArgs;

    (void)ssl;
    (void)args;

    if (args->verifySig) {
        XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        args->verifySig = NULL;
    }
}

static int GetDhPublicKey(WOLFSSL* ssl, const byte* input, word32 size,
                          DskeArgs* args)
{
    int             ret = 0;
    word16          length;
#ifdef HAVE_PUBLIC_FFDHE
    const DhParams* params = NULL;
#endif
    word16          group = 0;

    if (ssl->buffers.weOwnDH) {
        if (ssl->buffers.serverDH_P.buffer) {
            XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ssl->buffers.serverDH_P.buffer = NULL;
        }

        if (ssl->buffers.serverDH_G.buffer) {
            XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ssl->buffers.serverDH_G.buffer = NULL;
        }

    }

    if (ssl->buffers.serverDH_Pub.buffer) {
        XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_Pub.buffer = NULL;
    }

    /* p */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length < ssl->options.minDhKeySz) {
        WOLFSSL_MSG("Server using a DH key that is too small");
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }
    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a DH key that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_P.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_P.buffer) {
        ssl->buffers.serverDH_P.length = length;
    }
    else {
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_P.buffer, input + args->idx,
                                                        length);
    args->idx += length;

    ssl->options.dhKeySz = length;

    /* g */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a DH key generator that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_G.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_G.buffer) {
        ssl->buffers.serverDH_G.length = length;
    }
    else {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_G.buffer, input + args->idx,
                                                        length);
    args->idx += length;

    /* pub */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a public DH key that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_Pub.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_Pub.buffer) {
        ssl->buffers.serverDH_Pub.length = length;
    }
    else {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_Pub.buffer, input + args->idx,
                                                        length);
    ssl->buffers.weOwnDH = 1;
    args->idx += length;

    switch (ssl->options.dhKeySz) {
        case 2048/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe2048_Get();
            #endif
            group = WOLFSSL_FFDHE_2048;
            break;
    #ifdef HAVE_FFDHE_3072
        case 3072/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe3072_Get();
            #endif
            group = WOLFSSL_FFDHE_3072;
            break;
    #endif
    #ifdef HAVE_FFDHE_4096
        case 4096/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe4096_Get();
            #endif
            group = WOLFSSL_FFDHE_4096;
            break;
    #endif
    #ifdef HAVE_FFDHE_6144
        case 6144/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe6144_Get();
            #endif
            group = WOLFSSL_FFDHE_6144;
            break;
    #endif
    #ifdef HAVE_FFDHE_8192
        case 8192/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe8192_Get();
            #endif
            group = WOLFSSL_FFDHE_8192;
            break;
    #endif
        default:
            break;
    }


#ifdef HAVE_PUBLIC_FFDHE
    if (params == NULL || params->g_len != ssl->buffers.serverDH_G.length ||
            (XMEMCMP(ssl->buffers.serverDH_G.buffer, params->g,
                    params->g_len) != 0) ||
            (XMEMCMP(ssl->buffers.serverDH_P.buffer, params->p,
                    params->p_len) != 0))
#else
    if (!wc_DhCmpNamedKey(group, 1,
            ssl->buffers.serverDH_P.buffer, ssl->buffers.serverDH_P.length,
            ssl->buffers.serverDH_G.buffer, ssl->buffers.serverDH_G.length,
            NULL, 0))
#endif
    {
        WOLFSSL_MSG("Server not using FFDHE parameters");
    #ifdef WOLFSSL_REQUIRE_FFDHE
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_PARAMS_NOT_FFDHE_E, exit_gdpk);
    #endif
    }
    else {
        ssl->namedGroup = group;
        ssl->options.dhDoKeyTest = 0;
    }

exit_gdpk:
    return ret;
}

/* handle processing of server_key_exchange (12) */
static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                               word32* inOutIdx, word32 size)
{
    int ret = 0;
    DskeArgs  args[1];

    (void)input;
    (void)size;

    WOLFSSL_START(WC_FUNC_SERVER_KEY_EXCHANGE_DO);
    WOLFSSL_ENTER("DoServerKeyExchange");

    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(DskeArgs));
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
        args->sigAlgo = ssl->specs.sig_algo;
        args->hashAlgo = sha_mac;
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {

            switch(ssl->specs.kea)
            {
                case diffie_hellman_kea:
                {
                    ret = GetDhPublicKey(ssl, input, size, args);
                    if (ret != 0)
                        goto exit_dske;
                    break;
                }
                case ecc_diffie_hellman_kea:
                {
                    byte b;
                    int curveId;
                    int curveOid;
                    word16 length;

                    if ((args->idx - args->begin) + ENUM_LEN + OPAQUE16_LEN +
                                                        OPAQUE8_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    b = input[args->idx++];
                    if (b != named_curve) {
                        ERROR_OUT(ECC_CURVETYPE_ERROR, exit_dske);
                    }

                    args->idx += 1;   /* curve type, eat leading 0 */
                    b = input[args->idx++];
                    if ((curveOid = CheckCurveId(b)) < 0) {
                        ERROR_OUT(ECC_CURVE_ERROR, exit_dske);
                    }
                    ssl->ecdhCurveOID = curveOid;
                    ssl->namedGroup = 0;

                    length = input[args->idx++];
                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    if (ssl->peerEccKey == NULL) {
                        ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                       (void**)&ssl->peerEccKey);
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    } else if (ssl->peerEccKeyPresent) {
                        ret = ReuseKey(ssl, DYNAMIC_TYPE_ECC, ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    }

                    curveId = wc_ecc_get_oid(curveOid, NULL, NULL);
                    if (wc_ecc_import_x963_ex(input + args->idx, length,
                                        ssl->peerEccKey, curveId) != 0) {
                        ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                    }

                    {
                        ecc_key const* ecc = (ecc_key const*)ssl->peerEccKey;
                        sparky_tls_log(10, "ssl->peerEccKey.pub.x",  ecc->pubkey.x, ecc->dp->size);
                        sparky_tls_log(10, "ssl->peerEccKey.pub.y",  ecc->pubkey.y, ecc->dp->size);
                        sparky_tls_log(10, "ssl->peerEccKey.pub.z",  ecc->pubkey.z, ecc->dp->size);
                    }

                    args->idx += length;
                    ssl->peerEccKeyPresent = 1;
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
                    enum wc_HashType hashType;
                    word16 verifySz;
                    byte sigAlgo;

                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    verifySz = (word16)(args->idx - args->begin);
                    if (verifySz > MAX_DH_SZ) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    if (IsAtLeastTLSv1_2(ssl)) {
                        if ((args->idx - args->begin) + ENUM_LEN + ENUM_LEN >
                                                                        size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dske);
                        }

                        DecodeSigAlg(&input[args->idx], &args->hashAlgo,
                                     &sigAlgo);
                        if (sigAlgo == rsa_pss_sa_algo &&
                                                 args->sigAlgo == rsa_sa_algo) {
                            args->sigAlgo = sigAlgo;
                        }
                        else
                        /* Signature algorithm from message must match signature
                         * algorithm in cipher suite. */
                        if (sigAlgo != args->sigAlgo) {
                            ERROR_OUT(ALGO_ID_E, exit_dske);
                        }
                        args->idx += 2;
                        hashType = HashAlgoToType(args->hashAlgo);
                        if (hashType == WC_HASH_TYPE_NONE) {
                            ERROR_OUT(ALGO_ID_E, exit_dske);
                        }
                    } else {
                        /* only using sha and md5 for rsa */
                            hashType = WC_HASH_TYPE_SHA;
                            if (args->sigAlgo == rsa_sa_algo) {
                                hashType = WC_HASH_TYPE_MD5_SHA;
                            }
                    }

                    /* signature */
                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &args->verifySigSz);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + args->verifySigSz > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* buffer for signature */
                    ssl->buffers.sig.buffer = (byte*)XMALLOC(SEED_LEN + verifySz,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                    if (ssl->buffers.sig.buffer == NULL) {
                        ERROR_OUT(MEMORY_E, exit_dske);
                    }
                    ssl->buffers.sig.length = SEED_LEN + verifySz;

                    /* build message to hash */
                    XMEMCPY(ssl->buffers.sig.buffer,
                        ssl->arrays->clientRandom, RAN_LEN);
                    XMEMCPY(&ssl->buffers.sig.buffer[RAN_LEN],
                        ssl->arrays->serverRandom, RAN_LEN);
                    XMEMCPY(&ssl->buffers.sig.buffer[RAN_LEN * 2],
                        input + args->begin, verifySz); /* message */

                    if (args->sigAlgo != ed25519_sa_algo) {
                        int digest_sz = wc_HashGetDigestSize(hashType);
                        if (digest_sz <= 0) {
                            ERROR_OUT(BUFFER_ERROR, exit_dske);
                        }
                        ssl->buffers.digest.length = (unsigned int)digest_sz;

                        /* buffer for hash */
                        ssl->buffers.digest.buffer = (byte*)XMALLOC(
                            ssl->buffers.digest.length, ssl->heap,
                            DYNAMIC_TYPE_DIGEST);
                        if (ssl->buffers.digest.buffer == NULL) {
                            ERROR_OUT(MEMORY_E, exit_dske);
                        }

                        /* Perform hash */
                        ret = wc_Hash(hashType, ssl->buffers.sig.buffer,
                                                    ssl->buffers.sig.length,
                                                    ssl->buffers.digest.buffer,
                                                    ssl->buffers.digest.length);
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    }

                    switch (args->sigAlgo)
                    {
                        case rsa_sa_algo:
                        {
                            if (ssl->peerRsaKey == NULL ||
                                                    !ssl->peerRsaKeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }
                        case ecc_dsa_sa_algo:
                        {
                            if (!ssl->peerEccDsaKeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }

                    default:
                        ret = ALGO_ID_E;
                    } /* switch (args->sigAlgo) */

                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    if (args->verifySig == NULL) {
                        args->verifySig = (byte*)XMALLOC(args->verifySigSz,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                        if (args->verifySig == NULL) {
                            ERROR_OUT(MEMORY_E, exit_dske);
                        }
                        XMEMCPY(args->verifySig, input + args->idx,
                                                            args->verifySigSz);
                    }

                    switch (args->sigAlgo)
                    {
                        case rsa_sa_algo:
                        {
                            ret = RsaVerify(ssl,
                                args->verifySig, args->verifySigSz,
                                &args->output,
                                args->sigAlgo, args->hashAlgo,
                                ssl->peerRsaKey,
                                NULL
                            );

                            if (ret >= 0) {
                                args->sigSz = (word16)ret;
                                ret = 0;
                            }
                            {
                                /* peerRsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_RSA,
                                                      (void**)&ssl->peerRsaKey);
                                ssl->peerRsaKeyPresent = 0;
                            }
                            break;
                        }
                        case ecc_dsa_sa_algo:
                        {
                            ret = EccVerify(ssl,
                                args->verifySig, args->verifySigSz,
                                ssl->buffers.digest.buffer,
                                ssl->buffers.digest.length,
                                ssl->peerEccDsaKey,
                                NULL
                            );

                            {
                                /* peerEccDsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                   (void**)&ssl->peerEccDsaKey);
                                ssl->peerEccDsaKeyPresent = 0;
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert && (ret == 0);
                            break;
                        }

                    default:
                        ret = ALGO_ID_E;
                    } /* switch (sigAlgo) */
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    /* increment index after verify is done */
                    args->idx += args->verifySigSz;

                    switch(args->sigAlgo)
                    {
                        case rsa_sa_algo:
                        {
                            #if (defined(WOLFSSL_RENESAS_SCEPROTECT) && \
                                defined(WOLFSSL_RENESAS_SCEPROTECT_ECC)) || \
                                defined(WOLFSSL_RENESAS_TSIP_TLS)
                            /* already checked signature result by SCE */
                            /* skip the sign checks below              */
                            if (Renesas_cmn_usable(ssl, 0)) {
                                break;
                             }
                            #endif
                            if (IsAtLeastTLSv1_2(ssl)) {
                                byte   encodedSig[MAX_ENCODED_SIG_SZ];
                                word32 encSigSz;


                                encSigSz = wc_EncodeSignature(encodedSig,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    TypeHash(args->hashAlgo));
                                if (encSigSz != args->sigSz || !args->output ||
                                    XMEMCMP(args->output, encodedSig,
                                            min(encSigSz, MAX_ENCODED_SIG_SZ)) != 0) {
                                    ret = VERIFY_SIGN_ERROR;
                                }
                                if (ret != 0) {
                                    goto exit_dske;
                                }
                            }
                            else if (args->sigSz != FINISHED_SZ ||
                                    !args->output ||
                                    XMEMCMP(args->output,
                                            ssl->buffers.digest.buffer,
                                            FINISHED_SZ) != 0) {
                                ERROR_OUT(VERIFY_SIGN_ERROR, exit_dske);
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert;
                            break;
                        }
                        case ecc_dsa_sa_algo:
                            /* Nothing to do in this algo */
                            break;
                        default:
                            ret = ALGO_ID_E;
                    } /* switch (sigAlgo) */
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            if (IsEncryptionOn(ssl, 0)) {
                args->idx += ssl->keys.padSz;
                if (ssl->options.startedETMRead)
                    args->idx += MacSize(ssl);
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            /* return index */
            *inOutIdx = args->idx;

            ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_dske:

    WOLFSSL_LEAVE("DoServerKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_SERVER_KEY_EXCHANGE_DO);


    /* Final cleanup */
    FreeDskeArgs(ssl, args);
    FreeKeyExchange(ssl);

    return ret;
}

typedef struct SckeArgs {
    byte*  output; /* not allocated */
    byte*  encSecret;
    byte*  input;
    word32 encSz;
    word32 length;
    int    sendSz;
    int    inputSz;
} SckeArgs;

static void FreeSckeArgs(WOLFSSL* ssl, void* pArgs)
{
    SckeArgs* args = (SckeArgs*)pArgs;

    (void)ssl;

    if (args->encSecret) {
        XFREE(args->encSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
        args->encSecret = NULL;
    }
    if (args->input) {
        XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
        args->input = NULL;
    }
}

/* handle generation client_key_exchange (16) */
int SendClientKeyExchange(WOLFSSL* ssl)
{
    int ret = 0;
    SckeArgs  args[1];

    WOLFSSL_START(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);
    WOLFSSL_ENTER("SendClientKeyExchange");


    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(SckeArgs));
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            switch (ssl->specs.kea) {
                case rsa_kea:
                    if (ssl->peerRsaKey == NULL ||
                        ssl->peerRsaKeyPresent == 0) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }
                    break;
                case diffie_hellman_kea:
                    if (ssl->buffers.serverDH_P.buffer == NULL ||
                        ssl->buffers.serverDH_G.buffer == NULL ||
                        ssl->buffers.serverDH_Pub.buffer == NULL) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }
                    break;
                case ecc_diffie_hellman_kea:
                {
                    ecc_key* peerKey;


                    if (ssl->specs.static_ecdh) {
                        /* Note: EccDsa is really fixed Ecc key here */
                        if (!ssl->peerEccDsaKey || !ssl->peerEccDsaKeyPresent) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }
                        peerKey = ssl->peerEccDsaKey;
                    }
                    else {
                        if (!ssl->peerEccKey || !ssl->peerEccKeyPresent) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }
                        peerKey = ssl->peerEccKey;
                    }
                    if (peerKey == NULL) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }

                    /* create ephemeral private key */
                    ssl->hsType = DYNAMIC_TYPE_ECC;
                    ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                    if (ret != 0) {
                        goto exit_scke;
                    }

                    ret = EccMakeKey(ssl, (ecc_key*)ssl->hsKey, peerKey);

                    break;
                }

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            args->encSz = MAX_ENCRYPT_SZ;
            args->encSecret = (byte*)XMALLOC(MAX_ENCRYPT_SZ, ssl->heap,
                                                    DYNAMIC_TYPE_SECRET);
            if (args->encSecret == NULL) {
                ERROR_OUT(MEMORY_E, exit_scke);
            }
            if (ssl->arrays->preMasterSecret == NULL) {
                ssl->arrays->preMasterSz = ENCRYPT_LEN;
                ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN,
                                                ssl->heap, DYNAMIC_TYPE_SECRET);
                if (ssl->arrays->preMasterSecret == NULL) {
                    ERROR_OUT(MEMORY_E, exit_scke);
                }
                XMEMSET(ssl->arrays->preMasterSecret, 0, ENCRYPT_LEN);
            }

            switch(ssl->specs.kea)
            {
                case rsa_kea:
                {
                    {
                        /* build PreMasterSecret with RNG data */
                        ret = wc_RNG_GenerateBlock(ssl->rng,
                            &ssl->arrays->preMasterSecret[VERSION_SZ],
                            SECRET_LEN - VERSION_SZ);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ssl->arrays->preMasterSecret[0] = ssl->chVersion.major;
                        ssl->arrays->preMasterSecret[1] = ssl->chVersion.minor;

                        ssl->arrays->preMasterSz = SECRET_LEN;
                    }
                    break;
                }
                case diffie_hellman_kea:
                {
                    ssl->buffers.sig.length = ENCRYPT_LEN;
                    ssl->buffers.sig.buffer = (byte*)XMALLOC(ENCRYPT_LEN,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                    if (ssl->buffers.sig.buffer == NULL) {
                        ERROR_OUT(MEMORY_E, exit_scke);
                    }

                    ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                    if (ret != 0) {
                        goto exit_scke;
                    }

#if !defined(HAVE_PUBLIC_FFDHE)
                    if (ssl->namedGroup) {
                        ret = wc_DhSetNamedKey(ssl->buffers.serverDH_Key,
                                ssl->namedGroup);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                        ssl->buffers.sig.length =
                            wc_DhGetNamedKeyMinSize(ssl->namedGroup);
                    }
                    else
#endif
                    if (ssl->options.dhDoKeyTest &&
                        !ssl->options.dhKeyTested)
                    {
                        ret = wc_DhSetCheckKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length,
                            NULL, 0, 0, ssl->rng);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                        ssl->options.dhKeyTested = 1;
                    }
                    else
                    {
                        ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                    }

                    /* for DH, encSecret is Yc, agree is pre-master */
                    ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                        ssl->buffers.sig.buffer, (word32*)&ssl->buffers.sig.length,
                        args->encSecret, &args->encSz);

                    /* set the max agree result size */
                    ssl->arrays->preMasterSz = ENCRYPT_LEN;
                    break;
                }
                case ecc_diffie_hellman_kea:
                {
                    ssl->arrays->preMasterSz = ENCRYPT_LEN;


                    /* Place ECC key in buffer, leaving room for size */
                    PRIVATE_KEY_UNLOCK();
                    ret = wc_ecc_export_x963((ecc_key*)ssl->hsKey,
                                args->encSecret + OPAQUE8_LEN, &args->encSz);
                    PRIVATE_KEY_LOCK();
                    sparky_tls_log(11, "args->encSecret", args->encSecret + OPAQUE8_LEN, args->encSz);
                    if (ret != 0) {
                        ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                    }
                    break;
                }

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            switch(ssl->specs.kea)
            {
                case rsa_kea:
                {
                        ret = RsaEnc(ssl,
                            ssl->arrays->preMasterSecret, SECRET_LEN,
                            args->encSecret, &args->encSz,
                            ssl->peerRsaKey,
                            NULL
                        );

                    break;
                }
                case diffie_hellman_kea:
                {
                    ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                        ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                        ssl->buffers.serverDH_Pub.buffer,
                        ssl->buffers.serverDH_Pub.length,
                        ssl->arrays->preMasterSecret,
                        &ssl->arrays->preMasterSz,
                        ssl->buffers.serverDH_P.buffer,
                        ssl->buffers.serverDH_P.length);
                    break;
                }
                case ecc_diffie_hellman_kea:
                {
                    ecc_key* peerKey;

                    peerKey = (ssl->specs.static_ecdh) ?
                              ssl->peerEccDsaKey : ssl->peerEccKey;

                    // Fabio
                    {
                        ecc_key const* srv_dh_kpub = (ecc_key const*)peerKey;
                        (void) srv_dh_kpub;
                        //sparky_tls_log("ssl->peerEccKey.pub.x", srv_dh_kpub->pubkey.x, srv_dh_kpub->dp->size);
                        //sparky_tls_log("ssl->peerEccKey.pub.y", srv_dh_kpub->pubkey.y, srv_dh_kpub->dp->size);
                        //sparky_tls_log("ssl->peerEccKey.pub.z", srv_dh_kpub->pubkey.z, srv_dh_kpub->dp->size);

                        //sparky_tls_log("PMS  pub_key", ssl->peerEccKey, 32);
                        ecc_key const* kpair = ssl->hsKey;
                        (void) kpair;
                        //sparky_tls_log("hsKey->pub.x ", kpair->pubkey.x, kpair->dp->size);
                        //sparky_tls_log("hsKey->pub.y ", kpair->pubkey.y, kpair->dp->size);
                        //sparky_tls_log("hsKey->pub.z ", kpair->pubkey.z, kpair->dp->size);
                        //sparky_tls_log("hsKey->prv.dp", kpair->k.dp,     kpair->dp->size);
                    }


                    ret = EccSharedSecret(ssl,
                        (ecc_key*)ssl->hsKey, peerKey,
                        args->encSecret + OPAQUE8_LEN, &args->encSz,
                        ssl->arrays->preMasterSecret,
                        &ssl->arrays->preMasterSz,
                        WOLFSSL_CLIENT_END
                    );

                    sparky_tls_log(12, "PRE-MASTER SECRET",
                        ssl->arrays->preMasterSecret,
                        ssl->arrays->preMasterSz);

                    if (!ssl->specs.static_ecdh
                     && !ssl->options.keepResources) {
                        FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                      (void**)&ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                    }

                    break;
                }

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            switch(ssl->specs.kea)
            {
                case rsa_kea:
                {
                    break;
                }
                case diffie_hellman_kea:
                {
                    break;
                }
                case ecc_diffie_hellman_kea:
                {
                    /* place size of public key in buffer */
                    *args->encSecret = (byte)args->encSz;
                    args->encSz += OPAQUE8_LEN;
                    break;
                }

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            word32 tlsSz = 0;
            word32 idx = 0;

            if (ssl->options.tls || ssl->specs.kea == diffie_hellman_kea) {
                tlsSz = 2;
            }

            if (ssl->specs.kea == ecc_diffie_hellman_kea ||
                ssl->specs.kea == dhe_psk_kea ||
                ssl->specs.kea == ecdhe_psk_kea) { /* always off */
                tlsSz = 0;
            }

            idx = HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
            args->sendSz = args->encSz + tlsSz + idx;


            if (IsEncryptionOn(ssl, 1)) {
                args->sendSz += MAX_MSG_EXTRA;
            }

            /* check for available size */
            if ((ret = CheckAvailableSize(ssl, args->sendSz)) != 0) {
                goto exit_scke;
            }

            /* get output buffer */
            args->output = ssl->buffers.outputBuffer.buffer +
                           ssl->buffers.outputBuffer.length;

            AddHeaders(args->output, args->encSz + tlsSz, client_key_exchange, ssl);

            if (tlsSz) {
                c16toa((word16)args->encSz, &args->output[idx]);
                idx += OPAQUE16_LEN;
            }
            XMEMCPY(args->output + idx, args->encSecret, args->encSz);
            idx += args->encSz;

            if (IsEncryptionOn(ssl, 1)) {
                int recordHeaderSz = RECORD_HEADER_SZ;

                if (ssl->options.dtls)
                    recordHeaderSz += DTLS_RECORD_EXTRA;
                args->inputSz = idx - recordHeaderSz; /* buildmsg adds rechdr */
                args->input = (byte*)XMALLOC(args->inputSz, ssl->heap,
                                                       DYNAMIC_TYPE_IN_BUFFER);
                if (args->input == NULL) {
                    ERROR_OUT(MEMORY_E, exit_scke);
                }

                XMEMCPY(args->input, args->output + recordHeaderSz,
                                                                args->inputSz);
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            if (IsEncryptionOn(ssl, 1)) {
                ret = BuildMessage(ssl, args->output, args->sendSz,
                            args->input, args->inputSz, handshake, 1, 0, 0, CUR_ORDER);
                XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                args->input = NULL; /* make sure its not double free'd on cleanup */

                if (ret >= 0) {
                    args->sendSz = ret;
                    ret = 0;
                }
            }
            else {
                ret = HashOutput(ssl, args->output, args->sendSz, 0);
            }

            if (ret != 0) {
                goto exit_scke;
            }


            ssl->buffers.outputBuffer.length += args->sendSz;

            if (!ssl->options.groupMessages) {
                ret = SendBuffered(ssl);
            }
            if (ret == 0 || ret == WANT_WRITE) {
                int tmpRet = MakeMasterSecret(ssl);
                if (tmpRet != 0) {
                    ret = tmpRet;   /* save WANT_WRITE unless more serious */
                }
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
            }
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_scke:

    WOLFSSL_LEAVE("SendClientKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);


    // Fabio
    sparky_tls_log(12, "PRE-MASTER SECRET", ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);

    /* No further need for PMS */
    if (ssl->arrays->preMasterSecret != NULL) {
        ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
    }
    ssl->arrays->preMasterSz = 0;

    /* Final cleanup */
    FreeSckeArgs(ssl, args);
    FreeKeyExchange(ssl);

    return ret;
}













    /* returns the WOLFSSL_* version of the curve from the OID sum */
    word16 GetCurveByOID(int oidSum) {
        switch(oidSum) {
    #if ECC_MIN_KEY_SZ <= 224
            case ECC_SECP224R1_OID:
                return WOLFSSL_ECC_SECP224R1;
    #endif
    #if ECC_MIN_KEY_SZ <= 256
            case ECC_SECP256R1_OID:
                return WOLFSSL_ECC_SECP256R1;
    #endif
    #if ECC_MIN_KEY_SZ <= 384
            case ECC_SECP384R1_OID:
                return WOLFSSL_ECC_SECP384R1;
    #endif
    #if ECC_MIN_KEY_SZ <= 521
            case ECC_SECP521R1_OID:
                return WOLFSSL_ECC_SECP521R1;
    #endif
            default:
                WOLFSSL_MSG("Curve OID not compiled in or implemented");
                return 0;
        }
    }






/**
 * Return the max fragment size. This is essentially the maximum
 * fragment_length available.
 * @param ssl         WOLFSSL object containing ciphersuite information.
 * @param maxFragment The amount of space we want to check is available. This
 *                    is only the fragment length WITHOUT the (D)TLS headers.
 * @return            Max fragment size
 */
int wolfSSL_GetMaxFragSize(WOLFSSL* ssl, int maxFragment)
{
    (void) ssl; /* Avoid compiler warnings */

    if (maxFragment > MAX_RECORD_SIZE) {
        maxFragment = MAX_RECORD_SIZE;
    }


    return maxFragment;
}




#undef ERROR_OUT

#endif /* WOLFCRYPT_ONLY */

void sparky_tls_log(int star_no, char const* msg, void const* buf, word32 len)
{
    unsigned char const* cbuf = (unsigned char const*)buf;
    fprintf(stderr, "@@@ %02d \033[1;33;49m %s \033[0m (%u B) ", star_no, msg, len);
    if(!buf)
        fprintf(stderr, "<NULL>");
    else
        for(word32 ii = 0; ii < len; ++ii)
            fprintf(stderr, "%02x", cbuf[ii]);
    fprintf(stderr, "\n");
}

