/* x509.c
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

#if !defined(WOLFSSL_X509_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning x509.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY









#if  defined(KEEP_OUR_CERT)

/* return the next, if any, altname from the peer cert */
WOLFSSL_ABI
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509* cert)
{
    char* ret = NULL;
    WOLFSSL_ENTER("wolfSSL_X509_get_next_altname");

    /* don't have any to work with */
    if (cert == NULL || cert->altNames == NULL)
        return NULL;

    /* already went through them */
    if (cert->altNamesNext == NULL)
        return NULL;

    ret = cert->altNamesNext->name;
#if defined(WOLFSSL_IP_ALT_NAME)
    /* return the IP address as a string */
    if (cert->altNamesNext->type == ASN_IP_TYPE) {
        ret = cert->altNamesNext->ipString;
    }
#endif
    cert->altNamesNext = cert->altNamesNext->next;

    return ret;
}

int wolfSSL_X509_get_signature(WOLFSSL_X509* x509,
                                                unsigned char* buf, int* bufSz)
{
    WOLFSSL_ENTER("wolfSSL_X509_get_signature");
    if (x509 == NULL || bufSz == NULL || (*bufSz < (int)x509->sig.length &&
                buf != NULL))
        return WOLFSSL_FATAL_ERROR;

    if (buf != NULL)
        XMEMCPY(buf, x509->sig.buffer, x509->sig.length);
    *bufSz = x509->sig.length;

    return WOLFSSL_SUCCESS;
}


/* Getter function that copies over the DER public key buffer to "buf" and
    * sets the size in bufSz. If "buf" is NULL then just bufSz is set to needed
    * buffer size. "bufSz" passed in should initially be set by the user to be
    * the size of "buf". This gets checked to make sure the buffer is large
    * enough to hold the public key.
    *
    * Note: this is the X.509 form of key with "header" info.
    * return WOLFSSL_SUCCESS on success
    */
int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509,
                                            unsigned char* buf, int* bufSz)
{
    DecodedCert cert[1];
    word32 idx;
    const byte*  der;
    int length = 0;
    int    ret = 0, derSz = 0;
    int badDate = 0;
    const byte* pubKeyX509 = NULL;
    int   pubKeyX509Sz = 0;

    WOLFSSL_ENTER("wolfSSL_X509_get_pubkey_buffer");
    if (x509 == NULL || bufSz == NULL) {
        WOLFSSL_LEAVE("wolfSSL_X509_get_pubkey_buffer", BAD_FUNC_ARG);
        return WOLFSSL_FATAL_ERROR;
    }



    der = wolfSSL_X509_get_der(x509, &derSz);
    if (der != NULL) {
        InitDecodedCert(cert, der, derSz, NULL);
        ret = wc_GetPubX509(cert, 0, &badDate);
        if (ret >= 0) {
            idx = cert->srcIdx;
            pubKeyX509 = cert->source + cert->srcIdx;
            ret = GetSequence(cert->source, &cert->srcIdx, &length,
                    cert->maxIdx);
            pubKeyX509Sz = length + (cert->srcIdx - idx);
        }
        FreeDecodedCert(cert);
    }

    if (ret < 0) {
        WOLFSSL_LEAVE("wolfSSL_X509_get_pubkey_buffer", ret);
        return WOLFSSL_FATAL_ERROR;
    }

    if (buf != NULL && pubKeyX509 != NULL) {
        if (pubKeyX509Sz > *bufSz) {
            WOLFSSL_LEAVE("wolfSSL_X509_get_pubkey_buffer", BUFFER_E);
            return WOLFSSL_FATAL_ERROR;
        }
        XMEMCPY(buf, pubKeyX509, pubKeyX509Sz);
    }
    *bufSz = pubKeyX509Sz;

    return WOLFSSL_SUCCESS;
}


/* Getter function for the public key OID value
    * return public key OID stored in WOLFSSL_X509 structure */
int wolfSSL_X509_get_pubkey_type(WOLFSSL_X509* x509)
{
    if (x509 == NULL)
        return WOLFSSL_FAILURE;
    return x509->pubKeyOID;
}

#endif /* OPENSSL_EXTRA || KEEP_OUR_CERT || KEEP_PEER_CERT || SESSION_CERTS */

#if  defined(KEEP_OUR_CERT)

/* write X509 serial number in unsigned binary to buffer
    buffer needs to be at least EXTERNAL_SERIAL_SIZE (32) for all cases
    return WOLFSSL_SUCCESS on success */
int wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509,
                                    byte* in, int* inOutSz)
{
    WOLFSSL_ENTER("wolfSSL_X509_get_serial_number");
    if (x509 == NULL || inOutSz == NULL) {
        WOLFSSL_MSG("Null argument passed in");
        return BAD_FUNC_ARG;
    }

    if (in != NULL) {
        if (*inOutSz < x509->serialSz) {
            WOLFSSL_MSG("Serial buffer too small");
            return BUFFER_E;
        }
        XMEMCPY(in, x509->serial, x509->serialSz);
    }
    *inOutSz = x509->serialSz;

    return WOLFSSL_SUCCESS;
}

/* not an openssl compatibility function - getting for derCert */
const byte* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz)
{
    WOLFSSL_ENTER("wolfSSL_X509_get_der");

    if (x509 == NULL || x509->derCert == NULL || outSz == NULL)
        return NULL;

    *outSz = (int)x509->derCert->length;
    return x509->derCert->buffer;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || KEEP_OUR_CERT || KEEP_PEER_CERT || SESSION_CERTS */

#if defined(KEEP_OUR_CERT)

/* used by JSSE (not a standard compatibility function) */
WOLFSSL_ABI
const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509)
{
    WOLFSSL_ENTER("wolfSSL_X509_notBefore");

    if (x509 == NULL)
        return NULL;

    XMEMSET(x509->notBeforeData, 0, sizeof(x509->notBeforeData));
    x509->notBeforeData[0] = (byte)x509->notBefore.type;
    x509->notBeforeData[1] = (byte)x509->notBefore.length;
    XMEMCPY(&x509->notBeforeData[2], x509->notBefore.data, x509->notBefore.length);

    return x509->notBeforeData;
}

/* used by JSSE (not a standard compatibility function) */
WOLFSSL_ABI
const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509)
{
    WOLFSSL_ENTER("wolfSSL_X509_notAfter");

    if (x509 == NULL)
        return NULL;

    XMEMSET(x509->notAfterData, 0, sizeof(x509->notAfterData));
    x509->notAfterData[0] = (byte)x509->notAfter.type;
    x509->notAfterData[1] = (byte)x509->notAfter.length;
    XMEMCPY(&x509->notAfterData[2], x509->notAfter.data, x509->notAfter.length);

    return x509->notAfterData;
}

int wolfSSL_X509_version(WOLFSSL_X509* x509)
{
    WOLFSSL_ENTER("wolfSSL_X509_version");

    if (x509 == NULL)
        return 0;

    return x509->version;
}
#endif


/* require OPENSSL_EXTRA since wolfSSL_X509_free is wrapped by OPENSSL_EXTRA */
































#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL)
#ifndef NO_BIO

#ifdef WOLFSSL_CERT_GEN

#ifdef WOLFSSL_CERT_REQ
/* writes the x509 from x to the WOLFSSL_BIO bp
 *
 * returns WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on fail
 */
int wolfSSL_PEM_write_bio_X509_REQ(WOLFSSL_BIO *bp, WOLFSSL_X509 *x)
{
    byte* pem;
    int   pemSz = 0;
    const unsigned char* der;
    int derSz;
    int ret;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_X509_REQ()");

    if (x == NULL || bp == NULL) {
        return WOLFSSL_FAILURE;
    }

    der = wolfSSL_X509_get_der(x, &derSz);
    if (der == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* get PEM size */
    pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, CERTREQ_TYPE);
    if (pemSz < 0) {
        return WOLFSSL_FAILURE;
    }

    /* create PEM buffer and convert from DER */
    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (wc_DerToPemEx(der, derSz, pem, pemSz, NULL, CERTREQ_TYPE) < 0) {
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* write the PEM to BIO */
    ret = wolfSSL_BIO_write(bp, pem, pemSz);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret <= 0) return WOLFSSL_FAILURE;
    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_CERT_REQ */


/* writes the x509 from x to the WOLFSSL_BIO bp
 *
 * returns WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on fail
 */
int wolfSSL_PEM_write_bio_X509_AUX(WOLFSSL_BIO *bp, WOLFSSL_X509 *x)
{
    byte* pem;
    int   pemSz = 0;
    const unsigned char* der;
    int derSz;
    int ret;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_X509_AUX()");

    if (bp == NULL || x == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return WOLFSSL_FAILURE;
    }

    der = wolfSSL_X509_get_der(x, &derSz);
    if (der == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* get PEM size */
    pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, CERT_TYPE);
    if (pemSz < 0) {
        return WOLFSSL_FAILURE;
    }

    /* create PEM buffer and convert from DER */
    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (wc_DerToPemEx(der, derSz, pem, pemSz, NULL, CERT_TYPE) < 0) {
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* write the PEM to BIO */
    ret = wolfSSL_BIO_write(bp, pem, pemSz);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret <= 0) return WOLFSSL_FAILURE;
    return WOLFSSL_SUCCESS;
}

int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bio, WOLFSSL_X509 *cert)
{
    byte* pem = NULL;
    int   pemSz = 0;
    /* Get large buffer to hold cert der */
    int derSz = X509_BUFFER_SZ;
    byte der[X509_BUFFER_SZ];
    int ret;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_X509()");

    if (bio == NULL || cert == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return WOLFSSL_FAILURE;
    }


    if (wolfssl_x509_make_der(cert, 0, der, &derSz, 1) != WOLFSSL_SUCCESS) {
        goto error;
    }

    /* get PEM size */
    pemSz = wc_DerToPemEx(der, derSz, NULL, 0, NULL, CERT_TYPE);
    if (pemSz < 0) {
        goto error;
    }

    /* create PEM buffer and convert from DER */
    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        goto error;
    }
    if (wc_DerToPemEx(der, derSz, pem, pemSz, NULL, CERT_TYPE) < 0) {
        goto error;
    }

    /* write the PEM to BIO */
    ret = wolfSSL_BIO_write(bio, pem, pemSz);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret <= 0) return WOLFSSL_FAILURE;
    return WOLFSSL_SUCCESS;

error:
    if (pem)
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFSSL_FAILURE;
}
#endif /* WOLFSSL_CERT_GEN */

#endif /* !NO_BIO */
#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE */

#if defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) ||  defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) ||  defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)

WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_sk_X509_NAME_new(wolf_sk_compare_cb cb)
{
    WOLFSSL_STACK* sk;
    (void)cb;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_new");

    sk = wolfSSL_sk_new_node(NULL);
    if (sk != NULL) {
        sk->type = STACK_TYPE_X509_NAME;
    }

    return sk;
}

int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_num");

    if (sk == NULL)
        return BAD_FUNC_ARG;

    return (int)sk->num;
}

/* Getter function for WOLFSSL_X509_NAME pointer
 *
 * sk is the stack to retrieve pointer from
 * i  is the index value in stack
 *
 * returns a pointer to a WOLFSSL_X509_NAME structure on success and NULL on
 *         fail
 */
WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(const STACK_OF(WOLFSSL_X509_NAME)* sk,
    int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_value");
    return (WOLFSSL_X509_NAME*)wolfSSL_sk_value(sk, i);
}

WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_X509_NAME* name;

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    name = sk->data.name;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.name = node->data.name;
        sk->next = node->next;
        XFREE(node, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    else { /* last x509 in stack */
        sk->data.name = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return name;
}

void wolfSSL_sk_X509_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    void (*f) (WOLFSSL_X509_NAME*))
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_pop_free");
    wolfSSL_sk_pop_free(sk, (wolfSSL_sk_freefunc)f);
}

/* Free only the sk structure, NOT X509_NAME members */
void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_free");
    wolfSSL_sk_free(sk);
}

int wolfSSL_sk_X509_NAME_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    WOLFSSL_X509_NAME* name)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_push");

    return wolfSSL_sk_push(sk, name);
}

/* return index of found, or negative to indicate not found */
int wolfSSL_sk_X509_NAME_find(const WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk,
    WOLFSSL_X509_NAME *name)
{
    int i;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_find");

    if (sk == NULL)
        return BAD_FUNC_ARG;

    for (i = 0; sk; i++, sk = sk->next) {
        if (wolfSSL_X509_NAME_cmp(sk->data.name, name) == 0) {
            return i;
        }
    }
    return -1;
}

/* Name Entry */
WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* wolfSSL_sk_X509_NAME_ENTRY_new(
    wolf_sk_compare_cb cb)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);
    if (sk != NULL) {
        sk->type = STACK_TYPE_X509_NAME_ENTRY;
        (void)cb;
    }
    return sk;
}

int wolfSSL_sk_X509_NAME_ENTRY_push(WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk,
    WOLFSSL_X509_NAME_ENTRY* name_entry)
{
    return wolfSSL_sk_push(sk, name_entry);
}

WOLFSSL_X509_NAME_ENTRY* wolfSSL_sk_X509_NAME_ENTRY_value(
    const WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk, int i)
{
    return (WOLFSSL_X509_NAME_ENTRY*)wolfSSL_sk_value(sk, i);
}

int wolfSSL_sk_X509_NAME_ENTRY_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk)
{
    if (sk == NULL)
        return BAD_FUNC_ARG;
    return (int)sk->num;
}

void wolfSSL_sk_X509_NAME_ENTRY_free(WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk)
{
    wolfSSL_sk_free(sk);
}

#endif /* OPENSSL_EXTRA || HAVE_STUNNEL || WOLFSSL_NGINX ||
            HAVE_LIGHTY || WOLFSSL_HAPROXY ||
            WOLFSSL_OPENSSH || HAVE_SBLIM_SFCB */




#if defined(HAVE_EX_DATA) && ( defined(WOLFSSL_NGINX)  || defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY))

int wolfSSL_X509_get_ex_new_index(int idx, void *arg, void *a, void *b, void *c)
{

    WOLFSSL_ENTER("wolfSSL_X509_get_ex_new_index");
    (void)idx;
    (void)arg;
    (void)a;
    (void)b;
    (void)c;

    return wolfssl_get_ex_new_index(CRYPTO_EX_INDEX_X509);
}
#endif



#ifndef NO_ASN
int wolfSSL_X509_check_host(WOLFSSL_X509 *x, const char *chk, size_t chklen,
                    unsigned int flags, char **peername)
{
    int         ret;
    DecodedCert dCert;

    WOLFSSL_ENTER("wolfSSL_X509_check_host");

    /* flags and peername not needed for Nginx. */
    (void)flags;
    (void)peername;

    if ((x == NULL) || (chk == NULL)) {
        WOLFSSL_MSG("Invalid parameter");
        return WOLFSSL_FAILURE;
    }

    if (flags == WOLFSSL_NO_WILDCARDS) {
        WOLFSSL_MSG("X509_CHECK_FLAG_NO_WILDCARDS not yet implemented");
        return WOLFSSL_FAILURE;
    }
    if (flags == WOLFSSL_NO_PARTIAL_WILDCARDS) {
        WOLFSSL_MSG("X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS not yet implemented");
        return WOLFSSL_FAILURE;
    }

    InitDecodedCert(&dCert, x->derCert->buffer, x->derCert->length, NULL);
    ret = ParseCertRelative(&dCert, CERT_TYPE, 0, NULL);
    if (ret != 0) {
        FreeDecodedCert(&dCert);
        return WOLFSSL_FAILURE;
    }

    ret = CheckHostName(&dCert, (char *)chk, chklen);
    FreeDecodedCert(&dCert);
    if (ret != 0)
        return WOLFSSL_FAILURE;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_X509_check_ip_asc(WOLFSSL_X509 *x, const char *ipasc,
        unsigned int flags)
{
    int ret = WOLFSSL_FAILURE;
    DecodedCert dCert;

    WOLFSSL_ENTER("wolfSSL_X509_check_ip_asc");

    /* flags not yet implemented */
    (void)flags;

    if ((x == NULL) || (x->derCert == NULL) || (ipasc == NULL)) {
        WOLFSSL_MSG("Invalid parameter");
    }
    else {
        ret = WOLFSSL_SUCCESS;
    }

    if (ret == WOLFSSL_SUCCESS) {
        InitDecodedCert(&dCert, x->derCert->buffer, x->derCert->length, NULL);
        ret = ParseCertRelative(&dCert, CERT_TYPE, 0, NULL);
        if (ret != 0) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = CheckIPAddr(&dCert, ipasc);
            if (ret != 0) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                ret = WOLFSSL_SUCCESS;
            }
        }
        FreeDecodedCert(&dCert);
    }

    return ret;
}
#endif


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_LIGHTY)

int wolfSSL_X509_NAME_digest(const WOLFSSL_X509_NAME *name,
        const WOLFSSL_EVP_MD *type, unsigned char *md, unsigned int *len)
{
    WOLFSSL_ENTER("wolfSSL_X509_NAME_digest");

    if (name == NULL || type == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_FILESYSTEM) && !defined(NO_PWDBASED)
    return wolfSSL_EVP_Digest((unsigned char*)name->name,
                              name->sz, md, len, type, NULL);
#else
    (void)md;
    (void)len;
    return NOT_COMPILED_IN;
#endif
}

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

/**
 * Find the issuing cert of the input cert. On a self-signed cert this
 * function will return an error.
 * @param issuer The issuer x509 struct is returned here
 * @param cm     The cert manager that is queried for the issuer
 * @param x      This cert's issuer will be queried in cm
 * @return       WOLFSSL_SUCCESS on success
 *               WOLFSSL_FAILURE on error
 */
static int x509GetIssuerFromCM(WOLFSSL_X509 **issuer, WOLFSSL_CERT_MANAGER* cm,
        WOLFSSL_X509 *x)
{
    Signer* ca = NULL;
    DecodedCert  cert[1];

    if (cm == NULL || x == NULL || x->derCert == NULL) {
        WOLFSSL_MSG("No cert DER buffer or NULL cm. Defining "
                    "WOLFSSL_SIGNER_DER_CERT could solve the issue");
        return WOLFSSL_FAILURE;
    }


    /* Use existing CA retrieval APIs that use DecodedCert. */
    InitDecodedCert(cert, x->derCert->buffer, x->derCert->length, NULL);
    if (ParseCertRelative(cert, CERT_TYPE, 0, NULL) == 0
            && !cert->selfSigned) {
    #ifndef NO_SKID
        if (cert->extAuthKeyIdSet)
            ca = GetCA(cm, cert->extAuthKeyId);
        if (ca == NULL)
            ca = GetCAByName(cm, cert->issuerHash);
    #else /* NO_SKID */
        ca = GetCA(cm, cert->issuerHash);
    #endif /* NO SKID */
    }
    FreeDecodedCert(cert);

    if (ca == NULL)
        return WOLFSSL_FAILURE;

#ifdef WOLFSSL_SIGNER_DER_CERT
    /* populate issuer with Signer DER */
    if (wolfSSL_X509_d2i(issuer, ca->derCert->buffer,
            ca->derCert->length) == NULL)
        return WOLFSSL_FAILURE;
#else
    /* Create an empty certificate as CA doesn't have a certificate. */
    *issuer = (WOLFSSL_X509 *)XMALLOC(sizeof(WOLFSSL_X509), 0,
        DYNAMIC_TYPE_OPENSSL);
    if (*issuer == NULL)
        return WOLFSSL_FAILURE;

    InitX509((*issuer), 1, NULL);
#endif

    return WOLFSSL_SUCCESS;
}

void wolfSSL_X509_email_free(WOLF_STACK_OF(WOLFSSL_STRING) *sk)
{
    WOLFSSL_STACK *curr;

    while (sk != NULL) {
        curr = sk;
        sk = sk->next;

        XFREE(curr, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

WOLF_STACK_OF(WOLFSSL_STRING) *wolfSSL_X509_get1_ocsp(WOLFSSL_X509 *x)
{
    WOLFSSL_STACK* list = NULL;
    char*          url;

    if (x == NULL || x->authInfoSz == 0)
        return NULL;

    list = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK) + x->authInfoSz + 1,
                                   NULL, DYNAMIC_TYPE_OPENSSL);
    if (list == NULL)
        return NULL;

    url = (char*)list;
    url += sizeof(WOLFSSL_STACK);
    XMEMCPY(url, x->authInfo, x->authInfoSz);
    url[x->authInfoSz] = '\0';

    list->data.string = url;
    list->next = NULL;

    return list;
}

int wolfSSL_X509_check_issued(WOLFSSL_X509 *issuer, WOLFSSL_X509 *subject)
{
    WOLFSSL_X509_NAME *issuerName = wolfSSL_X509_get_issuer_name(subject);
    WOLFSSL_X509_NAME *subjectName = wolfSSL_X509_get_subject_name(issuer);

    if (issuerName == NULL || subjectName == NULL)
        return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;

    /* Literal matching of encoded names and key ids. */
    if (issuerName->sz != subjectName->sz ||
           XMEMCMP(issuerName->name, subjectName->name, subjectName->sz) != 0) {
        return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
    }

    if (subject->authKeyId != NULL && issuer->subjKeyId != NULL) {
        if (subject->authKeyIdSz != issuer->subjKeyIdSz ||
                XMEMCMP(subject->authKeyId, issuer->subjKeyId,
                        issuer->subjKeyIdSz) != 0) {
            return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
        }
    }

    return X509_V_OK;
}

#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */











#endif /* !WOLFCRYPT_ONLY */

#endif /* WOLFSSL_X509_INCLUDED */
