/* pk.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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


#if !defined(WOLFSSL_PK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning pk.c does not need to be compiled separately from ssl.c
    #endif
#else

    #include <wolfssl/wolfcrypt/rsa.h>

/*******************************************************************************
 * COMMON FUNCTIONS
 ******************************************************************************/


/*******************************************************************************
 * START OF RSA API
 ******************************************************************************/





#if defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY)  || defined(WOLFSSL_NGINX)

#ifndef NO_BIO

#if !defined(HAVE_FAST_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_USER_RSA)
/* Converts an rsa key from a bio buffer into an internal rsa structure.
Returns a pointer to the new WOLFSSL_RSA structure. */
WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO *bio, WOLFSSL_RSA **out)
{
    const unsigned char* bioMem = NULL;
    int bioMemSz = 0;
    WOLFSSL_RSA* key = NULL;
    unsigned char *maxKeyBuf = NULL;
    unsigned char* bufPtr = NULL;
    unsigned char* extraBioMem = NULL;
    int extraBioMemSz = 0;
    int derLength = 0;
    int j = 0, i = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPrivateKey_bio()");

    if (bio == NULL) {
        WOLFSSL_MSG("Bad Function Argument");
        return NULL;
    }
    (void)out;

    bioMemSz = wolfSSL_BIO_get_len(bio);
    if (bioMemSz <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_get_len() failure");
        return NULL;
    }

    bioMem = (unsigned char*)XMALLOC(bioMemSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (bioMem == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return NULL;
    }

    maxKeyBuf = (unsigned char*)XMALLOC(4096, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (maxKeyBuf == NULL) {
        WOLFSSL_MSG("Malloc failure");
        XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    bufPtr = maxKeyBuf;
    if (wolfSSL_BIO_read(bio, (unsigned char*)bioMem, (int)bioMemSz) == bioMemSz) {
        const byte* bioMemPt = bioMem; /* leave bioMem pointer unaltered */
        if ((key = wolfSSL_d2i_RSAPrivateKey(NULL, &bioMemPt, bioMemSz)) == NULL) {
            XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* This function is used to get the total length of the rsa key. */
        derLength = wolfSSL_i2d_RSAPrivateKey(key, &bufPtr);

        /* Write extra data back into bio object if necessary. */
        extraBioMemSz = (bioMemSz - derLength);
        if (extraBioMemSz > 0) {
            extraBioMem = (unsigned char *)XMALLOC(extraBioMemSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (extraBioMem == NULL) {
                WOLFSSL_MSG("Malloc failure");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)bioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }

            for (i = derLength; i < bioMemSz; i++) {
                *(extraBioMem + j) = *(bioMem + i);
                j++;
            }

            wolfSSL_BIO_write(bio, extraBioMem, extraBioMemSz);
            if (wolfSSL_BIO_get_len(bio) <= 0) {
                WOLFSSL_MSG("Failed to write memory to bio");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)bioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
            XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        }

        if (out != NULL && key != NULL) {
            *out = key;
        }
    }
    XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* !HAVE_FAST_RSA && WOLFSSL_KEY_GEN && !HAVE_USER_RSA */

#endif /* !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */





/*******************************************************************************
 * END OF RSA API
 ******************************************************************************/


/*******************************************************************************
 * START OF DSA API
 ******************************************************************************/


/*******************************************************************************
 * END OF DSA API
 ******************************************************************************/


/*******************************************************************************
 * START OF DH API
 ******************************************************************************/



#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL)

#ifndef NO_BIO
WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bio, WOLFSSL_DH **x,
        wc_pem_password_cb *cb, void *u)
{
#ifndef NO_FILESYSTEM
    WOLFSSL_DH* localDh = NULL;
    unsigned char* mem  = NULL;
    word32 size;
    long   sz;
    int    ret;
    DerBuffer *der = NULL;
    byte*  p = NULL;
    byte*  g = NULL;
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;
    int    memAlloced = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DHparams");
    (void)cb;
    (void)u;

    if (bio == NULL) {
        WOLFSSL_MSG("Bad Function Argument bio is NULL");
        return NULL;
    }

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        /* Use the buffer directly. */
        ret = wolfSSL_BIO_get_mem_data(bio, &mem);
        if (mem == NULL || ret <= 0) {
            WOLFSSL_MSG("Failed to get data from bio struct");
            goto end;
        }
        size = ret;
    }
    else if (bio->type == WOLFSSL_BIO_FILE) {
        /* Read whole file into a new buffer. */
        if (XFSEEK((XFILE)bio->ptr, 0, SEEK_END) != 0)
            goto end;
        sz = XFTELL((XFILE)bio->ptr);
        if (XFSEEK((XFILE)bio->ptr, 0, SEEK_SET) != 0)
            goto end;
        if (sz > MAX_WOLFSSL_FILE_SIZE || sz <= 0L) {
            WOLFSSL_MSG("PEM_read_bio_DHparams file size error");
            goto end;
        }
        mem = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_PEM);
        if (mem == NULL)
            goto end;
        memAlloced = 1;

        if (wolfSSL_BIO_read(bio, (char *)mem, (int)sz) <= 0)
            goto end;
        size = (word32)sz;
    }
    else {
        WOLFSSL_MSG("BIO type not supported for reading DH parameters");
        goto end;
    }

    ret = PemToDer(mem, size, DH_PARAM_TYPE, &der, NULL, NULL, NULL);
    if (ret < 0) {
        /* Also try X9.42 format */
        ret = PemToDer(mem, size, X942_PARAM_TYPE, &der, NULL, NULL, NULL);
    }
    if (ret != 0)
        goto end;

    /* Use the object passed in, otherwise allocate a new object */
    if (x != NULL)
        localDh = *x;
    if (localDh == NULL) {
        localDh = wolfSSL_DH_new();
        if (localDh == NULL)
            goto end;
    }

    /* Load data in manually */
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (p == NULL || g == NULL)
        goto end;
    /* Extract the p and g as data from the DER encoded DH parameters. */
    ret = wc_DhParamsLoad(der->buffer, der->length, p, &pSz, g, &gSz);
    if (ret != 0) {
        if (x != NULL && localDh != *x)
            XFREE(localDh, NULL, DYNAMIC_TYPE_OPENSSL);
        localDh = NULL;
        goto end;
    }

    if (x != NULL)
        *x = localDh;

    /* Put p and g in as big numbers. */
    if (localDh->p != NULL) {
        wolfSSL_BN_free(localDh->p);
        localDh->p = NULL;
    }
    if (localDh->g != NULL) {
        wolfSSL_BN_free(localDh->g);
        localDh->g = NULL;
    }
    localDh->p = wolfSSL_BN_bin2bn(p, pSz, NULL);
    localDh->g = wolfSSL_BN_bin2bn(g, gSz, NULL);
    if (localDh->p == NULL || localDh->g == NULL) {
        if (x != NULL && localDh != *x)
            wolfSSL_DH_free(localDh);
        localDh = NULL;
    }

    if (localDh != NULL && localDh->inSet == 0) {
        if (SetDhInternal(localDh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Unable to set internal DH structure");
            wolfSSL_DH_free(localDh);
            localDh = NULL;
        }
    }

end:
    if (memAlloced) XFREE(mem, NULL, DYNAMIC_TYPE_PEM);
    if (der != NULL) FreeDer(&der);
    XFREE(p, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(g, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    return localDh;
#else
    (void)bio;
    (void)x;
    (void)cb;
    (void)u;
    return NULL;
#endif
}

#ifndef NO_FILESYSTEM
/* Reads DH parameters from a file pointer into WOLFSSL_DH structure.
 *
 * fp  file pointer to read DH parameter file from
 * x   output WOLFSSL_DH to be created and populated from fp
 * cb  password callback, to be used to decrypt encrypted DH parameters PEM
 * u   context pointer to user-defined data to be received back in password cb
 *
 * Returns new WOLFSSL_DH structure pointer on success, NULL on failure. */
WOLFSSL_DH *wolfSSL_PEM_read_DHparams(XFILE fp, WOLFSSL_DH **x,
        wc_pem_password_cb *cb, void *u)
{
    WOLFSSL_BIO* fbio = NULL;
    WOLFSSL_DH* dh = NULL;

    if (fp == NULL) {
        WOLFSSL_MSG("DH parameter file cannot be NULL");
        return NULL;
    }

    fbio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (fbio == NULL) {
        WOLFSSL_MSG("Unable to create file BIO to process DH PEM");
        return NULL;
    }

    if (wolfSSL_BIO_set_fp(fbio, fp, BIO_NOCLOSE) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(fbio);
        WOLFSSL_MSG("wolfSSL_BIO_set_fp error");
        return NULL;
    }

    /* wolfSSL_PEM_read_bio_DHparams() sanitizes x, cb, u args */
    dh = wolfSSL_PEM_read_bio_DHparams(fbio, x, cb, u);
    wolfSSL_BIO_free(fbio);
    return dh;
}
#endif /* !NO_FILESYSTEM */

#endif /* !NO_BIO */

#if defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
/* Writes the DH parameters in PEM format from "dh" out to the file pointer
 * passed in.
 *
 * returns WOLFSSL_SUCCESS on success
 */
int wolfSSL_PEM_write_DHparams(XFILE fp, WOLFSSL_DH* dh)
{
    int ret;
    word32 derSz = 0, pemSz = 0;
    byte *der, *pem;
    DhKey* key;

    WOLFSSL_ENTER("wolfSSL_PEM_write_DHparams");

    if (dh == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    if (dh->inSet == 0) {
        if (SetDhInternal(dh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Unable to set internal DH structure");
            return WOLFSSL_FAILURE;
        }
    }
    key = (DhKey*)dh->internal;
    ret = wc_DhParamsToDer(key, NULL, &derSz);
    if (ret != LENGTH_ONLY_E) {
        WOLFSSL_MSG("Failed to get size of DH params");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        return WOLFSSL_FAILURE;
    }

    der = (byte*)XMALLOC(derSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", MEMORY_E);
        return WOLFSSL_FAILURE;
    }
    ret = wc_DhParamsToDer(key, der, &derSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Failed to export DH params");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* convert to PEM */
    ret = wc_DerToPem(der, derSz, NULL, 0, DH_PARAM_TYPE);
    if (ret < 0) {
        WOLFSSL_MSG("Failed to convert DH params to PEM");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    pemSz = (word32)ret;

    pem = (byte*)XMALLOC(pemSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", MEMORY_E);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    ret = wc_DerToPem(der, derSz, pem, pemSz, DH_PARAM_TYPE);
    XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret < 0) {
        WOLFSSL_MSG("Failed to convert DH params to PEM");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(pem, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = (int)XFWRITE(pem, 1, pemSz, fp);
    XFREE(pem, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret <= 0) {
        WOLFSSL_MSG("Failed to write to file");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        return WOLFSSL_FAILURE;
    }
    WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_DH_EXTRA && !NO_FILESYSTEM */

#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE ||
        * OPENSSL_EXTRA */




/*******************************************************************************
 * END OF DH API
 ******************************************************************************/


/*******************************************************************************
 * START OF EC API
 ******************************************************************************/








/*******************************************************************************
 * END OF EC API
 ******************************************************************************/

#endif /* !WOLFSSL_PK_INCLUDED */

