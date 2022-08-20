/* keys.c
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


/* Name change compatibility layer no longer needs to be included here */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
    #ifndef NO_STDIO_FILESYSTEM
        #include <stdio.h>
    #endif

#if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

int SetCipherSpecs(WOLFSSL* ssl)
{
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        /* server side verified before SetCipherSpecs call */
        if (VerifyClientSuite(ssl) != 1) {
            WOLFSSL_MSG("SetCipherSpecs() client has an unusable suite");
            return UNSUPPORTED_SUITE;
        }
    }

    /* Chacha extensions, 0xcc */
    if (ssl->options.cipherSuite0 == CHACHA_BYTE) {

    switch (ssl->options.cipherSuite) {







    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs ChaCha");
        return UNSUPPORTED_SUITE;
    }
    }

    /* ECC extensions, AES-CCM or TLS 1.3 Integrity-only */
    if (ssl->options.cipherSuite0 == ECC_BYTE) {

    switch (ssl->options.cipherSuite) {




    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
        ssl->specs.bulk_cipher_algorithm = wolfssl_aes;
        ssl->specs.cipher_type           = block;
        ssl->specs.mac_algorithm         = sha_mac;
        ssl->specs.kea                   = ecc_diffie_hellman_kea;
        ssl->specs.sig_algo              = rsa_sa_algo;
        ssl->specs.hash_size             = WC_SHA_DIGEST_SIZE;
        ssl->specs.pad_size              = PAD_SHA;
        ssl->specs.static_ecdh           = 0;
        ssl->specs.key_size              = AES_128_KEY_SIZE;
        ssl->specs.block_size            = AES_BLOCK_SIZE;
        ssl->specs.iv_size               = AES_IV_SIZE;

        break;




    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
        ssl->specs.bulk_cipher_algorithm = wolfssl_aes_gcm;
        ssl->specs.cipher_type           = aead;
        ssl->specs.mac_algorithm         = sha256_mac;
        ssl->specs.kea                   = ecc_diffie_hellman_kea;
        ssl->specs.sig_algo              = rsa_sa_algo;
        ssl->specs.hash_size             = WC_SHA256_DIGEST_SIZE;
        ssl->specs.pad_size              = PAD_SHA;
        ssl->specs.static_ecdh           = 0;
        ssl->specs.key_size              = AES_128_KEY_SIZE;
        ssl->specs.block_size            = AES_BLOCK_SIZE;
        ssl->specs.iv_size               = AESGCM_IMP_IV_SZ;
        ssl->specs.aead_mac_size         = AES_GCM_AUTH_SZ;

        break;














































    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs ECC");
        return UNSUPPORTED_SUITE;
    }   /* switch */
    }   /* if     */

    /* TLSi v1.3 cipher suites, 0x13 */
    if (ssl->options.cipherSuite0 == TLS13_BYTE) {
        switch (ssl->options.cipherSuite) {

        default:
            break;
        }
    }

    if (ssl->options.cipherSuite0 != ECC_BYTE &&
            ssl->options.cipherSuite0 != CHACHA_BYTE &&
            ssl->options.cipherSuite0 != TLS13_BYTE) {   /* normal suites */
    switch (ssl->options.cipherSuite) {


#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    case SSL_RSA_WITH_RC4_128_MD5 :
        ssl->specs.bulk_cipher_algorithm = wolfssl_rc4;
        ssl->specs.cipher_type           = stream;
        ssl->specs.mac_algorithm         = md5_mac;
        ssl->specs.kea                   = rsa_kea;
        ssl->specs.sig_algo              = rsa_sa_algo;
        ssl->specs.hash_size             = WC_MD5_DIGEST_SIZE;
        ssl->specs.pad_size              = PAD_MD5;
        ssl->specs.static_ecdh           = 0;
        ssl->specs.key_size              = RC4_KEY_SIZE;
        ssl->specs.iv_size               = 0;
        ssl->specs.block_size            = 0;

        break;
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
        ssl->specs.bulk_cipher_algorithm = wolfssl_triple_des;
        ssl->specs.cipher_type           = block;
        ssl->specs.mac_algorithm         = sha_mac;
        ssl->specs.kea                   = rsa_kea;
        ssl->specs.sig_algo              = rsa_sa_algo;
        ssl->specs.hash_size             = WC_SHA_DIGEST_SIZE;
        ssl->specs.pad_size              = PAD_SHA;
        ssl->specs.static_ecdh           = 0;
        ssl->specs.key_size              = DES3_KEY_SIZE;
        ssl->specs.block_size            = DES_BLOCK_SIZE;
        ssl->specs.iv_size               = DES_IV_SIZE;

        break;
#endif










































#ifdef BUILD_WDM_WITH_NULL_SHA256
        case WDM_WITH_NULL_SHA256 :
            ssl->specs.bulk_cipher_algorithm = wolfssl_cipher_null;
            ssl->specs.cipher_type           = stream;
            ssl->specs.mac_algorithm         = sha256_mac;
            ssl->specs.kea                   = no_kea;
            ssl->specs.sig_algo              = anonymous_sa_algo;
            ssl->specs.hash_size             = WC_SHA256_DIGEST_SIZE;
            ssl->specs.pad_size              = PAD_SHA;

            break;
#endif

    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs");
        return UNSUPPORTED_SUITE;
    }  /* switch */
    }  /* if ECC / Normal suites else */

    /* set TLS if it hasn't been turned off */
    if (ssl->version.major == SSLv3_MAJOR &&
            ssl->version.minor >= TLSv1_MINOR) {
        ssl->options.tls = 1;
        #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
            !defined(WOLFSSL_RENESAS_TSIP_TLS)
        ssl->hmac = TLS_hmac;
        #else
        ssl->hmac = Renesas_cmn_TLS_hmac;
        #endif
        if (ssl->version.minor >= TLSv1_1_MINOR) {
            ssl->options.tls1_1 = 1;
            if (ssl->version.minor >= TLSv1_3_MINOR)
                ssl->options.tls1_3 = 1;
        }
    }

    if (IsAtLeastTLSv1_3(ssl->version) || ssl->specs.cipher_type != block)
       ssl->options.encThenMac = 0;


    if (ssl->specs.sig_algo == anonymous_sa_algo) {
        /* CLIENT/SERVER: No peer authentication to be performed. */
        ssl->options.peerAuthGood = 1;
    }

    return 0;
}


enum KeyStuff {
    MASTER_ROUNDS = 3,
    PREFIX        = 3,     /* up to three letters for master prefix */
    KEY_PREFIX    = 9      /* up to 9 prefix letters for key rounds */


};

/* true or false, zero for error */
static int SetPrefix(byte* sha_input, int idx)
{
    switch (idx) {
    case 0:
        XMEMCPY(sha_input, "A", 1);
        break;
    case 1:
        XMEMCPY(sha_input, "BB", 2);
        break;
    case 2:
        XMEMCPY(sha_input, "CCC", 3);
        break;
    case 3:
        XMEMCPY(sha_input, "DDDD", 4);
        break;
    case 4:
        XMEMCPY(sha_input, "EEEEE", 5);
        break;
    case 5:
        XMEMCPY(sha_input, "FFFFFF", 6);
        break;
    case 6:
        XMEMCPY(sha_input, "GGGGGGG", 7);
        break;
    case 7:
        XMEMCPY(sha_input, "HHHHHHHH", 8);
        break;
    case 8:
        XMEMCPY(sha_input, "IIIIIIIII", 9);
        break;
    default:
        WOLFSSL_MSG("Set Prefix error, bad input");
        return 0;
    }
    return 1;
}


static int SetKeys(Ciphers* enc, Ciphers* dec, Keys* keys, CipherSpecs* specs,
                   int side, void* heap, int devId, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;





    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 16) /* AES_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for AES
    #endif

    if (specs->bulk_cipher_algorithm == wolfssl_aes) {
        int aesRet = 0;

        if (enc) {
            if (enc->aes == NULL) {
                enc->aes = (Aes*)XMALLOC(sizeof(Aes), heap, DYNAMIC_TYPE_CIPHER);
                if (enc->aes == NULL)
                    return MEMORY_E;
            } else {
                wc_AesFree(enc->aes);
            }

            XMEMSET(enc->aes, 0, sizeof(Aes));
        }
        if (dec) {
            if (dec->aes == NULL) {
                dec->aes = (Aes*)XMALLOC(sizeof(Aes), heap, DYNAMIC_TYPE_CIPHER);
                if (dec->aes == NULL)
                    return MEMORY_E;
            } else {
                wc_AesFree(dec->aes);
            }

            XMEMSET(dec->aes, 0, sizeof(Aes));
        }
        if (enc) {
            if (wc_AesInit(enc->aes, heap, devId) != 0) {
                WOLFSSL_MSG("AesInit failed in SetKeys");
                return ASYNC_INIT_E;
            }
        }
        if (dec) {
            if (wc_AesInit(dec->aes, heap, devId) != 0) {
                WOLFSSL_MSG("AesInit failed in SetKeys");
                return ASYNC_INIT_E;
            }
        }

        if (side == WOLFSSL_CLIENT_END) {
            if (enc) {
                aesRet = wc_AesSetKey(enc->aes, keys->client_write_key,
                                   specs->key_size, keys->client_write_IV,
                                   AES_ENCRYPTION);
                if (aesRet != 0) return aesRet;
            }
            if (dec) {
                aesRet = wc_AesSetKey(dec->aes, keys->server_write_key,
                                   specs->key_size, keys->server_write_IV,
                                   AES_DECRYPTION);
                if (aesRet != 0) return aesRet;
            }
        }
        else {
            if (enc) {
                aesRet = wc_AesSetKey(enc->aes, keys->server_write_key,
                                   specs->key_size, keys->server_write_IV,
                                   AES_ENCRYPTION);
                if (aesRet != 0) return aesRet;
            }
            if (dec) {
                aesRet = wc_AesSetKey(dec->aes, keys->client_write_key,
                                   specs->key_size, keys->client_write_IV,
                                   AES_DECRYPTION);
                if (aesRet != 0) return aesRet;
            }
        }
        if (enc)
            enc->setup = 1;
        if (dec)
            dec->setup = 1;
    }

    /* check that buffer sizes are sufficient */
    #if (AEAD_MAX_IMP_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ too small for AESGCM
    #endif
    #if (AEAD_MAX_EXP_SZ < 8) /* AESGCM_EXP_IV_SZ */
        #error AEAD_MAX_EXP_SZ too small for AESGCM
    #endif
    #if (MAX_WRITE_IV_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ too small for AESGCM
    #endif

    if (specs->bulk_cipher_algorithm == wolfssl_aes_gcm) {
        int gcmRet;

        if (enc) {
            if (enc->aes == NULL) {
                enc->aes = (Aes*)XMALLOC(sizeof(Aes), heap, DYNAMIC_TYPE_CIPHER);
                if (enc->aes == NULL)
                    return MEMORY_E;
            } else {
                wc_AesFree(enc->aes);
            }

            XMEMSET(enc->aes, 0, sizeof(Aes));
        }
        if (dec) {
            if (dec->aes == NULL) {
                dec->aes = (Aes*)XMALLOC(sizeof(Aes), heap, DYNAMIC_TYPE_CIPHER);
                if (dec->aes == NULL)
                    return MEMORY_E;
            } else {
                wc_AesFree(dec->aes);
            }

            XMEMSET(dec->aes, 0, sizeof(Aes));
        }

        if (enc) {
            if (wc_AesInit(enc->aes, heap, devId) != 0) {
                WOLFSSL_MSG("AesInit failed in SetKeys");
                return ASYNC_INIT_E;
            }
        }
        if (dec) {
            if (wc_AesInit(dec->aes, heap, devId) != 0) {
                WOLFSSL_MSG("AesInit failed in SetKeys");
                return ASYNC_INIT_E;
            }
        }

        if (side == WOLFSSL_CLIENT_END) {
            if (enc) {
                gcmRet = wc_AesGcmSetKey(enc->aes, keys->client_write_key,
                                      specs->key_size);
                if (gcmRet != 0) return gcmRet;
                XMEMCPY(keys->aead_enc_imp_IV, keys->client_write_IV,
                        AEAD_MAX_IMP_SZ);
#if !defined(NO_PUBLIC_GCM_SET_IV)
                if (!tls13) {
                    gcmRet = wc_AesGcmSetIV(enc->aes, AESGCM_NONCE_SZ,
                            keys->client_write_IV, AESGCM_IMP_IV_SZ, rng);
                    if (gcmRet != 0) return gcmRet;
                }
#endif
            }
            if (dec) {
                gcmRet = wc_AesGcmSetKey(dec->aes, keys->server_write_key,
                                      specs->key_size);
                if (gcmRet != 0) return gcmRet;
                XMEMCPY(keys->aead_dec_imp_IV, keys->server_write_IV,
                        AEAD_MAX_IMP_SZ);
            }
        }
        else {
            if (enc) {
                gcmRet = wc_AesGcmSetKey(enc->aes, keys->server_write_key,
                                      specs->key_size);
                if (gcmRet != 0) return gcmRet;
                XMEMCPY(keys->aead_enc_imp_IV, keys->server_write_IV,
                        AEAD_MAX_IMP_SZ);
#if !defined(NO_PUBLIC_GCM_SET_IV)
                if (!tls13) {
                    gcmRet = wc_AesGcmSetIV(enc->aes, AESGCM_NONCE_SZ,
                            keys->server_write_IV, AESGCM_IMP_IV_SZ, rng);
                    if (gcmRet != 0) return gcmRet;
                }
#endif
            }
            if (dec) {
                gcmRet = wc_AesGcmSetKey(dec->aes, keys->client_write_key,
                                      specs->key_size);
                if (gcmRet != 0) return gcmRet;
                XMEMCPY(keys->aead_dec_imp_IV, keys->client_write_IV,
                        AEAD_MAX_IMP_SZ);
            }
        }
        if (enc)
            enc->setup = 1;
        if (dec)
            dec->setup = 1;
    }




    if (enc) {
        keys->sequence_number_hi      = 0;
        keys->sequence_number_lo      = 0;
    }
    if (dec) {
        keys->peer_sequence_number_hi = 0;
        keys->peer_sequence_number_lo = 0;
    }
    (void)side;
    (void)heap;
    (void)enc;
    (void)dec;
    (void)specs;
    (void)devId;

    return 0;
}


/* set one time authentication keys */
static int SetAuthKeys(OneTimeAuth* authentication, Keys* keys,
                       CipherSpecs* specs, void* heap, int devId)
{

        /* set up memory space for poly1305 */
        if (authentication && authentication->poly1305 == NULL)
            authentication->poly1305 =
                (Poly1305*)XMALLOC(sizeof(Poly1305), heap, DYNAMIC_TYPE_CIPHER);
        if (authentication && authentication->poly1305 == NULL)
            return MEMORY_E;
        if (authentication)
            authentication->setup = 1;
        (void)authentication;
        (void)heap;
        (void)keys;
        (void)specs;
        (void)devId;

        return 0;
}



/* Set wc_encrypt/wc_decrypt or both sides of key setup
 * note: use wc_encrypt to avoid shadowing global encrypt
 * declared in unistd.h
 */
int SetKeysSide(WOLFSSL* ssl, enum encrypt_side side)
{
    int ret, copy = 0;
    Ciphers* wc_encrypt = NULL;
    Ciphers* wc_decrypt = NULL;
    Keys*    keys    = &ssl->keys;

    (void)copy;


    switch (side) {
        case ENCRYPT_SIDE_ONLY:
            wc_encrypt = &ssl->encrypt;
            break;

        case DECRYPT_SIDE_ONLY:
            wc_decrypt = &ssl->decrypt;
            break;

        case ENCRYPT_AND_DECRYPT_SIDE:
            wc_encrypt = &ssl->encrypt;
            wc_decrypt = &ssl->decrypt;
            break;

        default:
            return BAD_FUNC_ARG;
    }

    if (!ssl->auth.setup && ssl->specs.bulk_cipher_algorithm == wolfssl_chacha){
        ret = SetAuthKeys(&ssl->auth, keys, &ssl->specs, ssl->heap, ssl->devId);
        if (ret != 0)
           return ret;
    }

    {
        ret = SetKeys(wc_encrypt, wc_decrypt, keys, &ssl->specs, ssl->options.side,
                      ssl->heap, ssl->devId, ssl->rng, ssl->options.tls1_3);
    }


    return ret;
}


/* TLS can call too */
int StoreKeys(WOLFSSL* ssl, const byte* keyData, int side)
{
    int sz, i = 0;
    Keys* keys = &ssl->keys;



    if (ssl->specs.cipher_type != aead) {
        sz = ssl->specs.hash_size;
        if (side & PROVISION_CLIENT) {
            XMEMCPY(keys->client_write_MAC_secret,&keyData[i], sz);
            i += sz;
        }
        if (side & PROVISION_SERVER) {
            XMEMCPY(keys->server_write_MAC_secret,&keyData[i], sz);
            i += sz;
        }
    }
    sz = ssl->specs.key_size;
    if (side & PROVISION_CLIENT) {
        XMEMCPY(keys->client_write_key, &keyData[i], sz);
        i += sz;
    }
    if (side & PROVISION_SERVER) {
        XMEMCPY(keys->server_write_key, &keyData[i], sz);
        i += sz;
    }

    sz = ssl->specs.iv_size;
    if (side & PROVISION_CLIENT) {
        XMEMCPY(keys->client_write_IV, &keyData[i], sz);
        i += sz;
    }
    if (side & PROVISION_SERVER) {
        XMEMCPY(keys->server_write_IV, &keyData[i], sz);
    }

    if (ssl->specs.cipher_type == aead) {
        /* Initialize the AES-GCM/CCM explicit IV to a zero. */
        XMEMSET(keys->aead_exp_IV, 0, AEAD_MAX_EXP_SZ);
    }

    return 0;
}

int DeriveKeys(WOLFSSL* ssl)
{
    int    length = 2 * ssl->specs.hash_size +
                    2 * ssl->specs.key_size  +
                    2 * ssl->specs.iv_size;
    int    rounds = (length + WC_MD5_DIGEST_SIZE - 1 ) / WC_MD5_DIGEST_SIZE, i;
    int    ret = 0;

    byte   shaOutput[WC_SHA_DIGEST_SIZE];
    byte   md5Input[SECRET_LEN + WC_SHA_DIGEST_SIZE];
    byte   shaInput[KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN];
    byte   keyData[KEY_PREFIX * WC_MD5_DIGEST_SIZE];
    wc_Md5 md5[1];
    wc_Sha sha[1];

    XMEMSET(shaOutput, 0, WC_SHA_DIGEST_SIZE);
    ret = wc_InitMd5(md5);
    if (ret == 0) {
        ret = wc_InitSha(sha);
    }
    if (ret == 0) {
        XMEMCPY(md5Input, ssl->arrays->masterSecret, SECRET_LEN);

        for (i = 0; i < rounds; ++i) {
            int j   = i + 1;
            int idx = j;

            if (!SetPrefix(shaInput, i)) {
                ret = PREFIX_ERROR;
                break;
            }

            XMEMCPY(shaInput + idx, ssl->arrays->masterSecret, SECRET_LEN);
            idx += SECRET_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->serverRandom, RAN_LEN);
            idx += RAN_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->clientRandom, RAN_LEN);
            if (ret == 0) {
                ret = wc_ShaUpdate(sha, shaInput,
                    (KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN) - KEY_PREFIX + j);
            }
            if (ret == 0) {
                ret = wc_ShaFinal(sha, shaOutput);
            }

            XMEMCPY(md5Input + SECRET_LEN, shaOutput, WC_SHA_DIGEST_SIZE);
            if (ret == 0) {
                ret = wc_Md5Update(md5, md5Input, SECRET_LEN + WC_SHA_DIGEST_SIZE);
            }
            if (ret == 0) {
                ret = wc_Md5Final(md5, keyData + i * WC_MD5_DIGEST_SIZE);
            }
        }

        if (ret == 0)
            ret = StoreKeys(ssl, keyData, PROVISION_CLIENT_SERVER);
    }


    return ret;
}


static int CleanPreMaster(WOLFSSL* ssl)
{
    int i, ret, sz = ssl->arrays->preMasterSz;

    for (i = 0; i < sz; i++)
        ssl->arrays->preMasterSecret[i] = 0;

    ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->preMasterSecret, sz);
    if (ret != 0)
        return ret;

    for (i = 0; i < sz; i++)
        ssl->arrays->preMasterSecret[i] = 0;

    XFREE(ssl->arrays->preMasterSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
    ssl->arrays->preMasterSecret = NULL;
    ssl->arrays->preMasterSz = 0;

    return 0;
}


/* Create and store the master secret see page 32, 6.1 */
static int MakeSslMasterSecret(WOLFSSL* ssl)
{
    int    i, ret;
    word32 idx;
    word32 pmsSz = ssl->arrays->preMasterSz;

    byte   shaOutput[WC_SHA_DIGEST_SIZE];
    byte   md5Input[ENCRYPT_LEN + WC_SHA_DIGEST_SIZE];
    byte   shaInput[PREFIX + ENCRYPT_LEN + 2 * RAN_LEN];
    wc_Md5 md5[1];
    wc_Sha sha[1];

    if (ssl->arrays->preMasterSecret == NULL) {
        return BAD_FUNC_ARG;
    }

    {
        word32 j;
        printf("pre master secret: ");
        for (j = 0; j < pmsSz; j++)
            printf("%02x", ssl->arrays->preMasterSecret[j]);
        printf("\n");
    }

    XMEMSET(shaOutput, 0, WC_SHA_DIGEST_SIZE);

    ret = wc_InitMd5(md5);
    if (ret == 0) {
        ret = wc_InitSha(sha);
    }
    if (ret == 0) {
        XMEMCPY(md5Input, ssl->arrays->preMasterSecret, pmsSz);

        for (i = 0; i < MASTER_ROUNDS; ++i) {
            byte prefix[KEY_PREFIX];      /* only need PREFIX bytes but static */
            if (!SetPrefix(prefix, i)) {  /* analysis thinks will overrun      */
                ret = PREFIX_ERROR;
                break;
            }

            idx = 0;
            XMEMCPY(shaInput, prefix, i + 1);
            idx += i + 1;

            XMEMCPY(shaInput + idx, ssl->arrays->preMasterSecret, pmsSz);
            idx += pmsSz;
            XMEMCPY(shaInput + idx, ssl->arrays->clientRandom, RAN_LEN);
            idx += RAN_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->serverRandom, RAN_LEN);
            idx += RAN_LEN;
            if (ret == 0) {
                ret = wc_ShaUpdate(sha, shaInput, idx);
            }
            if (ret == 0) {
                ret = wc_ShaFinal(sha, shaOutput);
            }
            idx = pmsSz;  /* preSz */
            XMEMCPY(md5Input + idx, shaOutput, WC_SHA_DIGEST_SIZE);
            idx += WC_SHA_DIGEST_SIZE;
            if (ret == 0) {
                ret = wc_Md5Update(md5, md5Input, idx);
            }
            if (ret == 0) {
                ret = wc_Md5Final(md5,
                            &ssl->arrays->masterSecret[i * WC_MD5_DIGEST_SIZE]);
            }
        }

        {
            word32 j;
            printf("master secret: ");
            for (j = 0; j < SECRET_LEN; j++)
                printf("%02x", ssl->arrays->masterSecret[j]);
            printf("\n");
        }

        if (ret == 0)
            ret = DeriveKeys(ssl);
    }


    if (ret == 0)
        ret = CleanPreMaster(ssl);
    else
        CleanPreMaster(ssl);

    return ret;
}


/* Master wrapper, doesn't use SSL stack space in TLS mode */
int MakeMasterSecret(WOLFSSL* ssl)
{
    /* append secret to premaster : premaster | SerSi | CliSi */
    if (ssl->options.tls) return MakeTlsMasterSecret(ssl);
    return MakeSslMasterSecret(ssl);
}

#endif /* WOLFCRYPT_ONLY */
