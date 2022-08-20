/* wc_encrypt.c
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
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rc2.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/logging.h>

    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>

#if defined(HAVE_AES_CBC)
#ifdef HAVE_AES_DECRYPT
int wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                  const byte* key, word32 keySz, const byte* iv)
{
    int  ret = 0;
    Aes  aes[1];

    if (out == NULL || in == NULL || key == NULL || iv == NULL) {
        return BAD_FUNC_ARG;
    }


    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keySz, iv, AES_DECRYPTION);
        if (ret == 0)
            ret = wc_AesCbcDecrypt(aes, out, in, inSz);

        wc_AesFree(aes);
    }


    return ret;
}
#endif /* HAVE_AES_DECRYPT */

int wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                            const byte* key, word32 keySz, const byte* iv)
{
    int  ret = 0;
    Aes  aes[1];


    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keySz, iv, AES_ENCRYPTION);
        if (ret == 0)
            ret = wc_AesCbcEncrypt(aes, out, in, inSz);

        wc_AesFree(aes);
    }


    return ret;
}
#endif /* !NO_AES && HAVE_AES_CBC */




#if defined(WOLFSSL_ENCRYPTED_KEYS)

int wc_BufferKeyDecrypt(EncryptedInfo* info, byte* der, word32 derSz,
    const byte* password, int passwordSz, int hashType)
{
    int ret = NOT_COMPILED_IN;
    byte  key[WC_MAX_SYM_KEY_SIZE];

    (void)derSz;
    (void)passwordSz;
    (void)hashType;

    if (der == NULL || password == NULL || info == NULL || info->keySz == 0) {
        return BAD_FUNC_ARG;
    }

    /* use file's salt for key derivation, hex decode first */
    if (Base16_Decode(info->iv, info->ivSz, info->iv, &info->ivSz) != 0) {
        return BUFFER_E;
    }
    if (info->ivSz < PKCS5_SALT_SZ)
        return BUFFER_E;


    (void)XMEMSET(key, 0, WC_MAX_SYM_KEY_SIZE);

#ifndef NO_PWDBASED
    if ((ret = wc_PBKDF1(key, password, passwordSz, info->iv, PKCS5_SALT_SZ, 1,
                                        info->keySz, hashType)) != 0) {
        return ret;
    }
#endif

#if defined(HAVE_AES_CBC) && defined(HAVE_AES_DECRYPT)
    if (info->cipherType == WC_CIPHER_AES_CBC)
        ret = wc_AesCbcDecryptWithKey(der, der, derSz, key, info->keySz,
            info->iv);
#endif /* !NO_AES && HAVE_AES_CBC && HAVE_AES_DECRYPT */


    return ret;
}

int wc_BufferKeyEncrypt(EncryptedInfo* info, byte* der, word32 derSz,
    const byte* password, int passwordSz, int hashType)
{
    int ret = NOT_COMPILED_IN;
    byte  key[WC_MAX_SYM_KEY_SIZE];

    (void)derSz;
    (void)passwordSz;
    (void)hashType;

    if (der == NULL || password == NULL || info == NULL || info->keySz == 0 ||
            info->ivSz < PKCS5_SALT_SZ) {
        return BAD_FUNC_ARG;
    }


    (void)XMEMSET(key, 0, WC_MAX_SYM_KEY_SIZE);

#ifndef NO_PWDBASED
    if ((ret = wc_PBKDF1(key, password, passwordSz, info->iv, PKCS5_SALT_SZ, 1,
                                        info->keySz, hashType)) != 0) {
        return ret;
    }
#endif

#if defined(HAVE_AES_CBC)
    if (info->cipherType == WC_CIPHER_AES_CBC)
        ret = wc_AesCbcEncryptWithKey(der, der, derSz, key, info->keySz,
            info->iv);
#endif /* !NO_AES && HAVE_AES_CBC */


    return ret;
}

#endif /* !NO_ASN && WOLFSSL_ENCRYPTED_KEYS */


#if !defined(NO_PWDBASED)

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
/* Decrypt/Encrypt input in place from parameters based on id
 *
 * returns a negative value on fail case
 */
int wc_CryptKey(const char* password, int passwordSz, byte* salt,
                      int saltSz, int iterations, int id, byte* input,
                      int length, int version, byte* cbcIv, int enc, int shaOid)
{
    int typeH = WC_HASH_TYPE_NONE;
    int derivedLen = 0;
    int ret = 0;
    byte key[PKCS_MAX_KEY_SIZE];

    (void)input;
    (void)length;
    (void)enc;

    WOLFSSL_ENTER("wc_CryptKey");

    switch (id) {
    #if defined(WOLFSSL_AES_256)
        case PBE_AES256_CBC:
            switch(shaOid) {
                case HMAC_SHA256_OID:
                    typeH = WC_SHA256;
                    derivedLen = 32;
                    break;
                default:
                    typeH = WC_SHA;
                    derivedLen = 32;
                    break;
            }
            break;
    #endif /* WOLFSSL_AES_256 && !NO_SHA */
    #if defined(WOLFSSL_AES_128)
        case PBE_AES128_CBC:
            switch(shaOid) {
                case HMAC_SHA256_OID:
                    typeH = WC_SHA256;
                    derivedLen = 16;
                    break;
                default:
                    typeH = WC_SHA;
                    derivedLen = 16;
                    break;
            }
            break;
    #endif /* WOLFSSL_AES_128 && !NO_SHA */
    #ifdef WC_RC2
        case PBE_SHA1_40RC2_CBC:
            typeH = WC_SHA;
            derivedLen = 5;
            break;
    #endif
        default:
            WOLFSSL_MSG("Unknown/Unsupported encrypt/decrypt id");
            (void)shaOid;
            return ALGO_ID_E;
    }


    switch (version) {
    case PKCS5v2:
        ret = wc_PBKDF2(key, (byte*)password, passwordSz,
                        salt, saltSz, iterations, derivedLen, typeH);
        break;
    case PKCS5:
        ret = wc_PBKDF1(key, (byte*)password, passwordSz,
                        salt, saltSz, iterations, derivedLen, typeH);
        break;
#ifdef HAVE_PKCS12
    case PKCS12v1:
    {
        int  i, idx = 0;
        byte unicodePasswd[MAX_UNICODE_SZ];

        if ( (passwordSz * 2 + 2) > (int)sizeof(unicodePasswd)) {
            ForceZero(key, PKCS_MAX_KEY_SIZE);
            return UNICODE_SIZE_E;
        }

        for (i = 0; i < passwordSz; i++) {
            unicodePasswd[idx++] = 0x00;
            unicodePasswd[idx++] = (byte)password[i];
        }
        /* add trailing NULL */
        unicodePasswd[idx++] = 0x00;
        unicodePasswd[idx++] = 0x00;

        ret =  wc_PKCS12_PBKDF(key, unicodePasswd, idx, salt, saltSz,
                            iterations, derivedLen, typeH, 1);
        if (id != PBE_SHA1_RC4_128) {
            ret += wc_PKCS12_PBKDF(cbcIv, unicodePasswd, idx, salt, saltSz,
                                iterations, 8, typeH, 2);
        }
        break;
    }
#endif /* HAVE_PKCS12 */
    default:
        ForceZero(key, PKCS_MAX_KEY_SIZE);
        WOLFSSL_MSG("Unknown/Unsupported PKCS version");
        return ALGO_ID_E;
    } /* switch (version) */

    if (ret != 0) {
        ForceZero(key, PKCS_MAX_KEY_SIZE);
        return ret;
    }

    switch (id) {
#if defined(HAVE_AES_CBC)
    #ifdef WOLFSSL_AES_256
        case PBE_AES256_CBC:
        case PBE_AES128_CBC:
        {
            int free_aes;

            Aes aes[1];
            free_aes = 0;
            ret = wc_AesInit(aes, NULL, INVALID_DEVID);
            if (ret == 0) {
                free_aes = 1;
                if (enc) {
                    ret = wc_AesSetKey(aes, key, derivedLen, cbcIv,
                                                                AES_ENCRYPTION);
                }
                else {
                    ret = wc_AesSetKey(aes, key, derivedLen, cbcIv,
                                                                AES_DECRYPTION);
                }
            }
            if (ret == 0) {
                if (enc)
                    ret = wc_AesCbcEncrypt(aes, input, input, length);
                else
                    ret = wc_AesCbcDecrypt(aes, input, input, length);
            }
            if (free_aes)
                wc_AesFree(aes);
            ForceZero(aes, sizeof(Aes));
            if (ret != 0) {
                ForceZero(key, PKCS_MAX_KEY_SIZE);
                return ret;
            }
            break;
        }
    #endif /* WOLFSSL_AES_256 */
#endif /* !NO_AES && HAVE_AES_CBC */
#ifdef WC_RC2
        case PBE_SHA1_40RC2_CBC:
        {
            Rc2 rc2;
            /* effective key size for RC2-40-CBC is 40 bits */
            ret = wc_Rc2SetKey(&rc2, key, derivedLen, cbcIv, 40);
            if (ret == 0) {
                if (enc)
                    ret = wc_Rc2CbcEncrypt(&rc2, input, input, length);
                else
                    ret = wc_Rc2CbcDecrypt(&rc2, input, input, length);
            }
            if (ret != 0) {
                ForceZero(key, PKCS_MAX_KEY_SIZE);
                return ret;
            }
            ForceZero(&rc2, sizeof(Rc2));
            break;
        }
#endif

        default:
            ForceZero(key, PKCS_MAX_KEY_SIZE);
            WOLFSSL_MSG("Unknown/Unsupported encrypt/decryption algorithm");
            return ALGO_ID_E;
    }

    ForceZero(key, PKCS_MAX_KEY_SIZE);

    return ret;
}

#endif /* HAVE_PKCS8 || HAVE_PKCS12 */
#endif /* !NO_PWDBASED && !NO_ASN */
