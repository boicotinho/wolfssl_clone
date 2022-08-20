/* wc_encrypt.h
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

/*!
    \file wolfssl/wolfcrypt/wc_encrypt.h
*/


#ifndef WOLF_CRYPT_ENCRYPT_H
#define WOLF_CRYPT_ENCRYPT_H

#include <wolfssl/wolfcrypt/types.h>
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/chacha.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* determine max cipher key size - cannot use enum values here, must be define,
 * since WC_MAX_SYM_KEY_SIZE is used in if macro logic. */
    #define WC_MAX_SYM_KEY_SIZE     (AES_MAX_KEY_SIZE/8)




WOLFSSL_API int wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                                        const byte* key, word32 keySz,
                                        const byte* iv);
WOLFSSL_API int wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                        const byte* key, word32 keySz,
                                        const byte* iv);






#ifdef WOLFSSL_ENCRYPTED_KEYS
    struct EncryptedInfo;
    WOLFSSL_API int wc_BufferKeyDecrypt(struct EncryptedInfo* info, byte* der, word32 derSz,
        const byte* password, int passwordSz, int hashType);
    WOLFSSL_API int wc_BufferKeyEncrypt(struct EncryptedInfo* info, byte* der, word32 derSz,
        const byte* password, int passwordSz, int hashType);
#endif /* WOLFSSL_ENCRYPTED_KEYS */

#ifndef NO_PWDBASED
    WOLFSSL_LOCAL int wc_CryptKey(const char* password, int passwordSz,
        byte* salt, int saltSz, int iterations, int id, byte* input, int length,
        int version, byte* cbcIv, int enc, int shaOid);
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ENCRYPT_H */

