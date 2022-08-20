/* evp.h
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
    \file wolfssl/openssl/evp.h
    \brief evp.h defines mini evp openssl compatibility layer
 */


#ifndef WOLFSSL_EVP_H_
#define WOLFSSL_EVP_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_evp.h"
#endif

#ifndef NO_MD5
    #include <wolfssl/openssl/md5.h>
#endif
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/sha3.h>
#include <wolfssl/openssl/ripemd.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/dsa.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/dh.h>
#include <wolfssl/openssl/compat_types.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include <wolfssl/wolfcrypt/coding.h>

#ifdef __cplusplus
    extern "C" {
#endif


#ifndef NO_MD5
    WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_md5(void);
#endif
WOLFSSL_API void wolfSSL_EVP_set_pw_prompt(const char *prompt);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_mdc2(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha1(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha224(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha256(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha384(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha512(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_shake128(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_shake256(void);
WOLFSSL_API const WOLFSSL_EVP_MD *wolfSSL_EVP_sha512_224(void);
WOLFSSL_API const WOLFSSL_EVP_MD *wolfSSL_EVP_sha512_256(void);
WOLFSSL_API const WOLFSSL_EVP_MD *wolfSSL_EVP_ripemd160(void);

WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_224(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_256(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_384(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_sha3_512(void);

WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ecb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ecb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ecb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cbc(void);
#if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_DIRECT)
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cbc(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cbc(void);
#endif
#ifdef WOLFSSL_AES_CFB
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb1(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb1(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb1(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb8(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb8(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb8(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_cfb128(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_cfb128(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_cfb128(void);
#endif
#ifdef WOLFSSL_AES_OFB
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ofb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ofb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ofb(void);
#endif
#ifdef WOLFSSL_AES_XTS
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_xts(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_xts(void);
#endif
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_gcm(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_gcm(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_gcm(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_128_ctr(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_192_ctr(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_aes_256_ctr(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ecb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_ecb(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_cbc(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_des_ede3_cbc(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_rc4(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_enc_null(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_rc2_cbc(void);
WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_chacha20_poly1305(void);


typedef union {
    #ifndef NO_MD5
        WOLFSSL_MD5_CTX    md5;
    #endif
        WOLFSSL_SHA_CTX    sha;
        WOLFSSL_SHA224_CTX sha224;
        WOLFSSL_SHA256_CTX sha256;
        WOLFSSL_SHA384_CTX sha384;
        WOLFSSL_SHA512_CTX sha512;
    #ifndef WOLFSSL_NOSHA3_224
        WOLFSSL_SHA3_224_CTX sha3_224;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        WOLFSSL_SHA3_256_CTX sha3_256;
    #endif
        WOLFSSL_SHA3_384_CTX sha3_384;
    #ifndef WOLFSSL_NOSHA3_512
        WOLFSSL_SHA3_512_CTX sha3_512;
    #endif
} WOLFSSL_Hasher;


struct WOLFSSL_EVP_MD_CTX {
    union {
        WOLFSSL_Hasher digest;
        Hmac hmac;
    } hash;
    enum wc_HashType macType;
    WOLFSSL_EVP_PKEY_CTX *pctx;
    unsigned int isHMAC;
};


typedef union {
    Aes  aes;
#ifdef WOLFSSL_AES_XTS
    XtsAes xts;
#endif
    Arc4 arc4;
    ChaChaPoly_Aead chachaPoly;
} WOLFSSL_Cipher;



#define WOLFSSL_EVP_BUF_SIZE 16
struct WOLFSSL_EVP_CIPHER_CTX {
    int            keyLen;         /* user may set for variable */
    int            block_size;
    unsigned long  flags;
    unsigned char  enc;            /* if encrypt side, then true */
    unsigned char  cipherType;
    /* working iv pointer into cipher */
    ALIGN16 unsigned char  iv[AES_BLOCK_SIZE];
    WOLFSSL_Cipher  cipher;
    ALIGN16 byte buf[WOLFSSL_EVP_BUF_SIZE];
    int  bufUsed;
    ALIGN16 byte lastBlock[WOLFSSL_EVP_BUF_SIZE];
    int  lastUsed;
#define HAVE_WOLFSSL_EVP_CIPHER_CTX_IV
    int    ivSz;
    byte*   gcmBuffer;
    int     gcmBufferLen;
    byte*   gcmAuthIn;
    int     gcmAuthInSz;
    ALIGN16 unsigned char authTag[AES_BLOCK_SIZE];
    int     authTagSz;
};

struct WOLFSSL_EVP_PKEY_CTX {
    WOLFSSL_EVP_PKEY *pkey;
    WOLFSSL_EVP_PKEY *peerKey;
    int op; /* operation */
    int padding;
    int nbits;
    int curveNID;
};

struct WOLFSSL_ASN1_PCTX {
    int dummy;
};

#define   BASE64_ENCODE_BLOCK_SIZE  48
#define   BASE64_ENCODE_RESULT_BLOCK_SIZE 64
#define   BASE64_DECODE_BLOCK_SIZE  4

struct WOLFSSL_EVP_ENCODE_CTX {
    void* heap;
    int   remaining;     /* num of bytes in data[] */
    byte  data[BASE64_ENCODE_BLOCK_SIZE];/* storage for unprocessed raw data */
};
typedef struct WOLFSSL_EVP_ENCODE_CTX WOLFSSL_EVP_ENCODE_CTX;

WOLFSSL_API struct WOLFSSL_EVP_ENCODE_CTX* wolfSSL_EVP_ENCODE_CTX_new(void);
WOLFSSL_API void wolfSSL_EVP_ENCODE_CTX_free(WOLFSSL_EVP_ENCODE_CTX* ctx);

WOLFSSL_API void wolfSSL_EVP_EncodeInit(WOLFSSL_EVP_ENCODE_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_EncodeUpdate(WOLFSSL_EVP_ENCODE_CTX* ctx,
                 unsigned char*out, int *outl, const unsigned char*in, int inl);
WOLFSSL_API void wolfSSL_EVP_EncodeFinal(WOLFSSL_EVP_ENCODE_CTX* ctx,
                 unsigned char*out, int *outl);
WOLFSSL_API int wolfSSL_EVP_EncodeBlock(unsigned char *out,
                const unsigned char *in, int inLen);
WOLFSSL_API int wolfSSL_EVP_DecodeBlock(unsigned char *out,
                const unsigned char *in, int inLen);

#if defined(WOLFSSL_BASE64_DECODE)
WOLFSSL_API void wolfSSL_EVP_DecodeInit(WOLFSSL_EVP_ENCODE_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_DecodeUpdate(WOLFSSL_EVP_ENCODE_CTX* ctx,
                unsigned char*out, int *outl, const unsigned char*in, int inl);
WOLFSSL_API int wolfSSL_EVP_DecodeFinal(WOLFSSL_EVP_ENCODE_CTX* ctx,
                unsigned char*out, int *outl);
#endif /* WOLFSSL_BASE64_DECODE */

WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_blake2b512(void);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_blake2s256(void);

WOLFSSL_API void wolfSSL_EVP_init(void);
WOLFSSL_API int  wolfSSL_EVP_MD_size(const WOLFSSL_EVP_MD* type);
WOLFSSL_API int  wolfSSL_EVP_MD_type(const WOLFSSL_EVP_MD* type);
WOLFSSL_API int  wolfSSL_EVP_MD_block_size(const WOLFSSL_EVP_MD* type);
WOLFSSL_API int  wolfSSL_EVP_MD_pkey_type(const WOLFSSL_EVP_MD* type);

WOLFSSL_API WOLFSSL_EVP_MD_CTX *wolfSSL_EVP_MD_CTX_new (void);
WOLFSSL_API void                wolfSSL_EVP_MD_CTX_free(WOLFSSL_EVP_MD_CTX* ctx);
WOLFSSL_API void wolfSSL_EVP_MD_CTX_init(WOLFSSL_EVP_MD_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_cleanup(WOLFSSL_EVP_MD_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_copy(WOLFSSL_EVP_MD_CTX *out, const WOLFSSL_EVP_MD_CTX *in);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_copy_ex(WOLFSSL_EVP_MD_CTX *out, const WOLFSSL_EVP_MD_CTX *in);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_type(const WOLFSSL_EVP_MD_CTX *ctx);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_size(const WOLFSSL_EVP_MD_CTX *ctx);
WOLFSSL_API int  wolfSSL_EVP_MD_CTX_block_size(const WOLFSSL_EVP_MD_CTX *ctx);
WOLFSSL_API const WOLFSSL_EVP_MD *wolfSSL_EVP_MD_CTX_md(const WOLFSSL_EVP_MD_CTX *ctx);
WOLFSSL_API const WOLFSSL_EVP_CIPHER *wolfSSL_EVP_get_cipherbyname(const char *name);
WOLFSSL_API const WOLFSSL_EVP_MD     *wolfSSL_EVP_get_digestbyname(const char *name);
WOLFSSL_API int wolfSSL_EVP_CIPHER_nid(const WOLFSSL_EVP_CIPHER *cipher);

WOLFSSL_API int wolfSSL_EVP_DigestInit(WOLFSSL_EVP_MD_CTX* ctx,
                                     const WOLFSSL_EVP_MD* type);
WOLFSSL_API int wolfSSL_EVP_DigestUpdate(WOLFSSL_EVP_MD_CTX* ctx, const void* data,
                                       size_t sz);
WOLFSSL_API int wolfSSL_EVP_DigestFinal(WOLFSSL_EVP_MD_CTX* ctx, unsigned char* md,
                                      unsigned int* s);
WOLFSSL_API int wolfSSL_EVP_DigestFinal_ex(WOLFSSL_EVP_MD_CTX* ctx,
                                            unsigned char* md, unsigned int* s);
WOLFSSL_API int wolfSSL_EVP_DigestSignUpdate(WOLFSSL_EVP_MD_CTX *ctx,
                                             const void *d, unsigned int cnt);
WOLFSSL_API int wolfSSL_EVP_DigestSignFinal(WOLFSSL_EVP_MD_CTX *ctx,
                                            unsigned char *sig, size_t *siglen);
WOLFSSL_API int wolfSSL_EVP_DigestVerifyUpdate(WOLFSSL_EVP_MD_CTX *ctx,
                                               const void *d, size_t cnt);
WOLFSSL_API int wolfSSL_EVP_DigestVerifyFinal(WOLFSSL_EVP_MD_CTX *ctx,
                                              const unsigned char *sig,
                                              size_t siglen);

WOLFSSL_API int wolfSSL_EVP_BytesToKey(const WOLFSSL_EVP_CIPHER* type,
                       const WOLFSSL_EVP_MD* md, const byte* salt,
                       const byte* data, int sz, int count, byte* key, byte* iv);

WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_init(WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_cleanup(WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_ctrl(WOLFSSL_EVP_CIPHER_CTX *ctx, \
                                             int type, int arg, void *ptr);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_iv_length(
                                    const WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_iv_length(const WOLFSSL_EVP_CIPHER* cipher);
WOLFSSL_API int wolfSSL_EVP_Cipher_key_length(const WOLFSSL_EVP_CIPHER* c);


WOLFSSL_API int  wolfSSL_EVP_CipherInit(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    const unsigned char* key,
                                    const unsigned char* iv,
                                    int enc);
WOLFSSL_API int wolfSSL_EVP_CipherUpdate(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl);
WOLFSSL_API int  wolfSSL_EVP_CipherFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);
WOLFSSL_API int  wolfSSL_EVP_CipherFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl, int enc);
WOLFSSL_API int  wolfSSL_EVP_EncryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);
WOLFSSL_API int  wolfSSL_EVP_EncryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);
WOLFSSL_API int  wolfSSL_EVP_DecryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);
WOLFSSL_API int  wolfSSL_EVP_DecryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);
WOLFSSL_API int  wolfSSL_EVP_DecryptFinal_legacy(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl);

WOLFSSL_API WOLFSSL_EVP_CIPHER_CTX *wolfSSL_EVP_CIPHER_CTX_new(void);
WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_free(WOLFSSL_EVP_CIPHER_CTX *ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_reset(WOLFSSL_EVP_CIPHER_CTX *ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_key_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                                     int keylen);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_iv_length(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                                     int ivLen);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, byte* iv,
                                                     int ivLen);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_get_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, byte* iv,
                                                     int ivLen);
WOLFSSL_API int  wolfSSL_EVP_Cipher(WOLFSSL_EVP_CIPHER_CTX* ctx,
                          unsigned char* dst, unsigned char* src,
                          unsigned int len);

WOLFSSL_API const WOLFSSL_EVP_CIPHER* wolfSSL_EVP_get_cipherbynid(int id);
WOLFSSL_API const WOLFSSL_EVP_MD* wolfSSL_EVP_get_digestbynid(int id);
WOLFSSL_API const WOLFSSL_EVP_CIPHER *wolfSSL_EVP_CIPHER_CTX_cipher(const WOLFSSL_EVP_CIPHER_CTX *ctx);

WOLFSSL_API int wolfSSL_EVP_PKEY_assign_RSA(WOLFSSL_EVP_PKEY* pkey,
                                            WOLFSSL_RSA* key);
WOLFSSL_API int wolfSSL_EVP_PKEY_assign_EC_KEY(WOLFSSL_EVP_PKEY* pkey,
                                               WOLFSSL_EC_KEY* key);
WOLFSSL_API int wolfSSL_EVP_PKEY_assign_DSA(WOLFSSL_EVP_PKEY* pkey, WOLFSSL_DSA* key);
WOLFSSL_API int wolfSSL_EVP_PKEY_assign_DH(WOLFSSL_EVP_PKEY* pkey, WOLFSSL_DH* key);
WOLFSSL_API WOLFSSL_RSA* wolfSSL_EVP_PKEY_get0_RSA(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_DSA* wolfSSL_EVP_PKEY_get0_DSA(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_RSA* wolfSSL_EVP_PKEY_get1_RSA(WOLFSSL_EVP_PKEY* key);
WOLFSSL_API WOLFSSL_DSA* wolfSSL_EVP_PKEY_get1_DSA(WOLFSSL_EVP_PKEY* key);
WOLFSSL_API WOLFSSL_EC_KEY *wolfSSL_EVP_PKEY_get0_EC_KEY(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API WOLFSSL_EC_KEY *wolfSSL_EVP_PKEY_get1_EC_KEY(WOLFSSL_EVP_PKEY *key);
WOLFSSL_API WOLFSSL_DH* wolfSSL_EVP_PKEY_get0_DH(WOLFSSL_EVP_PKEY* key);
WOLFSSL_API WOLFSSL_DH* wolfSSL_EVP_PKEY_get1_DH(WOLFSSL_EVP_PKEY* key);
WOLFSSL_API int wolfSSL_EVP_PKEY_set1_RSA(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_RSA *key);
WOLFSSL_API int wolfSSL_EVP_PKEY_set1_DSA(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_DSA *key);
WOLFSSL_API int wolfSSL_EVP_PKEY_set1_DH(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_DH *key);
WOLFSSL_API int wolfSSL_EVP_PKEY_set1_EC_KEY(WOLFSSL_EVP_PKEY *pkey, WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_EVP_PKEY_assign(WOLFSSL_EVP_PKEY *pkey, int type, void *key);

WOLFSSL_API const unsigned char* wolfSSL_EVP_PKEY_get0_hmac(const WOLFSSL_EVP_PKEY* pkey,
        size_t* len);
WOLFSSL_API int wolfSSL_EVP_PKEY_sign_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_sign(WOLFSSL_EVP_PKEY_CTX *ctx,
  unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
WOLFSSL_API int wolfSSL_EVP_PKEY_verify_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_verify(WOLFSSL_EVP_PKEY_CTX *ctx, const unsigned char *sig,
  size_t siglen, const unsigned char *tbs, size_t tbslen);
WOLFSSL_API int wolfSSL_EVP_PKEY_paramgen_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(WOLFSSL_EVP_PKEY_CTX *ctx,
        int nid);
WOLFSSL_API int wolfSSL_EVP_PKEY_paramgen(WOLFSSL_EVP_PKEY_CTX* ctx,
                                          WOLFSSL_EVP_PKEY** pkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set_ec_param_enc(WOLFSSL_EVP_PKEY_CTX *ctx,
        int flag);
WOLFSSL_API int wolfSSL_EVP_PKEY_keygen_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_keygen(WOLFSSL_EVP_PKEY_CTX *ctx,
  WOLFSSL_EVP_PKEY **ppkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_bits(const WOLFSSL_EVP_PKEY *pkey);
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
WOLFSSL_API void wolfSSL_EVP_PKEY_CTX_free(WOLFSSL_EVP_PKEY_CTX *ctx);
#else
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_free(WOLFSSL_EVP_PKEY_CTX *ctx);
#endif
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set_rsa_padding(WOLFSSL_EVP_PKEY_CTX *ctx, int padding);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set_rsa_keygen_bits(WOLFSSL_EVP_PKEY_CTX *ctx, int bits);

WOLFSSL_API int wolfSSL_EVP_PKEY_derive_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_derive_set_peer(WOLFSSL_EVP_PKEY_CTX *ctx, WOLFSSL_EVP_PKEY *peer);
WOLFSSL_API int wolfSSL_EVP_PKEY_derive(WOLFSSL_EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_ctrl_str(WOLFSSL_EVP_PKEY_CTX *ctx,
                          const char *name, const char *value);

WOLFSSL_API int wolfSSL_EVP_PKEY_decrypt(WOLFSSL_EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);
WOLFSSL_API int wolfSSL_EVP_PKEY_decrypt_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_PKEY_encrypt(WOLFSSL_EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);
WOLFSSL_API int wolfSSL_EVP_PKEY_encrypt_init(WOLFSSL_EVP_PKEY_CTX *ctx);
WOLFSSL_API WOLFSSL_EVP_PKEY *wolfSSL_EVP_PKEY_new(void);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_EVP_PKEY_new_ex(void* heap);
WOLFSSL_API void wolfSSL_EVP_PKEY_free(WOLFSSL_EVP_PKEY* key);
WOLFSSL_API int wolfSSL_EVP_PKEY_size(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_copy_parameters(WOLFSSL_EVP_PKEY *to, const WOLFSSL_EVP_PKEY *from);
WOLFSSL_API int wolfSSL_EVP_PKEY_missing_parameters(WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_cmp(const WOLFSSL_EVP_PKEY *a, const WOLFSSL_EVP_PKEY *b);
WOLFSSL_API int wolfSSL_EVP_PKEY_type(int type);
WOLFSSL_API int wolfSSL_EVP_PKEY_id(const WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_base_id(const WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_PKEY_get_default_digest_nid(WOLFSSL_EVP_PKEY *pkey, int *pnid);
WOLFSSL_API WOLFSSL_EVP_PKEY* wolfSSL_EVP_PKCS82PKEY(const WOLFSSL_PKCS8_PRIV_KEY_INFO* p8);
WOLFSSL_API WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_EVP_PKEY2PKCS8(const WOLFSSL_EVP_PKEY* pkey);

WOLFSSL_API int wolfSSL_EVP_SignFinal(WOLFSSL_EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_SignInit(WOLFSSL_EVP_MD_CTX *ctx, const WOLFSSL_EVP_MD *type);
WOLFSSL_API int wolfSSL_EVP_SignUpdate(WOLFSSL_EVP_MD_CTX *ctx, const void *data, size_t len);
WOLFSSL_API int wolfSSL_EVP_VerifyFinal(WOLFSSL_EVP_MD_CTX *ctx,
        const unsigned char* sig, unsigned int sig_len, WOLFSSL_EVP_PKEY *pkey);
WOLFSSL_API int wolfSSL_EVP_VerifyInit(WOLFSSL_EVP_MD_CTX *ctx, const WOLFSSL_EVP_MD *type);
WOLFSSL_API int wolfSSL_EVP_VerifyUpdate(WOLFSSL_EVP_MD_CTX *ctx, const void *data, size_t len);


/* these next ones don't need real OpenSSL type, for OpenSSH compat only */
WOLFSSL_API void* wolfSSL_EVP_X_STATE(const WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int   wolfSSL_EVP_X_STATE_LEN(const WOLFSSL_EVP_CIPHER_CTX* ctx);

WOLFSSL_API void  wolfSSL_3des_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                                unsigned char* iv, int len);
WOLFSSL_API void  wolfSSL_aes_ctr_iv(WOLFSSL_EVP_CIPHER_CTX* ctx, int doset,
                                unsigned char* iv, int len);

WOLFSSL_API int  wolfSSL_StoreExternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int  wolfSSL_SetInternalIV(WOLFSSL_EVP_CIPHER_CTX* ctx);

WOLFSSL_API int wolfSSL_EVP_CIPHER_CTX_block_size(const WOLFSSL_EVP_CIPHER_CTX *ctx);
WOLFSSL_API int wolfSSL_EVP_CIPHER_block_size(const WOLFSSL_EVP_CIPHER *cipher);
WOLFSSL_API unsigned long WOLFSSL_EVP_CIPHER_mode(const WOLFSSL_EVP_CIPHER *cipher);
WOLFSSL_API unsigned long WOLFSSL_CIPHER_mode(const WOLFSSL_EVP_CIPHER *cipher);
WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_flags(const WOLFSSL_EVP_CIPHER *cipher);
WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_set_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);
WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_clear_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags);
WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_CTX_flags(const WOLFSSL_EVP_CIPHER_CTX *ctx);
WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_CTX_mode(const WOLFSSL_EVP_CIPHER_CTX *ctx);
WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_padding(WOLFSSL_EVP_CIPHER_CTX *c, int pad);
WOLFSSL_API int  wolfSSL_EVP_add_digest(const WOLFSSL_EVP_MD *digest);
WOLFSSL_API int  wolfSSL_EVP_add_cipher(const WOLFSSL_EVP_CIPHER *cipher);
WOLFSSL_API void wolfSSL_EVP_cleanup(void);
WOLFSSL_API int  wolfSSL_add_all_algorithms(void);
WOLFSSL_API int  wolfSSL_OpenSSL_add_all_algorithms_conf(void);
WOLFSSL_API int  wolfSSL_OpenSSL_add_all_algorithms_noconf(void);
WOLFSSL_API int wolfSSL_EVP_read_pw_string(char*, int, const char*, int);

WOLFSSL_API int wolfSSL_PKCS5_PBKDF2_HMAC_SHA1(const char * pass, int passlen,
                                               const unsigned char * salt,
                                               int saltlen, int iter,
                                               int keylen, unsigned char *out);

WOLFSSL_API int wolfSSL_PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                                           const unsigned char *salt,
                                           int saltlen, int iter,
                                           const WOLFSSL_EVP_MD *digest,
                                           int keylen, unsigned char *out);

#if defined(HAVE_SCRYPT) && defined(HAVE_PBKDF2) && !defined(NO_PWDBASED)
WOLFSSL_API int wolfSSL_EVP_PBE_scrypt(const char *pass, size_t passlen,
                            const unsigned char *salt, size_t saltlen,
                            word64 N, word64 r, word64 p,
                            word64 maxmem, unsigned char *key, size_t keylen);
#endif /* HAVE_SCRYPT && HAVE_PBKDF2 && !NO_PWDBASED && !NO_SHA */

WOLFSSL_LOCAL int wolfSSL_EVP_get_hashinfo(const WOLFSSL_EVP_MD* evp,
                                           int* pHash, int* pHashSz);

WOLFSSL_API void wolfSSL_EVP_MD_do_all(void (*fn) (const WOLFSSL_EVP_MD *md,
                                                   const char* from, const char* to,
                                                   void* xx), void* args);

#ifdef HAVE_HKDF
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set_hkdf_md(WOLFSSL_EVP_PKEY_CTX* ctx,
                                                 const WOLFSSL_EVP_MD* md);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set1_hkdf_salt(WOLFSSL_EVP_PKEY_CTX* ctx,
                                                    byte* salt, int saltSz);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_set1_hkdf_key(WOLFSSL_EVP_PKEY_CTX* ctx,
                                                   byte* key, int keySz);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_add1_hkdf_info(WOLFSSL_EVP_PKEY_CTX* ctx,
                                                    byte* info, int infoSz);
WOLFSSL_API int wolfSSL_EVP_PKEY_CTX_hkdf_mode(WOLFSSL_EVP_PKEY_CTX* ctx,
                                               int mode);
#endif

#define WOLFSSL_EVP_CIPH_MODE            0x0007
#define WOLFSSL_EVP_CIPH_STREAM_CIPHER      0x0
#define WOLFSSL_EVP_CIPH_ECB_MODE           0x1
#define WOLFSSL_EVP_CIPH_CBC_MODE           0x2
#define WOLFSSL_EVP_CIPH_CFB_MODE           0x3
#define WOLFSSL_EVP_CIPH_OFB_MODE           0x4
#define WOLFSSL_EVP_CIPH_CTR_MODE           0x5
#define WOLFSSL_EVP_CIPH_GCM_MODE           0x6
#define WOLFSSL_EVP_CIPH_CCM_MODE           0x7
#define WOLFSSL_EVP_CIPH_XTS_MODE          0x10
#define WOLFSSL_EVP_CIPH_FLAG_AEAD_CIPHER  0x20
#define WOLFSSL_EVP_CIPH_NO_PADDING       0x100
#define WOLFSSL_EVP_CIPH_VARIABLE_LENGTH  0x200
#define WOLFSSL_EVP_CIPH_TYPE_INIT         0xff



#ifdef __cplusplus
    } /* extern "C" */
#endif

#include <wolfssl/openssl/objects.h>

#endif /* WOLFSSL_EVP_H_ */
