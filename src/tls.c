/* tls.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>



static int TLSX_PopulateSupportedGroups(WOLFSSL* ssl, TLSX** extensions);


/* Digest enable checks */


/* Warn if secrets logging is enabled */
        #warning The SHOW_SECRETS and WOLFSSL_SSLKEYLOGFILE options should only be used for debugging and never in a production environment

/* Optional Pre-Master-Secret logging for Wireshark */
#if !defined(NO_FILESYSTEM)
#ifndef WOLFSSL_SSLKEYLOGFILE_OUTPUT
    #define WOLFSSL_SSLKEYLOGFILE_OUTPUT "sslkeylog.log"
#endif
#endif


    #define HSHASH_SZ WC_SHA384_DIGEST_SIZE

int BuildTlsHandshakeHash(WOLFSSL* ssl, byte* hash, word32* hashLen)
{
    int ret = 0;
    word32 hashSz = FINISHED_SZ;

    if (ssl == NULL || hash == NULL || hashLen == NULL || *hashLen < HSHASH_SZ)
        return BAD_FUNC_ARG;

    /* for constant timing perform these even if error */
    ret |= wc_Md5GetHash(&ssl->hsHashes->hashMd5, hash);
    ret |= wc_ShaGetHash(&ssl->hsHashes->hashSha, &hash[WC_MD5_DIGEST_SIZE]);

    if (IsAtLeastTLSv1_2(ssl)) {
        if (ssl->specs.mac_algorithm <= sha256_mac ||
            ssl->specs.mac_algorithm == blake2b_mac) {
            ret |= wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);
            hashSz = WC_SHA256_DIGEST_SIZE;
        }
        if (ssl->specs.mac_algorithm == sha384_mac) {
            ret |= wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);
            hashSz = WC_SHA384_DIGEST_SIZE;
        }
    }

    *hashLen = hashSz;

    if (ret != 0)
        ret = BUILD_MSG_ERROR;

    return ret;
}


int BuildTlsFinished(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret;
    const byte* side = NULL;
    word32 hashSz = HSHASH_SZ;
    byte handshake_hash[HSHASH_SZ];

    ret = BuildTlsHandshakeHash(ssl, handshake_hash, &hashSz);
    if (ret == 0) {
        if (XSTRNCMP((const char*)sender, (const char*)client, SIZEOF_SENDER) == 0)
            side = tls_client;
        else if (XSTRNCMP((const char*)sender, (const char*)server, SIZEOF_SENDER)
                 == 0)
            side = tls_server;
        else {
            ret = BAD_FUNC_ARG;
            WOLFSSL_MSG("Unexpected sender value");
        }
    }

    if (ret == 0) {
#ifdef WOLFSSL_HAVE_PRF
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_PRF_TLS((byte*)hashes, TLS_FINISHED_SZ,
                    ssl->arrays->masterSecret,
                   SECRET_LEN, side, FINISHED_LABEL_SZ, handshake_hash, hashSz,
                   IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
                   ssl->heap, ssl->devId);
            PRIVATE_KEY_LOCK();
        }
#else
        /* Pseudo random function must be enabled in the configuration. */
        ret = PRF_MISSING;
        WOLFSSL_MSG("Pseudo-random function is not enabled");

        (void)side;
        (void)hashes;
#endif
    }


    return ret;
}



#ifdef WOLFSSL_ALLOW_TLSV10
ProtocolVersion MakeTLSv1(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_MINOR;

    return pv;
}
#endif /* WOLFSSL_ALLOW_TLSV10 */


ProtocolVersion MakeTLSv1_1(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_1_MINOR;

    return pv;
}




ProtocolVersion MakeTLSv1_2(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_2_MINOR;

    return pv;
}




static const byte ext_master_label[EXT_MASTER_LABEL_SZ + 1] =
                                                      "extended master secret";
static const byte master_label[MASTER_LABEL_SZ + 1] = "master secret";
static const byte key_label   [KEY_LABEL_SZ + 1]    = "key expansion";

static int _DeriveTlsKeys(byte* key_dig, word32 key_dig_len,
                         const byte* ms, word32 msLen,
                         const byte* sr, const byte* cr,
                         int tls1_2, int hash_type,
                         void* heap, int devId)
{
    int ret;
    byte seed[SEED_LEN];

    XMEMCPY(seed,           sr, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, cr, RAN_LEN);

#ifdef WOLFSSL_HAVE_PRF
    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(key_dig, key_dig_len, ms, msLen, key_label, KEY_LABEL_SZ,
               seed, SEED_LEN, tls1_2, hash_type, heap, devId);
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration. */
    ret = PRF_MISSING;
    WOLFSSL_MSG("Pseudo-random function is not enabled");

    (void)key_dig;
    (void)key_dig_len;
    (void)ms;
    (void)msLen;
    (void)tls1_2;
    (void)hash_type;
    (void)heap;
    (void)devId;
    (void)key_label;
    (void)master_label;
    (void)ext_master_label;
#endif


    return ret;
}

/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_DeriveTlsKeys(byte* key_dig, word32 key_dig_len,
                         const byte* ms, word32 msLen,
                         const byte* sr, const byte* cr,
                         int tls1_2, int hash_type)
{
    return _DeriveTlsKeys(key_dig, key_dig_len, ms, msLen, sr, cr, tls1_2,
        hash_type, NULL, INVALID_DEVID);
}


int DeriveTlsKeys(WOLFSSL* ssl)
{
    int   ret;
    int   key_dig_len = 2 * ssl->specs.hash_size +
                        2 * ssl->specs.key_size  +
                        2 * ssl->specs.iv_size;
    byte  key_dig[MAX_PRF_DIG];

        ret = _DeriveTlsKeys(key_dig, key_dig_len,
                         ssl->arrays->masterSecret, SECRET_LEN,
                         ssl->arrays->serverRandom, ssl->arrays->clientRandom,
                         IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
                         ssl->heap, ssl->devId);
    if (ret == 0)
        ret = StoreKeys(ssl, key_dig, PROVISION_CLIENT_SERVER);


    return ret;
}

static int _MakeTlsMasterSecret(byte* ms, word32 msLen,
                               const byte* pms, word32 pmsLen,
                               const byte* cr, const byte* sr,
                               int tls1_2, int hash_type,
                               void* heap, int devId)
{
    int ret;
    byte seed[SEED_LEN];

    XMEMCPY(seed,           cr, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, sr, RAN_LEN);

#ifdef WOLFSSL_HAVE_PRF
    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(ms, msLen, pms, pmsLen, master_label, MASTER_LABEL_SZ,
               seed, SEED_LEN, tls1_2, hash_type, heap, devId);
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration. */
    ret = PRF_MISSING;
    WOLFSSL_MSG("Pseudo-random function is not enabled");

    (void)ms;
    (void)msLen;
    (void)pms;
    (void)pmsLen;
    (void)tls1_2;
    (void)hash_type;
    (void)heap;
    (void)devId;
#endif


    // Fabio
    fprintf(stderr, "@@@@@@ MASTER SECRET: ");
    for(word32 ii = 0; ii < msLen; ++ii)
        fprintf(stderr, "%02x", ms[ii]);
    fprintf(stderr, " @@@@@@\n");

    return ret;
}

/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_MakeTlsMasterSecret(byte* ms, word32 msLen,
                               const byte* pms, word32 pmsLen,
                               const byte* cr, const byte* sr,
                               int tls1_2, int hash_type)
{
    return _MakeTlsMasterSecret(ms, msLen, pms, pmsLen, cr, sr, tls1_2,
        hash_type, NULL, INVALID_DEVID);
}



static int _MakeTlsExtendedMasterSecret(byte* ms, word32 msLen,
                                        const byte* pms, word32 pmsLen,
                                        const byte* sHash, word32 sHashLen,
                                        int tls1_2, int hash_type,
                                        void* heap, int devId)
{
    int ret;

#ifdef WOLFSSL_HAVE_PRF
    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(ms, msLen, pms, pmsLen, ext_master_label, EXT_MASTER_LABEL_SZ,
               sHash, sHashLen, tls1_2, hash_type, heap, devId);
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration. */
    ret = PRF_MISSING;
    WOLFSSL_MSG("Pseudo-random function is not enabled");

    (void)ms;
    (void)msLen;
    (void)pms;
    (void)pmsLen;
    (void)sHash;
    (void)sHashLen;
    (void)tls1_2;
    (void)hash_type;
    (void)heap;
    (void)devId;
#endif
    return ret;
}

/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_MakeTlsExtendedMasterSecret(byte* ms, word32 msLen,
                                        const byte* pms, word32 pmsLen,
                                        const byte* sHash, word32 sHashLen,
                                        int tls1_2, int hash_type)
{
    return _MakeTlsExtendedMasterSecret(ms, msLen, pms, pmsLen, sHash, sHashLen,
        tls1_2, hash_type, NULL, INVALID_DEVID);
}



int MakeTlsMasterSecret(WOLFSSL* ssl)
{
    int ret;

    if (ssl->options.haveEMS) {
        word32 hashSz = HSHASH_SZ;
        byte handshake_hash[HSHASH_SZ];

        ret = BuildTlsHandshakeHash(ssl, handshake_hash, &hashSz);
        if (ret == 0) {
            ret = _MakeTlsExtendedMasterSecret(
                ssl->arrays->masterSecret, SECRET_LEN,
                ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
                handshake_hash, hashSz,
                IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
                ssl->heap, ssl->devId);
        }

    }
    else
    {

        ret = _MakeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
              ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
              ssl->arrays->clientRandom, ssl->arrays->serverRandom,
              IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
              ssl->heap, ssl->devId);
    }
    if (ret == 0) {
        /* Wireshark Pre-Master-Secret Format:
         *  CLIENT_RANDOM <clientrandom> <mastersecret>
         */
        const char* CLIENT_RANDOM_LABEL = "CLIENT_RANDOM";
        int i, pmsPos = 0;
        char pmsBuf[13 + 1 + 64 + 1 + 96 + 1 + 1];

        XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%s ",
            CLIENT_RANDOM_LABEL);
        pmsPos += XSTRLEN(CLIENT_RANDOM_LABEL) + 1;
        for (i = 0; i < RAN_LEN; i++) {
            XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%02x",
                ssl->arrays->clientRandom[i]);
            pmsPos += 2;
        }
        XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, " ");
        pmsPos += 1;
        for (i = 0; i < SECRET_LEN; i++) {
            XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "%02x",
                ssl->arrays->masterSecret[i]);
            pmsPos += 2;
        }
        XSNPRINTF(&pmsBuf[pmsPos], sizeof(pmsBuf) - pmsPos, "\n");
        pmsPos += 1;

        /* print master secret */
        puts(pmsBuf);

        #if !defined(NO_FILESYSTEM)
        {
            FILE* f = XFOPEN(WOLFSSL_SSLKEYLOGFILE_OUTPUT, "a");
            if (f != XBADFILE) {
                XFWRITE(pmsBuf, 1, pmsPos, f);
                XFCLOSE(f);
            }
        }
        #endif

        ret = DeriveTlsKeys(ssl);
    }

    return ret;
}


/* Used by EAP-TLS and EAP-TTLS to derive keying material from
 * the master_secret. */
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* msk, unsigned int len,
                                                              const char* label)
{
    int   ret;
    byte  seed[SEED_LEN];


    /*
     * As per RFC-5281, the order of the client and server randoms is reversed
     * from that used by the TLS protocol to derive keys.
     */
    XMEMCPY(seed,           ssl->arrays->clientRandom, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, ssl->arrays->serverRandom, RAN_LEN);

#ifdef WOLFSSL_HAVE_PRF
    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS((byte*)msk, len, ssl->arrays->masterSecret, SECRET_LEN,
              (const byte *)label, (word32)XSTRLEN(label), seed, SEED_LEN,
              IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
              ssl->heap, ssl->devId);
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration. */
    ret = PRF_MISSING;
    WOLFSSL_MSG("Pseudo-random function is not enabled");

    (void)msk;
    (void)len;
    (void)label;
#endif


    return ret;
}


/* return HMAC digest type in wolfSSL format */
int wolfSSL_GetHmacType(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (ssl->specs.mac_algorithm) {
        #ifndef NO_MD5
        case md5_mac:
        {
            return WC_MD5;
        }
        #endif
        case sha256_mac:
        {
            return WC_SHA256;
        }
        case sha384_mac:
        {
            return WC_SHA384;
        }

        case sha_mac:
        {
            return WC_SHA;
        }
        #ifdef HAVE_BLAKE2
        case blake2b_mac:
        {
            return BLAKE2B_ID;
        }
        #endif
        default:
        {
            return WOLFSSL_FATAL_ERROR;
        }
    }
}


int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner, word32 sz, int content,
                           int verify)
{
    if (ssl == NULL || inner == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(inner, 0, WOLFSSL_TLS_HMAC_INNER_SZ);

    WriteSEQ(ssl, verify, inner);
    inner[SEQ_SZ] = (byte)content;
    inner[SEQ_SZ + ENUM_LEN]            = ssl->version.major;
    inner[SEQ_SZ + ENUM_LEN + ENUM_LEN] = ssl->version.minor;
    c16toa((word16)sz, inner + SEQ_SZ + ENUM_LEN + VERSION_SZ);

    return 0;
}


#if !defined(WOLFSSL_NO_HASH_RAW) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)

/* Update the hash in the HMAC.
 *
 * hmac  HMAC object.
 * data  Data to be hashed.
 * sz    Size of data to hash.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_HashUpdate(Hmac* hmac, const byte* data, word32 sz)
{
    int ret = BAD_FUNC_ARG;

    switch (hmac->macType) {
        case WC_SHA:
            ret = wc_ShaUpdate(&hmac->hash.sha, data, sz);
            break;

        case WC_SHA256:
            ret = wc_Sha256Update(&hmac->hash.sha256, data, sz);
            break;

        case WC_SHA384:
            ret = wc_Sha384Update(&hmac->hash.sha384, data, sz);
            break;

        case WC_SHA512:
            ret = wc_Sha512Update(&hmac->hash.sha512, data, sz);
            break;

        default:
            break;
    }

    return ret;
}

/* Finalize the hash but don't put the EOC, padding or length in.
 *
 * hmac  HMAC object.
 * hash  Hash result.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_HashFinalRaw(Hmac* hmac, unsigned char* hash)
{
    int ret = BAD_FUNC_ARG;

    switch (hmac->macType) {
        case WC_SHA:
            ret = wc_ShaFinalRaw(&hmac->hash.sha, hash);
            break;

        case WC_SHA256:
            ret = wc_Sha256FinalRaw(&hmac->hash.sha256, hash);
            break;

        case WC_SHA384:
            ret = wc_Sha384FinalRaw(&hmac->hash.sha384, hash);
            break;

        case WC_SHA512:
            ret = wc_Sha512FinalRaw(&hmac->hash.sha512, hash);
            break;

        default:
            break;
    }

    return ret;
}

/* Finalize the HMAC by performing outer hash.
 *
 * hmac  HMAC object.
 * mac   MAC result.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_OuterHash(Hmac* hmac, unsigned char* mac)
{
    int ret = BAD_FUNC_ARG;
    wc_HashAlg hash;
    enum wc_HashType hashType = (enum wc_HashType)hmac->macType;
    int digestSz = wc_HashGetDigestSize(hashType);
    int blockSz = wc_HashGetBlockSize(hashType);

    if ((digestSz >= 0) && (blockSz >= 0)) {
        ret = wc_HashInit(&hash, hashType);
    }
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, (byte*)hmac->opad,
            blockSz);
        if (ret == 0)
            ret = wc_HashUpdate(&hash, hashType, (byte*)hmac->innerHash,
                digestSz);
        if (ret == 0)
            ret = wc_HashFinal(&hash, hashType, mac);
        wc_HashFree(&hash, hashType);
    }

    return ret;
}

/* Calculate the HMAC of the header + message data.
 * Constant time implementation using wc_Sha*FinalRaw().
 *
 * hmac    HMAC object.
 * digest  MAC result.
 * in      Message data.
 * sz      Size of the message data.
 * header  Constructed record header with length of handshake data.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_UpdateFinal_CT(Hmac* hmac, byte* digest, const byte* in,
                               word32 sz, int macLen, byte* header)
{
    byte         lenBytes[8];
    int          i, j;
    unsigned int k;
    int          blockBits, blockMask;
    int          lastBlockLen, extraLen, eocIndex;
    int          blocks, safeBlocks, lenBlock, eocBlock;
    unsigned int maxLen;
    int          blockSz, padSz;
    int          ret;
    word32       realLen;
    byte         extraBlock;

    switch (hmac->macType) {
        case WC_SHA:
            blockSz = WC_SHA_BLOCK_SIZE;
            blockBits = 6;
            padSz = WC_SHA_BLOCK_SIZE - WC_SHA_PAD_SIZE + 1;
            break;

        case WC_SHA256:
            blockSz = WC_SHA256_BLOCK_SIZE;
            blockBits = 6;
            padSz = WC_SHA256_BLOCK_SIZE - WC_SHA256_PAD_SIZE + 1;
            break;

        case WC_SHA384:
            blockSz = WC_SHA384_BLOCK_SIZE;
            blockBits = 7;
            padSz = WC_SHA384_BLOCK_SIZE - WC_SHA384_PAD_SIZE + 1;
            break;

        case WC_SHA512:
            blockSz = WC_SHA512_BLOCK_SIZE;
            blockBits = 7;
            padSz = WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE + 1;
            break;

        default:
            return BAD_FUNC_ARG;
    }
    blockMask = blockSz - 1;

    /* Size of data to HMAC if padding length byte is zero. */
    maxLen = WOLFSSL_TLS_HMAC_INNER_SZ + sz - 1 - macLen;
    /* Complete data (including padding) has block for EOC and/or length. */
    extraBlock = ctSetLTE((maxLen + padSz) & blockMask, padSz);
    /* Total number of blocks for data including padding. */
    blocks = ((maxLen + blockSz - 1) >> blockBits) + extraBlock;
    /* Up to last 6 blocks can be hashed safely. */
    safeBlocks = blocks - 6;

    /* Length of message data. */
    realLen = maxLen - in[sz - 1];
    /* Number of message bytes in last block. */
    lastBlockLen = realLen & blockMask;
    /* Number of padding bytes in last block. */
    extraLen = ((blockSz * 2 - padSz - lastBlockLen) & blockMask) + 1;
    /* Number of blocks to create for hash. */
    lenBlock = (realLen + extraLen) >> blockBits;
    /* Block containing EOC byte. */
    eocBlock = realLen >> blockBits;
    /* Index of EOC byte in block. */
    eocIndex = realLen & blockMask;

    /* Add length of hmac's ipad to total length. */
    realLen += blockSz;
    /* Length as bits - 8 bytes bigendian. */
    c32toa(realLen >> ((sizeof(word32) * 8) - 3), lenBytes);
    c32toa(realLen << 3, lenBytes + sizeof(word32));

    ret = Hmac_HashUpdate(hmac, (unsigned char*)hmac->ipad, blockSz);
    if (ret != 0)
        return ret;

    XMEMSET(hmac->innerHash, 0, macLen);

    if (safeBlocks > 0) {
        ret = Hmac_HashUpdate(hmac, header, WOLFSSL_TLS_HMAC_INNER_SZ);
        if (ret != 0)
            return ret;
        ret = Hmac_HashUpdate(hmac, in, safeBlocks * blockSz -
                                                     WOLFSSL_TLS_HMAC_INNER_SZ);
        if (ret != 0)
            return ret;
    }
    else
        safeBlocks = 0;

    XMEMSET(digest, 0, macLen);
    k = safeBlocks * blockSz;
    for (i = safeBlocks; i < blocks; i++) {
        unsigned char hashBlock[WC_MAX_BLOCK_SIZE];
        unsigned char isEocBlock = ctMaskEq(i, eocBlock);
        unsigned char isOutBlock = ctMaskEq(i, lenBlock);

        for (j = 0; j < blockSz; j++) {
            unsigned char atEoc = ctMaskEq(j, eocIndex) & isEocBlock;
            unsigned char pastEoc = ctMaskGT(j, eocIndex) & isEocBlock;
            unsigned char b = 0;

            if (k < WOLFSSL_TLS_HMAC_INNER_SZ)
                b = header[k];
            else if (k < maxLen)
                b = in[k - WOLFSSL_TLS_HMAC_INNER_SZ];
            k++;

            b = ctMaskSel(atEoc, 0x80, b);
            b &= (unsigned char)~(word32)pastEoc;
            b &= ((unsigned char)~(word32)isOutBlock) | isEocBlock;

            if (j >= blockSz - 8) {
                b = ctMaskSel(isOutBlock, lenBytes[j - (blockSz - 8)], b);
            }

            hashBlock[j] = b;
        }

        ret = Hmac_HashUpdate(hmac, hashBlock, blockSz);
        if (ret != 0)
            return ret;
        ret = Hmac_HashFinalRaw(hmac, hashBlock);
        if (ret != 0)
            return ret;
        for (j = 0; j < macLen; j++)
            ((unsigned char*)hmac->innerHash)[j] |= hashBlock[j] & isOutBlock;
    }

    ret = Hmac_OuterHash(hmac, digest);

    return ret;
}

#endif

#if defined(WOLFSSL_NO_HASH_RAW) || defined(HAVE_FIPS) || \
    defined(HAVE_SELFTEST) || defined(HAVE_BLAKE2)

/* Calculate the HMAC of the header + message data.
 * Constant time implementation using normal hashing operations.
 * Update-Final need to be constant time.
 *
 * hmac    HMAC object.
 * digest  MAC result.
 * in      Message data.
 * sz      Size of the message data.
 * header  Constructed record header with length of handshake data.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_UpdateFinal(Hmac* hmac, byte* digest, const byte* in,
                            word32 sz, byte* header)
{
    byte       dummy[WC_MAX_BLOCK_SIZE] = {0};
    int        ret;
    word32     msgSz, blockSz, macSz, padSz, maxSz, realSz;
    word32     currSz, offset = 0;
    int        msgBlocks, blocks, blockBits;
    int        i;

    switch (hmac->macType) {
        case WC_SHA:
            blockSz = WC_SHA_BLOCK_SIZE;
            blockBits = 6;
            macSz = WC_SHA_DIGEST_SIZE;
            padSz = WC_SHA_BLOCK_SIZE - WC_SHA_PAD_SIZE + 1;
            break;

        case WC_SHA256:
            blockSz = WC_SHA256_BLOCK_SIZE;
            blockBits = 6;
            macSz = WC_SHA256_DIGEST_SIZE;
            padSz = WC_SHA256_BLOCK_SIZE - WC_SHA256_PAD_SIZE + 1;
            break;

        case WC_SHA384:
            blockSz = WC_SHA384_BLOCK_SIZE;
            blockBits = 7;
            macSz = WC_SHA384_DIGEST_SIZE;
            padSz = WC_SHA384_BLOCK_SIZE - WC_SHA384_PAD_SIZE + 1;
            break;

        case WC_SHA512:
            blockSz = WC_SHA512_BLOCK_SIZE;
            blockBits = 7;
            macSz = WC_SHA512_DIGEST_SIZE;
            padSz = WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE + 1;
            break;

    #ifdef HAVE_BLAKE2
        case WC_HASH_TYPE_BLAKE2B:
            blockSz = BLAKE2B_BLOCKBYTES;
            blockBits = 7;
            macSz = BLAKE2B_256;
            padSz = 0;
            break;
    #endif /* HAVE_BLAKE2 */

        default:
            return BAD_FUNC_ARG;
    }

    msgSz = sz - (1 + in[sz - 1] + macSz);
    /* Make negative result 0 */
    msgSz &= ~(0 - (msgSz >> 31));
    realSz = WOLFSSL_TLS_HMAC_INNER_SZ + msgSz;
    maxSz = WOLFSSL_TLS_HMAC_INNER_SZ + (sz - 1) - macSz;

    /* Calculate #blocks processed in HMAC for max and real data. */
    blocks      = maxSz >> blockBits;
    blocks     += ((maxSz + padSz) % blockSz) < padSz;
    msgBlocks   = realSz >> blockBits;
    /* #Extra blocks to process. */
    blocks -= msgBlocks + ((((realSz + padSz) % blockSz) < padSz) ? 1 : 0);
    /* Calculate whole blocks. */
    msgBlocks--;

    ret = wc_HmacUpdate(hmac, header, WOLFSSL_TLS_HMAC_INNER_SZ);
    if (ret == 0) {
        /* Fill the rest of the block with any available data. */
        currSz = ctMaskLT(msgSz, blockSz) & msgSz;
        currSz |= ctMaskGTE(msgSz, blockSz) & blockSz;
        currSz -= WOLFSSL_TLS_HMAC_INNER_SZ;
        currSz &= ~(0 - (currSz >> 31));
        ret = wc_HmacUpdate(hmac, in, currSz);
        offset = currSz;
    }
    if (ret == 0) {
        /* Do the hash operations on a block basis. */
        for (i = 0; i < msgBlocks; i++, offset += blockSz) {
            ret = wc_HmacUpdate(hmac, in + offset, blockSz);
            if (ret != 0)
                break;
        }
    }
    if (ret == 0)
        ret = wc_HmacUpdate(hmac, in + offset, msgSz - offset);
    if (ret == 0)
        ret = wc_HmacFinal(hmac, digest);
    if (ret == 0) {
        /* Do the dummy hash operations. Do at least one. */
        for (i = 0; i < blocks + 1; i++) {
            ret = wc_HmacUpdate(hmac, dummy, blockSz);
            if (ret != 0)
                break;
        }
    }

    return ret;
}

#endif

int TLS_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz, int padSz,
             int content, int verify, int epochOrder)
{
    Hmac   hmac;
    byte   myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    int    ret = 0;
    const byte* macSecret = NULL;
    word32 hashSz = 0;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    hashSz = ssl->specs.hash_size;


    if (!ssl->options.dtls)
        wolfSSL_SetTlsHmacInner(ssl, myInner, sz, content, verify);
    else
        wolfSSL_SetTlsHmacInner(ssl, myInner, sz, content, epochOrder);

    ret = wc_HmacInit(&hmac, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;


    macSecret = wolfSSL_GetMacSecret(ssl, verify);
    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
                                              macSecret,
                                              ssl->specs.hash_size);

    if (ret == 0) {
        /* Constant time verification required. */
        if (verify && padSz >= 0) {
#if !defined(WOLFSSL_NO_HASH_RAW) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
    #ifdef HAVE_BLAKE2
            if (wolfSSL_GetHmacType(ssl) == WC_HASH_TYPE_BLAKE2B) {
                ret = Hmac_UpdateFinal(&hmac, digest, in,
                                              sz + hashSz + padSz + 1, myInner);
            }
            else
    #endif
            {
                ret = Hmac_UpdateFinal_CT(&hmac, digest, in,
                                      sz + hashSz + padSz + 1, hashSz, myInner);
            }
#else
            ret = Hmac_UpdateFinal(&hmac, digest, in, sz + hashSz + padSz + 1,
                                                                       myInner);
#endif
        }
        else {
            ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
            if (ret == 0)
                ret = wc_HmacUpdate(&hmac, in, sz);                /* content */
            if (ret == 0)
                ret = wc_HmacFinal(&hmac, digest);
        }
    }

    wc_HmacFree(&hmac);

    return ret;
}



/**
 * The TLSX semaphore is used to calculate the size of the extensions to be sent
 * from one peer to another.
 */

/** Supports up to 64 flags. Increase as needed. */
#define SEMAPHORE_SIZE 8

/**
 * Converts the extension type (id) to an index in the semaphore.
 *
 * Official reference for TLS extension types:
 *   http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml
 *
 * Motivation:
 *   Previously, we used the extension type itself as the index of that
 *   extension in the semaphore as the extension types were declared
 *   sequentially, but maintain a semaphore as big as the number of available
 *   extensions is no longer an option since the release of renegotiation_info.
 *
 * How to update:
 *   Assign extension types that extrapolate the number of available semaphores
 *   to the first available index going backwards in the semaphore array.
 *   When adding a new extension type that don't extrapolate the number of
 *   available semaphores, check for a possible collision with with a
 *   'remapped' extension type.
 */
static WC_INLINE word16 TLSX_ToSemaphore(word16 type)
{
    switch (type) {

        case TLSX_RENEGOTIATION_INFO: /* 0xFF01 */
            return 63;

        default:
            if (type > 62) {
                /* This message SHOULD only happens during the adding of
                   new TLS extensions in which its IANA number overflows
                   the current semaphore's range, or if its number already
                   is assigned to be used by another extension.
                   Use this check value for the new extension and decrement
                   the check value by one. */
                WOLFSSL_MSG("### TLSX semaphore collision or overflow detected!");
            }
    }

    return type;
}

/** Checks if a specific light (tls extension) is not set in the semaphore. */
#define IS_OFF(semaphore, light) \
    (!(((semaphore)[(light) / 8] &  (byte) (0x01 << ((light) % 8)))))

/** Turn on a specific light (tls extension) in the semaphore. */
/* the semaphore marks the extensions already written to the message */
#define TURN_ON(semaphore, light) \
    ((semaphore)[(light) / 8] |= (byte) (0x01 << ((light) % 8)))

/** Turn off a specific light (tls extension) in the semaphore. */
#define TURN_OFF(semaphore, light) \
    ((semaphore)[(light) / 8] &= (byte) ~(0x01 << ((light) % 8)))

/** Creates a new extension. */
static TLSX* TLSX_New(TLSX_Type type, const void* data, void* heap)
{
    TLSX* extension = (TLSX*)XMALLOC(sizeof(TLSX), heap, DYNAMIC_TYPE_TLSX);

    (void)heap;

    if (extension) {
        extension->type = type;
        extension->data = (void*)data;
        extension->resp = 0;
        extension->next = NULL;
    }

    return extension;
}

/**
 * Creates a new extension and pushes it to the provided list.
 * Checks for duplicate extensions, keeps the newest.
 */
static int TLSX_Push(TLSX** list, TLSX_Type type, const void* data, void* heap)
{
    TLSX* extension = TLSX_New(type, data, heap);

    if (extension == NULL)
        return MEMORY_E;

    /* pushes the new extension on the list. */
    extension->next = *list;
    *list = extension;

    /* remove duplicate extensions, there should be only one of each type. */
    do {
        if (extension->next && extension->next->type == type) {
            TLSX *next = extension->next;

            extension->next = next->next;
            next->next = NULL;

            TLSX_FreeAll(next, heap);

            /* there is no way to occur more than
             * two extensions of the same type.
             */
            break;
        }
    } while ((extension = extension->next));

    return 0;
}



int TLSX_CheckUnsupportedExtension(WOLFSSL* ssl, TLSX_Type type);

int TLSX_CheckUnsupportedExtension(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX *extension = TLSX_Find(ssl->extensions, type);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, type);

    return extension == NULL;
}

int TLSX_HandleUnsupportedExtension(WOLFSSL* ssl);

int TLSX_HandleUnsupportedExtension(WOLFSSL* ssl)
{
    SendAlert(ssl, alert_fatal, unsupported_extension);
    return UNSUPPORTED_EXTENSION;
}


/** Mark an extension to be sent back to the client. */
void TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type);

void TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX *extension = TLSX_Find(ssl->extensions, type);

    if (extension)
        extension->resp = 1;
}

/******************************************************************************/
/* Application-Layer Protocol Negotiation                                     */
/******************************************************************************/

#ifdef HAVE_ALPN
/** Creates a new ALPN object, providing protocol name to use. */
static ALPN* TLSX_ALPN_New(char *protocol_name, word16 protocol_nameSz,
                                                                     void* heap)
{
    ALPN *alpn;

    WOLFSSL_ENTER("TLSX_ALPN_New");

    if (protocol_name == NULL ||
        protocol_nameSz > WOLFSSL_MAX_ALPN_PROTO_NAME_LEN) {
        WOLFSSL_MSG("Invalid arguments");
        return NULL;
    }

    alpn = (ALPN*)XMALLOC(sizeof(ALPN), heap, DYNAMIC_TYPE_TLSX);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return NULL;
    }

    alpn->next = NULL;
    alpn->negotiated = 0;
    alpn->options = 0;

    alpn->protocol_name = (char*)XMALLOC(protocol_nameSz + 1,
                                         heap, DYNAMIC_TYPE_TLSX);
    if (alpn->protocol_name == NULL) {
        WOLFSSL_MSG("Memory failure");
        XFREE(alpn, heap, DYNAMIC_TYPE_TLSX);
        return NULL;
    }

    XMEMCPY(alpn->protocol_name, protocol_name, protocol_nameSz);
    alpn->protocol_name[protocol_nameSz] = 0;

    (void)heap;

    return alpn;
}

/** Releases an ALPN object. */
static void TLSX_ALPN_Free(ALPN *alpn, void* heap)
{
    (void)heap;

    if (alpn == NULL)
        return;

    XFREE(alpn->protocol_name, heap, DYNAMIC_TYPE_TLSX);
    XFREE(alpn, heap, DYNAMIC_TYPE_TLSX);
}

/** Releases all ALPN objects in the provided list. */
static void TLSX_ALPN_FreeAll(ALPN *list, void* heap)
{
    ALPN* alpn;

    while ((alpn = list)) {
        list = alpn->next;
        TLSX_ALPN_Free(alpn, heap);
    }
}

/** Tells the buffered size of the ALPN objects in a list. */
static word16 TLSX_ALPN_GetSize(ALPN *list)
{
    ALPN* alpn;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((alpn = list)) {
        list = alpn->next;

        length++; /* protocol name length is on one byte */
        length += (word16)XSTRLEN(alpn->protocol_name);
    }

    return length;
}

/** Writes the ALPN objects of a list in a buffer. */
static word16 TLSX_ALPN_Write(ALPN *list, byte *output)
{
    ALPN* alpn;
    word16 length = 0;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((alpn = list)) {
        list = alpn->next;

        length = (word16)XSTRLEN(alpn->protocol_name);

        /* protocol name length */
        output[offset++] = (byte)length;

        /* protocol name value */
        XMEMCPY(output + offset, alpn->protocol_name, length);

        offset += length;
    }

    /* writing list length */
    c16toa(offset - OPAQUE16_LEN, output);

    return offset;
}

/** Finds a protocol name in the provided ALPN list */
static ALPN* TLSX_ALPN_Find(ALPN *list, char *protocol_name, word16 size)
{
    ALPN *alpn;

    if (list == NULL || protocol_name == NULL)
        return NULL;

    alpn = list;
    while (alpn != NULL && (
           (word16)XSTRLEN(alpn->protocol_name) != size ||
           XSTRNCMP(alpn->protocol_name, protocol_name, size)))
        alpn = alpn->next;

    return alpn;
}

/** Set the ALPN matching client and server requirements */
static int TLSX_SetALPN(TLSX** extensions, const void* data, word16 size,
                                                                     void* heap)
{
    ALPN *alpn;
    int  ret;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    alpn = TLSX_ALPN_New((char *)data, size, heap);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_E;
    }

    alpn->negotiated = 1;

    ret = TLSX_Push(extensions, TLSX_APPLICATION_LAYER_PROTOCOL, (void*)alpn,
                                                                          heap);
    if (ret != 0) {
        TLSX_ALPN_Free(alpn, heap);
        return ret;
    }

    return WOLFSSL_SUCCESS;
}

/** Parses a buffer of ALPN extensions and set the first one matching
 * client and server requirements */
static int TLSX_ALPN_ParseAndSet(WOLFSSL *ssl, const byte *input, word16 length,
                                 byte isRequest)
{
    word16  size = 0, offset = 0, idx = 0;
    int     r = BUFFER_ERROR;
    byte    match = 0;
    TLSX    *extension;
    ALPN    *alpn = NULL, *list;

    if (OPAQUE16_LEN > length)
        return BUFFER_ERROR;

    ato16(input, &size);
    offset += OPAQUE16_LEN;

    if (size == 0)
        return BUFFER_ERROR;

    extension = TLSX_Find(ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL)
        extension = TLSX_Find(ssl->ctx->extensions,
                              TLSX_APPLICATION_LAYER_PROTOCOL);

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
    if (ssl->alpnSelect != NULL && ssl->options.side == WOLFSSL_SERVER_END) {
        const byte* out;
        unsigned char outLen;

        if (ssl->alpnSelect(ssl, &out, &outLen, input + offset, size,
                            ssl->alpnSelectArg) == 0) {
            WOLFSSL_MSG("ALPN protocol match");
            /* clears out all current ALPN extensions set */
            TLSX_Remove(&ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL, ssl->heap);
            extension = NULL;
            if (TLSX_UseALPN(&ssl->extensions, (char*)out, outLen, 0, ssl->heap)
                                                           == WOLFSSL_SUCCESS) {
                extension = TLSX_Find(ssl->extensions,
                                      TLSX_APPLICATION_LAYER_PROTOCOL);
            }
        }
    }
#endif

    if (extension == NULL || extension->data == NULL) {
        return isRequest ? 0
                         : TLSX_HandleUnsupportedExtension(ssl);
    }

    /* validating alpn list length */
    if (length != OPAQUE16_LEN + size)
        return BUFFER_ERROR;

    list = (ALPN*)extension->data;

    /* keep the list sent by client */
    if (isRequest) {
        if (ssl->alpn_client_list != NULL)
            XFREE(ssl->alpn_client_list, ssl->heap, DYNAMIC_TYPE_ALPN);

        ssl->alpn_client_list = (char *)XMALLOC(size, ssl->heap,
                                                DYNAMIC_TYPE_ALPN);
        if (ssl->alpn_client_list == NULL)
            return MEMORY_ERROR;
    }

    for (size = 0; offset < length; offset += size) {

        size = input[offset++];
        if (offset + size > length || size == 0)
            return BUFFER_ERROR;

        if (isRequest) {
            XMEMCPY(ssl->alpn_client_list+idx, (char*)input + offset, size);
            idx += size;
            ssl->alpn_client_list[idx++] = ',';
        }

        if (!match) {
            alpn = TLSX_ALPN_Find(list, (char*)input + offset, size);
            if (alpn != NULL) {
                WOLFSSL_MSG("ALPN protocol match");
                match = 1;

                /* skip reading other values if not required */
                if (!isRequest)
                    break;
            }
        }
    }

    if (isRequest)
        ssl->alpn_client_list[idx-1] = 0;

    if (!match) {
        WOLFSSL_MSG("No ALPN protocol match");

        /* do nothing if no protocol match between client and server and option
         is set to continue (like OpenSSL) */
        if (list->options & WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) {
            WOLFSSL_MSG("Continue on mismatch");
            return 0;
        }

        SendAlert(ssl, alert_fatal, no_application_protocol);
        return UNKNOWN_ALPN_PROTOCOL_NAME_E;
    }

    /* set the matching negotiated protocol */
    r = TLSX_SetALPN(&ssl->extensions,
                     alpn->protocol_name,
                     (word16)XSTRLEN(alpn->protocol_name),
                     ssl->heap);
    if (r != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("TLSX_UseALPN failed");
        return BUFFER_ERROR;
    }

    /* reply to ALPN extension sent from client */
    if (isRequest) {
    }

    return 0;
}

/** Add a protocol name to the list of accepted usable ones */
int TLSX_UseALPN(TLSX** extensions, const void* data, word16 size, byte options,
                                                                     void* heap)
{
    ALPN *alpn;
    TLSX *extension;
    int  ret;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    alpn = TLSX_ALPN_New((char *)data, size, heap);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_E;
    }

    /* Set Options of ALPN */
    alpn->options = options;

    extension = TLSX_Find(*extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL) {
        ret = TLSX_Push(extensions, TLSX_APPLICATION_LAYER_PROTOCOL,
                                                             (void*)alpn, heap);
        if (ret != 0) {
            TLSX_ALPN_Free(alpn, heap);
            return ret;
        }
    }
    else {
        /* push new ALPN object to extension data. */
        alpn->next = (ALPN*)extension->data;
        extension->data = (void*)alpn;
    }

    return WOLFSSL_SUCCESS;
}

/** Get the protocol name set by the server */
int TLSX_ALPN_GetRequest(TLSX* extensions, void** data, word16 *dataSz)
{
    TLSX *extension;
    ALPN *alpn;

    if (extensions == NULL || data == NULL || dataSz == NULL)
        return BAD_FUNC_ARG;

    extension = TLSX_Find(extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL) {
        WOLFSSL_MSG("TLS extension not found");
        return WOLFSSL_ALPN_NOT_FOUND;
    }

    alpn = (ALPN *)extension->data;
    if (alpn == NULL) {
        WOLFSSL_MSG("ALPN extension not found");
        *data = NULL;
        *dataSz = 0;
        return WOLFSSL_FATAL_ERROR;
    }

    if (alpn->negotiated != 1) {

        /* consider as an error */
        if (alpn->options & WOLFSSL_ALPN_FAILED_ON_MISMATCH) {
            WOLFSSL_MSG("No protocol match with peer -> Failed");
            return WOLFSSL_FATAL_ERROR;
        }

        /* continue without negotiated protocol */
        WOLFSSL_MSG("No protocol match with peer -> Continue");
        return WOLFSSL_ALPN_NOT_FOUND;
    }

    if (alpn->next != NULL) {
        WOLFSSL_MSG("Only one protocol name must be accepted");
        return WOLFSSL_FATAL_ERROR;
    }

    *data = alpn->protocol_name;
    *dataSz = (word16)XSTRLEN((char*)*data);

    return WOLFSSL_SUCCESS;
}

#define ALPN_FREE_ALL     TLSX_ALPN_FreeAll
#define ALPN_GET_SIZE     TLSX_ALPN_GetSize
#define ALPN_WRITE        TLSX_ALPN_Write
#define ALPN_PARSE        TLSX_ALPN_ParseAndSet

#else /* HAVE_ALPN */

#define ALPN_FREE_ALL(list, heap)
#define ALPN_GET_SIZE(list)     0
#define ALPN_WRITE(a, b)        0
#define ALPN_PARSE(a, b, c, d)  0

#endif /* HAVE_ALPN */

/******************************************************************************/
/* Server Name Indication                                                     */
/******************************************************************************/


/** Creates a new SNI object. */
static SNI* TLSX_SNI_New(byte type, const void* data, word16 size, void* heap)
{
    SNI* sni = (SNI*)XMALLOC(sizeof(SNI), heap, DYNAMIC_TYPE_TLSX);

    (void)heap;

    if (sni) {
        sni->type = type;
        sni->next = NULL;


        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                sni->data.host_name = (char*)XMALLOC(size + 1, heap,
                                                     DYNAMIC_TYPE_TLSX);
                if (sni->data.host_name) {
                    XSTRNCPY(sni->data.host_name, (const char*)data, size);
                    sni->data.host_name[size] = '\0';
                } else {
                    XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                    sni = NULL;
                }
            break;

            default: /* invalid type */
                XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                sni = NULL;
        }
    }

    return sni;
}

/** Releases a SNI object. */
static void TLSX_SNI_Free(SNI* sni, void* heap)
{
    if (sni) {
        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                XFREE(sni->data.host_name, heap, DYNAMIC_TYPE_TLSX);
            break;
        }

        XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

/** Releases all SNI objects in the provided list. */
static void TLSX_SNI_FreeAll(SNI* list, void* heap)
{
    SNI* sni;

    while ((sni = list)) {
        list = sni->next;
        TLSX_SNI_Free(sni, heap);
    }
}

/** Tells the buffered size of the SNI objects in a list. */
static word16 TLSX_SNI_GetSize(SNI* list)
{
    SNI* sni;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((sni = list)) {
        list = sni->next;

        length += ENUM_LEN + OPAQUE16_LEN; /* sni type + sni length */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length += (word16)XSTRLEN((char*)sni->data.host_name);
            break;
        }
    }

    return length;
}

/** Writes the SNI objects of a list in a buffer. */
static word16 TLSX_SNI_Write(SNI* list, byte* output)
{
    SNI* sni;
    word16 length = 0;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((sni = list)) {
        list = sni->next;

        output[offset++] = sni->type; /* sni type */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length = (word16)XSTRLEN((char*)sni->data.host_name);

                c16toa(length, output + offset); /* sni length */
                offset += OPAQUE16_LEN;

                XMEMCPY(output + offset, sni->data.host_name, length);

                offset += length;
            break;
        }
    }

    c16toa(offset - OPAQUE16_LEN, output); /* writing list length */

    return offset;
}

/** Finds a SNI object in the provided list. */
static SNI* TLSX_SNI_Find(SNI *list, byte type)
{
    SNI* sni = list;

    while (sni && sni->type != type)
        sni = sni->next;

    return sni;
}

/** Sets the status of a SNI object. */
static void TLSX_SNI_SetStatus(TLSX* extensions, byte type, byte status)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        sni->status = status;
}

/** Gets the status of a SNI object. */
byte TLSX_SNI_Status(TLSX* extensions, byte type)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        return sni->status;

    return 0;
}

/** Parses a buffer of SNI extensions. */
static int TLSX_SNI_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                          byte isRequest)
{

    TLSX *extension = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, TLSX_SERVER_NAME);

    if (!isRequest) {
            if (!extension || !extension->data)
                return TLSX_HandleUnsupportedExtension(ssl);

            if (length > 0)
                return BUFFER_ERROR; /* SNI response MUST be empty. */

            /* This call enables wolfSSL_SNI_GetRequest() to be called in the
             * client side to fetch the used SNI. It will only work if the SNI
             * was set at the SSL object level. Right now we only support one
             * name type, WOLFSSL_SNI_HOST_NAME, but in the future, the
             * inclusion of other name types will turn this method inaccurate,
             * as the extension response doesn't contains information of which
             * name was accepted.
             */
            TLSX_SNI_SetStatus(ssl->extensions, WOLFSSL_SNI_HOST_NAME,
                                                        WOLFSSL_SNI_REAL_MATCH);

            return 0;
    }

    (void)input;


    return 0;
}

static int TLSX_SNI_VerifyParse(WOLFSSL* ssl,  byte isRequest)
{
    (void)ssl;

    if (isRequest) {
    }

    return 0;
}

int TLSX_UseSNI(TLSX** extensions, byte type, const void* data, word16 size,
                                                                     void* heap)
{
    TLSX* extension;
    SNI* sni = NULL;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    if ((sni = TLSX_SNI_New(type, data, size, heap)) == NULL)
        return MEMORY_E;

    extension = TLSX_Find(*extensions, TLSX_SERVER_NAME);
    if (!extension) {
        int ret = TLSX_Push(extensions, TLSX_SERVER_NAME, (void*)sni, heap);

        if (ret != 0) {
            TLSX_SNI_Free(sni, heap);
            return ret;
        }
    }
    else {
        /* push new SNI object to extension data. */
        sni->next = (SNI*)extension->data;
        extension->data = (void*)sni;

        /* remove duplicate SNI, there should be only one of each type. */
        do {
            if (sni->next && sni->next->type == type) {
                SNI* next = sni->next;

                sni->next = next->next;
                TLSX_SNI_Free(next, heap);

                /* there is no way to occur more than
                 * two SNIs of the same type.
                 */
                break;
            }
        } while ((sni = sni->next));
    }

    return WOLFSSL_SUCCESS;
}


#define SNI_FREE_ALL     TLSX_SNI_FreeAll
#define SNI_GET_SIZE     TLSX_SNI_GetSize
#define SNI_WRITE        TLSX_SNI_Write
#define SNI_PARSE        TLSX_SNI_Parse
#define SNI_VERIFY_PARSE TLSX_SNI_VerifyParse


/******************************************************************************/
/* Trusted CA Key Indication                                                  */
/******************************************************************************/

#ifdef HAVE_TRUSTED_CA

/** Creates a new TCA object. */
static TCA* TLSX_TCA_New(byte type, const byte* id, word16 idSz, void* heap)
{
    TCA* tca = (TCA*)XMALLOC(sizeof(TCA), heap, DYNAMIC_TYPE_TLSX);

    if (tca) {
        XMEMSET(tca, 0, sizeof(TCA));
        tca->type = type;

        switch (type) {
            case WOLFSSL_TRUSTED_CA_PRE_AGREED:
                break;

            case WOLFSSL_TRUSTED_CA_KEY_SHA1:
            case WOLFSSL_TRUSTED_CA_CERT_SHA1:
                if (idSz == WC_SHA_DIGEST_SIZE &&
                        (tca->id =
                            (byte*)XMALLOC(idSz, heap, DYNAMIC_TYPE_TLSX))) {
                    XMEMCPY(tca->id, id, idSz);
                    tca->idSz = idSz;
                }
                else {
                    XFREE(tca, heap, DYNAMIC_TYPE_TLSX);
                    tca = NULL;
                }
                break;

            case WOLFSSL_TRUSTED_CA_X509_NAME:
                if (idSz > 0 &&
                        (tca->id =
                            (byte*)XMALLOC(idSz, heap, DYNAMIC_TYPE_TLSX))) {
                    XMEMCPY(tca->id, id, idSz);
                    tca->idSz = idSz;
                }
                else {
                    XFREE(tca, heap, DYNAMIC_TYPE_TLSX);
                    tca = NULL;
                }
                break;

            default: /* invalid type */
                XFREE(tca, heap, DYNAMIC_TYPE_TLSX);
                tca = NULL;
        }
    }

    (void)heap;

    return tca;
}

/** Releases a TCA object. */
static void TLSX_TCA_Free(TCA* tca, void* heap)
{
    (void)heap;

    if (tca) {
        if (tca->id)
            XFREE(tca->id, heap, DYNAMIC_TYPE_TLSX);
        XFREE(tca, heap, DYNAMIC_TYPE_TLSX);
    }
}

/** Releases all TCA objects in the provided list. */
static void TLSX_TCA_FreeAll(TCA* list, void* heap)
{
    TCA* tca;

    while ((tca = list)) {
        list = tca->next;
        TLSX_TCA_Free(tca, heap);
    }
}

/** Tells the buffered size of the TCA objects in a list. */
static word16 TLSX_TCA_GetSize(TCA* list)
{
    TCA* tca;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((tca = list)) {
        list = tca->next;

        length += ENUM_LEN; /* tca type */

        switch (tca->type) {
            case WOLFSSL_TRUSTED_CA_PRE_AGREED:
                break;
            case WOLFSSL_TRUSTED_CA_KEY_SHA1:
            case WOLFSSL_TRUSTED_CA_CERT_SHA1:
                length += tca->idSz;
                break;
            case WOLFSSL_TRUSTED_CA_X509_NAME:
                length += OPAQUE16_LEN + tca->idSz;
                break;
        }
    }

    return length;
}

/** Writes the TCA objects of a list in a buffer. */
static word16 TLSX_TCA_Write(TCA* list, byte* output)
{
    TCA* tca;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((tca = list)) {
        list = tca->next;

        output[offset++] = tca->type; /* tca type */

        switch (tca->type) {
            case WOLFSSL_TRUSTED_CA_PRE_AGREED:
                break;
            case WOLFSSL_TRUSTED_CA_KEY_SHA1:
            case WOLFSSL_TRUSTED_CA_CERT_SHA1:
                if (tca->id != NULL) {
                    XMEMCPY(output + offset, tca->id, tca->idSz);
                    offset += tca->idSz;
                }
                else {
                    /* ID missing. Set to an empty string. */
                    c16toa(0, output + offset);
                    offset += OPAQUE16_LEN;
                }
                break;
            case WOLFSSL_TRUSTED_CA_X509_NAME:
                if (tca->id != NULL) {
                    c16toa(tca->idSz, output + offset); /* tca length */
                    offset += OPAQUE16_LEN;
                    XMEMCPY(output + offset, tca->id, tca->idSz);
                    offset += tca->idSz;
                }
                else {
                    /* ID missing. Set to an empty string. */
                    c16toa(0, output + offset);
                    offset += OPAQUE16_LEN;
                }
                break;
            default:
                /* ID unknown. Set to an empty string. */
                c16toa(0, output + offset);
                offset += OPAQUE16_LEN;
        }
    }

    c16toa(offset - OPAQUE16_LEN, output); /* writing list length */

    return offset;
}


/** Parses a buffer of TCA extensions. */
static int TLSX_TCA_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                          byte isRequest)
{

    TLSX *extension = TLSX_Find(ssl->extensions, TLSX_TRUSTED_CA_KEYS);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, TLSX_TRUSTED_CA_KEYS);

    if (!isRequest) {
            if (!extension || !extension->data)
                return TLSX_HandleUnsupportedExtension(ssl);

            if (length > 0)
                return BUFFER_ERROR; /* TCA response MUST be empty. */

            /* Set the flag that we're good for keys */
            TLSX_SetResponse(ssl, TLSX_TRUSTED_CA_KEYS);

            return 0;
    }

    (void)input;

    return 0;
}

/* Checks to see if the server sent a response for the TCA. */
static int TLSX_TCA_VerifyParse(WOLFSSL* ssl, byte isRequest)
{
    (void)ssl;

    if (!isRequest) {
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_TRUSTED_CA_KEYS);

        if (extension && !extension->resp) {
            SendAlert(ssl, alert_fatal, handshake_failure);
            return TCA_ABSENT_ERROR;
        }
    }

    return 0;
}

int TLSX_UseTrustedCA(TLSX** extensions, byte type,
                    const byte* id, word16 idSz, void* heap)
{
    TLSX* extension;
    TCA* tca = NULL;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    if ((tca = TLSX_TCA_New(type, id, idSz, heap)) == NULL)
        return MEMORY_E;

    extension = TLSX_Find(*extensions, TLSX_TRUSTED_CA_KEYS);
    if (!extension) {
        int ret = TLSX_Push(extensions, TLSX_TRUSTED_CA_KEYS, (void*)tca, heap);

        if (ret != 0) {
            TLSX_TCA_Free(tca, heap);
            return ret;
        }
    }
    else {
        /* push new TCA object to extension data. */
        tca->next = (TCA*)extension->data;
        extension->data = (void*)tca;
    }

    return WOLFSSL_SUCCESS;
}

#define TCA_FREE_ALL     TLSX_TCA_FreeAll
#define TCA_GET_SIZE     TLSX_TCA_GetSize
#define TCA_WRITE        TLSX_TCA_Write
#define TCA_PARSE        TLSX_TCA_Parse
#define TCA_VERIFY_PARSE TLSX_TCA_VerifyParse

#else /* HAVE_TRUSTED_CA */

#define TCA_FREE_ALL(list, heap)
#define TCA_GET_SIZE(list)     0
#define TCA_WRITE(a, b)        0
#define TCA_PARSE(a, b, c, d)  0
#define TCA_VERIFY_PARSE(a, b) 0

#endif /* HAVE_TRUSTED_CA */

/******************************************************************************/
/* Max Fragment Length Negotiation                                            */
/******************************************************************************/


#define MFL_FREE_ALL(a, b)
#define MFL_GET_SIZE(a)       0
#define MFL_WRITE(a, b)       0
#define MFL_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Truncated HMAC                                                             */
/******************************************************************************/


#define THM_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Certificate Status Request                                                 */
/******************************************************************************/


#define CSR_FREE_ALL(data, heap)
#define CSR_GET_SIZE(a, b)    0
#define CSR_WRITE(a, b, c)    0
#define CSR_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Certificate Status Request v2                                              */
/******************************************************************************/

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

static void TLSX_CSR2_FreeAll(CertificateStatusRequestItemV2* csr2, void* heap)
{
    CertificateStatusRequestItemV2* next;

    for (; csr2; csr2 = next) {
        next = csr2->next;

        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
            case WOLFSSL_CSR2_OCSP_MULTI:
                while(csr2->requests--)
                    FreeOcspRequest(&csr2->request.ocsp[csr2->requests]);
            break;
        }

        XFREE(csr2, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static word16 TLSX_CSR2_GetSize(CertificateStatusRequestItemV2* csr2,
                                                                 byte isRequest)
{
    word16 size = 0;

    /* shut up compiler warnings */
    (void) csr2; (void) isRequest;

    if (isRequest) {
        CertificateStatusRequestItemV2* next;

        for (size = OPAQUE16_LEN; csr2; csr2 = next) {
            next = csr2->next;

            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                case WOLFSSL_CSR2_OCSP_MULTI:
                    size += ENUM_LEN + 3 * OPAQUE16_LEN;

                    if (csr2->request.ocsp[0].nonceSz)
                        size += OCSP_NONCE_EXT_SZ;
                break;
            }
        }
    }

    return size;
}

static word16 TLSX_CSR2_Write(CertificateStatusRequestItemV2* csr2,
                                                   byte* output, byte isRequest)
{
    /* shut up compiler warnings */
    (void) csr2; (void) output; (void) isRequest;

    if (isRequest) {
        word16 offset;
        word16 length;

        for (offset = OPAQUE16_LEN; csr2 != NULL; csr2 = csr2->next) {
            /* status_type */
            output[offset++] = csr2->status_type;

            /* request */
            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                case WOLFSSL_CSR2_OCSP_MULTI:
                    /* request_length */
                    length = 2 * OPAQUE16_LEN;

                    if (csr2->request.ocsp[0].nonceSz)
                        length += OCSP_NONCE_EXT_SZ;

                    c16toa(length, output + offset);
                    offset += OPAQUE16_LEN;

                    /* responder id list */
                    c16toa(0, output + offset);
                    offset += OPAQUE16_LEN;

                    /* request extensions */
                    length = 0;

                    if (csr2->request.ocsp[0].nonceSz)
                        length = (word16)EncodeOcspRequestExtensions(
                                                 &csr2->request.ocsp[0],
                                                 output + offset + OPAQUE16_LEN,
                                                 OCSP_NONCE_EXT_SZ);

                    c16toa(length, output + offset);
                    offset += OPAQUE16_LEN + length;
                break;
            }
        }

        /* list size */
        c16toa(offset - OPAQUE16_LEN, output);

        return offset;
    }

    return 0;
}

static int TLSX_CSR2_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                           byte isRequest)
{
    int ret;

    /* shut up compiler warnings */
    (void) ssl; (void) input;

    if (!isRequest) {
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
        CertificateStatusRequestItemV2* csr2 = extension ?
                        (CertificateStatusRequestItemV2*)extension->data : NULL;

        if (!csr2) {
            /* look at context level */
            extension = TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST_V2);
            csr2 = extension ?
                        (CertificateStatusRequestItemV2*)extension->data : NULL;

            if (!csr2) /* unexpected extension */
                return TLSX_HandleUnsupportedExtension(ssl);

            /* enable extension at ssl level */
            for (; csr2; csr2 = csr2->next) {
                ret = TLSX_UseCertificateStatusRequestV2(&ssl->extensions,
                                    csr2->status_type, csr2->options, ssl->heap,
                                                                    ssl->devId);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;

                switch (csr2->status_type) {
                    case WOLFSSL_CSR2_OCSP:
                        /* followed by */
                    case WOLFSSL_CSR2_OCSP_MULTI:
                        /* propagate nonce */
                        if (csr2->request.ocsp[0].nonceSz) {
                            OcspRequest* request =
                             (OcspRequest*)TLSX_CSR2_GetRequest(ssl->extensions,
                                                          csr2->status_type, 0);

                            if (request) {
                                XMEMCPY(request->nonce,
                                        csr2->request.ocsp[0].nonce,
                                        csr2->request.ocsp[0].nonceSz);

                                request->nonceSz =
                                                  csr2->request.ocsp[0].nonceSz;
                            }
                        }
                    break;
                }
            }
        }

        ssl->status_request_v2 = 1;

        return length ? BUFFER_ERROR : 0; /* extension_data MUST be empty. */
    }
    else {
    }

    return 0;
}

int TLSX_CSR2_InitRequests(TLSX* extensions, DecodedCert* cert, byte isPeer,
                                                                     void* heap)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ?
        (CertificateStatusRequestItemV2*)extension->data : NULL;
    int ret = 0;

    for (; csr2; csr2 = csr2->next) {
        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
                if (!isPeer || csr2->requests != 0)
                    break;

                FALL_THROUGH; /* followed by */

            case WOLFSSL_CSR2_OCSP_MULTI: {
                if (csr2->requests < 1 + MAX_CHAIN_DEPTH) {
                    byte nonce[MAX_OCSP_NONCE_SZ];
                    int  nonceSz = csr2->request.ocsp[0].nonceSz;

                    /* preserve nonce, replicating nonce of ocsp[0] */
                    XMEMCPY(nonce, csr2->request.ocsp[0].nonce, nonceSz);

                    if ((ret = InitOcspRequest(
                                      &csr2->request.ocsp[csr2->requests], cert,
                                                                 0, heap)) != 0)
                        return ret;

                    /* restore nonce */
                    XMEMCPY(csr2->request.ocsp[csr2->requests].nonce,
                                                                nonce, nonceSz);
                    csr2->request.ocsp[csr2->requests].nonceSz = nonceSz;
                    csr2->requests++;
                }
            }
            break;
        }
    }

    (void)cert;
    return ret;
}

void* TLSX_CSR2_GetRequest(TLSX* extensions, byte status_type, byte idx)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ?
                        (CertificateStatusRequestItemV2*)extension->data : NULL;

    for (; csr2; csr2 = csr2->next) {
        if (csr2->status_type == status_type) {
            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                    /* followed by */

                case WOLFSSL_CSR2_OCSP_MULTI:
                    /* requests are initialized in the reverse order */
                    return idx < csr2->requests
                         ? &csr2->request.ocsp[csr2->requests - idx - 1]
                         : NULL;
            }
        }
    }

    return NULL;
}

int TLSX_CSR2_ForceRequest(WOLFSSL* ssl)
{
    TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ?
                        (CertificateStatusRequestItemV2*)extension->data : NULL;

    /* forces only the first one */
    if (csr2) {
        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
                /* followed by */

            case WOLFSSL_CSR2_OCSP_MULTI:
                if (SSL_CM(ssl)->ocspEnabled) {
                    csr2->request.ocsp[0].ssl = ssl;
                    return CheckOcspRequest(SSL_CM(ssl)->ocsp,
                                                  &csr2->request.ocsp[0], NULL);
                }
                else
                    return OCSP_LOOKUP_FAIL;
        }
    }

    return 0;
}

int TLSX_UseCertificateStatusRequestV2(TLSX** extensions, byte status_type,
                                           byte options, void* heap, int devId)
{
    TLSX* extension = NULL;
    CertificateStatusRequestItemV2* csr2 = NULL;
    int ret = 0;

    if (!extensions)
        return BAD_FUNC_ARG;

    if (status_type != WOLFSSL_CSR2_OCSP
    &&  status_type != WOLFSSL_CSR2_OCSP_MULTI)
        return BAD_FUNC_ARG;

    csr2 = (CertificateStatusRequestItemV2*)
       XMALLOC(sizeof(CertificateStatusRequestItemV2), heap, DYNAMIC_TYPE_TLSX);
    if (!csr2)
        return MEMORY_E;

    ForceZero(csr2, sizeof(CertificateStatusRequestItemV2));

    csr2->status_type = status_type;
    csr2->options     = options;
    csr2->next        = NULL;

    switch (csr2->status_type) {
        case WOLFSSL_CSR2_OCSP:
        case WOLFSSL_CSR2_OCSP_MULTI:
            if (options & WOLFSSL_CSR2_OCSP_USE_NONCE) {
                WC_RNG rng;

            #ifndef HAVE_FIPS
                ret = wc_InitRng_ex(&rng, heap, devId);
            #else
                ret = wc_InitRng(&rng);
                (void)devId;
            #endif
                if (ret == 0) {
                    if (wc_RNG_GenerateBlock(&rng, csr2->request.ocsp[0].nonce,
                                                        MAX_OCSP_NONCE_SZ) == 0)
                        csr2->request.ocsp[0].nonceSz = MAX_OCSP_NONCE_SZ;

                    wc_FreeRng(&rng);
                }
            }
        break;
    }

    /* append new item */
    if ((extension = TLSX_Find(*extensions, TLSX_STATUS_REQUEST_V2))) {
        CertificateStatusRequestItemV2* last =
                               (CertificateStatusRequestItemV2*)extension->data;

        for (; last->next; last = last->next);

        last->next = csr2;
    }
    else if ((ret = TLSX_Push(extensions, TLSX_STATUS_REQUEST_V2, csr2,heap))) {
        XFREE(csr2, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return WOLFSSL_SUCCESS;
}

#define CSR2_FREE_ALL TLSX_CSR2_FreeAll
#define CSR2_GET_SIZE TLSX_CSR2_GetSize
#define CSR2_WRITE    TLSX_CSR2_Write
#define CSR2_PARSE    TLSX_CSR2_Parse

#else

#define CSR2_FREE_ALL(data, heap)
#define CSR2_GET_SIZE(a, b)    0
#define CSR2_WRITE(a, b, c)    0
#define CSR2_PARSE(a, b, c, d) 0

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

/******************************************************************************/
/* Supported Elliptic Curves                                                  */
/******************************************************************************/



static int TLSX_SupportedCurve_New(SupportedCurve** curve, word16 name,
                                                                     void* heap)
{
    if (curve == NULL)
        return BAD_FUNC_ARG;

    (void)heap;

    *curve = (SupportedCurve*)XMALLOC(sizeof(SupportedCurve), heap,
                                                             DYNAMIC_TYPE_TLSX);
    if (*curve == NULL)
        return MEMORY_E;

    (*curve)->name = name;
    (*curve)->next = NULL;

    return 0;
}

static int TLSX_PointFormat_New(PointFormat** point, byte format, void* heap)
{
    if (point == NULL)
        return BAD_FUNC_ARG;

    (void)heap;

    *point = (PointFormat*)XMALLOC(sizeof(PointFormat), heap,
                                                             DYNAMIC_TYPE_TLSX);
    if (*point == NULL)
        return MEMORY_E;

    (*point)->format = format;
    (*point)->next = NULL;

    return 0;
}

static void TLSX_SupportedCurve_FreeAll(SupportedCurve* list, void* heap)
{
    SupportedCurve* curve;

    while ((curve = list)) {
        list = curve->next;
        XFREE(curve, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static void TLSX_PointFormat_FreeAll(PointFormat* list, void* heap)
{
    PointFormat* point;

    while ((point = list)) {
        list = point->next;
        XFREE(point, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static int TLSX_SupportedCurve_Append(SupportedCurve* list, word16 name,
                                                                     void* heap)
{
    int ret = BAD_FUNC_ARG;

    while (list) {
        if (list->name == name) {
            ret = 0; /* curve already in use */
            break;
        }

        if (list->next == NULL) {
            ret = TLSX_SupportedCurve_New(&list->next, name, heap);
            break;
        }

        list = list->next;
    }

    return ret;
}

static int TLSX_PointFormat_Append(PointFormat* list, byte format, void* heap)
{
    int ret = BAD_FUNC_ARG;

    while (list) {
        if (list->format == format) {
            ret = 0; /* format already in use */
            break;
        }

        if (list->next == NULL) {
            ret = TLSX_PointFormat_New(&list->next, format, heap);
            break;
        }

        list = list->next;
    }

    return ret;
}


#if defined(HAVE_FFDHE)
static void TLSX_SupportedCurve_ValidateRequest(const WOLFSSL* ssl,
                                                const byte* semaphore)
{
    /* If all pre-defined parameter types for key exchange are supported then
     * always send SupportedGroups extension.
     */
    (void)ssl;
    (void)semaphore;
}
#else
static void TLSX_SupportedCurve_ValidateRequest(WOLFSSL* ssl, byte* semaphore)
{
    word16 i;

    for (i = 0; i < ssl->suites->suiteSz; i += 2) {
        if (ssl->suites->suites[i] == TLS13_BYTE)
            return;
        if ((ssl->suites->suites[i] == ECC_BYTE) ||
                (ssl->suites->suites[i] == CHACHA_BYTE)) {
            return;
        }
        #ifdef HAVE_FFDHE
        else {
            return;
        }
        #endif
    }

    /* turns semaphore on to avoid sending this extension. */
    TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_SUPPORTED_GROUPS));
}
#endif

/* Only send PointFormats if TLSv13, ECC or CHACHA cipher suite present.
 */
static void TLSX_PointFormat_ValidateRequest(WOLFSSL* ssl, byte* semaphore)
{
    word16 i;

    for (i = 0; i < ssl->suites->suiteSz; i += 2) {
        if (ssl->suites->suites[i] == TLS13_BYTE)
            return;
        if ((ssl->suites->suites[i] == ECC_BYTE) ||
                (ssl->suites->suites[i] == CHACHA_BYTE)) {
            return;
        }
    }
#ifdef HAVE_FFDHE
    (void)semaphore;
    return;
#else
   /* turns semaphore on to avoid sending this extension. */
   TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_EC_POINT_FORMATS));
#endif
}




static word16 TLSX_SupportedCurve_GetSize(SupportedCurve* list)
{
    SupportedCurve* curve;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((curve = list)) {
        list = curve->next;
        length += OPAQUE16_LEN; /* curve length */
    }

    return length;
}


static word16 TLSX_PointFormat_GetSize(PointFormat* list)
{
    PointFormat* point;
    word16 length = ENUM_LEN; /* list length */

    while ((point = list)) {
        list = point->next;
        length += ENUM_LEN; /* format length */
    }

    return length;
}


static word16 TLSX_SupportedCurve_Write(SupportedCurve* list, byte* output)
{
    word16 offset = OPAQUE16_LEN;

    while (list) {
        c16toa(list->name, output + offset);
        offset += OPAQUE16_LEN;
        list = list->next;
    }

    c16toa(offset - OPAQUE16_LEN, output); /* writing list length */

    return offset;
}


static word16 TLSX_PointFormat_Write(PointFormat* list, byte* output)
{
    word16 offset = ENUM_LEN;

    while (list) {
        output[offset++] = list->format;
        list = list->next;
    }

    output[0] = (byte)(offset - ENUM_LEN);

    return offset;
}





int TLSX_UseSupportedCurve(TLSX** extensions, word16 name, void* heap)
{
    TLSX* extension = NULL;
    SupportedCurve* curve = NULL;
    int ret;

    if (extensions == NULL) {
        return BAD_FUNC_ARG;
    }


    extension = TLSX_Find(*extensions, TLSX_SUPPORTED_GROUPS);

    if (!extension) {
        ret = TLSX_SupportedCurve_New(&curve, name, heap);
        if (ret != 0)
            return ret;

        ret = TLSX_Push(extensions, TLSX_SUPPORTED_GROUPS, curve, heap);
        if (ret != 0) {
            XFREE(curve, heap, DYNAMIC_TYPE_TLSX);
            return ret;
        }
    }
    else {
        ret = TLSX_SupportedCurve_Append((SupportedCurve*)extension->data, name,
                                                                          heap);
        if (ret != 0)
            return ret;
    }

    return WOLFSSL_SUCCESS;
}

int TLSX_UsePointFormat(TLSX** extensions, byte format, void* heap)
{
    TLSX* extension = NULL;
    PointFormat* point = NULL;
    int ret = 0;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    extension = TLSX_Find(*extensions, TLSX_EC_POINT_FORMATS);

    if (!extension) {
        ret = TLSX_PointFormat_New(&point, format, heap);
        if (ret != 0)
            return ret;

        ret = TLSX_Push(extensions, TLSX_EC_POINT_FORMATS, point, heap);
        if (ret != 0) {
            XFREE(point, heap, DYNAMIC_TYPE_TLSX);
            return ret;
        }
    }
    else {
        ret = TLSX_PointFormat_Append((PointFormat*)extension->data, format,
                                                                          heap);
        if (ret != 0)
            return ret;
    }

    return WOLFSSL_SUCCESS;
}

#define EC_FREE_ALL         TLSX_SupportedCurve_FreeAll
#define EC_VALIDATE_REQUEST TLSX_SupportedCurve_ValidateRequest

#define EC_GET_SIZE TLSX_SupportedCurve_GetSize
#define EC_WRITE    TLSX_SupportedCurve_Write

#define EC_PARSE(a, b, c, d)      0

#define PF_FREE_ALL          TLSX_PointFormat_FreeAll
#define PF_VALIDATE_REQUEST  TLSX_PointFormat_ValidateRequest
#define PF_VALIDATE_RESPONSE TLSX_PointFormat_ValidateResponse

#define PF_GET_SIZE TLSX_PointFormat_GetSize
#define PF_WRITE    TLSX_PointFormat_Write

#define PF_PARSE(a, b, c, d)      0


/******************************************************************************/
/* Renegotiation Indication                                                   */
/******************************************************************************/


static byte TLSX_SecureRenegotiation_GetSize(SecureRenegotiation* data,
                                                                  int isRequest)
{
    byte length = OPAQUE8_LEN; /* empty info length */

    /* data will be NULL for HAVE_SERVER_RENEGOTIATION_INFO only */
    if (data && data->enabled && data->verifySet) {
        /* client sends client_verify_data only */
        length += TLS_FINISHED_SZ;

        /* server also sends server_verify_data */
        if (!isRequest)
            length += TLS_FINISHED_SZ;
    }

    return length;
}

static word16 TLSX_SecureRenegotiation_Write(SecureRenegotiation* data,
                                                    byte* output, int isRequest)
{
    word16 offset = OPAQUE8_LEN; /* RenegotiationInfo length */
    if (data && data->enabled && data->verifySet) {
        /* client sends client_verify_data only */
        XMEMCPY(output + offset, data->client_verify_data, TLS_FINISHED_SZ);
        offset += TLS_FINISHED_SZ;

        /* server also sends server_verify_data */
        if (!isRequest) {
            XMEMCPY(output + offset, data->server_verify_data, TLS_FINISHED_SZ);
            offset += TLS_FINISHED_SZ;
        }
    }

    output[0] = (byte)(offset - 1);  /* info length - self */

    return offset;
}

static int TLSX_SecureRenegotiation_Parse(WOLFSSL* ssl, const byte* input,
                                          word16 length, byte isRequest)
{
    int ret = SECURE_RENEGOTIATION_E;

    if (length >= OPAQUE8_LEN) {
        if (isRequest) {
        }
        else if (ssl->secure_renegotiation != NULL) {
            if (!ssl->secure_renegotiation->enabled) {
                if (*input == 0) {
                    ssl->secure_renegotiation->enabled = 1;
                    ret = 0;
                }
            }
            else if (*input == 2 * TLS_FINISHED_SZ &&
                     length == 2 * TLS_FINISHED_SZ + OPAQUE8_LEN) {
                input++;  /* get past size */

                /* validate client and server verify data */
                if (XMEMCMP(input,
                            ssl->secure_renegotiation->client_verify_data,
                            TLS_FINISHED_SZ) == 0 &&
                    XMEMCMP(input + TLS_FINISHED_SZ,
                            ssl->secure_renegotiation->server_verify_data,
                            TLS_FINISHED_SZ) == 0) {
                    WOLFSSL_MSG("SCR client and server verify data match");
                    ret = 0;  /* verified */
                } else {
                    /* already in error state */
                    WOLFSSL_MSG("SCR client and server verify data Failure");
                }
            }
        }
    }

    if (ret != 0) {
        SendAlert(ssl, alert_fatal, handshake_failure);
    }

    return ret;
}

int TLSX_UseSecureRenegotiation(TLSX** extensions, void* heap)
{
    int ret = 0;
    SecureRenegotiation* data;

    data = (SecureRenegotiation*)XMALLOC(sizeof(SecureRenegotiation), heap,
                                                             DYNAMIC_TYPE_TLSX);
    if (data == NULL)
        return MEMORY_E;

    XMEMSET(data, 0, sizeof(SecureRenegotiation));

    ret = TLSX_Push(extensions, TLSX_RENEGOTIATION_INFO, data, heap);
    if (ret != 0) {
        XFREE(data, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return WOLFSSL_SUCCESS;
}


int TLSX_AddEmptyRenegotiationInfo(TLSX** extensions, void* heap)
{
    int ret;

    /* send empty renegotiation_info extension */
    TLSX* ext = TLSX_Find(*extensions, TLSX_RENEGOTIATION_INFO);
    if (ext == NULL) {
        ret = TLSX_UseSecureRenegotiation(extensions, heap);
        if (ret != WOLFSSL_SUCCESS)
            return ret;

        ext = TLSX_Find(*extensions, TLSX_RENEGOTIATION_INFO);
    }
    if (ext)
        ext->resp = 1;

    return WOLFSSL_SUCCESS;
}



#define SCR_FREE_ALL(data, heap) XFREE(data, (heap), DYNAMIC_TYPE_TLSX)
#define SCR_GET_SIZE       TLSX_SecureRenegotiation_GetSize
#define SCR_WRITE          TLSX_SecureRenegotiation_Write
#define SCR_PARSE          TLSX_SecureRenegotiation_Parse


/******************************************************************************/
/* Session Tickets                                                            */
/******************************************************************************/


#define WOLF_STK_FREE(a, b)
#define WOLF_STK_VALIDATE_REQUEST(a)
#define WOLF_STK_GET_SIZE(a, b)      0
#define WOLF_STK_WRITE(a, b, c)      0
#define WOLF_STK_PARSE(a, b, c, d)   0


/******************************************************************************/
/* Encrypt-then-MAC                                                           */
/******************************************************************************/

static int TLSX_EncryptThenMac_Use(WOLFSSL* ssl);

/**
 * Get the size of the Encrypt-Then-MAC extension.
 *
 * msgType  Type of message to put extension into.
 * pSz      Size of extension data.
 * return SANITY_MSG_E when the message is not allowed to have extension and
 *        0 otherwise.
 */
static int TLSX_EncryptThenMac_GetSize(byte msgType, word16* pSz)
{
    (void)pSz;

    if (msgType != client_hello && msgType != server_hello) {
        return SANITY_MSG_E;
    }

    /* Empty extension */

    return 0;
}

/**
 * Write the Encrypt-Then-MAC extension.
 *
 * data     Unused
 * output   Extension data buffer. Unused.
 * msgType  Type of message to put extension into.
 * pSz      Size of extension data.
 * return SANITY_MSG_E when the message is not allowed to have extension and
 *        0 otherwise.
 */
static int TLSX_EncryptThenMac_Write(void* data, byte* output, byte msgType,
                                     word16* pSz)
{
    (void)data;
    (void)output;
    (void)pSz;

    if (msgType != client_hello && msgType != server_hello) {
        return SANITY_MSG_E;
    }

    /* Empty extension */

    return 0;
}

/**
 * Parse the Encrypt-Then-MAC extension.
 *
 * ssl      SSL object
 * input    Extension data buffer.
 * length   Length of this extension's data.
 * msgType  Type of message to extension appeared in.
 * return SANITY_MSG_E when the message is not allowed to have extension,
 *        BUFFER_ERROR when the extension's data is invalid,
 *        MEMORY_E when unable to allocate memory and
 *        0 otherwise.
 */
static int TLSX_EncryptThenMac_Parse(WOLFSSL* ssl, const byte* input,
                                     word16 length, byte msgType)
{
    int ret;

    (void)input;

    if (msgType != client_hello && msgType != server_hello) {
        return SANITY_MSG_E;
    }

    /* Empty extension */
    if (length != 0)
        return BUFFER_ERROR;

    if (msgType == client_hello) {
        /* Check the user hasn't disallowed use of Encrypt-Then-Mac. */
        if (!ssl->options.disallowEncThenMac) {
            ssl->options.encThenMac = 1;
            /* Set the extension reply. */
            ret = TLSX_EncryptThenMac_Use(ssl);
            if (ret != 0)
                return ret;
        }
        return 0;
    }

    /* Server Hello */
    if (ssl->options.disallowEncThenMac)
        return SANITY_MSG_E;

    ssl->options.encThenMac = 1;
    return 0;

}

/**
 * Add the Encrypt-Then-MAC extension to list.
 *
 * ssl      SSL object
 * return MEMORY_E when unable to allocate memory and 0 otherwise.
 */
static int TLSX_EncryptThenMac_Use(WOLFSSL* ssl)
{
    int   ret = 0;
    TLSX* extension;

    /* Find the Encrypt-Then-Mac extension if it exists. */
    extension = TLSX_Find(ssl->extensions, TLSX_ENCRYPT_THEN_MAC);
    if (extension == NULL) {
        /* Push new Encrypt-Then-Mac extension. */
        ret = TLSX_Push(&ssl->extensions, TLSX_ENCRYPT_THEN_MAC, NULL,
            ssl->heap);
        if (ret != 0)
            return ret;
    }

    return 0;
}

/**
 * Set the Encrypt-Then-MAC extension as one to respond too.
 *
 * ssl      SSL object
 * return EXT_MISSING when EncryptThenMac extension not in list.
 */
int TLSX_EncryptThenMac_Respond(WOLFSSL* ssl)
{
    TLSX* extension;

    extension = TLSX_Find(ssl->extensions, TLSX_ENCRYPT_THEN_MAC);
    if (extension == NULL)
        return EXT_MISSING;
    extension->resp = 1;

    return 0;
}

#define ETM_GET_SIZE  TLSX_EncryptThenMac_GetSize
#define ETM_WRITE     TLSX_EncryptThenMac_Write
#define ETM_PARSE     TLSX_EncryptThenMac_Parse




#ifdef WOLFSSL_SRTP

/******************************************************************************/
/* DTLS SRTP (Secure Real-time Transport Protocol)                            */
/******************************************************************************/

/* Only support single SRTP profile */
typedef struct TlsxSrtp {
    word16 profileCount;
    word16 ids; /* selected bits */
} TlsxSrtp;

static int TLSX_UseSRTP_GetSize(TlsxSrtp *srtp)
{
    /*   SRTP Profile Len (2)
     *      SRTP Profiles (2)
     *   MKI (master key id) Length */
    return (OPAQUE16_LEN + (srtp->profileCount * OPAQUE16_LEN) + 1);
}

static TlsxSrtp* TLSX_UseSRTP_New(word16 ids, void* heap)
{
    TlsxSrtp* srtp;
    int i;

    srtp = (TlsxSrtp*)XMALLOC(sizeof(TlsxSrtp), heap, DYNAMIC_TYPE_TLSX);
    if (srtp == NULL) {
        WOLFSSL_MSG("TLSX SRTP Memory failure");
        return NULL;
    }

    /* count and test each bit set */
    srtp->profileCount = 0;
    for (i=0; i<16; i++) {
        if (ids & (1 << i)) {
            srtp->profileCount++;
        }
    }
    srtp->ids = ids;

    return srtp;
}

static void TLSX_UseSRTP_Free(TlsxSrtp *srtp, void* heap)
{
    if (srtp != NULL) {
        XFREE(srtp, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static int TLSX_UseSRTP_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
{
    int ret = BAD_FUNC_ARG;
    word16 profile_len = 0;
    word16 profile_value = 0;
    word16 offset = 0;

    if (length < OPAQUE16_LEN) {
        return BUFFER_ERROR;
    }

    /* reset selected DTLS SRTP profile ID */
    ssl->dtlsSrtpId = 0;

    /* total length, not include itself */
    ato16(input, &profile_len);
    offset += OPAQUE16_LEN;

    if (!isRequest) {
        if (length < offset + OPAQUE16_LEN)
            return BUFFER_ERROR;

        ato16(input + offset, &profile_value);

        /* check that the profile received was in the ones we support */
        if (profile_value < 16 &&
                               (ssl->dtlsSrtpProfiles & (1 << profile_value))) {
            ssl->dtlsSrtpId = profile_value;
            ret = 0; /* success */
        }
    }
    (void)profile_len;

    return ret;
}

static word16 TLSX_UseSRTP_Write(TlsxSrtp* srtp, byte* output)
{
    word16 offset = 0;
    int i, j;

    c16toa(srtp->profileCount*2, output+offset);
    offset += OPAQUE16_LEN;
    for (i=0; i< srtp->profileCount; i+=2) {
        for (j=0; j<16; j++) {
            if (srtp->ids & (1 << j)) {
                c16toa(j, output+offset);
                offset += OPAQUE16_LEN;
            }
        }
    }
    output[offset++] = 0x00; /* MKI Length */

    return offset;
}

static int TLSX_UseSRTP(TLSX** extensions, word16 profiles, void* heap)
{
    int ret = 0;
    TLSX* extension;

    if (extensions == NULL) {
        return BAD_FUNC_ARG;
    }

    extension = TLSX_Find(*extensions, TLSX_USE_SRTP);
    if (extension == NULL) {
        TlsxSrtp* srtp = TLSX_UseSRTP_New(profiles, heap);
        if (srtp == NULL) {
            return MEMORY_E;
        }

        ret = TLSX_Push(extensions, TLSX_USE_SRTP, (void*)srtp, heap);
        if (ret != 0) {
            TLSX_UseSRTP_Free(srtp, heap);
        }
    }

    return ret;
}

    #define SRTP_FREE(a, b)
    #define SRTP_PARSE(a, b, c, d)      0
    #define SRTP_WRITE(a, b)            0
    #define SRTP_GET_SIZE(a)            0

#endif /* WOLFSSL_SRTP */


/******************************************************************************/
/* Supported Versions                                                         */
/******************************************************************************/


#define SV_GET_SIZE(a, b, c) 0
#define SV_WRITE(a, b, c, d) 0
#define SV_PARSE(a, b, c, d) 0



#define CKE_FREE_ALL(a, b)    0
#define CKE_GET_SIZE(a, b, c) 0
#define CKE_WRITE(a, b, c, d) 0
#define CKE_PARSE(a, b, c, d) 0

#if !defined(WOLFSSL_NO_SIGALG)
/******************************************************************************/
/* Signature Algorithms                                                       */
/******************************************************************************/

/* Return the size of the SignatureAlgorithms extension's data.
 *
 * data  Unused
 * returns the length of data that will be in the extension.
 */

static word16 TLSX_SignatureAlgorithms_GetSize(void* data)
{
    WOLFSSL* ssl = (WOLFSSL*)data;

    return OPAQUE16_LEN + ssl->suites->hashSigAlgoSz;
}

/* Creates a bit string of supported hash algorithms with RSA PSS.
 * The bit string is used when determining which signature algorithm to use
 * when creating the CertificateVerify message.
 * Note: Valid data has an even length as each signature algorithm is two bytes.
 *
 * ssl     The SSL/TLS object.
 * input   The buffer with the list of supported signature algorithms.
 * length  The length of the list in bytes.
 * returns 0 on success, BUFFER_ERROR when the length is not even.
 */
static int TLSX_SignatureAlgorithms_MapPss(WOLFSSL *ssl, const byte* input,
                                           word16 length)
{
    word16 i;

    if ((length & 1) == 1)
        return BUFFER_ERROR;

    ssl->pssAlgo = 0;
    for (i = 0; i < length; i += 2) {
        if (input[i] == rsa_pss_sa_algo && input[i + 1] <= sha512_mac)
            ssl->pssAlgo |= 1 << input[i + 1];
    }

    return 0;
}

/* Writes the SignatureAlgorithms extension into the buffer.
 *
 * data    Unused
 * output  The buffer to write the extension into.
 * returns the length of data that was written.
 */
static word16 TLSX_SignatureAlgorithms_Write(void* data, byte* output)
{
    WOLFSSL* ssl = (WOLFSSL*)data;

    c16toa(ssl->suites->hashSigAlgoSz, output);
    XMEMCPY(output + OPAQUE16_LEN, ssl->suites->hashSigAlgo,
            ssl->suites->hashSigAlgoSz);

    TLSX_SignatureAlgorithms_MapPss(ssl, output + OPAQUE16_LEN,
                                    ssl->suites->hashSigAlgoSz);

    return OPAQUE16_LEN + ssl->suites->hashSigAlgoSz;
}

/* Parse the SignatureAlgorithms extension.
 *
 * ssl     The SSL/TLS object.
 * input   The buffer with the extension data.
 * length  The length of the extension data.
 * returns 0 on success, otherwise failure.
 */
static int TLSX_SignatureAlgorithms_Parse(WOLFSSL *ssl, const byte* input,
                                  word16 length, byte isRequest, Suites* suites)
{
    word16 len;

    if (!isRequest)
        return BUFFER_ERROR;

    /* Must contain a length and at least algorithm. */
    if (length < OPAQUE16_LEN + OPAQUE16_LEN || (length & 1) != 0)
        return BUFFER_ERROR;

    ato16(input, &len);
    input += OPAQUE16_LEN;

    /* Algorithm array must fill rest of data. */
    if (length != OPAQUE16_LEN + len)
        return BUFFER_ERROR;

    /* Sig Algo list size must be even. */
    if (suites->hashSigAlgoSz % 2 != 0)
        return BUFFER_ERROR;

    /* truncate hashSigAlgo list if too long */
    suites->hashSigAlgoSz = len;
    if (suites->hashSigAlgoSz > WOLFSSL_MAX_SIGALGO) {
        WOLFSSL_MSG("TLSX SigAlgo list exceeds max, truncating");
        suites->hashSigAlgoSz = WOLFSSL_MAX_SIGALGO;
    }
    XMEMCPY(suites->hashSigAlgo, input, suites->hashSigAlgoSz);

    return TLSX_SignatureAlgorithms_MapPss(ssl, input, len);
}

/* Sets a new SignatureAlgorithms extension into the extension list.
 *
 * extensions  The list of extensions.
 * data        The extensions specific data.
 * heap        The heap used for allocation.
 * returns 0 on success, otherwise failure.
 */
static int TLSX_SetSignatureAlgorithms(TLSX** extensions, const void* data,
                                       void* heap)
{
    if (extensions == NULL)
        return BAD_FUNC_ARG;

    return TLSX_Push(extensions, TLSX_SIGNATURE_ALGORITHMS, data, heap);
}

#define SA_GET_SIZE  TLSX_SignatureAlgorithms_GetSize
#define SA_WRITE     TLSX_SignatureAlgorithms_Write
#define SA_PARSE     TLSX_SignatureAlgorithms_Parse
#endif
/******************************************************************************/
/* Signature Algorithms Certificate                                           */
/******************************************************************************/



/******************************************************************************/
/* Key Share                                                                  */
/******************************************************************************/


#define KS_FREE_ALL(a, b)
#define KS_GET_SIZE(a, b)    0
#define KS_WRITE(a, b, c)    0
#define KS_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Pre-Shared Key                                                             */
/******************************************************************************/


#define PSK_FREE_ALL(a, b)
#define PSK_GET_SIZE(a, b, c) 0
#define PSK_WRITE(a, b, c, d) 0
#define PSK_PARSE(a, b, c, d) 0


/******************************************************************************/
/* PSK Key Exchange Modes                                                     */
/******************************************************************************/


#define PKM_GET_SIZE(a, b, c) 0
#define PKM_WRITE(a, b, c, d) 0
#define PKM_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Post-Handshake Authentication                                              */
/******************************************************************************/


#define PHA_GET_SIZE(a, b)    0
#define PHA_WRITE(a, b, c)    0
#define PHA_PARSE(a, b, c, d) 0


/******************************************************************************/
/* Early Data Indication                                                      */
/******************************************************************************/


#define EDI_GET_SIZE(a, b)    0
#define EDI_WRITE(a, b, c, d) 0
#define EDI_PARSE(a, b, c, d) 0


/******************************************************************************/
/* TLS Extensions Framework                                                   */
/******************************************************************************/

/** Finds an extension in the provided list. */
TLSX* TLSX_Find(TLSX* list, TLSX_Type type)
{
    TLSX* extension = list;

    while (extension && extension->type != type)
        extension = extension->next;

    return extension;
}

/** Remove an extension. */
void TLSX_Remove(TLSX** list, TLSX_Type type, void* heap)
{
    TLSX* extension = *list;
    TLSX** next = list;

    while (extension && extension->type != type) {
        next = &extension->next;
        extension = extension->next;
    }

    if (extension) {
        *next = extension->next;
        extension->next = NULL;
        TLSX_FreeAll(extension, heap);
    }
}

/** Releases all extensions in the provided list. */
void TLSX_FreeAll(TLSX* list, void* heap)
{
    TLSX* extension;

    while ((extension = list)) {
        list = extension->next;

        switch (extension->type) {

            case TLSX_SERVER_NAME:
                SNI_FREE_ALL((SNI*)extension->data, heap);
                break;

            case TLSX_TRUSTED_CA_KEYS:
                TCA_FREE_ALL((TCA*)extension->data, heap);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                MFL_FREE_ALL(extension->data, heap);
                break;

            case TLSX_EXTENDED_MASTER_SECRET:
            case TLSX_TRUNCATED_HMAC:
                /* Nothing to do. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                EC_FREE_ALL((SupportedCurve*)extension->data, heap);
                break;

            case TLSX_EC_POINT_FORMATS:
                PF_FREE_ALL((PointFormat*)extension->data, heap);
                break;

            case TLSX_STATUS_REQUEST:
                CSR_FREE_ALL((CertificateStatusRequest*)extension->data, heap);
                break;

            case TLSX_STATUS_REQUEST_V2:
                CSR2_FREE_ALL((CertificateStatusRequestItemV2*)extension->data,
                        heap);
                break;

            case TLSX_RENEGOTIATION_INFO:
                SCR_FREE_ALL(extension->data, heap);
                break;

            case TLSX_SESSION_TICKET:
                WOLF_STK_FREE(extension->data, heap);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                ALPN_FREE_ALL((ALPN*)extension->data, heap);
                break;
#if !defined(WOLFSSL_NO_SIGALG)
            case TLSX_SIGNATURE_ALGORITHMS:
                break;
#endif
            case TLSX_ENCRYPT_THEN_MAC:
                break;
#ifdef WOLFSSL_SRTP
            case TLSX_USE_SRTP:
                SRTP_FREE((TlsxSrtp*)extension->data, heap);
                break;
#endif

            default:
                break;
        }

        XFREE(extension, heap, DYNAMIC_TYPE_TLSX);
    }

    (void)heap;
}

/** Checks if the tls extensions are supported based on the protocol version. */
int TLSX_SupportExtensions(WOLFSSL* ssl) {
    return ssl && (IsTLS(ssl) || ssl->version.major == DTLS_MAJOR);
}

/** Tells the buffered size of the extensions in a list. */
static int TLSX_GetSize(TLSX* list, byte* semaphore, byte msgType,
                        word16* pLength)
{
    int    ret = 0;
    TLSX*  extension;
    word16 length = 0;
    byte   isRequest = (msgType == client_hello ||
                        msgType == certificate_request);

    while ((extension = list)) {
        list = extension->next;

        /* only extensions marked as response are sent back to the client. */
        if (!isRequest && !extension->resp)
            continue; /* skip! */

        /* ssl level extensions are expected to override ctx level ones. */
        if (!IS_OFF(semaphore, TLSX_ToSemaphore(extension->type)))
            continue; /* skip! */

        /* extension type + extension data length. */
        length += HELLO_EXT_TYPE_SZ + OPAQUE16_LEN;

        switch (extension->type) {

            case TLSX_SERVER_NAME:
                /* SNI only sends the name on the request. */
                if (isRequest)
                    length += SNI_GET_SIZE((SNI*)extension->data);
                break;

            case TLSX_TRUSTED_CA_KEYS:
                /* TCA only sends the list on the request. */
                if (isRequest)
                    length += TCA_GET_SIZE((TCA*)extension->data);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                length += MFL_GET_SIZE(extension->data);
                break;

            case TLSX_EXTENDED_MASTER_SECRET:
            case TLSX_TRUNCATED_HMAC:
                /* always empty. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                length += EC_GET_SIZE((SupportedCurve*)extension->data);
                break;

            case TLSX_EC_POINT_FORMATS:
                length += PF_GET_SIZE((PointFormat*)extension->data);
                break;

            case TLSX_STATUS_REQUEST:
                length += CSR_GET_SIZE(
                         (CertificateStatusRequest*)extension->data, isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                length += CSR2_GET_SIZE(
                        (CertificateStatusRequestItemV2*)extension->data,
                        isRequest);
                break;

            case TLSX_RENEGOTIATION_INFO:
                length += SCR_GET_SIZE((SecureRenegotiation*)extension->data,
                        isRequest);
                break;

            case TLSX_SESSION_TICKET:
                length += WOLF_STK_GET_SIZE((SessionTicket*)extension->data,
                        isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                length += ALPN_GET_SIZE((ALPN*)extension->data);
                break;
#if !defined(WOLFSSL_NO_SIGALG)
            case TLSX_SIGNATURE_ALGORITHMS:
                length += SA_GET_SIZE(extension->data);
                break;
#endif
            case TLSX_ENCRYPT_THEN_MAC:
                ret = ETM_GET_SIZE(msgType, &length);
                break;
#ifdef WOLFSSL_SRTP
            case TLSX_USE_SRTP:
                length += SRTP_GET_SIZE((TlsxSrtp*)extension->data);
                break;
#endif
            default:
                break;
        }

        /* marks the extension as processed so ctx level */
        /* extensions don't overlap with ssl level ones. */
        TURN_ON(semaphore, TLSX_ToSemaphore(extension->type));
    }

    *pLength += length;

    return ret;
}

/** Writes the extensions of a list in a buffer. */
static int TLSX_Write(TLSX* list, byte* output, byte* semaphore,
                         byte msgType, word16* pOffset)
{
    int    ret = 0;
    TLSX*  extension;
    word16 offset = 0;
    word16 length_offset = 0;
    byte   isRequest = (msgType == client_hello ||
                        msgType == certificate_request);

    while ((extension = list)) {
        list = extension->next;

        /* only extensions marked as response are written in a response. */
        if (!isRequest && !extension->resp)
            continue; /* skip! */

        /* ssl level extensions are expected to override ctx level ones. */
        if (!IS_OFF(semaphore, TLSX_ToSemaphore(extension->type)))
            continue; /* skip! */

        /* writes extension type. */
        c16toa(extension->type, output + offset);
        offset += HELLO_EXT_TYPE_SZ + OPAQUE16_LEN;
        length_offset = offset;

        /* extension data should be written internally. */
        switch (extension->type) {
            case TLSX_SERVER_NAME:
                if (isRequest) {
                    WOLFSSL_MSG("SNI extension to write");
                    offset += SNI_WRITE((SNI*)extension->data, output + offset);
                }
                break;

            case TLSX_TRUSTED_CA_KEYS:
                WOLFSSL_MSG("Trusted CA Indication extension to write");
                if (isRequest) {
                    offset += TCA_WRITE((TCA*)extension->data, output + offset);
                }
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                WOLFSSL_MSG("Max Fragment Length extension to write");
                offset += MFL_WRITE((byte*)extension->data, output + offset);
                break;

            case TLSX_EXTENDED_MASTER_SECRET:
                WOLFSSL_MSG("Extended Master Secret");
                /* always empty. */
                break;

            case TLSX_TRUNCATED_HMAC:
                WOLFSSL_MSG("Truncated HMAC extension to write");
                /* always empty. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                WOLFSSL_MSG("Supported Groups extension to write");
                offset += EC_WRITE((SupportedCurve*)extension->data,
                                    output + offset);
                break;

            case TLSX_EC_POINT_FORMATS:
                WOLFSSL_MSG("Point Formats extension to write");
                offset += PF_WRITE((PointFormat*)extension->data,
                                    output + offset);
                break;

            case TLSX_STATUS_REQUEST:
                WOLFSSL_MSG("Certificate Status Request extension to write");
                offset += CSR_WRITE((CertificateStatusRequest*)extension->data,
                        output + offset, isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                WOLFSSL_MSG("Certificate Status Request v2 extension to write");
                offset += CSR2_WRITE(
                        (CertificateStatusRequestItemV2*)extension->data,
                        output + offset, isRequest);
                break;

            case TLSX_RENEGOTIATION_INFO:
                WOLFSSL_MSG("Secure Renegotiation extension to write");
                offset += SCR_WRITE((SecureRenegotiation*)extension->data,
                        output + offset, isRequest);
                break;

            case TLSX_SESSION_TICKET:
                WOLFSSL_MSG("Session Ticket extension to write");
                offset += WOLF_STK_WRITE((SessionTicket*)extension->data,
                        output + offset, isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                WOLFSSL_MSG("ALPN extension to write");
                offset += ALPN_WRITE((ALPN*)extension->data, output + offset);
                break;
#if !defined(WOLFSSL_NO_SIGALG)
            case TLSX_SIGNATURE_ALGORITHMS:
                WOLFSSL_MSG("Signature Algorithms extension to write");
                offset += SA_WRITE(extension->data, output + offset);
                break;
#endif
            case TLSX_ENCRYPT_THEN_MAC:
                WOLFSSL_MSG("Encrypt-Then-Mac extension to write");
                ret = ETM_WRITE(extension->data, output, msgType, &offset);
                break;
#ifdef WOLFSSL_SRTP
            case TLSX_USE_SRTP:
                offset += SRTP_WRITE((TlsxSrtp*)extension->data, output+offset);
                break;
#endif
            default:
                break;
        }

        /* writes extension data length. */
        c16toa(offset - length_offset, output + length_offset - OPAQUE16_LEN);

        /* marks the extension as processed so ctx level */
        /* extensions don't overlap with ssl level ones. */
        TURN_ON(semaphore, TLSX_ToSemaphore(extension->type));
    }

    *pOffset += offset;

    return ret;
}


/* Populates the default supported groups / curves */
static int TLSX_PopulateSupportedGroups(WOLFSSL* ssl, TLSX** extensions)
{
    int ret = WOLFSSL_SUCCESS;

        /* list in order by strength, since not all servers choose by strength */
        #if ECC_MIN_KEY_SZ <= 521
                ret = TLSX_UseSupportedCurve(extensions,
                                              WOLFSSL_ECC_SECP521R1, ssl->heap);
                if (ret != WOLFSSL_SUCCESS) return ret;
        #endif
        #if ECC_MIN_KEY_SZ <= 384
                ret = TLSX_UseSupportedCurve(extensions,
                                              WOLFSSL_ECC_SECP384R1, ssl->heap);
                if (ret != WOLFSSL_SUCCESS) return ret;
        #endif

        #ifndef HAVE_FIPS
        #endif /* HAVE_FIPS */

        #if ECC_MIN_KEY_SZ <= 256
                ret = TLSX_UseSupportedCurve(extensions,
                                              WOLFSSL_ECC_SECP256R1, ssl->heap);
                if (ret != WOLFSSL_SUCCESS) return ret;
        #endif

        #ifndef HAVE_FIPS
        #endif /* HAVE_FIPS */

        #if ECC_MIN_KEY_SZ <= 224
                ret = TLSX_UseSupportedCurve(extensions,
                                              WOLFSSL_ECC_SECP224R1, ssl->heap);
                if (ret != WOLFSSL_SUCCESS) return ret;
        #endif

    #ifndef HAVE_FIPS
    #endif /* HAVE_FIPS */

            /* Add FFDHE supported groups. */
        #ifdef HAVE_FFDHE_8192
            if (8192/8 >= ssl->options.minDhKeySz &&
                                            8192/8 <= ssl->options.maxDhKeySz) {
                ret = TLSX_UseSupportedCurve(extensions,
                                             WOLFSSL_FFDHE_8192, ssl->heap);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }
        #endif
        #ifdef HAVE_FFDHE_6144
            if (6144/8 >= ssl->options.minDhKeySz &&
                                            6144/8 <= ssl->options.maxDhKeySz) {
                ret = TLSX_UseSupportedCurve(extensions,
                                             WOLFSSL_FFDHE_6144, ssl->heap);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }
        #endif
        #ifdef HAVE_FFDHE_4096
            if (4096/8 >= ssl->options.minDhKeySz &&
                                            4096/8 <= ssl->options.maxDhKeySz) {
                ret = TLSX_UseSupportedCurve(extensions,
                                             WOLFSSL_FFDHE_4096, ssl->heap);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }
        #endif
        #ifdef HAVE_FFDHE_3072
            if (3072/8 >= ssl->options.minDhKeySz &&
                                            3072/8 <= ssl->options.maxDhKeySz) {
                ret = TLSX_UseSupportedCurve(extensions,
                                             WOLFSSL_FFDHE_3072, ssl->heap);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }
        #endif
            if (2048/8 >= ssl->options.minDhKeySz &&
                                            2048/8 <= ssl->options.maxDhKeySz) {
                ret = TLSX_UseSupportedCurve(extensions,
                                             WOLFSSL_FFDHE_2048, ssl->heap);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }


    (void)ssl;
    (void)extensions;

    return ret;
}



int TLSX_PopulateExtensions(WOLFSSL* ssl, byte isServer)
{
    int ret = 0;
    byte* public_key      = NULL;
    word16 public_key_len = 0;

    /* server will add extension depending on what is parsed from client */
    if (!isServer) {
        if (!ssl->options.disallowEncThenMac) {
            ret = TLSX_EncryptThenMac_Use(ssl);
            if (ret != 0)
                return ret;
        }

        if (!ssl->options.userCurves && !ssl->ctx->userCurves) {
            if (TLSX_Find(ssl->ctx->extensions,
                                               TLSX_SUPPORTED_GROUPS) == NULL) {
                ret = TLSX_PopulateSupportedGroups(ssl, &ssl->extensions);
                if (ret != WOLFSSL_SUCCESS)
                    return ret;
            }
        }
        if ((!IsAtLeastTLSv1_3(ssl->version) || ssl->options.downgrade) &&
               TLSX_Find(ssl->ctx->extensions, TLSX_EC_POINT_FORMATS) == NULL &&
               TLSX_Find(ssl->extensions, TLSX_EC_POINT_FORMATS) == NULL) {
             ret = TLSX_UsePointFormat(&ssl->extensions,
                                         WOLFSSL_EC_PF_UNCOMPRESSED, ssl->heap);
             if (ret != WOLFSSL_SUCCESS)
                 return ret;
        }

#ifdef WOLFSSL_SRTP
        if (ssl->options.dtls && ssl->dtlsSrtpProfiles != 0) {
            WOLFSSL_MSG("Adding DTLS SRTP extension");
            if ((ret = TLSX_UseSRTP(&ssl->extensions, ssl->dtlsSrtpProfiles,
                                                                ssl->heap)) != 0) {
                return ret;
            }
        }
#endif
    } /* is not server */

#if !defined(WOLFSSL_NO_SIGALG)
    WOLFSSL_MSG("Adding signature algorithms extension");
    if ((ret = TLSX_SetSignatureAlgorithms(&ssl->extensions, ssl, ssl->heap))
                                                                         != 0) {
            return ret;
    }
#else
    ret = 0;
#endif

    (void)isServer;
    (void)public_key;
    (void)public_key_len;
    (void)ssl;

    return ret;
}



/** Tells the buffered size of extensions to be sent into the client hello. */
int TLSX_GetRequestSize(WOLFSSL* ssl, byte msgType, word16* pLength)
{
    int ret = 0;
    word16 length = 0;
    byte semaphore[SEMAPHORE_SIZE] = {0};

    if (!TLSX_SupportExtensions(ssl))
        return 0;
    if (msgType == client_hello) {
        EC_VALIDATE_REQUEST(ssl, semaphore);
        PF_VALIDATE_REQUEST(ssl, semaphore);
        WOLF_STK_VALIDATE_REQUEST(ssl);
#if !defined(WOLFSSL_NO_SIGALG)
        if (ssl->suites->hashSigAlgoSz == 0)
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_SIGNATURE_ALGORITHMS));
#endif
    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
        if (!SSL_CM(ssl)->ocspStaplingEnabled) {
            /* mark already sent, so it won't send it */
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_STATUS_REQUEST));
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_STATUS_REQUEST_V2));
        }
    #endif
    }

    if (ssl->extensions) {
        ret = TLSX_GetSize(ssl->extensions, semaphore, msgType, &length);
        if (ret != 0)
            return ret;
    }
    if (ssl->ctx && ssl->ctx->extensions) {
        ret = TLSX_GetSize(ssl->ctx->extensions, semaphore, msgType, &length);
        if (ret != 0)
            return ret;
    }

    if (msgType == client_hello && ssl->options.haveEMS &&
                  (!IsAtLeastTLSv1_3(ssl->version) || ssl->options.downgrade)) {
        length += HELLO_EXT_SZ;
    }

    if (length)
        length += OPAQUE16_LEN; /* for total length storage. */

    *pLength += length;

    return ret;
}

/** Writes the extensions to be sent into the client hello. */
int TLSX_WriteRequest(WOLFSSL* ssl, byte* output, byte msgType, word16* pOffset)
{
    int ret = 0;
    word16 offset = 0;
    byte semaphore[SEMAPHORE_SIZE] = {0};

    if (!TLSX_SupportExtensions(ssl) || output == NULL)
        return 0;

    offset += OPAQUE16_LEN; /* extensions length */

    if (msgType == client_hello) {
        EC_VALIDATE_REQUEST(ssl, semaphore);
        PF_VALIDATE_REQUEST(ssl, semaphore);
        WOLF_STK_VALIDATE_REQUEST(ssl);
#if !defined(WOLFSSL_NO_SIGALG)
        if (ssl->suites->hashSigAlgoSz == 0)
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_SIGNATURE_ALGORITHMS));
#endif
    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
         /* mark already sent, so it won't send it */
        if (!SSL_CM(ssl)->ocspStaplingEnabled) {
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_STATUS_REQUEST));
            TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_STATUS_REQUEST_V2));
        }
    #endif
    }
    if (ssl->extensions) {
        ret = TLSX_Write(ssl->extensions, output + offset, semaphore,
                         msgType, &offset);
        if (ret != 0)
            return ret;
    }
    if (ssl->ctx && ssl->ctx->extensions) {
        ret = TLSX_Write(ssl->ctx->extensions, output + offset, semaphore,
                         msgType, &offset);
        if (ret != 0)
            return ret;
    }

    if (msgType == client_hello && ssl->options.haveEMS &&
                  (!IsAtLeastTLSv1_3(ssl->version) || ssl->options.downgrade)) {
        WOLFSSL_MSG("EMS extension to write");
        c16toa(HELLO_EXT_EXTMS, output + offset);
        offset += HELLO_EXT_TYPE_SZ;
        c16toa(0, output + offset);
        offset += HELLO_EXT_SZ_SZ;
    }


    if (offset > OPAQUE16_LEN || msgType != client_hello)
        c16toa(offset - OPAQUE16_LEN, output); /* extensions length */

     *pOffset += offset;

    return ret;
}




/** Parses a buffer of TLS extensions. */
int TLSX_Parse(WOLFSSL* ssl, const byte* input, word16 length, byte msgType,
                                                                 Suites *suites)
{
    int ret = 0;
    word16 offset = 0;
    byte isRequest = (msgType == client_hello ||
                      msgType == certificate_request);

    byte pendingEMS = 0;

    if (!ssl || !input || (isRequest && !suites))
        return BAD_FUNC_ARG;

    while (ret == 0 && offset < length) {
        word16 type;
        word16 size;


        if (length - offset < HELLO_EXT_TYPE_SZ + OPAQUE16_LEN)
            return BUFFER_ERROR;

        ato16(input + offset, &type);
        offset += HELLO_EXT_TYPE_SZ;

        ato16(input + offset, &size);
        offset += OPAQUE16_LEN;

        if (length - offset < size)
            return BUFFER_ERROR;

        switch (type) {
            case TLSX_SERVER_NAME:
                WOLFSSL_MSG("SNI extension received");

                ret = SNI_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_TRUSTED_CA_KEYS:
                WOLFSSL_MSG("Trusted CA extension received");

                ret = TCA_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                WOLFSSL_MSG("Max Fragment Length extension received");

                ret = MFL_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_TRUNCATED_HMAC:
                WOLFSSL_MSG("Truncated HMAC extension received");

                ret = THM_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_SUPPORTED_GROUPS:
                WOLFSSL_MSG("Supported Groups extension received");

                ret = EC_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_EC_POINT_FORMATS:
                WOLFSSL_MSG("Point Formats extension received");

                ret = PF_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_STATUS_REQUEST:
                WOLFSSL_MSG("Certificate Status Request extension received");

                ret = CSR_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                WOLFSSL_MSG("Certificate Status Request v2 extension received");

                ret = CSR2_PARSE(ssl, input + offset, size, isRequest);
                break;

            case HELLO_EXT_EXTMS:
                WOLFSSL_MSG("Extended Master Secret extension received");

                if (size != 0)
                    return BUFFER_ERROR;

                pendingEMS = 1;
                break;

            case TLSX_RENEGOTIATION_INFO:
                WOLFSSL_MSG("Secure Renegotiation extension received");

                ret = SCR_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_SESSION_TICKET:
                WOLFSSL_MSG("Session Ticket extension received");

                ret = WOLF_STK_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                WOLFSSL_MSG("ALPN extension received");


                ret = ALPN_PARSE(ssl, input + offset, size, isRequest);
                break;
#if !defined(WOLFSSL_NO_SIGALG)
            case TLSX_SIGNATURE_ALGORITHMS:
                WOLFSSL_MSG("Signature Algorithms extension received");

                if (!IsAtLeastTLSv1_2(ssl))
                    break;
                ret = SA_PARSE(ssl, input + offset, size, isRequest, suites);
                break;
#endif

            case TLSX_ENCRYPT_THEN_MAC:
                WOLFSSL_MSG("Encrypt-Then-Mac extension received");

                /* Ignore for TLS 1.3+ */
                if (IsAtLeastTLSv1_3(ssl->version))
                    break;

                ret = ETM_PARSE(ssl, input + offset, size, msgType);
                break;

#ifdef WOLFSSL_SRTP
            case TLSX_USE_SRTP:
                WOLFSSL_MSG("Use SRTP extension received");
                ret = SRTP_PARSE(ssl, input + offset, size, isRequest);
                break;
#endif
            default:
                WOLFSSL_MSG("Unknown TLS extension type");
        }

        /* offset should be updated here! */
        offset += size;
    }

    if (IsAtLeastTLSv1_3(ssl->version) && msgType == hello_retry_request) {
        /* Don't change EMS status until server_hello received.
         * Second ClientHello must have same extensions.
         */
    }
    else if (!isRequest && ssl->options.haveEMS && !pendingEMS)
        ssl->options.haveEMS = 0;

    if (ret == 0)
        ret = SNI_VERIFY_PARSE(ssl, isRequest);
    if (ret == 0)
        ret = TCA_VERIFY_PARSE(ssl, isRequest);

    return ret;
}

/* undefining semaphore macros */
#undef IS_OFF
#undef TURN_ON
#undef SEMAPHORE_SIZE



    WOLFSSL_METHOD* wolfTLS_client_method(void)
    {
        return wolfTLS_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfTLS_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("TLS_client_method_ex");
        if (method) {
            InitSSL_Method(method, MakeTLSv1_2());

            method->downgrade = 1;
            method->side      = WOLFSSL_CLIENT_END;
        }
        return method;
    }

    #ifdef WOLFSSL_ALLOW_TLSV10
    WOLFSSL_METHOD* wolfTLSv1_client_method(void)
    {
        return wolfTLSv1_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfTLSv1_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                             (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("TLSv1_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeTLSv1());
        return method;
    }
    #endif /* WOLFSSL_ALLOW_TLSV10 */

    WOLFSSL_METHOD* wolfTLSv1_1_client_method(void)
    {
        return wolfTLSv1_1_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfTLSv1_1_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("TLSv1_1_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeTLSv1_1());
        return method;
    }

    WOLFSSL_ABI
    WOLFSSL_METHOD* wolfTLSv1_2_client_method(void)
    {
        return wolfTLSv1_2_client_method_ex(NULL);
    }
    WOLFSSL_METHOD* wolfTLSv1_2_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        WOLFSSL_ENTER("TLSv1_2_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeTLSv1_2());
        return method;
    }





/* EITHER SIDE METHODS */



#endif /* WOLFCRYPT_ONLY */
