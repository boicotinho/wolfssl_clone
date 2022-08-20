/* asn.c
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

/*
 * DESCRIPTION
 * This library provides the interface to Abstract Syntax Notation One (ASN.1)
 * objects.
 * ASN.1 is a standard interface description language for defining data
 * structures that can be serialized and deserialized in a cross-platform way.
 *
 * Encoding of ASN.1 is either using Basic Encoding Rules (BER) or
 * Distinguished Encoding Rules (DER). DER has only one possible encoding for a
 * ASN.1 description and the data.
 * Encode using DER and decode BER or DER.
 *
 * Provides routines to convert BER into DER. Replaces indefinite length
 * encoded items with explicit lengths.
 */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
ASN Options:
 * NO_ASN_TIME: Disables time parts of the ASN code for systems without an RTC
    or wishing to save space.
 * IGNORE_NAME_CONSTRAINTS: Skip ASN name checks.
 * ASN_DUMP_OID: Allows dump of OID information for debugging.
 * RSA_DECODE_EXTRA: Decodes extra information in RSA public key.
 * WOLFSSL_CERT_GEN: Cert generation. Saves extra certificate info in GetName.
 * WOLFSSL_NO_ASN_STRICT: Disable strict RFC compliance checks to
    restore 3.13.0 behavior.
 * WOLFSSL_NO_OCSP_OPTIONAL_CERTS: Skip optional OCSP certs (responder issuer
    must still be trusted)
 * WOLFSSL_NO_TRUSTED_CERTS_VERIFY: Workaround for situation where entire cert
    chain is not loaded. This only matches on subject and public key and
    does not perform a PKI validation, so it is not a secure solution.
    Only enabled for OCSP.
 * WOLFSSL_NO_OCSP_ISSUER_CHECK: Can be defined for backwards compatibility to
    disable checking of OCSP subject hash with issuer hash.
 * WOLFSSL_SMALL_CERT_VERIFY: Verify the certificate signature without using
    DecodedCert. Doubles up on some code but allows smaller dynamic memory
    usage.
 * WOLFSSL_NO_OCSP_DATE_CHECK: Disable date checks for OCSP responses. This
    may be required when the system's real-time clock is not very accurate.
    It is recommended to enforce the nonce check instead if possible.
 * WOLFSSL_FORCE_OCSP_NONCE_CHECK: Require nonces to be available in OCSP
    responses. The nonces are optional and may not be supported by all
    responders. If it can be ensured that the used responder sends nonces this
    option may improve security.
 * WOLFSSL_ASN_TEMPLATE: Encoding and decoding using a template.
 * WOLFSSL_DEBUG_ASN_TEMPLATE: Enables debugging output when using ASN.1
    templates.
 * WOLFSSL_ASN_TEMPLATE_TYPE_CHECK: Use ASN functions to better test compiler
    type issues for testing
 * CRLDP_VALIDATE_DATA: For ASN template only, validates the reason data
 * WOLFSSL_AKID_NAME: Enable support for full AuthorityKeyIdentifier extension.
    Only supports copying full AKID from an existing certificate.
 * WOLFSSL_CUSTOM_OID: Enable custom OID support for subject and request
    extensions
 * WOLFSSL_HAVE_ISSUER_NAMES: Store pointers to issuer name components and their
    lengths and encodings.
*/

#ifndef NO_ASN

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/md2.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rc2.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>


    #include <wolfssl/wolfcrypt/sha512.h>

    #include <wolfssl/wolfcrypt/sha256.h>

    #include <wolfssl/wolfcrypt/ecc.h>





#if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
    #include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

    #include <wolfssl/wolfcrypt/rsa.h>
#if defined(WOLFSSL_XILINX_CRYPT)
extern int wc_InitRsaHw(RsaKey* key);
#endif

    typedef void* DsaKey;





#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

#if !defined(NO_SKID)
    #ifndef WOLFSSL_AES_KEY_SIZE_ENUM
    #define WOLFSSL_AES_KEY_SIZE_ENUM
    enum Asn_Misc {
        AES_IV_SIZE         = 16,
        AES_128_KEY_SIZE    = 16,
        AES_192_KEY_SIZE    = 24,
        AES_256_KEY_SIZE    = 32
    };
    #endif
#endif


/* Calculates the minimum number of bytes required to encode the value.
 *
 * @param [in] value  Value to be encoded.
 * @return  Number of bytes to encode value.
 */
static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = (word32)sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}

/* DER encodes the length value in output buffer.
 *
 *    0 ->  2^7-1: <len byte>.
 *  2^7 ->       : <0x80 + #bytes> <len big-endian bytes>
 *
 * @param [in]      length  Value to encode.
 * @param [in, out] output  Buffer to encode into.
 * @return  Number of bytes used in encoding.
 */
WOLFSSL_LOCAL word32 SetASNLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* Calculate the size of a DER encoded length value.
 *
 *    0 ->  2^7-1: <length byte>.
 *  2^7 ->       : <0x80 + #bytes> <big-endian length bytes>
 *
 * @param [in] length  Value to encode.
 * @return  Number of bytes required to encode.
 */
static word32 SizeASNLength(word32 length)
{
    return 1 + ((length >= ASN_LONG_LENGTH) ? BytePrecision(length) : 0);
}

/* Calculate the size of a DER encoded header.
 *
 * Header = Tag | Encoded length
 *
 * @param [in] length  Length value to encode.
 * @return  Number of bytes required to encode a DER header.
 */
#define SizeASNHeader(length) \
    (1 + SizeASNLength(length))
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
    /* Declare the variable that is the dynamic data for decoding BER data.
     *
     * @param [in] name  Variable name to declare.
     * @param [in] cnt   Number of elements required.
     */
    #define DECL_ASNGETDATA(name, cnt)                  \
        ASNGetData name[cnt]

    /* No implementation as declartion is static.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      cnt   Number of elements required.
     * @param [in, out] err   Error variable.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define ALLOC_ASNGETDATA(name, cnt, err, heap)

    /* Clears the memory of the dynamic BER encoding data.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      cnt   Number of elements required.
     * @param [in, out] err   Error variable.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define CALLOC_ASNGETDATA(name, cnt, err, heap)     \
        XMEMSET(name, 0, sizeof(name))

    /* No implementation as declartion is static.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define FREE_ASNGETDATA(name, heap)

    /* Declare the variable that is the dynamic data for encoding DER data.
     *
     * @param [in] name  Variable name to declare.
     * @param [in] cnt   Number of elements required.
     */
    #define DECL_ASNSETDATA(name, cnt)                  \
        ASNSetData name[cnt]

    /* No implementation as declartion is static.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      cnt   Number of elements required.
     * @param [in, out] err   Error variable.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define ALLOC_ASNSETDATA(name, cnt, err, heap)

    /* Clears the memory of the dynamic BER encoding data.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      cnt   Number of elements required.
     * @param [in, out] err   Error variable.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define CALLOC_ASNSETDATA(name, cnt, err, heap)     \
        XMEMSET(name, 0, sizeof(name))

    /* No implementation as declartion is static.
     *
     * @param [in]      name  Variable name to declare.
     * @param [in]      heap  Dynamic memory allocation hint.
     */
    #define FREE_ASNSETDATA(name, heap)


    /* Enable this when debugging the parsing or creation of ASN.1 data. */
    #if 0
        #define WOLFSSL_DEBUG_ASN_TEMPLATE
    #endif

#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
/* String representations of tags. */
static const char* tagString[4][32] = {
    /* Universal */
    {
        "EOC",
        "BOOLEAN",
        "INTEGER",
        "BIT STRING",
        "OCTET STRING",
        "NULL",
        "OBJECT ID",
        "ObjectDescriptor",
        "INSTANCE OF",
        "REAL",
        "ENUMERATED",
        "EMBEDDED PDV",
        "UT8String",
        "RELATIVE-OID",
        "(0x0e) 14",
        "(0x0f) 15",
        "SEQUENCE",
        "SET",
        "NumericString",
        "PrintableString",
        "T61String",
        "VideotexString",
        "IA5String",
        "UTCTime",
        "GeneralizedTime",
        "GraphicString",
        "ISO646String",
        "GeneralString",
        "UniversalString",
        "CHARACTER STRING",
        "BMPString",
        "(0x1f) 31",
    },
    /* Application */
    {
         "[A 0]",  "[A 1]",  "[A 2]",  "[A 3]",
         "[A 4]",  "[A 5]",  "[A 6]",  "[A 7]",
         "[A 8]",  "[A 9]", "[A 10]", "[A 11]",
        "[A 12]", "[A 13]", "[A 14]", "[A 15]",
        "[A 16]", "[A 17]", "[A 18]", "[A 19]",
        "[A 20]", "[A 21]", "[A 22]", "[A 23]",
        "[A 24]", "[A 25]", "[A 26]", "[A 27]",
        "[A 28]", "[A 20]", "[A 30]", "[A 31]"
    },
    /* Context-Specific */
    {
         "[0]",  "[1]",  "[2]",  "[3]",  "[4]",  "[5]",  "[6]",  "[7]",
         "[8]",  "[9]", "[10]", "[11]", "[12]", "[13]", "[14]", "[15]",
        "[16]", "[17]", "[18]", "[19]", "[20]", "[21]", "[22]", "[23]",
        "[24]", "[25]", "[26]", "[27]", "[28]", "[20]", "[30]", "[31]"
    },
    /* Private */
    {
         "[P 0]",  "[P 1]",  "[P 2]",  "[P 3]",
         "[P 4]",  "[P 5]",  "[P 6]",  "[P 7]",
         "[P 8]",  "[P 9]", "[P 10]", "[P 11]",
        "[P 12]", "[P 13]", "[P 14]", "[P 15]",
        "[P 16]", "[P 17]", "[P 18]", "[P 19]",
        "[P 20]", "[P 21]", "[P 22]", "[P 23]",
        "[P 24]", "[P 25]", "[P 26]", "[P 27]",
        "[P 28]", "[P 20]", "[P 30]", "[P 31]"
    }
};

/* Converts a tag byte to string.
 *
 * @param [in] tag  BER tag value to interpret.
 * @return  String corresponding to tag.
 */
static const char* TagString(byte tag)
{
    return tagString[tag >> 6][tag & ASN_TYPE_MASK];
}

#include <stdarg.h>

/* Log a message that has the printf format string.
 *
 * @param [in] <va_args>  printf style arguments.
 */
#define WOLFSSL_MSG_VSNPRINTF(...)                    \
    do {                                              \
      char line[81];                                  \
      snprintf(line, sizeof(line) - 1, __VA_ARGS__);  \
      line[sizeof(line) - 1] = '\0';                  \
      WOLFSSL_MSG(line);                              \
    }                                                 \
    while (0)
#endif

/* Returns whether ASN.1 item is an integer and the Most-Significant Bit is set.
 *
 * @param [in] asn     ASN.1 items to encode.
 * @param [in] data_a  Data to place in each item. Lengths set were not known.
 * @param [in] i       Index of item to check.
 * @return  1 when ASN.1 item is an integer and MSB is 1.
 * @erturn  0 otherwise.
 */
#define ASNIntMSBSet(asn, data_a, i)                  \
    (((asn)[i].tag == ASN_INTEGER) &&                 \
      ((data_a)[i].data.buffer.data != NULL &&        \
      ((data_a)[i].data.buffer.data[0] & 0x80) == 0x80))


/* Calculate the size of a DER encoded number.
 *
 * @param [in] n     Number to be encoded.
 * @param [in] bits  Maximum number of bits to encode.
 * @param [in] tag   BER tag e.g. INTEGER, BIT_STRING, etc.
 * @return  Number of bytes to the ASN.1 item.
 */
static word32 SizeASN_Num(word32 n, int bits, byte tag)
{
    int    j;
    word32 len;

    len = 1 + 1 + bits / 8;
    /* Discover actual size by checking for high zeros. */
    for (j = bits - 8; j > 0; j -= 8) {
        if (n >> j)
            break;
        len--;
    }
    if (tag == ASN_BIT_STRING)
        len++;
    else if ((tag == ASN_INTEGER) && (((n >> j) & 0x80) == 0x80))
        len++;

    return len;
}

/* Calculate the size of the data in the constructed item based on the
 * length of the ASN.1 items below.
 *
 * @param [in]      asn    ASN.1 items to encode.
 * @param [in, out] data   Data to place in each item. Lengths set were not
 *                         known.
 * @param [in]      idx    Index of item working on.
 */
static void SizeASN_CalcDataLength(const ASNItem* asn, ASNSetData *data,
                                   int idx, int max)
{
    int j;

    data[idx].data.buffer.length = 0;
    /* Sum the item length of all items underneath. */
    for (j = idx + 1; j < max; j++) {
        /* Stop looking if the next ASN.1 is same level or higher. */
        if (asn[j].depth <= asn[idx].depth)
            break;
        /* Only add in length if it is one level below. */
        if (asn[j].depth - 1 == asn[idx].depth) {
            data[idx].data.buffer.length += data[j].length;
            /* The length of a header only item doesn't include the data unless
             * a replacement buffer is supplied.
             */
            if (asn[j].headerOnly && data[j].data.buffer.data == NULL &&
                    data[j].dataType != ASN_DATA_TYPE_REPLACE_BUFFER) {
                data[idx].data.buffer.length += data[j].data.buffer.length;
            }
        }
    }
}

/* Calculate the size of the DER encoding.
 *
 * Call SetASN_Items() to write encoding to a buffer.
 *
 * @param [in]      asn    ASN.1 items to encode.
 * @param [in, out] data   Data to place in each item. Lengths set were not
 *                         known.
 * @param [in]      count  Count of items to encode.
 * @param [out]     encSz  Length of the DER encoding.
 * @return  0 on success.
 * @return  BAD_STATE_E when the data type is not supported.
 */
int SizeASN_Items(const ASNItem* asn, ASNSetData *data, int count, int* encSz)
{
    int    i;
    word32 sz = 0;
    word32 len;
    word32 dataLen;
    int    length;

#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
    WOLFSSL_ENTER("SizeASN_Items");
#endif

    for (i = count - 1; i >= 0; i--) {
        /* Skip this ASN.1 item when encoding. */
        if (data[i].noOut) {
            /* Set the offset to the current size - used in writing DER. */
            data[i].offset = sz;
            continue;
        }

        len = 0;
        switch (data[i].dataType) {
            /* Calculate the size of the number of different sizes. */
            case ASN_DATA_TYPE_WORD8:
                len = SizeASN_Num(data[i].data.u8, 8, asn[i].tag);
                break;
            case ASN_DATA_TYPE_WORD16:
                len = SizeASN_Num(data[i].data.u16, 16, asn[i].tag);
                break;
        #ifdef WOLFSSL_ASN_TEMPLATE_NEED_SET_INT32
            /* Not used yet! */
            case ASN_DATA_TYPE_WORD32:
                len = SizeASN_Num(data[i].data.u32, 32, asn[i].tag);
                break;
        #endif

            case ASN_DATA_TYPE_MP:
                /* Calculate the size of the MP integer data. */
                length = mp_unsigned_bin_size(data[i].data.mp);
                length += mp_leading_bit(data[i].data.mp) ? 1 : 0;
                len = SizeASNHeader(length) + length;
                break;

            case ASN_DATA_TYPE_REPLACE_BUFFER:
                /* Buffer is put in directly - use the length. */
                len = data[i].data.buffer.length;
                break;

            case ASN_DATA_TYPE_NONE:
                /* Calculate the size based on the data to be included.
                 * Mostly used for constructed items.
                 */
                if (asn[i].headerOnly) {
                    if (data[i].data.buffer.data != NULL) {
                        /* Force all child nodes to be ignored. Buffer
                         * overwrites children. */
                        {
                            int ii;
                            for (ii = i + 1; ii < count; ii++) {
                                if (asn[ii].depth <= asn[i].depth)
                                    break;
                                sz -= data[ii].length;
                                data[ii].noOut = 1;
                            }
                        }
                    }
                    else {
                        /* Calculate data length from items below if no buffer
                         * supplied. */
                        SizeASN_CalcDataLength(asn, data, i, count);
                    }
                }
                if (asn[i].tag == ASN_BOOLEAN) {
                    dataLen = 1;
                }
                else {
                    dataLen = data[i].data.buffer.length;
                }
                /* BIT_STRING and INTEGER have one byte prepended. */
                if ((asn[i].tag == ASN_BIT_STRING) ||
                                                   ASNIntMSBSet(asn, data, i)) {
                    dataLen++;
                    /* ASN.1 items are below and cannot include extra byte. */
                    if (asn[i].headerOnly) {
                        len++;
                    }
                }
                /* Add in the size of tag and length. */
                len += SizeASNHeader(dataLen);
                /* Include data in length if not header only or if
                 * buffer supplied. */
                if (!asn[i].headerOnly || data[i].data.buffer.data != NULL) {
                    len += dataLen;
                }
                break;

            default:
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("%2d: %d", i, data[i].dataType);
                WOLFSSL_MSG("Bad data type");
            #endif
                return BAD_STATE_E;
        }

        /* Set the total length of the item. */
        data[i].length = len;
        /* Add length to total size. */
        sz += len;
        /* Set the offset to the current size - used in writing DER. */
        data[i].offset = sz;

    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG_VSNPRINTF("%2d: %4d %4d %c %*s %-16s", i,
                data[i].offset, data[i].length, asn[i].constructed ? '+' : ' ',
                asn[i].depth, "", TagString(asn[i].tag));
    #endif
    }

    *encSz = sz;
    return 0;
}

/* Create the DER encoding of a number.
 *
 * Assumes that the out buffer is large enough for encoding.
 *
 * @param [in] n     Number to be encoded.
 * @param [in] bits  Maximum number of bits to encode.
 * @param [in] tag   DER tag e.g. INTEGER, BIT_STRING, etc.
 */
static void SetASN_Num(word32 n, int bits, byte* out, byte tag)
{
    int    j;
    word32 idx;
    byte   len;

    /* Encoding: Tag (1 byte) | Length (1 byte) | Data (number) */

    /* Data will start at index 2 unless BIT_STRING or INTEGER */
    idx = 2;

    /* Set the length of the number based on maximum bit length. */
    len = bits / 8;
    /* Discover actual size by checking for leading zero bytes. */
    for (j = bits - 8; j > 0; j -= 8) {
        if ((n >> j) != 0) {
            break;
        }
        len--;
    }
    /* Keep j, index of first non-zero byte, for writing out. */

    /* A BIT_STRING has the number of unused bits in last byte prepended to
     * data.
     */
    if (tag == ASN_BIT_STRING) {
        byte unusedBits = 0;
        byte lastByte = n >> j;

        /* Quick check last bit. */
        if ((lastByte & 0x01) == 0x00) {
            unusedBits++;
            /* Check each bit for first least significant bit set. */
            while (((lastByte >> unusedBits) & 0x01) == 0x00)
                unusedBits++;
        }
        /* Add unused bits byte. */
        len++;
        out[idx++] = unusedBits;
    }

    /* An INTEGER has a prepended byte if MSB of number is 1 - makes encoded
     * value positive. */
    if ((tag == ASN_INTEGER) && (((n >> j) & 0x80) == 0x80)) {
        len++;
        out[idx++] = 0;
    }

    /* Go back and put in length. */
    out[1] = len;
    /* Place in the required bytes of the number. */
    for (; j >= 0; j -= 8)
        out[idx++] = n >> j;
}

/* Creates the DER encoding of the ASN.1 items.
 *
 * Assumes the output buffer is large enough to hold encoding.
 * Must call SizeASN_Items() to determine size of encoding and offsets.
 *
 * @param [in]      asn     ASN.1 items to encode.
 * @param [in]      data    Data to place in each item.
 * @param [in]      count   Count of items to encode.
 * @param [in, out] output  Buffer to write encoding into.
 * @return  Size of the DER encoding in bytes.
 */
int SetASN_Items(const ASNItem* asn, ASNSetData *data, int count, byte* output)
{
    int    i;
    int    length;
    int    err;
    word32 sz;
    word32 idx;
    byte*  out;

#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
    WOLFSSL_ENTER("SetASN_Items");
#endif

    /* Offset of first item is the total length.
     * SizeASN_Items() calculated this. */
    sz = data[0].offset;

    /* Write out each item. */
    for (i = 0; i < count; i++) {
        /* Skip items not writing out. */
        if (data[i].noOut)
            continue;

        /* Start position to write item based on reverse offsets. */
        out = output + sz - data[i].offset;
        /* Index from start of item out. */
        idx = 0;

        if (data[i].dataType != ASN_DATA_TYPE_REPLACE_BUFFER) {
            /* Put in the tag - not dumping in DER from buffer. */
            out[idx++] = asn[i].tag |
                         (asn[i].constructed ? ASN_CONSTRUCTED : 0);
        }

    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG_VSNPRINTF("%2d: %4d %4d %c %*s %-16s", i,
                sz - data[i].offset,
                data[i].length, asn[i].constructed ? '+' : ' ', asn[i].depth,
                "", TagString(asn[i].tag));
    #endif

        switch (data[i].dataType) {
            /* Write out the length and data of a number. */
            case ASN_DATA_TYPE_WORD8:
                SetASN_Num(data[i].data.u8, 8, out, asn[i].tag);
                break;
            case ASN_DATA_TYPE_WORD16:
                SetASN_Num(data[i].data.u16, 16, out, asn[i].tag);
                break;
        #ifdef WOLFSSL_ASN_TEMPLATE_NEED_SET_INT32
            /* Not used yet! */
            case ASN_DATA_TYPE_WORD32:
                SetASN_Num(data[i].data.u32, 32, out, asn[i].tag);
                break;
        #endif

            /* Write out the length and data of a multi-precision number. */
            case ASN_DATA_TYPE_MP:
                /* Get length in bytes. */
                length = mp_unsigned_bin_size(data[i].data.mp);
                /* Add one for leading zero to make encoding a positive num. */
                length += mp_leading_bit(data[i].data.mp) ? 1 : 0;
                /* Write out length. */
                idx += SetASNLength(length, out + idx);
                /* Write out leading zero to make positive. */
                if (mp_leading_bit(data[i].data.mp)) {
                    out[idx++] = 0;
                }
                /* Encode number in big-endian byte array. */
                err = mp_to_unsigned_bin(data[i].data.mp, out + idx);
                if (err != MP_OKAY) {
                    WOLFSSL_MSG("SetASN_Items: Failed to write mp_int");
                    return MP_TO_E;
                }
                break;

            case ASN_DATA_TYPE_REPLACE_BUFFER:
                if (data[i].data.buffer.data == NULL) {
                    /* Return pointer for caller to use. */
                    data[i].data.buffer.data = out + idx;
                }
                else {
                    /* Dump in the DER encoded data. */
                    XMEMCPY(out + idx, data[i].data.buffer.data,
                            data[i].data.buffer.length);
                }
                break;

            case ASN_DATA_TYPE_NONE:
                if (asn[i].tag == ASN_BOOLEAN) {
                    /* Always one byte of data. */
                    out[idx++] = 1;
                    /* TRUE = 0xff, FALSE = 0x00 */
                    out[idx] = data[i].data.u8 ? -1 : 0;
                }
                else if (asn[i].tag == ASN_TAG_NULL) {
                    /* NULL tag is always a zero length item. */
                    out[idx] = 0;
                }
                else {
                    word32 dataLen = data[i].data.buffer.length;
                    /* Add one to data length for BIT_STRING unused bits and
                     * INTEGER leading zero to make positive.
                     */
                    if ((asn[i].tag == ASN_BIT_STRING) ||
                                                   ASNIntMSBSet(asn, data, i)) {
                        dataLen++;
                    }
                    /* Write out length. */
                    idx += SetASNLength(dataLen, out + idx);
                    if ((asn[i].tag == ASN_BIT_STRING) ||
                                                   ASNIntMSBSet(asn, data, i)) {
                       /* Write out leading byte. BIT_STRING has no unused bits
                        * - use number data types if needed. */
                        out[idx++] = 0x00;
                    }
                    /* Record pointer for caller if data not supplied. */
                    if (data[i].data.buffer.data == NULL) {
                        data[i].data.buffer.data = out + idx;
                    }
                    /* Copy supplied data if not putting out header only or
                     * if buffer supplied. */
                    else if (!asn[i].headerOnly ||
                            data[i].data.buffer.data != NULL) {
                        /* Allow data to come from output buffer. */
                        XMEMMOVE(out + idx, data[i].data.buffer.data,
                                 data[i].data.buffer.length);
                    }
                }
                break;

            default:
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Bad data type: %d", data[i].dataType);
            #endif
                return BAD_STATE_E;
        }
    }

    return sz;
}


static int GetOID(const byte* input, word32* inOutIdx, word32* oid,
                  word32 oidType, int length);

/* Maximum supported depth in ASN.1 description. */
#define GET_ASN_MAX_DEPTH          7
/* Maximum number of checked numbered choices. Only one of the items with the
 * number is allowed.
 */
#define GET_ASN_MAX_CHOICES        2

/* Use existing function to decode BER length encoding. */
#define GetASN_Length GetLength_ex

/* Check an INTEGER's first byte - must be a positive number.
 *
 * @param [in] input    BER encoded data.
 * @param [in] idx      Index of BIT_STRING data.
 * @param [in] length   Length of input data.
 * @param [in] positive Indicates number must be positive.
 * @return  0 on success.
 * @return  ASN_PARSE_E when 0 is not required but seen.
 * @return  ASN_EXPECT_0_E when 0 is required and not seen.
 */
static int GetASN_Integer(const byte* input, word32 idx, int length,
                          int positive)
{
    if (input[idx] == 0) {
        /* Check leading zero byte required. */
        if ((length > 1) && ((input[idx + 1] & 0x80) == 0)) {
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG("Zero not required on INTEGER");
        #endif
            return ASN_PARSE_E;
        }
    }
    /* Check whether a leading zero byte was required. */
    else if (positive && (input[idx] & 0x80)) {
    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG("INTEGER is negative");
    #endif
        return ASN_EXPECT_0_E;
    }

    return 0;
}

/* Check a BIT_STRING's first byte - unused bits.
 *
 * @param [in] input   BER encoded data.
 * @param [in] idx     Index of BIT_STRING data.
 * @param [in] length  Length of input data.
 * @return  0 on success.
 * @return  ASN_PARSE_E when unused bits is invalid.
 */
static int GetASN_BitString(const byte* input, word32 idx, int length)
{
    /* Ensure unused bits value is valid range. */
    if (input[idx] > 7) {
    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG_VSNPRINTF("BIT STRING unused bits too big: %d > 7",
                input[idx]);
    #endif
        return ASN_PARSE_E;
    }
    /* Ensure unused bits are zero. */
    if ((byte)(input[idx + length - 1] << (8 - input[idx])) != 0) {
    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG_VSNPRINTF("BIT STRING unused bits used: %d %02x",
                input[idx], input[idx + length - 1]);
    #endif
        return ASN_PARSE_E;
    }

    return 0;
}

/* Get the ASN.1 items from the BER encoding.
 *
 * @param [in] asn         ASN.1 item expected.
 * @param [in] data        Data array to place found item into.
 * @param [in] input       BER encoded data.
 * @param [in] idx         Starting index of item data.
 * @param [in] len         Length of input buffer upto end of this item's data.
 * @param [in] zeroPadded  INTEGER was zero padded to make positive.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data is invalid.
 * @return  ASN_EXPECT_0_E when NULL tagged item has a non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 * @return  BAD_STATE_E when the data type is not supported.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
static int GetASN_StoreData(const ASNItem* asn, ASNGetData* data,
                            const byte* input, word32 idx, int len,
                            int zeroPadded)
{
    int i;
    int err;

    /* Parse data based on data type to extract. */
    switch (data->dataType) {
        /* Parse a data into a number of specified bits. */
        case ASN_DATA_TYPE_WORD8:
            /* Check data is small enough to fit. */
            if (len != 1) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Expecting one byte: %d", len);
            #endif
                return ASN_PARSE_E;
            }
            /* Fill number with all of data. */
            *data->data.u8 = input[idx];
            break;
        case ASN_DATA_TYPE_WORD16:
            /* Check data is small enough to fit. */
            if (len == 0 || len > 2) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Expecting 1 or 2 bytes: %d", len);
            #endif
                return ASN_PARSE_E;
            }
            /* Fill number with all of data. */
            *data->data.u16 = 0;
            for (i = 0; i < len; i++) {
                *data->data.u16 <<= 8;
                *data->data.u16 |= input[idx + i] ;
            }
            break;
        case ASN_DATA_TYPE_WORD32:
            /* Check data is small enough to fit. */
            if (len == 0 || len > 4) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Expecting 1 to 4 bytes: %d", len);
            #endif
                return ASN_PARSE_E;
            }
            /* Fill number with all of data. */
            *data->data.u32 = 0;
            for (i = 0; i < len; i++) {
                *data->data.u32 <<= 8;
                *data->data.u32 |= input[idx + i] ;
            }
            break;

        case ASN_DATA_TYPE_BUFFER:
            /* Check buffer is big enough to hold data. */
            if (len > (int)*data->data.buffer.length) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Buffer too small for data: %d %d", len,
                        *data->data.buffer.length);
            #endif
                return ASN_PARSE_E;
            }
            /* Copy in data and record actual length seen. */
            XMEMCPY(data->data.buffer.data, input + idx, len);
            *data->data.buffer.length = len;
            break;

        case ASN_DATA_TYPE_EXP_BUFFER:
            /* Check data is same size expected. */
            if (len != (int)data->data.ref.length) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Data not expected length: %d %d", len,
                        data->data.ref.length);
            #endif
                return ASN_PARSE_E;
            }
            /* Check data is same as expected. */
            if (XMEMCMP(data->data.ref.data, input + idx, len) != 0) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG("Data not as expected");
            #endif
                return ASN_PARSE_E;
            }
            break;

        case ASN_DATA_TYPE_MP:
        case ASN_DATA_TYPE_MP_POS_NEG:
            /* Initialize mp_int and read in big-endian byte array. */
            if (mp_init(data->data.mp) != MP_OKAY) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Failed to init mp: %p", data->data.mp);
            #endif
                return MP_INIT_E;
            }
            err = mp_read_unsigned_bin(data->data.mp, (byte*)input + idx, len);
            if (err != 0) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Failed to read mp: %d", err);
            #endif
                mp_clear(data->data.mp);
                return ASN_GETINT_E;
            }
        #ifdef HAVE_WOLF_BIGINT
            err = wc_bigint_from_unsigned_bin(&data->data.mp->raw, input + idx,
                    len);
            if (err != 0) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Failed to create bigint: %d", err);
            #endif
                mp_clear(data->data.mp);
                return ASN_GETINT_E;
            }
        #endif /* HAVE_WOLF_BIGINT */
            /* Don't always read as positive. */
            if ((data->dataType == ASN_DATA_TYPE_MP_POS_NEG) && (!zeroPadded) &&
                (input[idx] & 0x80)) {
                #ifdef MP_NEG
                    data->data.mp->sign = MP_NEG;
                #else
                    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                    WOLFSSL_MSG_VSNPRINTF("ASN negative integer without bignum support.");
                    #endif
                    mp_clear(data->data.mp);
                    return ASN_GETINT_E;
                #endif
            }
            break;

        case ASN_DATA_TYPE_CHOICE:
            /* Check if tag matched any of the choices specified. */
            for (i = 0; data->data.choice[i] != 0; i++)
                if (data->data.choice[i] == data->tag)
                    break;
            if (data->data.choice[i] == 0) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG("Tag didn't match a choice");
            #endif
                return ASN_PARSE_E;
            }

            /* Store data pointer and length for caller. */
            data->data.ref.data = input + idx;
            data->data.ref.length = len;
            break;

        case ASN_DATA_TYPE_NONE:
            /* Default behaviour based on tag. */
            if (asn->tag == ASN_BOOLEAN) {
                /* BOOLEAN has only one byte of data in BER. */
                if (len != 1) {
                #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                    WOLFSSL_MSG_VSNPRINTF("BOOLEAN length too long: %d", len);
                #endif
                    return ASN_PARSE_E;
                }
                if (data->data.u8 == NULL)
                    return BAD_STATE_E;
                /* Store C boolean value. */
                *data->data.u8 = (input[idx] != 0);
                break;
            }
            if (asn->tag == ASN_TAG_NULL) {
                /* NULL has no data in BER. */
                if (len != 0) {
                #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                    WOLFSSL_MSG_VSNPRINTF("NULL length too long: %d", len);
                #endif
                    return ASN_EXPECT_0_E;
                }
                data->data.ref.data = input + idx;
                break;
            }
            if (asn->tag == ASN_OBJECT_ID) {
                word32 oidIdx = 0;
                /* Store OID data pointer and length */
                data->data.oid.data = input + idx;
                data->data.oid.length = len;
                /* Get the OID sum. */
                err = GetOID(input + idx, &oidIdx, &data->data.oid.sum,
                        data->data.oid.type, len);
                if (err < 0) {
                #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                    WOLFSSL_MSG_VSNPRINTF("OID check failed: %d", err);
                #endif
                    return err;
                }
                break;
            }

            /* Otherwise store data pointer and length. */
            data->data.ref.data = input + idx;
            data->data.ref.length = len;
            break;

        default:
            /* Bad ASN data type. */
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG_VSNPRINTF("Bad data type: %d", data->dataType);
        #endif
            return BAD_STATE_E;
    }

    return 0;
}

/* Get the ASN.1 items from the BER encoding.
 *
 * @param [in]      asn       ASN.1 items expected.
 * @param [in]      data      Data array to place found items into.
 * @param [in]      count     Count of items to parse.
 * @param [in]      complete  Whether the whole buffer is to be used up.
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of data.
 *                            On out, end of parsed data.
 * @param [in]      length    Length of input buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 * @return  BAD_STATE_E when the data type is not supported.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int GetASN_Items(const ASNItem* asn, ASNGetData *data, int count, int complete,
                 const byte* input, word32* inOutIdx, word32 length)
{
    int    i;
    int    j;
    int    err;
    int    len;
    /* Current index into buffer. */
    word32 idx = *inOutIdx;
    /* Initialize the end index at each depth to be the length. */
    word32 endIdx[GET_ASN_MAX_DEPTH] = { length, length, length, length, length,
                                         length, length };
    /* Set choices to -1 to indicate they haven't been seen or found. */
    char   choiceMet[GET_ASN_MAX_CHOICES] = { -1, -1 };
    /* Not matching a choice right now. */
    int    choice = 0;
    /* Current depth of ASN.1 item. */
    int    depth;
    /* Minimum depth value seen. */
    int    minDepth;
    /* Integer had a zero prepended. */
    int    zeroPadded;

#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
    WOLFSSL_ENTER("GetASN_Items");
#endif

    /* Start depth at first items depth. */
    minDepth = depth = asn[0].depth;
    /* Check every ASN.1 item. */
    for (i = 0; i < count; i++) {
        /* Store offset of ASN.1 item. */
        data[i].offset = idx;
        /* Length of data in ASN.1 item starts empty. */
        data[i].length = 0;
        /* Get current item depth. */
        depth = asn[i].depth;
    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        if (depth > GET_ASN_MAX_DEPTH) {
            WOLFSSL_MSG("Depth in template too large");
            return ASN_PARSE_E;
        }
    #endif
        /* Keep track of minimum depth. */
        if (depth < minDepth) {
            minDepth = depth;
        }

        /* Reset choice if different from previous. */
        if (choice > 0 && asn[i].optional != choice) {
            choice = 0;
        }
        /* Check if first of numbered choice. */
        if (choice == 0 && asn[i].optional > 1) {
            choice = asn[i].optional;
            if (choiceMet[choice - 2] == -1) {
                /* Choice seen but not found a match yet. */
                choiceMet[choice - 2] = 0;
            }
        }

        /* Check for end of data or not a choice and tag not matching. */
        if (idx == endIdx[depth] || (data[i].dataType != ASN_DATA_TYPE_CHOICE &&
                              (input[idx] & ~ASN_CONSTRUCTED) != asn[i].tag)) {
            if (asn[i].optional) {
                /* Skip over ASN.1 items underneath this optional item. */
                for (j = i + 1; j < count; j++) {
                    if (asn[i].depth >= asn[j].depth)
                        break;
                    data[j].offset = idx;
                    data[j].length = 0;
                }
                i = j - 1;
                continue;
            }

            /* Check for end of data. */
            if (idx == length) {
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF(
                    "%2d: %4d %4d %c %*s %-16s%*s  (index past end)",
                    i, data[i].offset, data[i].length,
                    asn[i].constructed ? '+' : ' ', asn[i].depth, "",
                    TagString(asn[i].tag), 6 - asn[i].depth, "");
                WOLFSSL_MSG_VSNPRINTF("Index past end of data: %d %d", idx,
                        length);
        #endif
                return BUFFER_E;
            }
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            /* Show expected versus found. */
            WOLFSSL_MSG_VSNPRINTF(
                "%2d: %4d %4d %c %*s %-16s%*s  Tag=0x%02x (%s)",
                i, data[i].offset, data[i].length,
                asn[i].constructed ? '+' : ' ', asn[i].depth, "",
                TagString(asn[i].tag), 6 - asn[i].depth, "",
                input[idx], TagString(input[idx]));
        #endif
            /* Check for end of data at this depth. */
            if (idx == endIdx[depth]) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF("Index past outer item: %d %d", idx,
                        endIdx[depth]);
            #endif
                return ASN_PARSE_E;
            }

            /* Expecting an OBJECT_ID */
            if (asn[i].tag == ASN_OBJECT_ID) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG("Expecting OBJECT ID");
            #endif
                return ASN_OBJECT_ID_E;
            }
            /* Expecting a BIT_STRING */
            if (asn[i].tag == ASN_BIT_STRING) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG("Expecting BIT STRING");
            #endif
                return ASN_BITSTR_E;
            }
            /* Not the expected tag. */
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG("Bad tag");
        #endif
            return ASN_PARSE_E;
        }

        /* Store found tag in data. */
        data[i].tag = input[idx];
        if (data[i].dataType != ASN_DATA_TYPE_CHOICE) {
            int constructed = (input[idx] & ASN_CONSTRUCTED) == ASN_CONSTRUCTED;
            /* Check constructed match expected for non-choice ASN.1 item. */
            if (asn[i].constructed != constructed) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF(
                        "%2d: %4d %4d %c %*s %-16s%*s  Tag=0x%02x (%s)",
                        i, data[i].offset, data[i].length,
                        asn[i].constructed ? '+' : ' ', asn[i].depth, "",
                        TagString(asn[i].tag), 6 - asn[i].depth, "",
                        input[idx], TagString(input[idx]));
                if (!constructed) {
                    WOLFSSL_MSG("Not constructed");
                }
                else {
                    WOLFSSL_MSG("Not expected to be constructed");
                }
            #endif
                return ASN_PARSE_E;
            }
        }
        /* Move index to start of length. */
        idx++;
        /* Get the encoded length. */
        if (GetASN_Length(input, &idx, &len, endIdx[depth], 1) < 0) {
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG_VSNPRINTF("%2d: idx=%d len=%d end=%d", i, idx, len,
                    endIdx[depth]);
        #endif
            return ASN_PARSE_E;
        }
        /* Store length of data. */
        data[i].length = len;
        /* Note the max length of items under this one. */
        endIdx[depth + 1] = idx + len;
        if (choice > 1) {
            /* Note we found a number choice. */
            choiceMet[choice - 2] = 1;
        }

    #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
        WOLFSSL_MSG_VSNPRINTF("%2d: %4d %4d %c %*s %-16s", i,
                data[i].offset, data[i].length, asn[i].constructed ? '+' : ' ',
                asn[i].depth, "", TagString(data[i].tag));
    #endif

        /* Assume no zero padding on INTEGER. */
        zeroPadded = 0;
        /* Check data types that prepended a byte. */
        if (asn[i].tag == ASN_INTEGER) {
            /* Check validity of first byte. */
            err = GetASN_Integer(input, idx, len,
                    data[i].dataType == ASN_DATA_TYPE_MP);
            if (err != 0)
                return err;
            if (len > 1 && input[idx] == 0) {
                zeroPadded = 1;
                /* Move over prepended byte. */
                idx++;
                len--;
            }
        }
        else if (asn[i].tag == ASN_BIT_STRING) {
            /* Check prepended byte is correct. */
            err = GetASN_BitString(input, idx, len);
            if (err != 0)
                return err;
            /* Move over prepended byte. */
            idx++;
            len--;
        }
        else if ((asn[i].tag == ASN_OBJECT_ID) && (len < 3)) {
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG_VSNPRINTF("OID length must be 3 or more: %d", len);
        #endif
            return ASN_PARSE_E;
        }

        /* Don't parse data if only header required. */
        if (asn[i].headerOnly) {
            /* Store reference to data and length. */
            data[i].data.ref.data = input + idx;
            data[i].data.ref.length = len;
            continue;
        }

        /* Store the data at idx in the ASN data item. */
        err = GetASN_StoreData(&asn[i], &data[i], input, idx, len, zeroPadded);
        if (err != 0) {
            return err;
        }

        /* Move index to next item. */
        idx += len;

        /* When matched numbered choice ... */
        if (asn[i].optional > 1) {
            /* Skip over other ASN.1 items of the same number. */
            for (j = i + 1; j < count; j++) {
                if (asn[j].depth <= asn[i].depth &&
                                           asn[j].optional != asn[i].optional) {
                   break;
                }
            }
            i = j - 1;
        }
    }

    if (complete) {
        /* When expecting ASN.1 items to completely use data, check we did. */
        for (j = depth; j > minDepth; j--) {
            if (idx < endIdx[j]) {
            #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
                WOLFSSL_MSG_VSNPRINTF(
                    "More data in constructed item at depth: %d", j - 1);
            #endif
                return ASN_PARSE_E;
            }
        }
    }

    /* Check all choices where met - found an item for them. */
    for (j = 0; j < GET_ASN_MAX_CHOICES; j++) {
        if (choiceMet[j] == 0) {
        #ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG_VSNPRINTF("No choice seen: %d", j + 2);
        #endif
            return ASN_PARSE_E;
        }
    }

    /* Return index after ASN.1 data has been parsed. */
    *inOutIdx = idx;

    return 0;
}

#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
/* Calculate the size of the DER encoding.
 *
 * Call SetASN_Items() to write encoding to a buffer.
 *
 * @param [in]      asn    ASN.1 items to encode.
 * @param [in, out] data   Data to place in each item. Lengths set were not
 *                         known.
 * @param [in]      count  Count of items to encode.
 * @param [out]     len    Length of the DER encoding.
 * @return  Size of the DER encoding in bytes.
 */
static int SizeASN_ItemsDebug(const char* name, const ASNItem* asn,
    ASNSetData *data, int count, int* encSz)
{
    WOLFSSL_MSG_VSNPRINTF("TEMPLATE: %s", name);
    return SizeASN_Items(asn, data, count, encSz);
}

/* Creates the DER encoding of the ASN.1 items.
 *
 * Assumes the output buffer is large enough to hold encoding.
 * Must call SizeASN_Items() to determine size of encoding and offsets.
 *
 * Displays the template name first.
 *
 * @param [in]      name    Name of ASN.1 template.
 * @param [in]      asn     ASN.1 items to encode.
 * @param [in]      data    Data to place in each item.
 * @param [in]      count   Count of items to encode.
 * @param [in, out] output  Buffer to write encoding into.
 * @return  Size of the DER encoding in bytes.
 */
static int SetASN_ItemsDebug(const char* name, const ASNItem* asn,
    ASNSetData *data, int count, byte* output)
{
    WOLFSSL_MSG_VSNPRINTF("TEMPLATE: %s", name);
    return SetASN_Items(asn, data, count, output);
}

/* Get the ASN.1 items from the BER encoding.
 *
 * Displays the template name first.
 *
 * @param [in]      name      Name of ASN.1 template.
 * @param [in]      asn       ASN.1 items expected.
 * @param [in]      data      Data array to place found items into.
 * @param [in]      count     Count of items to parse.
 * @param [in]      complete  Whether the whole buffer is to be used up.
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of data.
 *                            On out, end of parsed data.
 * @param [in]      maxIdx    Maximum index of input data.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 * is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 * @return  BAD_STATE_E when the data type is not supported.
 */
static int GetASN_ItemsDebug(const char* name, const ASNItem* asn,
    ASNGetData *data, int count, int complete, const byte* input,
    word32* inOutIdx, word32 maxIdx)
{
    WOLFSSL_MSG_VSNPRINTF("TEMPLATE: %s", name);
    return GetASN_Items(asn, data, count, complete, input, inOutIdx, maxIdx);
}

/* Calculate the size of the DER encoding.
 *
 * Call SetASN_Items() to write encoding to a buffer.
 *
 * @param [in]      asn    ASN.1 items to encode.
 * @param [in, out] data   Data to place in each item. Lengths set were not
 *                         known.
 * @param [in]      count  Count of items to encode.
 * @param [out]     len    Length of the DER encoding.
 * @return  Size of the DER encoding in bytes.
 */
#define SizeASN_Items(asn, data, count, encSz)  \
    SizeASN_ItemsDebug(#asn, asn, data, count, encSz)

/* Creates the DER encoding of the ASN.1 items.
 *
 * Assumes the output buffer is large enough to hold encoding.
 * Must call SizeASN_Items() to determine size of encoding and offsets.
 *
 * Displays the template name first.
 *
 * @param [in]      name    Name of ASN.1 template.
 * @param [in]      asn     ASN.1 items to encode.
 * @param [in]      data    Data to place in each item.
 * @param [in]      count   Count of items to encode.
 * @param [in, out] output  Buffer to write encoding into.
 * @return  Size of the DER encoding in bytes.
 */
#define SetASN_Items(asn, data, count, output)  \
    SetASN_ItemsDebug(#asn, asn, data, count, output)

/* Get the ASN.1 items from the BER encoding.
 *
 * Displays the template name first.
 *
 * @param [in]      name      Name of ASN.1 template.
 * @param [in]      asn       ASN.1 items expected.
 * @param [in]      data      Data array to place found items into.
 * @param [in]      count     Count of items to parse.
 * @param [in]      complete  Whether the whole buffer is to be used up.
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of data.
 *                            On out, end of parsed data.
 * @param [in]      maxIdx    Maximum index of input data.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 * is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 * @return  BAD_STATE_E when the data type is not supported.
 */
#define GetASN_Items(asn, data, count, complete, input, inOutIdx, maxIdx)  \
    GetASN_ItemsDebug(#asn, asn, data, count, complete, input, inOutIdx, maxIdx)
#endif /* WOLFSSL_DEBUG_ASN_TEMPLATE */

/* Decode a BER encoded constructed sequence.
 *
 * @param [in]       input     Buffer of BER encoded data.
 * @param [in, out]  inOutIdx  On in, index to start decoding from.
 *                             On out, index of next encoded byte.
 * @param [out]      len       Length of data under SEQUENCE.
 * @param [in]       maxIdx    Maximim index of data. Index of byte after SEQ.
 * @param [in]       complete  All data used with SEQUENCE and data under.
 * @return  0 on success.
 * @return  BUFFER_E when not enough data to complete decode.
 * @return  ASN_PARSE when decoding failed.
 */
static int GetASN_Sequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int complete)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    /* Check buffer big enough for tag. */
    if (idx + 1 > maxIdx) {
        ret = BUFFER_E;
    }
    /* Check it is a constructed SEQUENCE. */
    if ((ret == 0) && (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED))) {
        ret = ASN_PARSE_E;
    }
    /* Get the length. */
    if ((ret == 0) && (GetASN_Length(input, &idx, len, maxIdx, 1) < 0)) {
        ret = ASN_PARSE_E;
    }
    /* Check all data used if complete set. */
    if ((ret == 0) && complete && (idx + *len != maxIdx)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* Return index of next byte of encoded data. */
        *inOutIdx = idx;
    }

    return ret;
}


#ifdef WOLFSSL_ASN_TEMPLATE_TYPE_CHECK
/* Setup ASN data item to get an 8-bit number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Pointer to an 8-bit variable.
 */
void GetASN_Int8Bit(ASNGetData *dataASN, byte* num)
{
    dataASN->dataType = ASN_DATA_TYPE_WORD8;
    dataASN->data.u8  = num;
}

/* Setup ASN data item to get a 16-bit number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Pointer to a 16-bit variable.
 */
void GetASN_Int16Bit(ASNGetData *dataASN, word16* num)
{
    dataASN->dataType = ASN_DATA_TYPE_WORD16;
    dataASN->data.u16 = num;
}

/* Setup ASN data item to get a 32-bit number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Pointer to a 32-bit variable.
 */
void GetASN_Int32Bit(ASNGetData *dataASN, word32* num)
{
    dataASN->dataType = ASN_DATA_TYPE_WORD32;
    dataASN->data.u32 = num;
}

/* Setup ASN data item to get data into a buffer of a specific length.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] data     Buffer to hold data.
 * @param [in] length   Length of buffer in bytes.
 */
void GetASN_Buffer(ASNGetData *dataASN, byte* data, word32* length)
{
    dataASN->dataType           = ASN_DATA_TYPE_BUFFER;
    dataASN->data.buffer.data   = data;
    dataASN->data.buffer.length = length;
}

/* Setup ASN data item to check parsed data against expected buffer.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] data     Buffer containing expected data.
 * @param [in] length   Length of buffer in bytes.
 */
void GetASN_ExpBuffer(ASNGetData *dataASN, const byte* data, word32 length)
{
    dataASN->dataType        = ASN_DATA_TYPE_EXP_BUFFER;
    dataASN->data.ref.data   = data;
    dataASN->data.ref.length = length;
}

/* Setup ASN data item to get a number into an mp_int.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Multi-precision number object.
 */
void GetASN_MP(ASNGetData *dataASN, mp_int* num)
{
    dataASN->dataType = ASN_DATA_TYPE_MP;
    dataASN->data.mp  = num;
}

/* Setup ASN data item to get a positive or negative number into an mp_int.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Multi-precision number object.
 */
void GetASN_MP_PosNeg(ASNGetData *dataASN, mp_int* num)
{
    dataASN->dataType = ASN_DATA_TYPE_MP_POS_NEG;
    dataASN->data.mp  = num;
}

/* Setup ASN data item to be a choice of tags.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] options  0 terminated list of tags that are valid.
 */
void GetASN_Choice(ASNGetData *dataASN, const byte* options)
{
    dataASN->dataType    = ASN_DATA_TYPE_CHOICE;
    dataASN->data.choice = options;
}

/* Setup ASN data item to get a boolean value.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Pointer to an 8-bit variable.
 */
void GetASN_Boolean(ASNGetData *dataASN, byte* num)
{
    dataASN->dataType    = ASN_DATA_TYPE_NONE;
    dataASN->data.choice = num;
}

/* Setup ASN data item to be a an OID of a specific type.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] oidType  Type of OID to expect.
 */
void GetASN_OID(ASNGetData *dataASN, int oidType)
{
    dataASN->data.oid.type = oidType;
}

/* Get the data and length from an ASN data item.
 *
 * @param [in]  dataASN  Dynamic ASN data item.
 * @param [out] data     Pointer to data of item.
 * @param [out] length   Length of buffer in bytes.
 */
void GetASN_GetConstRef(ASNGetData * dataASN, const byte** data, word32* length)
{
    *data   = dataASN->data.ref.data;
    *length = dataASN->data.ref.length;
}

/* Get the data and length from an ASN data item.
 *
 * @param [in]  dataASN  Dynamic ASN data item.
 * @param [out] data     Pointer to data of item.
 * @param [out] length   Length of buffer in bytes.
 */
void GetASN_GetRef(ASNGetData * dataASN, byte** data, word32* length)
{
    *data   = (byte*)dataASN->data.ref.data;
    *length =        dataASN->data.ref.length;
}

/* Get the data and length from an ASN data item that is an OID.
 *
 * @param [in]  dataASN  Dynamic ASN data item.
 * @param [out] data     Pointer to .
 * @param [out] length   Length of buffer in bytes.
 */
void GetASN_OIDData(ASNGetData * dataASN, byte** data, word32* length)
{
    *data   = (byte*)dataASN->data.oid.data;
    *length =        dataASN->data.oid.length;
}

/* Setup an ASN data item to set a boolean.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] val      Boolean value.
 */
void SetASN_Boolean(ASNSetData *dataASN, byte val)
{
    dataASN->dataType = ASN_DATA_TYPE_NONE;
    dataASN->data.u8  = val;
}

/* Setup an ASN data item to set an 8-bit number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      8-bit number to set.
 */
void SetASN_Int8Bit(ASNSetData *dataASN, byte num)
{
    dataASN->dataType = ASN_DATA_TYPE_WORD8;
    dataASN->data.u8  = num;
}

/* Setup an ASN data item to set a 16-bit number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      16-bit number to set.
 */
void SetASN_Int16Bit(ASNSetData *dataASN, word16 num)
{
    dataASN->dataType = ASN_DATA_TYPE_WORD16;
    dataASN->data.u16 = num;
}

/* Setup an ASN data item to set the data in a buffer.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] data     Buffer containing data to set.
 * @param [in] length   Length of data in buffer in bytes.
 */
void SetASN_Buffer(ASNSetData *dataASN, const byte* data, word32 length)
{
    dataASN->data.buffer.data   = data;
    dataASN->data.buffer.length = length;
}

/* Setup an ASN data item to set the DER encode data in a buffer.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] data     Buffer containing BER encoded data to set.
 * @param [in] length   Length of data in buffer in bytes.
 */
void SetASN_ReplaceBuffer(ASNSetData *dataASN, const byte* data, word32 length)
{
    dataASN->dataType           = ASN_DATA_TYPE_REPLACE_BUFFER;
    dataASN->data.buffer.data   = data;
    dataASN->data.buffer.length = length;
}

/* Setup an ASN data item to set an multi-precision number.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] num      Multi-precision number.
 */
void SetASN_MP(ASNSetData *dataASN, mp_int* num)
{
    dataASN->dataType = ASN_DATA_TYPE_MP;
    dataASN->data.mp  = num;
}

/* Setup an ASN data item to set an OID based on id and type.
 *
 * oid and oidType pair are unique.
 *
 * @param [in] dataASN  Dynamic ASN data item.
 * @param [in] oid      OID identifier.
 * @param [in] oidType  Type of OID.
 */
void SetASN_OID(ASNSetData *dataASN, int oid, int oidType)
{
    dataASN->data.buffer.data = OidFromId(oid, oidType,
                                                  &dataASN->data.buffer.length);
}
#endif /* WOLFSSL_ASN_TEMPLATE_TYPE_CHECK */

#ifdef CRLDP_VALIDATE_DATA
/* Get the data of the BIT_STRING as a 16-bit number.
 *
 * @param [in]  dataASN  Dynamic ASN data item.
 * @param [out] val      ASN.1 item's data as a 16-bit number.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BITSTRING value is more than 2 bytes.
 * @return  ASN_PARSE_E when unused bits of BITSTRING is invalid.
 */
static int GetASN_BitString_Int16Bit(ASNGetData* dataASN, word16* val)
{
    int ret;
    int i;
    const byte* input = dataASN->data.ref.data;
    int length = dataASN->data.ref.length;

    /* Validate the BIT_STRING data. */
    ret = GetASN_BitString(input, 0, length);
    if (ret == 0) {
        /* Skip unused bits byte. */
        input++;
        length--;

        /* Check the data is usable. */
        if (length == 0 || length > 2) {
#ifdef WOLFSSL_DEBUG_ASN_TEMPLATE
            WOLFSSL_MSG_VSNPRINTF("Expecting 1 or 2 bytes: %d", length);
#endif
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        /* Fill 16-bit var with all the data. */
        *val = 0;
        for (i = 0; i < length; i++) {
            *val <<= 8;
            *val |= input[i];
        }
    }
    return ret;
}
#endif /* CRLDP_VALIDATE_DATA */

#endif /* WOLFSSL_ASN_TEMPLATE */


/* Decode the BER/DER length field.
 *
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of length.
 *                            On out, end of parsed length.
 * @param [out]     len       Length value decoded.
 * @param [in]      maxIdx    Maximum index of input data.
 * @return  Length on success.
 * @return  ASN_PARSE_E if the encoding is invalid.
 * @return  BUFFER_E when not enough data to complete decode.
 */
int GetLength(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
    return GetLength_ex(input, inOutIdx, len, maxIdx, 1);
}


/* Decode the BER/DER length field and check the length is valid on request.
 *
 * BER/DER has Type-Length-Value triplets.
 * When requested will check that the Length decoded, indicating the number
 * of bytes in the Value, is available in the buffer after the Length bytes.
 *
 * Only supporting a length upto INT_MAX.
 *
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of length.
 *                            On out, end of parsed length.
 * @param [out]     len       Length value decoded.
 * @param [in]      maxIdx    Maximum index of input data.
 * @param [in]      check     Whether to check the buffer has at least the
 *                            decoded length of bytes remaining.
 * @return  Length on success.
 * @return  ASN_PARSE_E if the encoding is invalid.
 * @return  BUFFER_E when not enough data to complete decode.
 */
int GetLength_ex(const byte* input, word32* inOutIdx, int* len, word32 maxIdx,
                 int check)
{
    int     length = 0;
    word32  idx = *inOutIdx;
    byte    b;

    /* Ensure zero return length on error. */
    *len = 0;

    /* Check there is at least on byte available containing length information.
     */
    if ((idx + 1) > maxIdx) {
        WOLFSSL_MSG("GetLength - bad index on input");
        return BUFFER_E;
    }

    /* Get the first length byte. */
    b = input[idx++];
    /* Check if the first byte indicates the count of bytes. */
    if (b >= ASN_LONG_LENGTH) {
        /* Bottom 7 bits are the number of bytes to calculate length with.
         * Note: 0 indicates indefinte length encoding *not* 0 bytes of length.
         */
        word32 bytes = b & 0x7F;
        int minLen;

        /* Calculate minimum length to be encoded with bytes. */
        if (b == 0x80) {
            /* Indefinite length encoding - no length bytes. */
            minLen = 0;
        }
        else if (bytes == 1) {
            minLen = 0x80;
        }
        /* Only support up to the number of bytes that fit into return var. */
        else if (bytes > sizeof(length)) {
            WOLFSSL_MSG("GetLength - overlong data length spec");
            return ASN_PARSE_E;
        } else {
            minLen = 1 << ((bytes - 1) * 8);
        }

        /* Check the number of bytes required are available. */
        if ((idx + bytes) > maxIdx) {
            WOLFSSL_MSG("GetLength - bad long length");
            return BUFFER_E;
        }

        /* Big-endian encoding of number. */
        while (bytes--) {
            b = input[idx++];
            length = (length << 8) | b;
        }
        /* Negative value indicates we overflowed the signed int. */
        if (length < 0) {
            return ASN_PARSE_E;
        }
        /* Don't allow lengths that are longer than strictly required. */
        if (length < minLen) {
            return ASN_PARSE_E;
        }
    }
    else {
        /* Length in first byte. */
        length = b;
    }

    /* When request, check the buffer has at least length bytes left. */
    if (check && ((idx + length) > maxIdx)) {
        WOLFSSL_MSG("GetLength - value exceeds buffer length");
        return BUFFER_E;
    }

    /* Return index after length encoding. */
    *inOutIdx = idx;
    /* Return length if valid. */
    if (length > 0) {
        *len = length;
    }

    /* Return length calculated or error code. */
    return length;
}


/* Gets the tag of next BER/DER encoded item.
 *
 * Checks there is enough data in the buffer for the tag byte.
 *
 * @param [in]      input     BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of tag.
 *                            On out, end of parsed tag.
 * @param [out]     tag       Tag value found.
 * @param [in]      maxIdx    Maximum index of input data.
 *
 * return  0 on success
 * return  BAD_FUNC_ARG when tag, inOutIdx or input is NULL.
 * return  BUFFER_E when not enough space in buffer for tag.
 */
int GetASNTag(const byte* input, word32* inOutIdx, byte* tag, word32 maxIdx)
{
    int ret = 0;
    word32 idx = 0;

    /* Check validity of parameters. */
    if ((tag == NULL) || (inOutIdx == NULL) || (input == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Get index and ensure space for tag. */
        idx = *inOutIdx;
        if (idx + ASN_TAG_SZ > maxIdx) {
            WOLFSSL_MSG("Buffer too small for ASN tag");
            ret = BUFFER_E;
        }
    }
    if (ret == 0) {
        /* Return the tag and the index after tag. */
        *tag = input[idx];
        *inOutIdx = idx + ASN_TAG_SZ;
    }
    /* Return error code. */
    return ret;
}


/* Decode the DER/BER header (Type-Length) and check the length when requested.
 *
 * BER/DER has Type-Length-Value triplets.
 * Check that the tag/type is the required value.
 * When requested will check that the Length decoded, indicating the number
 * of bytes in the Value, is available in the buffer after the Length bytes.
 *
 * Only supporting a length upto INT_MAX.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in]      tag       ASN.1 tag value expected in header.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @param [in]      check     Whether to check the buffer has at least the
 *                            decoded length of bytes remaining.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the expected tag is not found or length is invalid.
 */
static int GetASNHeader_ex(const byte* input, byte tag, word32* inOutIdx,
                           int* len, word32 maxIdx, int check)
{
    int    ret = 0;
    word32 idx = *inOutIdx;
    byte   tagFound;
    int    length = 0;

    /* Get tag/type. */
    if (GetASNTag(input, &idx, &tagFound, maxIdx) != 0) {
        ret = ASN_PARSE_E;
    }
    /* Ensure tag is the expected value. */
    if ((ret == 0) && (tagFound != tag)) {
        ret = ASN_PARSE_E;
    }
    /* Get the encoded length. */
    if ((ret == 0) && (GetLength_ex(input, &idx, &length, maxIdx, check) < 0)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* Return the length of data and index after header. */
        *len      = length;
        *inOutIdx = idx;
        ret = length;
    }
    /* Return number of data bytes or error code. */
    return ret;
}


/* Decode the DER/BER header (Type-Length) and check the length.
 *
 * BER/DER has Type-Length-Value triplets.
 * Check that the tag/type is the required value.
 * Checks that the Length decoded, indicating the number of bytes in the Value,
 * is available in the buffer after the Length bytes.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in]      tag       ASN.1 tag value expected in header.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the expected tag is not found or length is invalid.
 */
static int GetASNHeader(const byte* input, byte tag, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    return GetASNHeader_ex(input, tag, inOutIdx, len, maxIdx, 1);
}

#ifndef WOLFSSL_ASN_TEMPLATE
static int GetHeader(const byte* input, byte* tag, word32* inOutIdx, int* len,
                     word32 maxIdx, int check)
{
    word32 idx = *inOutIdx;
    int    length;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    *tag = input[idx++];

    if (GetLength_ex(input, &idx, &length, maxIdx, check) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;
    return length;
}
#endif

/* Decode the header of a BER/DER encoded SEQUENCE.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a SEQUENCE or length is invalid.
 */
int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return GetASNHeader(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}

/* Decode the header of a BER/DER encoded SEQUENCE.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @param [in]      check     Whether to check the buffer has at least the
 *                            decoded length of bytes remaining.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a SEQUENCE or length is invalid.
 */
int GetSequence_ex(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}

/* Decode the header of a BER/DER encoded SET.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a SET or length is invalid.
 */
int GetSet(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    return GetASNHeader(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}

/* Decode the header of a BER/DER encoded SET.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @param [in]      check     Whether to check the buffer has at least the
 *                            decoded length of bytes remaining.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a SET or length is invalid.
 */
int GetSet_ex(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}

#if !defined(WOLFSSL_ASN_TEMPLATE)
/* Decode the BER/DER encoded NULL.
 *
 * No data in a NULL ASN.1 item.
 * Ensure that the all fields are as expected and move index past the element.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of NULL item.
 *                            On out, end of parsed NULL item.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  0 on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_TAG_NULL_E when the NULL tag is not found.
 * @return  ASN_EXPECT_0_E when the length is not zero.
 */
static int GetASNNull(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    /* Check buffer has enough data for a NULL item. */
    if ((idx + 2) > maxIdx) {
        ret = BUFFER_E;
    }
    /* Check the tag is NULL. */
    if ((ret == 0) && (input[idx++] != ASN_TAG_NULL)) {
        ret = ASN_TAG_NULL_E;
    }
    /* Check the length is zero. */
    if ((ret == 0) && (input[idx++] != 0)) {
        ret = ASN_EXPECT_0_E;
    }
    if (ret == 0) {
        /* Return the index after NULL tag. */
        *inOutIdx = idx;
    }
    /* Return error code. */
    return ret;
}
#endif

#ifndef WOLFSSL_ASN_TEMPLATE
/* Set the DER/BER encoding of the ASN.1 NULL element.
 *
 * output  Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
static int SetASNNull(byte* output)
{
    output[0] = ASN_TAG_NULL;
    output[1] = 0;

    return 2;
}
#endif

#ifndef WOLFSSL_ASN_TEMPLATE
/* Get the DER/BER encoding of an ASN.1 BOOLEAN.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the BOOLEAN tag is not found or length is not 1.
 *         Otherwise, 0 to indicate the value was false and 1 to indicate true.
 */
static int GetBoolean(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   b;

    if ((idx + 3) > maxIdx)
        return BUFFER_E;

    b = input[idx++];
    if (b != ASN_BOOLEAN)
        return ASN_PARSE_E;

    if (input[idx++] != 1)
        return ASN_PARSE_E;

    b = input[idx++] != 0;

    *inOutIdx = idx;
    return b;
}
#endif


/* Decode the header of a BER/DER encoded OCTET STRING.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  Number of bytes in the ASN.1 data on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a OCTET STRING or length is invalid.
 */
int GetOctetString(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
    return GetASNHeader(input, ASN_OCTET_STRING, inOutIdx, len, maxIdx);
}

#ifndef WOLFSSL_ASN_TEMPLATE
/* Get the DER/BER encoding of an ASN.1 INTEGER header.
 *
 * Removes the leading zero byte when found.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * len       The number of bytes in the ASN.1 data (excluding any leading zero).
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the INTEGER tag is not found, length is invalid,
 *         or invalid use of or missing leading zero.
 *         Otherwise, 0 to indicate success.
 */
static int GetASNInt(const byte* input, word32* inOutIdx, int* len,
                     word32 maxIdx)
{
    int    ret;

    ret = GetASNHeader(input, ASN_INTEGER, inOutIdx, len, maxIdx);
    if (ret < 0)
        return ret;

    if (*len > 0) {

#ifndef WOLFSSL_ASN_INT_LEAD_0_ANY
        /* check for invalid padding on negative integer.
         * c.f. X.690 (ISO/IEC 8825-2:2003 (E)) 10.4.6; RFC 5280 4.1
         */
        if (*len > 1) {
            if ((input[*inOutIdx] == 0xff) && (input[*inOutIdx + 1] & 0x80))
                return ASN_PARSE_E;
        }
#endif

        /* remove leading zero, unless there is only one 0x00 byte */
        if ((input[*inOutIdx] == 0x00) && (*len > 1)) {
            (*inOutIdx)++;
            (*len)--;

#ifndef WOLFSSL_ASN_INT_LEAD_0_ANY
            if (*len > 0 && (input[*inOutIdx] & 0x80) == 0)
                return ASN_PARSE_E;
#endif
        }
    }

    return 0;
}

/* Get the DER/BER encoding of an ASN.1 INTEGER that has a value of no more than
 * 7 bits.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the INTEGER tag is not found or length is invalid.
 *         Otherwise, the 7-bit value.
 */
static int GetInteger7Bit(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   b;

    if ((idx + 3) > maxIdx)
        return BUFFER_E;

    if (GetASNTag(input, &idx, &b, maxIdx) != 0)
        return ASN_PARSE_E;
    if (b != ASN_INTEGER)
        return ASN_PARSE_E;
    if (input[idx++] != 1)
        return ASN_PARSE_E;
    b = input[idx++];

    *inOutIdx = idx;
    return b;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_MD2
    static const char  sigMd2wRsaName[] = "md2WithRSAEncryption";
#endif
#ifndef NO_MD5
    static const char  sigMd5wRsaName[] = "md5WithRSAEncryption";
#endif
    static const char  sigSha1wRsaName[] = "sha1WithRSAEncryption";
    static const char sigSha224wRsaName[] = "sha224WithRSAEncryption";
    static const char sigSha256wRsaName[] = "sha256WithRSAEncryption";
    static const char sigSha384wRsaName[] = "sha384WithRSAEncryption";
    static const char sigSha512wRsaName[] = "sha512WithRSAEncryption";
#ifndef WOLFSSL_NOSHA3_224
    static const char sigSha3_224wRsaName[] = "sha3_224WithRSAEncryption";
#endif
#ifndef WOLFSSL_NOSHA3_256
    static const char sigSha3_256wRsaName[] = "sha3_256WithRSAEncryption";
#endif
#ifndef WOLFSSL_NOSHA3_384
    static const char sigSha3_384wRsaName[] = "sha3_384WithRSAEncryption";
#endif
#ifndef WOLFSSL_NOSHA3_512
    static const char sigSha3_512wRsaName[] = "sha3_512WithRSAEncryption";
#endif
    static const char sigSha1wEcdsaName[] = "SHAwECDSA";
    static const char sigSha224wEcdsaName[] = "SHA224wECDSA";
    static const char sigSha256wEcdsaName[] = "SHA256wECDSA";
    static const char sigSha384wEcdsaName[] = "SHA384wECDSA";
    static const char sigSha512wEcdsaName[] = "SHA512wECDSA";
#ifndef WOLFSSL_NOSHA3_224
    static const char sigSha3_224wEcdsaName[] = "SHA3_224wECDSA";
#endif
#ifndef WOLFSSL_NOSHA3_256
    static const char sigSha3_256wEcdsaName[] = "SHA3_256wECDSA";
#endif
#ifndef WOLFSSL_NOSHA3_384
    static const char sigSha3_384wEcdsaName[] = "SHA3_384wECDSA";
#endif
#ifndef WOLFSSL_NOSHA3_512
    static const char sigSha3_512wEcdsaName[] = "SHA3_512wECDSA";
#endif
static const char sigUnknownName[] = "Unknown";


/* Get the human readable string for a signature type
 *
 * oid  Oid value for signature
 */
const char* GetSigName(int oid) {
    switch (oid) {
        #ifdef WOLFSSL_MD2
        case CTC_MD2wRSA:
            return sigMd2wRsaName;
        #endif
        #ifndef NO_MD5
        case CTC_MD5wRSA:
            return sigMd5wRsaName;
        #endif
        case CTC_SHAwRSA:
            return sigSha1wRsaName;
        case CTC_SHA224wRSA:
            return sigSha224wRsaName;
        case CTC_SHA256wRSA:
            return sigSha256wRsaName;
        case CTC_SHA384wRSA:
            return sigSha384wRsaName;
        case CTC_SHA512wRSA:
            return sigSha512wRsaName;
        #ifndef WOLFSSL_NOSHA3_224
        case CTC_SHA3_224wRSA:
            return sigSha3_224wRsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_256
        case CTC_SHA3_256wRSA:
            return sigSha3_256wRsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        case CTC_SHA3_384wRSA:
            return sigSha3_384wRsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        case CTC_SHA3_512wRSA:
            return sigSha3_512wRsaName;
        #endif
        case CTC_SHAwECDSA:
            return sigSha1wEcdsaName;
        case CTC_SHA224wECDSA:
            return sigSha224wEcdsaName;
        case CTC_SHA256wECDSA:
            return sigSha256wEcdsaName;
        case CTC_SHA384wECDSA:
            return sigSha384wEcdsaName;
        case CTC_SHA512wECDSA:
            return sigSha512wEcdsaName;
        #ifndef WOLFSSL_NOSHA3_224
        case CTC_SHA3_224wECDSA:
            return sigSha3_224wEcdsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_256
        case CTC_SHA3_256wECDSA:
            return sigSha3_256wEcdsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        case CTC_SHA3_384wECDSA:
            return sigSha3_384wEcdsaName;
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        case CTC_SHA3_512wECDSA:
            return sigSha3_512wEcdsaName;
        #endif
        default:
            return sigUnknownName;
    }
}


#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS7)
/* Set the DER/BER encoding of the ASN.1 INTEGER header.
 *
 * When output is NULL, calculate the header length only.
 *
 * @param [in]  len        Length of INTEGER data in bytes.
 * @param [in]  firstByte  First byte of data, most significant byte of integer,
 *                         to encode.
 * @param [out] output     Buffer to write into.
 * @return  Number of bytes added to the buffer.
 */
int SetASNInt(int len, byte firstByte, byte* output)
{
    word32 idx = 0;

    if (output) {
        /* Write out tag. */
        output[idx] = ASN_INTEGER;
    }
    /* Step over tag. */
    idx += ASN_TAG_SZ;
    /* Check if first byte has top bit set in which case a 0 is needed to
     * maintain positive value. */
    if (firstByte & 0x80) {
        /* Add pre-prepended byte to length of data in INTEGER. */
        len++;
    }
    /* Encode length - passing NULL for output will not encode. */
    idx += SetLength(len, output ? output + idx : NULL);
    /* Put out pre-pended 0 as well. */
    if (firstByte & 0x80) {
        if (output) {
            /* Write out 0 byte. */
            output[idx] = 0x00;
        }
        /* Update index. */
        idx++;
    }

    /* Return index after header. */
    return idx;
}
#endif

#ifndef WOLFSSL_ASN_TEMPLATE
/* Set the DER/BER encoding of the ASN.1 INTEGER element with an mp_int.
 * The number is assumed to be positive.
 *
 * n       Multi-precision integer to encode.
 * maxSz   Maximum size of the encoded integer.
 *         A negative value indicates no check of length requested.
 * output  Buffer to write into.
 * returns BUFFER_E when the data is too long for the buffer.
 *         MP_TO_E when encoding the integer fails.
 *         Otherwise, the number of bytes added to the buffer.
 */
static int SetASNIntMP(mp_int* n, int maxSz, byte* output)
{
    int idx = 0;
    int leadingBit;
    int length;
    int err;

    leadingBit = mp_leading_bit(n);
    length = mp_unsigned_bin_size(n);
    if (maxSz >= 0 && (1 + length + (leadingBit ? 1 : 0)) > maxSz)
        return BUFFER_E;
    idx = SetASNInt(length, leadingBit ? 0x80 : 0x00, output);
    if (maxSz >= 0 && (idx + length) > maxSz)
        return BUFFER_E;

    if (output) {
        err = mp_to_unsigned_bin(n, output + idx);
        if (err != MP_OKAY)
            return MP_TO_E;
    }
    idx += length;

    return idx;
}

#if defined(HAVE_USER_RSA) &&  defined(WOLFSSL_CERT_GEN)
/* Set the DER/BER encoding of the ASN.1 INTEGER element with an mp_int from
 * an RSA key.
 * The number is assumed to be positive.
 *
 * n       Multi-precision integer to encode.
 * output  Buffer to write into.
 * returns BUFFER_E when the data is too long for the buffer.
 *         MP_TO_E when encoding the integer fails.
 *         Otherwise, the number of bytes added to the buffer.
 */
static int SetASNIntRSA(void* n, byte* output)
{
    int idx = 0;
    int leadingBit;
    int length;
    int err;

    leadingBit = wc_Rsa_leading_bit(n);
    length = wc_Rsa_unsigned_bin_size(n);
    idx = SetASNInt(length, leadingBit ? 0x80 : 0x00, output);
    if ((idx + length) > MAX_RSA_INT_SZ)
        return BUFFER_E;

    if (output) {
        err = wc_Rsa_to_unsigned_bin(n, output + idx, length);
        if (err != MP_OKAY)
            return MP_TO_E;
    }
    idx += length;

    return idx;
}
#endif /* !NO_RSA && HAVE_USER_RSA && WOLFSSL_CERT_GEN */
#endif /* !WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for an INTEGER. */
static const ASNItem intASN[] = {
/* INT */ { 0, ASN_INTEGER, 0, 0, 0 }
};
enum {
    INTASN_IDX_INT = 0
};

/* Number of items in ASN.1 template for an INTEGER. */
#define intASN_Length (sizeof(intASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */

/* Windows header clash for WinCE using GetVersion */
/* Decode Version - one byte INTEGER.
 *
 * @param [in]      input     Buffer of BER data.
 * @param [in, out] inOutIdx  On in, start of encoded Version.
 *                            On out, start of next encode ASN.1 item.
 * @param [out]     version   Number encoded in INTEGER.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the most significant bit is set.
 */
int GetMyVersion(const byte* input, word32* inOutIdx,
                               int* version, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = *inOutIdx;
    byte   tag;

    if ((idx + MIN_VERSION_SZ) > maxIdx)
        return ASN_PARSE_E;

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
#else
    ASNGetData dataASN[intASN_Length];
    int ret;
    byte num;

    /* Clear dynamic data and set the version number variable. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_Int8Bit(&dataASN[INTASN_IDX_INT], &num);
    /* Decode the version (INTEGER). */
    ret = GetASN_Items(intASN, dataASN, intASN_Length, 0, input, inOutIdx,
                       maxIdx);
    if (ret == 0) {
        /* Return version through variable and return value. */
        *version = num;
        ret = num;
    }
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


#ifndef NO_PWDBASED
/* Decode small integer, 32 bits or less.
 *
 * @param [in]      input     Buffer of BER data.
 * @param [in, out] inOutIdx  On in, start of encoded INTEGER.
 *                            On out, start of next encode ASN.1 item.
 * @param [out]     number    Number encoded in INTEGER.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the most significant bit is set.
 */
int GetShortInt(const byte* input, word32* inOutIdx, int* number, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = *inOutIdx;
    word32 len;
    byte   tag;

    *number = 0;

    /* check for type and length bytes */
    if ((idx + 2) > maxIdx)
        return BUFFER_E;

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag != ASN_INTEGER)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    if (len + idx > maxIdx)
        return ASN_PARSE_E;

    while (len--) {
        *number  = *number << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *number;
#else
    ASNGetData dataASN[intASN_Length];
    int ret;
    word32 num;

    /* Clear dynamic data and set the 32-bit number variable. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_Int32Bit(&dataASN[INTASN_IDX_INT], &num);
    /* Decode the short int (INTEGER). */
    ret = GetASN_Items(intASN, dataASN, intASN_Length, 0, input, inOutIdx,
                       maxIdx);
    if (ret == 0) {
        /* Return number through variable and return value. */
        *number = num;
        ret = num;
    }
    return ret;
#endif
}


#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS12)
/* Set small integer, 32 bits or less. DER encoding with no leading 0s
 * returns total amount written including ASN tag and length byte on success */
int SetShortInt(byte* input, word32* inOutIdx, word32 number, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    word32 len = 0;
    int    i;
    byte ar[MAX_LENGTH_SZ];

    /* check for room for type and length bytes */
    if ((idx + 2) > maxIdx)
        return BUFFER_E;

    input[idx++] = ASN_INTEGER;
    idx++; /* place holder for length byte */
    if (MAX_LENGTH_SZ + idx > maxIdx)
        return ASN_PARSE_E;

    /* find first non zero byte */
    XMEMSET(ar, 0, MAX_LENGTH_SZ);
    c32toa(number, ar);
    for (i = 0; i < MAX_LENGTH_SZ; i++) {
        if (ar[i] != 0) {
            break;
        }
    }

    /* handle case of 0 */
    if (i == MAX_LENGTH_SZ) {
        input[idx++] = 0; len++;
    }

    for (; i < MAX_LENGTH_SZ && idx < maxIdx; i++) {
        input[idx++] = ar[i]; len++;
    }

    /* jump back to beginning of input buffer using unaltered inOutIdx value
     * and set number of bytes for integer, then update the index value */
    input[*inOutIdx + 1] = (byte)len;
    *inOutIdx = idx;

    return len + 2; /* size of integer bytes plus ASN TAG and length byte */
}
#endif /* !WOLFSSL_ASN_TEMPLATE */
#endif /* !NO_PWDBASED */

#ifndef WOLFSSL_ASN_TEMPLATE
/* May not have one, not an error */
static int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version,
                              word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte tag;

    WOLFSSL_ENTER("GetExplicitVersion");

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        int ret;

        *inOutIdx = ++idx;  /* skip header */
        ret = GetMyVersion(input, inOutIdx, version, maxIdx);
        if (ret >= 0) {
            /* check if version is expected value rfc 5280 4.1 {0, 1, 2} */
            if (*version > MAX_X509_VERSION || *version < MIN_X509_VERSION) {
                WOLFSSL_MSG("Unexpected certificate version");
                ret = ASN_VERSION_E;
            }
        }
        return ret;
    }

    /* go back as is */
    *version = 0;

    return 0;
}
#endif

/* Decode small integer, 32 bits or less.
 *
 * mp_int is initialized.
 *
 * @param [out]     mpi       mp_int to hold number.
 * @param [in]      input     Buffer of BER data.
 * @param [in, out] inOutIdx  On in, start of encoded INTEGER.
 *                            On out, start of next encode ASN.1 item.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the most significant bit is set.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 */
int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = *inOutIdx;
    int    ret;
    int    length;

    ret = GetASNInt(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

#ifdef HAVE_WOLF_BIGINT
    if (wc_bigint_from_unsigned_bin(&mpi->raw, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

    *inOutIdx = idx + length;

    return 0;
#else
    ASNGetData dataASN[intASN_Length];

    /* Clear dynamic data and set the mp_int to fill with value. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_MP_PosNeg(&dataASN[INTASN_IDX_INT], mpi);
    /* Decode the big number (INTEGER). */
    return GetASN_Items(intASN, dataASN, intASN_Length, 0, input, inOutIdx,
                        maxIdx);
#endif
}

#if !defined(WOLFSSL_ASN_TEMPLATE)
static int GetIntPositive(mp_int* mpi, const byte* input, word32* inOutIdx,
    word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    ret;
    int    length;

    ret = GetASNInt(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    if (((input[idx] & 0x80) == 0x80) && (input[idx - 1] != 0x00))
        return MP_INIT_E;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

#ifdef HAVE_WOLF_BIGINT
    if (wc_bigint_from_unsigned_bin(&mpi->raw, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

    *inOutIdx = idx + length;

    return 0;
}
#endif /* (ECC || !NO_DSA) && !WOLFSSL_ASN_TEMPLATE */

#ifndef WOLFSSL_ASN_TEMPLATE
#if (!defined(WOLFSSL_KEY_GEN) && defined(RSA_LOW_MEM))  || defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if !defined(HAVE_USER_RSA)
static int SkipInt(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    ret;
    int    length;

    ret = GetASNInt(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    *inOutIdx = idx + length;

    return 0;
}
#endif
#endif
#endif /* !WOLFSSL_ASN_TEMPLATE */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for a BIT_STRING. */
static const ASNItem bitStringASN[] = {
/* BIT_STR */ { 0, ASN_BIT_STRING, 0, 1, 0 }
};
enum {
    BITSTRINGASN_IDX_BIT_STR = 0
};

/* Number of items in ASN.1 template for a BIT_STRING. */
#define bitStringASN_Length (sizeof(bitStringASN) / sizeof(ASNItem))
#endif

/* Decode and check the BIT_STRING is valid. Return length and unused bits.
 *
 * @param [in]      input       Buffer holding BER encoding.
 * @param [in, out] inOutIdx    On in, start of BIT_STRING.
 *                              On out, start of ASN.1 item after BIT_STRING.
 * @param [out]     len         Length of BIT_STRING data.
 * @param [in]      maxIdx      Maximum index of data in buffer.
 * @param [in]      zeroBits    Indicates whether zero unused bits is expected.
 * @param [in]      unusedBits  Number of unused bits in last byte.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when unused bits is not zero when expected.
 */
int CheckBitString(const byte* input, word32* inOutIdx, int* len,
                          word32 maxIdx, int zeroBits, byte* unusedBits)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = *inOutIdx;
    int    length;
    byte   b;

    if (GetASNTag(input, &idx, &b, maxIdx) != 0) {
        return ASN_BITSTR_E;
    }

    if (b != ASN_BIT_STRING) {
        return ASN_BITSTR_E;
    }

    if (GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    /* extra sanity check that length is greater than 0 */
    if (length <= 0) {
        WOLFSSL_MSG("Error length was 0 in CheckBitString");
        return BUFFER_E;
    }

    if (idx + 1 > maxIdx) {
        WOLFSSL_MSG("Attempted buffer read larger than input buffer");
        return BUFFER_E;
    }

    b = input[idx];
    if (zeroBits && b != 0x00)
        return ASN_EXPECT_0_E;
    if (b >= 0x08)
        return ASN_PARSE_E;
    if (b != 0) {
        if ((byte)(input[idx + length - 1] << (8 - b)) != 0)
            return ASN_PARSE_E;
    }
    idx++;
    length--; /* length has been checked for greater than 0 */

    *inOutIdx = idx;
    if (len != NULL)
        *len = length;
    if (unusedBits != NULL)
        *unusedBits = b;

    return 0;
#else
    ASNGetData dataASN[bitStringASN_Length];
    int ret;
    int bits;

    /* Parse BIT_STRING and check validity of unused bits. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    /* Decode BIT_STRING. */
    ret = GetASN_Items(bitStringASN, dataASN, bitStringASN_Length, 0, input,
            inOutIdx, maxIdx);
    if (ret == 0) {
        /* Get unused bits from dynamic ASN.1 data. */
        bits = GetASNItem_UnusedBits(dataASN[BITSTRINGASN_IDX_BIT_STR]);
        /* Check unused bits is 0 when expected. */
        if (zeroBits && (bits != 0)) {
            ret = ASN_EXPECT_0_E;
        }
    }
    if (ret == 0) {
        /* Return length of data and unused bits if required. */
        if (len != NULL) {
            *len = dataASN[BITSTRINGASN_IDX_BIT_STR].data.ref.length;
        }
        if (unusedBits != NULL) {
            *unusedBits = bits;
        }
    }

    return ret;
#endif
}

/* RSA (with CertGen or KeyGen) OR ECC OR ED25519 OR ED448 (with CertGen or
 * KeyGen) */

/* Set the DER/BER encoding of the ASN.1 BIT STRING header.
 *
 * When output is NULL, calculate the header length only.
 *
 * @param [in]  len         Length of BIT STRING data.
 *                          That is, the number of least significant zero bits
 *                          before a one.
 *                          The last byte is the most-significant non-zero byte
 *                          of a number.
 * @param [out] output      Buffer to write into.
 * @return  Number of bytes added to the buffer.
 */
word32 SetBitString(word32 len, byte unusedBits, byte* output)
{
    word32 idx = 0;

    if (output) {
        /* Write out tag. */
        output[idx] = ASN_BIT_STRING;
    }
    /* Step over tag. */
    idx += ASN_TAG_SZ;

    /* Encode length - passing NULL for output will not encode.
     * Add one to length for unused bits. */
    idx += SetLength(len + 1, output ? output + idx : NULL);
    if (output) {
        /* Write out unused bits. */
        output[idx] = unusedBits;
    }
    /* Skip over unused bits. */
    idx++;

    /* Return index after header. */
    return idx;
}

#ifdef ASN_BER_TO_DER
/* Convert BER to DER */

/* Pull informtation from the ASN.1 BER encoded item header */
static int GetBerHeader(const byte* data, word32* idx, word32 maxIdx,
                        byte* pTag, word32* pLen, int* indef)
{
    int len = 0;
    byte tag;
    word32 i = *idx;

    *indef = 0;

    /* Check there is enough data for a minimal header */
    if (i + 2 > maxIdx) {
        return ASN_PARSE_E;
    }

    /* Retrieve tag */
    tag = data[i++];

    /* Indefinite length handled specially */
    if (data[i] == ASN_INDEF_LENGTH) {
        /* Check valid tag for indefinite */
        if (((tag & 0xc0) == 0) && ((tag & ASN_CONSTRUCTED) == 0x00)) {
            return ASN_PARSE_E;
        }
        i++;
        *indef = 1;
    }
    else if (GetLength(data, &i, &len, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    /* Return tag, length and index after BER item header */
    *pTag = tag;
    *pLen = len;
    *idx = i;
    return 0;
}

#ifndef INDEF_ITEMS_MAX
#define INDEF_ITEMS_MAX       20
#endif

/* Indef length item data */
typedef struct Indef {
    word32 start;
    int depth;
    int headerLen;
    word32 len;
} Indef;

/* Indef length items */
typedef struct IndefItems
{
    Indef len[INDEF_ITEMS_MAX];
    int cnt;
    int idx;
    int depth;
} IndefItems;


/* Get header length of current item */
static int IndefItems_HeaderLen(IndefItems* items)
{
    return items->len[items->idx].headerLen;
}

/* Get data length of current item */
static word32 IndefItems_Len(IndefItems* items)
{
    return items->len[items->idx].len;
}

/* Add a indefinite length item */
static int IndefItems_AddItem(IndefItems* items, word32 start)
{
    int ret = 0;
    int i;

    if (items->cnt == INDEF_ITEMS_MAX) {
        ret = MEMORY_E;
    }
    else {
        i = items->cnt++;
        items->len[i].start = start;
        items->len[i].depth = items->depth++;
        items->len[i].headerLen = 1;
        items->len[i].len = 0;
        items->idx = i;
    }

    return ret;
}

/* Increase data length of current item */
static void IndefItems_AddData(IndefItems* items, word32 length)
{
    items->len[items->idx].len += length;
}

/* Update header length of current item to reflect data length */
static void IndefItems_UpdateHeaderLen(IndefItems* items)
{
    items->len[items->idx].headerLen +=
                                    SetLength(items->len[items->idx].len, NULL);
}

/* Go to indefinite parent of current item */
static void IndefItems_Up(IndefItems* items)
{
    int i;
    int depth = items->len[items->idx].depth - 1;

    for (i = items->cnt - 1; i >= 0; i--) {
        if (items->len[i].depth == depth) {
            break;
        }
    }
    items->idx = i;
    items->depth = depth + 1;
}

/* Calculate final length by adding length of indefinite child items */
static void IndefItems_CalcLength(IndefItems* items)
{
    int i;
    int idx = items->idx;

    for (i = idx + 1; i < items->cnt; i++) {
        if (items->len[i].depth == items->depth) {
            items->len[idx].len += items->len[i].headerLen;
            items->len[idx].len += items->len[i].len;
        }
    }
    items->len[idx].headerLen += SetLength(items->len[idx].len, NULL);
}

/* Add more data to indefinite length item */
static void IndefItems_MoreData(IndefItems* items, word32 length)
{
    if (items->cnt > 0 && items->idx >= 0) {
        items->len[items->idx].len += length;
    }
}

/* Convert a BER encoding with indefinite length items to DER.
 *
 * ber    BER encoded data.
 * berSz  Length of BER encoded data.
 * der    Buffer to hold DER encoded version of data.
 *        NULL indicates only the length is required.
 * derSz  The size of the buffer to hold the DER encoded data.
 *        Will be set if der is NULL, otherwise the value is checked as der is
 *        filled.
 * returns ASN_PARSE_E if the BER data is invalid and BAD_FUNC_ARG if ber or
 * derSz are NULL.
 */
int wc_BerToDer(const byte* ber, word32 berSz, byte* der, word32* derSz)
{
    int ret = 0;
    word32 i, j;
    IndefItems indefItems[1];
    byte tag, basic;
    word32 length;
    int indef;

    if (ber == NULL || derSz == NULL)
        return BAD_FUNC_ARG;


    XMEMSET(indefItems, 0, sizeof(*indefItems));

    /* Calculate indefinite item lengths */
    for (i = 0; i < berSz; ) {
        word32 start = i;

        /* Get next BER item */
        ret = GetBerHeader(ber, &i, berSz, &tag, &length, &indef);
        if (ret != 0) {
            goto end;
        }

        if (indef) {
            /* Indefinite item - add to list */
            ret = IndefItems_AddItem(indefItems, i);
            if (ret != 0) {
                goto end;
            }

            if ((tag & 0xC0) == 0 &&
                tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) &&
                tag != (ASN_SET      | ASN_CONSTRUCTED)) {
                /* Constructed basic type - get repeating tag */
                basic = tag & (~ASN_CONSTRUCTED);

                /* Add up lengths of each item below */
                for (; i < berSz; ) {
                    /* Get next BER_item */
                    ret = GetBerHeader(ber, &i, berSz, &tag, &length, &indef);
                    if (ret != 0) {
                        goto end;
                    }

                    /* End of content closes item */
                    if (tag == ASN_EOC) {
                        /* Must be zero length */
                        if (length != 0) {
                            ret = ASN_PARSE_E;
                            goto end;
                        }
                        break;
                    }

                    /* Must not be indefinite and tag must match parent */
                    if (indef || tag != basic) {
                        ret = ASN_PARSE_E;
                        goto end;
                    }

                    /* Add to length */
                    IndefItems_AddData(indefItems, length);
                    /* Skip data */
                    i += length;
                }

                /* Ensure we got an EOC and not end of data */
                if (tag != ASN_EOC) {
                    ret = ASN_PARSE_E;
                    goto end;
                }

                /* Set the header length to include the length field */
                IndefItems_UpdateHeaderLen(indefItems);
                /* Go to indefinte parent item */
                IndefItems_Up(indefItems);
            }
        }
        else if (tag == ASN_EOC) {
            /* End-of-content must be 0 length */
            if (length != 0) {
                ret = ASN_PARSE_E;
                goto end;
            }
            /* Check there is an item to close - missing EOC */
            if (indefItems->depth == 0) {
                ret = ASN_PARSE_E;
                goto end;
            }

            /* Finish calculation of data length for indefinite item */
            IndefItems_CalcLength(indefItems);
            /* Go to indefinte parent item */
            IndefItems_Up(indefItems);
        }
        else {
            /* Known length item to add in - make sure enough data for it */
            if (i + length > berSz) {
                ret = ASN_PARSE_E;
                goto end;
            }

            /* Include all data - can't have indefinite inside definite */
            i += length;
            /* Add entire item to current indefinite item */
            IndefItems_MoreData(indefItems, i - start);
        }
    }
    /* Check we had a EOC for each indefinite item */
    if (indefItems->depth != 0) {
        ret = ASN_PARSE_E;
        goto end;
    }

    /* Write out DER */

    j = 0;
    /* Reset index */
    indefItems->idx = 0;
    for (i = 0; i < berSz; ) {
        word32 start = i;

        /* Get item - checked above */
        (void)GetBerHeader(ber, &i, berSz, &tag, &length, &indef);
        if (indef) {
            if (der != NULL) {
                /* Check enough space for header */
                if (j + IndefItems_HeaderLen(indefItems) > *derSz) {
                    ret = BUFFER_E;
                    goto end;
                }

                if ((tag & 0xC0) == 0 &&
                    tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) &&
                    tag != (ASN_SET      | ASN_CONSTRUCTED)) {
                    /* Remove constructed tag for basic types */
                    tag &= ~ASN_CONSTRUCTED;
                }
                /* Add tag and length */
                der[j] = tag;
                (void)SetLength(IndefItems_Len(indefItems), der + j + 1);
            }
            /* Add header length of indefinite item */
            j += IndefItems_HeaderLen(indefItems);

            if ((tag & 0xC0) == 0 &&
                tag != (ASN_SEQUENCE | ASN_CONSTRUCTED) &&
                tag != (ASN_SET      | ASN_CONSTRUCTED)) {
                /* For basic type - get each child item and add data */
                for (; i < berSz; ) {
                    (void)GetBerHeader(ber, &i, berSz, &tag, &length, &indef);
                    if (tag == ASN_EOC) {
                        break;
                    }
                    if (der != NULL) {
                        if (j + length > *derSz) {
                            ret = BUFFER_E;
                            goto end;
                        }
                        XMEMCPY(der + j, ber + i, length);
                    }
                    j += length;
                    i += length;
                }
            }

            /* Move to next indef item in list */
            indefItems->idx++;
        }
        else if (tag == ASN_EOC) {
            /* End-Of-Content is not written out in DER */
        }
        else {
            /* Write out definite length item as is. */
            i += length;
            if (der != NULL) {
                /* Ensure space for item */
                if (j + i - start > *derSz) {
                    ret = BUFFER_E;
                    goto end;
                }
                /* Copy item as is */
                XMEMCPY(der + j, ber + start, i - start);
            }
            j += i - start;
        }
    }

    /* Return the length of the DER encoded ASN.1 */
    *derSz = j;
    if (der == NULL) {
        ret = LENGTH_ONLY_E;
    }
end:
    return ret;
}
#endif

#ifndef WOLFSSL_ASN_TEMPLATE
#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
/* Set the DER/BER encoding of the ASN.1 BIT_STRING with a 16-bit value.
 *
 * val         16-bit value to encode.
 * output      Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
static word32 SetBitString16Bit(word16 val, byte* output)
{
    word32 idx;
    int    len;
    byte   lastByte;
    byte   unusedBits = 0;

    if ((val >> 8) != 0) {
        len = 2;
        lastByte = (byte)(val >> 8);
    }
    else {
        len = 1;
        lastByte = (byte)val;
    }

    while (((lastByte >> unusedBits) & 0x01) == 0x00)
        unusedBits++;

    idx = SetBitString(len, unusedBits, output);
    output[idx++] = (byte)val;
    if (len > 1)
        output[idx++] = (byte)(val >> 8);

    return idx;
}
#endif /* WOLFSSL_CERT_EXT || WOLFSSL_CERT_GEN */
#endif /* !WOLFSSL_ASN_TEMPLATE */

/* hashType */
#ifdef WOLFSSL_MD2
    static const byte hashMd2hOid[] = {42, 134, 72, 134, 247, 13, 2, 2};
#endif
#ifndef NO_MD5
    static const byte hashMd5hOid[] = {42, 134, 72, 134, 247, 13, 2, 5};
#endif
    static const byte hashSha1hOid[] = {43, 14, 3, 2, 26};
    static const byte hashSha224hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 4};
    static const byte hashSha256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 1};
    static const byte hashSha384hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 2};
    static const byte hashSha512hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 3};
    #ifndef WOLFSSL_NOSHA512_224
    static const byte hashSha512_224hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 5};
    #endif
    #ifndef WOLFSSL_NOSHA512_256
    static const byte hashSha512_256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 6};
    #endif
#ifndef WOLFSSL_NOSHA3_224
    static const byte hashSha3_224hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 7};
#endif /* WOLFSSL_NOSHA3_224 */
#ifndef WOLFSSL_NOSHA3_256
    static const byte hashSha3_256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 8};
#endif /* WOLFSSL_NOSHA3_256 */
#ifndef WOLFSSL_NOSHA3_384
    static const byte hashSha3_384hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 9};
#endif /* WOLFSSL_NOSHA3_384 */
#ifndef WOLFSSL_NOSHA3_512
    static const byte hashSha3_512hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 10};
#endif /* WOLFSSL_NOSHA3_512 */

/* hmacType */
    static const byte hmacSha224Oid[] = {42, 134, 72, 134, 247, 13, 2, 8};
    static const byte hmacSha256Oid[] = {42, 134, 72, 134, 247, 13, 2, 9};
    static const byte hmacSha384Oid[] = {42, 134, 72, 134, 247, 13, 2, 10};
    static const byte hmacSha512Oid[] = {42, 134, 72, 134, 247, 13, 2, 11};

/* sigType */
    #ifdef WOLFSSL_MD2
    static const byte sigMd2wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 2};
    #endif
    #ifndef NO_MD5
    static const byte sigMd5wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 4};
    #endif
    static const byte sigSha1wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 5};
    static const byte sigSha224wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,14};
    static const byte sigSha256wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,11};
    static const byte sigSha384wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,12};
    static const byte sigSha512wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,13};
    #ifndef WOLFSSL_NOSHA3_224
    static const byte sigSha3_224wRsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 13};
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    static const byte sigSha3_256wRsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 14};
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    static const byte sigSha3_384wRsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 15};
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    static const byte sigSha3_512wRsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 16};
    #endif
    static const byte sigSha1wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 1};
    static const byte sigSha224wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 1};
    static const byte sigSha256wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 2};
    static const byte sigSha384wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 3};
    static const byte sigSha512wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 4};
    #ifndef WOLFSSL_NOSHA3_224
    static const byte sigSha3_224wEcdsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 9};
    #endif
    #ifndef WOLFSSL_NOSHA3_256
    static const byte sigSha3_256wEcdsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 10};
    #endif
    #ifndef WOLFSSL_NOSHA3_384
    static const byte sigSha3_384wEcdsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 11};
    #endif
    #ifndef WOLFSSL_NOSHA3_512
    static const byte sigSha3_512wEcdsaOid[] = {96, 134, 72, 1, 101, 3, 4, 3, 12};
    #endif

/* keyType */
    static const byte keyRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 1};
    static const byte keyEcdsaOid[] = {42, 134, 72, 206, 61, 2, 1};
    static const byte keyDhOid[] = {42, 134, 72, 134, 247, 13, 1, 3, 1};

/* curveType */
    /* See "ecc_sets" table in ecc.c */

#ifdef HAVE_AES_CBC
/* blkType */
    #ifdef WOLFSSL_AES_128
    static const byte blkAes128CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 2};
    #endif
    #ifdef WOLFSSL_AES_192
    static const byte blkAes192CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 22};
    #endif
    #ifdef WOLFSSL_AES_256
    static const byte blkAes256CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 42};
    #endif
#endif /* HAVE_AES_CBC */
    #ifdef WOLFSSL_AES_128
    static const byte blkAes128GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 6};
    #endif
    #ifdef WOLFSSL_AES_192
    static const byte blkAes192GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 26};
    #endif
    #ifdef WOLFSSL_AES_256
    static const byte blkAes256GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 46};
    #endif


/* keyWrapType */
#ifdef WOLFSSL_AES_128
    static const byte wrapAes128Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 5};
#endif
#ifdef WOLFSSL_AES_192
    static const byte wrapAes192Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 25};
#endif
#ifdef WOLFSSL_AES_256
    static const byte wrapAes256Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 45};
#endif
#ifdef HAVE_PKCS7
/* From RFC 3211 */
static const byte wrapPwriKekOid[] = {42, 134, 72, 134, 247, 13, 1, 9, 16, 3,9};
#endif

/* cmsKeyAgreeType */
    static const byte dhSinglePass_stdDH_sha1kdf_Oid[]   =
                                          {43, 129, 5, 16, 134, 72, 63, 0, 2};
    static const byte dhSinglePass_stdDH_sha224kdf_Oid[] = {43, 129, 4, 1, 11, 0};
    static const byte dhSinglePass_stdDH_sha256kdf_Oid[] = {43, 129, 4, 1, 11, 1};
    static const byte dhSinglePass_stdDH_sha384kdf_Oid[] = {43, 129, 4, 1, 11, 2};
    static const byte dhSinglePass_stdDH_sha512kdf_Oid[] = {43, 129, 4, 1, 11, 3};

/* ocspType */

/* certExtType */
static const byte extBasicCaOid[] = {85, 29, 19};
static const byte extAltNamesOid[] = {85, 29, 17};
static const byte extCrlDistOid[] = {85, 29, 31};
static const byte extAuthInfoOid[] = {43, 6, 1, 5, 5, 7, 1, 1};
static const byte extAuthKeyOid[] = {85, 29, 35};
static const byte extSubjKeyOid[] = {85, 29, 14};
static const byte extCertPolicyOid[] = {85, 29, 32};
static const byte extKeyUsageOid[] = {85, 29, 15};
static const byte extInhibitAnyOid[] = {85, 29, 54};
static const byte extExtKeyUsageOid[] = {85, 29, 37};
#ifndef IGNORE_NAME_CONSTRAINTS
    static const byte extNameConsOid[] = {85, 29, 30};
#endif

/* certAuthInfoType */
static const byte extAuthInfoOcspOid[] = {43, 6, 1, 5, 5, 7, 48, 1};
static const byte extAuthInfoCaIssuerOid[] = {43, 6, 1, 5, 5, 7, 48, 2};

/* certPolicyType */
static const byte extCertPolicyAnyOid[] = {85, 29, 32, 0};

/* certAltNameType */
static const byte extAltNamesHwNameOid[] = {43, 6, 1, 5, 5, 7, 8, 4};

/* certKeyUseType */
static const byte extExtKeyUsageAnyOid[] = {85, 29, 37, 0};
static const byte extExtKeyUsageServerAuthOid[]   = {43, 6, 1, 5, 5, 7, 3, 1};
static const byte extExtKeyUsageClientAuthOid[]   = {43, 6, 1, 5, 5, 7, 3, 2};
static const byte extExtKeyUsageCodeSigningOid[]  = {43, 6, 1, 5, 5, 7, 3, 3};
static const byte extExtKeyUsageEmailProtectOid[] = {43, 6, 1, 5, 5, 7, 3, 4};
static const byte extExtKeyUsageTimestampOid[]    = {43, 6, 1, 5, 5, 7, 3, 8};
static const byte extExtKeyUsageOcspSignOid[]     = {43, 6, 1, 5, 5, 7, 3, 9};

#if defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_GEN) ||  defined(WOLFSSL_ASN_TEMPLATE)
/* csrAttrType */
#define CSR_ATTR_TYPE_OID_BASE(num) {42, 134, 72, 134, 247, 13, 1, 9, num}
#if !defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_GEN)
static const byte attrEmailOid[] =             CSR_ATTR_TYPE_OID_BASE(1);
#endif
#ifdef WOLFSSL_CERT_REQ
static const byte attrUnstructuredNameOid[] =  CSR_ATTR_TYPE_OID_BASE(2);
static const byte attrPkcs9ContentTypeOid[] =  CSR_ATTR_TYPE_OID_BASE(3);
static const byte attrChallengePasswordOid[] = CSR_ATTR_TYPE_OID_BASE(7);
static const byte attrExtensionRequestOid[] =  CSR_ATTR_TYPE_OID_BASE(14);
static const byte attrSerialNumberOid[] = {85, 4, 5};
#endif
#endif

/* kdfType */
static const byte pbkdf2Oid[] = {42, 134, 72, 134, 247, 13, 1, 5, 12};

/* PKCS5 */
static const byte pbes2[] = {42, 134, 72, 134, 247, 13, 1, 5, 13};

/* PKCS12 */


#if defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_GEN) ||  defined(WOLFSSL_ASN_TEMPLATE)
/* Pilot attribute types (0.9.2342.19200300.100.1.*) */
static const byte uidOid[] = {9, 146, 38, 137, 147, 242, 44, 100, 1, 1}; /* user id */

static const byte dcOid[] = {9, 146, 38, 137, 147, 242, 44, 100, 1, 25}; /* domain component */
#endif


/* Looks up the ID/type of an OID.
 *
 * When known returns the OID as a byte array and its length.
 * ID-type are unique.
 *
 * Use oidIgnoreType to autofail.
 *
 * @param [in]  id     OID id.
 * @param [in]  type   Type of OID (enum Oid_Types).
 * @param [out] oidSz  Length of OID byte array returned.
 * @return  Array of bytes for the OID.
 * @return  NULL when ID/type not recognized.
 */
const byte* OidFromId(word32 id, word32 type, word32* oidSz)
{
    const byte* oid = NULL;

    *oidSz = 0;

    switch (type) {

        case oidHashType:
            switch (id) {
            #ifdef WOLFSSL_MD2
                case MD2h:
                    oid = hashMd2hOid;
                    *oidSz = sizeof(hashMd2hOid);
                    break;
            #endif
            #ifndef NO_MD5
                case MD5h:
                    oid = hashMd5hOid;
                    *oidSz = sizeof(hashMd5hOid);
                    break;
            #endif
                case SHAh:
                    oid = hashSha1hOid;
                    *oidSz = sizeof(hashSha1hOid);
                    break;
                case SHA224h:
                    oid = hashSha224hOid;
                    *oidSz = sizeof(hashSha224hOid);
                    break;
                case SHA256h:
                    oid = hashSha256hOid;
                    *oidSz = sizeof(hashSha256hOid);
                    break;
                case SHA384h:
                    oid = hashSha384hOid;
                    *oidSz = sizeof(hashSha384hOid);
                    break;
                #ifndef WOLFSSL_NOSHA512_224
                case SHA512_224h:
                    oid = hashSha512_224hOid;
                    *oidSz = sizeof(hashSha512_224hOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA512_256
                case SHA512_256h:
                    oid = hashSha512_256hOid;
                    *oidSz = sizeof(hashSha512_256hOid);
                    break;
                #endif
                case SHA512h:
                    oid = hashSha512hOid;
                    *oidSz = sizeof(hashSha512hOid);
                    break;
            #ifndef WOLFSSL_NOSHA3_224
                case SHA3_224h:
                    oid = hashSha3_224hOid;
                    *oidSz = sizeof(hashSha3_224hOid);
                    break;
            #endif /* WOLFSSL_NOSHA3_224 */
            #ifndef WOLFSSL_NOSHA3_256
                case SHA3_256h:
                    oid = hashSha3_256hOid;
                    *oidSz = sizeof(hashSha3_256hOid);
                    break;
            #endif /* WOLFSSL_NOSHA3_256 */
            #ifndef WOLFSSL_NOSHA3_384
                case SHA3_384h:
                    oid = hashSha3_384hOid;
                    *oidSz = sizeof(hashSha3_384hOid);
                    break;
            #endif /* WOLFSSL_NOSHA3_384 */
            #ifndef WOLFSSL_NOSHA3_512
                case SHA3_512h:
                    oid = hashSha3_512hOid;
                    *oidSz = sizeof(hashSha3_512hOid);
                    break;
            #endif /* WOLFSSL_NOSHA3_512 */
                default:
                    break;
            }
            break;

        case oidSigType:
            switch (id) {
                #ifdef WOLFSSL_MD2
                case CTC_MD2wRSA:
                    oid = sigMd2wRsaOid;
                    *oidSz = sizeof(sigMd2wRsaOid);
                    break;
                #endif
                #ifndef NO_MD5
                case CTC_MD5wRSA:
                    oid = sigMd5wRsaOid;
                    *oidSz = sizeof(sigMd5wRsaOid);
                    break;
                #endif
                case CTC_SHAwRSA:
                    oid = sigSha1wRsaOid;
                    *oidSz = sizeof(sigSha1wRsaOid);
                    break;
                case CTC_SHA224wRSA:
                    oid = sigSha224wRsaOid;
                    *oidSz = sizeof(sigSha224wRsaOid);
                    break;
                case CTC_SHA256wRSA:
                    oid = sigSha256wRsaOid;
                    *oidSz = sizeof(sigSha256wRsaOid);
                    break;
                case CTC_SHA384wRSA:
                    oid = sigSha384wRsaOid;
                    *oidSz = sizeof(sigSha384wRsaOid);
                    break;
                case CTC_SHA512wRSA:
                    oid = sigSha512wRsaOid;
                    *oidSz = sizeof(sigSha512wRsaOid);
                    break;
                #ifndef WOLFSSL_NOSHA3_224
                case CTC_SHA3_224wRSA:
                    oid = sigSha3_224wRsaOid;
                    *oidSz = sizeof(sigSha3_224wRsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_256
                case CTC_SHA3_256wRSA:
                    oid = sigSha3_256wRsaOid;
                    *oidSz = sizeof(sigSha3_256wRsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_384
                case CTC_SHA3_384wRSA:
                    oid = sigSha3_384wRsaOid;
                    *oidSz = sizeof(sigSha3_384wRsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_512
                case CTC_SHA3_512wRSA:
                    oid = sigSha3_512wRsaOid;
                    *oidSz = sizeof(sigSha3_512wRsaOid);
                    break;
                #endif
                case CTC_SHAwECDSA:
                    oid = sigSha1wEcdsaOid;
                    *oidSz = sizeof(sigSha1wEcdsaOid);
                    break;
                case CTC_SHA224wECDSA:
                    oid = sigSha224wEcdsaOid;
                    *oidSz = sizeof(sigSha224wEcdsaOid);
                    break;
                case CTC_SHA256wECDSA:
                    oid = sigSha256wEcdsaOid;
                    *oidSz = sizeof(sigSha256wEcdsaOid);
                    break;
                case CTC_SHA384wECDSA:
                    oid = sigSha384wEcdsaOid;
                    *oidSz = sizeof(sigSha384wEcdsaOid);
                    break;
                case CTC_SHA512wECDSA:
                    oid = sigSha512wEcdsaOid;
                    *oidSz = sizeof(sigSha512wEcdsaOid);
                    break;
                #ifndef WOLFSSL_NOSHA3_224
                case CTC_SHA3_224wECDSA:
                    oid = sigSha3_224wEcdsaOid;
                    *oidSz = sizeof(sigSha3_224wEcdsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_256
                case CTC_SHA3_256wECDSA:
                    oid = sigSha3_256wEcdsaOid;
                    *oidSz = sizeof(sigSha3_256wEcdsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_384
                case CTC_SHA3_384wECDSA:
                    oid = sigSha3_384wEcdsaOid;
                    *oidSz = sizeof(sigSha3_384wEcdsaOid);
                    break;
                #endif
                #ifndef WOLFSSL_NOSHA3_512
                case CTC_SHA3_512wECDSA:
                    oid = sigSha3_512wEcdsaOid;
                    *oidSz = sizeof(sigSha3_512wEcdsaOid);
                    break;
                #endif
                default:
                    break;
            }
            break;

        case oidKeyType:
            switch (id) {
                case RSAk:
                    oid = keyRsaOid;
                    *oidSz = sizeof(keyRsaOid);
                    break;
                case ECDSAk:
                    oid = keyEcdsaOid;
                    *oidSz = sizeof(keyEcdsaOid);
                    break;
                case DHk:
                    oid = keyDhOid;
                    *oidSz = sizeof(keyDhOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCurveType:
            if (wc_ecc_get_oid(id, &oid, oidSz) < 0) {
                WOLFSSL_MSG("ECC OID not found");
            }
            break;

        case oidBlkType:
            switch (id) {
    #ifdef HAVE_AES_CBC
        #ifdef WOLFSSL_AES_128
                case AES128CBCb:
                    oid = blkAes128CbcOid;
                    *oidSz = sizeof(blkAes128CbcOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_192
                case AES192CBCb:
                    oid = blkAes192CbcOid;
                    *oidSz = sizeof(blkAes192CbcOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_256
                case AES256CBCb:
                    oid = blkAes256CbcOid;
                    *oidSz = sizeof(blkAes256CbcOid);
                    break;
        #endif
    #endif /* HAVE_AES_CBC */
        #ifdef WOLFSSL_AES_128
                case AES128GCMb:
                    oid = blkAes128GcmOid;
                    *oidSz = sizeof(blkAes128GcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_192
                case AES192GCMb:
                    oid = blkAes192GcmOid;
                    *oidSz = sizeof(blkAes192GcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_256
                case AES256GCMb:
                    oid = blkAes256GcmOid;
                    *oidSz = sizeof(blkAes256GcmOid);
                    break;
        #endif
                default:
                    break;
            }
            break;


        case oidCertExtType:
            switch (id) {
                case BASIC_CA_OID:
                    oid = extBasicCaOid;
                    *oidSz = sizeof(extBasicCaOid);
                    break;
                case ALT_NAMES_OID:
                    oid = extAltNamesOid;
                    *oidSz = sizeof(extAltNamesOid);
                    break;
                case CRL_DIST_OID:
                    oid = extCrlDistOid;
                    *oidSz = sizeof(extCrlDistOid);
                    break;
                case AUTH_INFO_OID:
                    oid = extAuthInfoOid;
                    *oidSz = sizeof(extAuthInfoOid);
                    break;
                case AUTH_KEY_OID:
                    oid = extAuthKeyOid;
                    *oidSz = sizeof(extAuthKeyOid);
                    break;
                case SUBJ_KEY_OID:
                    oid = extSubjKeyOid;
                    *oidSz = sizeof(extSubjKeyOid);
                    break;
                case CERT_POLICY_OID:
                    oid = extCertPolicyOid;
                    *oidSz = sizeof(extCertPolicyOid);
                    break;
                case KEY_USAGE_OID:
                    oid = extKeyUsageOid;
                    *oidSz = sizeof(extKeyUsageOid);
                    break;
                case INHIBIT_ANY_OID:
                    oid = extInhibitAnyOid;
                    *oidSz = sizeof(extInhibitAnyOid);
                    break;
                case EXT_KEY_USAGE_OID:
                    oid = extExtKeyUsageOid;
                    *oidSz = sizeof(extExtKeyUsageOid);
                    break;
            #ifndef IGNORE_NAME_CONSTRAINTS
                case NAME_CONS_OID:
                    oid = extNameConsOid;
                    *oidSz = sizeof(extNameConsOid);
                    break;
            #endif
                default:
                    break;
            }
            break;

        case oidCrlExtType:
            break;

        case oidCertAuthInfoType:
            switch (id) {
                case AIA_OCSP_OID:
                    oid = extAuthInfoOcspOid;
                    *oidSz = sizeof(extAuthInfoOcspOid);
                    break;
                case AIA_CA_ISSUER_OID:
                    oid = extAuthInfoCaIssuerOid;
                    *oidSz = sizeof(extAuthInfoCaIssuerOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCertPolicyType:
            switch (id) {
                case CP_ANY_OID:
                    oid = extCertPolicyAnyOid;
                    *oidSz = sizeof(extCertPolicyAnyOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCertAltNameType:
            switch (id) {
                case HW_NAME_OID:
                    oid = extAltNamesHwNameOid;
                    *oidSz = sizeof(extAltNamesHwNameOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCertKeyUseType:
            switch (id) {
                case EKU_ANY_OID:
                    oid = extExtKeyUsageAnyOid;
                    *oidSz = sizeof(extExtKeyUsageAnyOid);
                    break;
                case EKU_SERVER_AUTH_OID:
                    oid = extExtKeyUsageServerAuthOid;
                    *oidSz = sizeof(extExtKeyUsageServerAuthOid);
                    break;
                case EKU_CLIENT_AUTH_OID:
                    oid = extExtKeyUsageClientAuthOid;
                    *oidSz = sizeof(extExtKeyUsageClientAuthOid);
                    break;
                case EKU_CODESIGNING_OID:
                    oid = extExtKeyUsageCodeSigningOid;
                    *oidSz = sizeof(extExtKeyUsageCodeSigningOid);
                    break;
                case EKU_EMAILPROTECT_OID:
                    oid = extExtKeyUsageEmailProtectOid;
                    *oidSz = sizeof(extExtKeyUsageEmailProtectOid);
                    break;
                case EKU_TIMESTAMP_OID:
                    oid = extExtKeyUsageTimestampOid;
                    *oidSz = sizeof(extExtKeyUsageTimestampOid);
                    break;
                case EKU_OCSP_SIGN_OID:
                    oid = extExtKeyUsageOcspSignOid;
                    *oidSz = sizeof(extExtKeyUsageOcspSignOid);
                    break;
                default:
                    break;
            }
            break;

        case oidKdfType:
            switch (id) {
                case PBKDF2_OID:
                    oid = pbkdf2Oid;
                    *oidSz = sizeof(pbkdf2Oid);
                    break;
                default:
                    break;
            }
            break;

        case oidPBEType:
            switch (id) {
                case PBES2_SUM:
                case PBES2:
                    oid = pbes2;
                    *oidSz = sizeof(pbes2);
                    break;
                default:
                    break;
            }
            break;

        case oidKeyWrapType:
            switch (id) {
            #ifdef WOLFSSL_AES_128
                case AES128_WRAP:
                    oid = wrapAes128Oid;
                    *oidSz = sizeof(wrapAes128Oid);
                    break;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192_WRAP:
                    oid = wrapAes192Oid;
                    *oidSz = sizeof(wrapAes192Oid);
                    break;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256_WRAP:
                    oid = wrapAes256Oid;
                    *oidSz = sizeof(wrapAes256Oid);
                    break;
            #endif
            #ifdef HAVE_PKCS7
                case PWRI_KEK_WRAP:
                    oid = wrapPwriKekOid;
                    *oidSz = sizeof(wrapPwriKekOid);
                    break;
            #endif
                default:
                    break;
            }
            break;

        case oidCmsKeyAgreeType:
            switch (id) {
                case dhSinglePass_stdDH_sha1kdf_scheme:
                    oid = dhSinglePass_stdDH_sha1kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha1kdf_Oid);
                    break;
                case dhSinglePass_stdDH_sha224kdf_scheme:
                    oid = dhSinglePass_stdDH_sha224kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha224kdf_Oid);
                    break;
                case dhSinglePass_stdDH_sha256kdf_scheme:
                    oid = dhSinglePass_stdDH_sha256kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha256kdf_Oid);
                    break;
                case dhSinglePass_stdDH_sha384kdf_scheme:
                    oid = dhSinglePass_stdDH_sha384kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha384kdf_Oid);
                    break;
                case dhSinglePass_stdDH_sha512kdf_scheme:
                    oid = dhSinglePass_stdDH_sha512kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha512kdf_Oid);
                    break;
                default:
                    break;
            }
            break;

        case oidHmacType:
            switch (id) {
                case HMAC_SHA224_OID:
                    oid = hmacSha224Oid;
                    *oidSz = sizeof(hmacSha224Oid);
                    break;
                case HMAC_SHA256_OID:
                    oid = hmacSha256Oid;
                    *oidSz = sizeof(hmacSha256Oid);
                    break;
                case HMAC_SHA384_OID:
                    oid = hmacSha384Oid;
                    *oidSz = sizeof(hmacSha384Oid);
                    break;
                case HMAC_SHA512_OID:
                    oid = hmacSha512Oid;
                    *oidSz = sizeof(hmacSha512Oid);
                    break;
                default:
                    break;
            }
            break;

#ifdef WOLFSSL_CERT_REQ
        case oidCsrAttrType:
            switch (id) {
                case UNSTRUCTURED_NAME_OID:
                    oid = attrUnstructuredNameOid;
                    *oidSz = sizeof(attrUnstructuredNameOid);
                    break;
                case PKCS9_CONTENT_TYPE_OID:
                    oid = attrPkcs9ContentTypeOid;
                    *oidSz = sizeof(attrPkcs9ContentTypeOid);
                    break;
                case CHALLENGE_PASSWORD_OID:
                    oid = attrChallengePasswordOid;
                    *oidSz = sizeof(attrChallengePasswordOid);
                    break;
                case SERIAL_NUMBER_OID:
                    oid = attrSerialNumberOid;
                    *oidSz = sizeof(attrSerialNumberOid);
                    break;
                case USER_ID_OID:
                    oid = uidOid;
                    *oidSz = sizeof(uidOid);
                    break;
                case EXTENSION_REQUEST_OID:
                    oid = attrExtensionRequestOid;
                    *oidSz = sizeof(attrExtensionRequestOid);
                    break;
                default:
                    break;
            }
            break;
#endif
        case oidIgnoreType:
        default:
            break;
    }

    return oid;
}


/* Check the OID id is for a known elliptic curve.
 *
 * @param [in]  oid  OID id.
 * @return  ECC set id on success.
 * @return  ALGO_ID_E when OID id is 0 or not supported.
 */
static int CheckCurve(word32 oid)
{
    int ret;
    word32 oidSz;

    /* Lookup OID id. */
    ret = wc_ecc_get_oid(oid, NULL, &oidSz);
    /* Check for error or zero length OID size (can't get OID for encoding). */
    if ((ret < 0) || (oidSz == 0)) {
        WOLFSSL_MSG("CheckCurve not found");
        ret = ALGO_ID_E;
    }

    /* Return ECC set id or error code. */
    return ret;
}


#ifdef HAVE_OID_ENCODING
/* Encode dotted form of OID into byte array version.
 *
 * @param [in]      in     Dotted form of OID.
 * @param [in]      inSz   Count of numbers in dotted form.
 * @param [in]      out    Buffer to hold OID.
 * @param [in, out] outSz  On in, size of buffer.
 *                         On out, number of bytes in buffer.
 * @return  0 on success
 * @return  BAD_FUNC_ARG when in or outSz is NULL.
 * @return  BUFFER_E when buffer too small.
 */
int EncodeObjectId(const word16* in, word32 inSz, byte* out, word32* outSz)
{
    int i, x, len;
    word32 d, t;

    /* check args */
    if (in == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* compute length of encoded OID */
    d = (in[0] * 40) + in[1];
    len = 0;
    for (i = 1; i < (int)inSz; i++) {
        x = 0;
        t = d;
        while (t) {
            x++;
            t >>= 1;
        }
        len += (x / 7) + ((x % 7) ? 1 : 0) + (d == 0 ? 1 : 0);

        if (i < (int)inSz - 1) {
            d = in[i + 1];
        }
    }

    if (out) {
        /* verify length */
        if ((int)*outSz < len) {
            return BUFFER_E; /* buffer provided is not large enough */
        }

        /* calc first byte */
        d = (in[0] * 40) + in[1];

        /* encode bytes */
        x = 0;
        for (i = 1; i < (int)inSz; i++) {
            if (d) {
                int y = x, z;
                byte mask = 0;
                while (d) {
                    out[x++] = (byte)((d & 0x7F) | mask);
                    d     >>= 7;
                    mask  |= 0x80;  /* upper bit is set on all but the last byte */
                }
                /* now swap bytes y...x-1 */
                z = x - 1;
                while (y < z) {
                    mask = out[y];
                    out[y] = out[z];
                    out[z] = mask;
                    ++y;
                    --z;
                }
            }
            else {
              out[x++] = 0x00; /* zero value */
            }

            /* next word */
            if (i < (int)inSz - 1) {
                d = in[i + 1];
            }
        }
    }

    /* return length */
    *outSz = len;

    return 0;
}
#endif /* HAVE_OID_ENCODING */

#ifdef HAVE_OID_DECODING
/* Encode dotted form of OID into byte array version.
 *
 * @param [in]      in     Byte array containing OID.
 * @param [in]      inSz   Size of OID in bytes.
 * @param [in]      out    Array to hold dotted form of OID.
 * @param [in, out] outSz  On in, number of elemnts in array.
 *                         On out, count of numbers in dotted form.
 * @return  0 on success
 * @return  BAD_FUNC_ARG when in or outSz is NULL.
 * @return  BUFFER_E when dotted form buffer too small.
 */
int DecodeObjectId(const byte* in, word32 inSz, word16* out, word32* outSz)
{
    int x = 0, y = 0;
    word32 t = 0;

    /* check args */
    if (in == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* decode bytes */
    while (inSz--) {
        t = (t << 7) | (in[x] & 0x7F);
        if (!(in[x] & 0x80)) {
            if (y >= (int)*outSz) {
                return BUFFER_E;
            }
            if (y == 0) {
                out[0] = (t / 40);
                out[1] = (t % 40);
                y = 2;
            }
            else {
                out[y++] = t;
            }
            t = 0; /* reset tmp */
        }
        x++;
    }

    /* return length */
    *outSz = y;

    return 0;
}
#endif /* HAVE_OID_DECODING */

/* Decode the header of a BER/DER encoded OBJECT ID.
 *
 * @param [in]      input     Buffer holding DER/BER encoded data.
 * @param [in, out] inOutIdx  On in, starting index of header.
 *                            On out, end of parsed header.
 * @param [out]     len       Number of bytes in the ASN.1 data.
 * @param [in]      maxIdx    Length of data in buffer.
 * @return  0 on success.
 * @return  BUFFER_E when there is not enough data to parse.
 * @return  ASN_PARSE_E when the tag is not a OBJECT ID or length is invalid.
 */
int GetASNObjectId(const byte* input, word32* inOutIdx, int* len, word32 maxIdx)
{
    int ret = GetASNHeader(input, ASN_OBJECT_ID, inOutIdx, len, maxIdx);
    if (ret > 0) {
        /* Only return 0 on success. */
        ret = 0;
    }
    return ret;
}

/* Set the DER/BER encoding of the ASN.1 OBJECT ID header.
 *
 * When output is NULL, calculate the header length only.
 *
 * @param [in]  len        Length of OBJECT ID data in bytes.
 * @param [out] output     Buffer to write into.
 * @return  Number of bytes added to the buffer.
 */
int SetObjectId(int len, byte* output)
{
    int idx = 0;

    if (output) {
        /* Write out tag. */
        output[idx] = ASN_OBJECT_ID;
    }
    /* Skip tag. */
    idx += ASN_TAG_SZ;
    /* Encode length - passing NULL for output will not encode. */
    idx += SetLength(len, output ? output + idx : NULL);

    /* Return index after header. */
    return idx;
}

#ifdef ASN_DUMP_OID
/* Dump the OID information.
 *
 * Decode the OID too if function available.
 *
 * @param [in] oidData  OID data from buffer.
 * @param [in] oidSz    Size of OID data in buffer.
 * @param [in] oid      OID id.
 * @param [in] oidType  Type of OID.
 * @return  0 on success.
 * @return  BUFFER_E when not enough bytes for proper decode.
 *          (HAVE_OID_DECODING)
 */
static int DumpOID(const byte* oidData, word32 oidSz, word32 oid,
                   word32 oidType)
{
    int    ret = 0;
    word32 i;

    /* support for dumping OID information */
    printf("OID (Type %d, Sz %d, Sum %d): ", oidType, oidSz, oid);
    /* Dump bytes in decimal. */
    for (i = 0; i < oidSz; i++) {
        printf("%d, ", oidData[i]);
    }
    printf("\n");
    /* Dump bytes in hexadecimal. */
    for (i = 0; i < oidSz; i++) {
        printf("%02x, ", oidData[i]);
    }
    printf("\n");

    #ifdef HAVE_OID_DECODING
    {
        word16 decOid[MAX_OID_SZ];
        word32 decOidSz = sizeof(decOid);
        /* Decode the OID into dotted form. */
        ret = DecodeObjectId(oidData, oidSz, decOid, &decOidSz);
        if (ret == 0) {
            printf("  Decoded (Sz %d): ", decOidSz);
            for (i=0; i<decOidSz; i++) {
                printf("%d.", decOid[i]);
            }
            printf("\n");
        }
        else {
            printf("DecodeObjectId failed: %d\n", ret);
        }
    }
    #endif /* HAVE_OID_DECODING */

    return ret;
}
#endif /* ASN_DUMP_OID */

/* Get the OID data and verify it is of the type specified when compiled in.
 *
 * @param [in]      input     Buffer holding OID.
 * @param [in, out] inOutIdx  On in, starting index of OID.
 *                            On out, end of parsed OID.
 * @param [out]     oid       OID id.
 * @param [in]      oidType   Expected type of OID. Define NO_VERIFY_OID to
 *                            not compile in check.
 * @param [in]      length    Length of OID data in buffer.
 * @return  0 on success.
 * @return  ASN_UNKNOWN_OID_E when OID is not recognized.
 * @return  BUFFER_E when not enough bytes for proper decode. (ASN_DUMP_OID and
 *          HAVE_OID_DECODING)
 */
static int GetOID(const byte* input, word32* inOutIdx, word32* oid,
                  word32 oidType, int length)
{
    int    ret = 0;
    word32 idx = *inOutIdx;
#ifndef NO_VERIFY_OID
    word32 actualOidSz;
    const byte* actualOid;
    const byte* checkOid = NULL;
    word32 checkOidSz;
#endif /* NO_VERIFY_OID */

    (void)oidType;
    *oid = 0;

#ifndef NO_VERIFY_OID
    /* Keep references to OID data and length for check. */
    actualOid = &input[idx];
    actualOidSz = (word32)length;
#endif /* NO_VERIFY_OID */

    /* Sum it up for now. */
    while (length--) {
        /* odd HC08 compiler behavior here when input[idx++] */
        *oid += (word32)input[idx];
        idx++;
    }

    /* Return the index after the OID data. */
    *inOutIdx = idx;

#ifndef NO_VERIFY_OID
    /* 'Ignore' type means we don't care which OID it is. */
    if (oidType != oidIgnoreType) {
        /* Get the OID data for the id-type. */
        checkOid = OidFromId(*oid, oidType, &checkOidSz);

    #ifdef ASN_DUMP_OID
        /* Dump out the data for debug. */
        ret = DumpOID(actualOid, actualOidSz, *oid, oidType);
    #endif

        /* TODO: Want to fail when checkOid is NULL.
         * Can't as too many situations where unknown OID is to be
         * supported. Extra parameter for must not be NULL?
         */
        /* Check that the OID data matches what we found for the OID id. */
        if ((ret == 0) && (checkOid != NULL) && ((checkOidSz != actualOidSz) ||
                (XMEMCMP(actualOid, checkOid, checkOidSz) != 0))) {
            WOLFSSL_MSG("OID Check Failed");
            ret = ASN_UNKNOWN_OID_E;
        }
    }
#endif /* NO_VERIFY_OID */

    return ret;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for an OBJECT_ID. */
static const ASNItem objectIdASN[] = {
/* OID */ { 0, ASN_OBJECT_ID, 0, 0, 0 }
};
enum {
    OBJECTIDASN_IDX_OID = 0
};

/* Number of items in ASN.1 template for an OBJECT_ID. */
#define objectIdASN_Length (sizeof(objectIdASN) / sizeof(ASNItem))
#endif

/* Get the OID id/sum from the BER encoded OBJECT_ID.
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of OBJECT_ID.
 *                            On out, start of ASN.1 item after OBJECT_ID.
 * @param [out]     oid       Id of OID in OBJECT_ID data.
 * @param [in]      oidType   Type of OID to expect.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                                  word32 oidType, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret, length;

    WOLFSSL_ENTER("GetObjectId()");

    ret = GetASNObjectId(input, inOutIdx, &length, maxIdx);
    if (ret != 0)
        return ret;

    return GetOID(input, inOutIdx, oid, oidType, length);
#else
    ASNGetData dataASN[objectIdASN_Length];
    int ret;

    WOLFSSL_ENTER("GetObjectId()");

    /* Clear dynamic data and set OID type expected. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_OID(&dataASN[OBJECTIDASN_IDX_OID], oidType);
    /* Decode OBJECT_ID. */
    ret = GetASN_Items(objectIdASN, dataASN, objectIdASN_Length, 0, input,
                       inOutIdx, maxIdx);
    if (ret == 0) {
        /* Return the id/sum. */
        *oid = dataASN[OBJECTIDASN_IDX_OID].data.oid.sum;
    }
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifndef WOLFSSL_ASN_TEMPLATE
static int SkipObjectId(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    length;
    int ret;

    ret = GetASNObjectId(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    idx += length;
    *inOutIdx = idx;

    return 0;
}
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for an algorithm identifier. */
static const ASNItem algoIdASN[] = {
/*  SEQ  */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/*  OID  */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/*  NULL */        { 1, ASN_TAG_NULL, 0, 0, 1 },
};
enum {
    ALGOIDASN_IDX_SEQ = 0,
    ALGOIDASN_IDX_OID,
    ALGOIDASN_IDX_NULL
};

/* Number of items in ASN.1 template for an algorithm identifier. */
#define algoIdASN_Length (sizeof(algoIdASN) / sizeof(ASNItem))
#endif

/* Get the OID id/sum from the BER encoding of an algorithm identifier.
 *
 * NULL tag is skipped if present.
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of algorithm identifier.
 *                            On out, start of ASN.1 item after algorithm id.
 * @param [out]     oid       Id of OID in algorithm identifier data.
 * @param [in]      oidType   Type of OID to expect.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when encoding is invalid.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid,
                     word32 oidType, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    length;
    word32 idx = *inOutIdx;
    int    ret;
    *oid = 0;

    WOLFSSL_ENTER("GetAlgoId");

    if (GetSequence(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetObjectId(input, &idx, oid, oidType, maxIdx) < 0)
        return ASN_OBJECT_ID_E;

    /* could have NULL tag and 0 terminator, but may not */
    if (idx < maxIdx) {
        word32 localIdx = idx; /*use localIdx to not advance when checking tag*/
        byte   tag;

        if (GetASNTag(input, &localIdx, &tag, maxIdx) == 0) {
            if (tag == ASN_TAG_NULL) {
                ret = GetASNNull(input, &idx, maxIdx);
                if (ret != 0)
                    return ret;
            }
        }
    }

    *inOutIdx = idx;

    return 0;
#else
    DECL_ASNGETDATA(dataASN, algoIdASN_Length);
    int ret = 0;

    WOLFSSL_ENTER("GetAlgoId");

    CALLOC_ASNGETDATA(dataASN, algoIdASN_Length, ret, NULL);
    if (ret == 0) {
        /* Set OID type expected. */
        GetASN_OID(&dataASN[ALGOIDASN_IDX_OID], oidType);
        /* Decode the algorithm identifier. */
        ret = GetASN_Items(algoIdASN, dataASN, algoIdASN_Length, 0, input, inOutIdx,
                           maxIdx);
    }
    if (ret == 0) {
        /* Return the OID id/sum. */
        *oid = dataASN[ALGOIDASN_IDX_OID].data.oid.sum;
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


#ifndef HAVE_USER_RSA
#if defined(WOLFSSL_ASN_TEMPLATE) || (  defined(WOLFSSL_KEY_GEN) ||  defined(WOLFSSL_KCAPI_RSA))
/* Byte offset of numbers in RSA key. */
size_t rsaIntOffset[] = {
    OFFSETOF(RsaKey, n),
    OFFSETOF(RsaKey, e),
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || defined(WOLFSSL_KEY_GEN)
    OFFSETOF(RsaKey, d),
    OFFSETOF(RsaKey, p),
    OFFSETOF(RsaKey, q),
    OFFSETOF(RsaKey, dP),
    OFFSETOF(RsaKey, dQ),
    OFFSETOF(RsaKey, u)
#endif
};

/* Get a number from the RSA key based on an index.
 *
 * Order: { n, e, d, p, q, dP, dQ, u }
 *
 * Caller must ensure index is not invalid!
 *
 * @param [in] key  RSA key object.
 * @param [in] idx  Index of number.
 * @return  A pointer to an mp_int when valid index.
 * @return  NULL when invalid index.
 */
static mp_int* GetRsaInt(RsaKey* key, byte idx)
{
    /* Cast key to byte array to and use offset to get to mp_int field. */
    return (mp_int*)(((byte*)key) + rsaIntOffset[idx]);
}
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for an RSA private key.
 * PKCS #1: RFC 8017, A.1.2 - RSAPrivateKey
 */
static const ASNItem rsaKeyASN[] = {
/*  SEQ */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/*  VER */        { 1, ASN_INTEGER, 0, 0, 0 },
                /* Integers need to be in this specific order
                 * as asn code depends on this. */
/*  N   */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  E   */        { 1, ASN_INTEGER, 0, 0, 0 },
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || defined(WOLFSSL_KEY_GEN)
/*  D   */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  P   */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  Q   */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  DP  */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  DQ  */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  U   */        { 1, ASN_INTEGER, 0, 0, 0 },
                /* otherPrimeInfos  OtherPrimeInfos OPTIONAL
                 * v2 - multiprime */
#endif
};
enum {
    RSAKEYASN_IDX_SEQ = 0,
    RSAKEYASN_IDX_VER,
    /* Integers need to be in this specific order
     * as asn code depends on this. */
    RSAKEYASN_IDX_N,
    RSAKEYASN_IDX_E,
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || defined(WOLFSSL_KEY_GEN)
    RSAKEYASN_IDX_D,
    RSAKEYASN_IDX_P,
    RSAKEYASN_IDX_Q,
    RSAKEYASN_IDX_DP,
    RSAKEYASN_IDX_DQ,
    RSAKEYASN_IDX_U,
#endif
};

/* Number of items in ASN.1 template for an RSA private key. */
#define rsaKeyASN_Length (sizeof(rsaKeyASN) / sizeof(ASNItem))
#endif

/* Decode RSA private key.
 *
 * PKCS #1: RFC 8017, A.1.2 - RSAPrivateKey
 *
 * Compiling with WOLFSSL_RSA_PUBLIC_ONLY will result in only the public fields
 * being extracted.
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of RSA private key.
 *                            On out, start of ASN.1 item after RSA private key.
 * @param [in, out] key       RSA key object.
 * @param [in]      inSz      Number of bytes in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 */
int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int version, length;
    word32 algId = 0;

    if (inOutIdx == NULL || input == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ||
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
        GetInt(&key->d,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0
#else
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0
#endif
       ) {
            return ASN_RSA_KEY_E;
       }
#if (defined(WOLFSSL_KEY_GEN) || !defined(RSA_LOW_MEM))  && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    if (GetInt(&key->dP, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dQ, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->u,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;
#else
    if (SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;
#endif

#if defined(WOLFSSL_XILINX_CRYPT)
    if (wc_InitRsaHw(key) != 0) {
        return BAD_STATE_E;
    }
#endif

    return 0;
#else
    DECL_ASNGETDATA(dataASN, rsaKeyASN_Length);
    int        ret = 0;
    int        i;
    byte       version = (byte)-1;
#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    word32 algId = 0;
#endif

    /* Check validity of parameters. */
    if (inOutIdx == NULL || input == NULL || key == NULL) {
        ret = BAD_FUNC_ARG;
    }

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    if (ret == 0) {
        /* if has pkcs8 header skip it */
        if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
            /* ignore error, did not have pkcs8 header */
        }
    }
#endif

    CALLOC_ASNGETDATA(dataASN, rsaKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Register variable to hold version field. */
        GetASN_Int8Bit(&dataASN[RSAKEYASN_IDX_VER], &version);
        /* Setup data to store INTEGER data in mp_int's in RSA object. */
    #if defined(WOLFSSL_RSA_PUBLIC_ONLY)
        /* Extract all public fields. */
        for (i = 0; i < RSA_PUB_INTS; i++) {
            GetASN_MP(&dataASN[(byte)RSAKEYASN_IDX_N + i], GetRsaInt(key, i));
        }
        /* Not extracting all data from BER encoding. */
        #define RSA_ASN_COMPLETE    0
    #else
        /* Extract all private fields. */
        for (i = 0; i < RSA_INTS; i++) {
            GetASN_MP(&dataASN[(byte)RSAKEYASN_IDX_N + i], GetRsaInt(key, i));
        }
        /* Extracting all data from BER encoding. */
        #define RSA_ASN_COMPLETE    1
    #endif
        /* Parse BER encoding for RSA private key. */
        ret = GetASN_Items(rsaKeyASN, dataASN, rsaKeyASN_Length,
            RSA_ASN_COMPLETE, input, inOutIdx, inSz);
    }
    /* Check version: 0 - two prime, 1 - multi-prime
     * Multi-prime has optional sequence after coefficient for extra primes.
     * If extra primes, parsing will fail as not all the buffer was used.
     */
    if ((ret == 0) && (version > PKCS1v1)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
    #if !defined(WOLFSSL_RSA_PUBLIC_ONLY)
        /* RSA key object has all private key values. */
        key->type = RSA_PRIVATE;
    #else
        /* RSA key object has all public key values. */
        key->type = RSA_PUBLIC;
    #endif

    #ifdef WOLFSSL_XILINX_CRYPT
        if (wc_InitRsaHw(key) != 0)
            ret = BAD_STATE_E;
    #endif
    }

    FREE_ASNGETDATA(dataASN, key->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}
#endif /* HAVE_USER_RSA */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for a PKCS #8 key.
 * Ignoring optional attributes and public key.
 * PKCS #8: RFC 5958, 2 - PrivateKeyInfo
 */
static const ASNItem pkcs8KeyASN[] = {
/*  SEQ                 */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/*  VER                 */        { 1, ASN_INTEGER, 0, 0, 0 },
/*  PKEY_ALGO_SEQ       */        { 1, ASN_SEQUENCE, 1, 1, 0 },
/*  PKEY_ALGO_OID_KEY   */            { 2, ASN_OBJECT_ID, 0, 0, 0 },
/*  PKEY_ALGO_OID_CURVE */            { 2, ASN_OBJECT_ID, 0, 0, 1 },
/*  PKEY_ALGO_NULL      */            { 2, ASN_TAG_NULL, 0, 0, 1 },
/*  PKEY_DATA           */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
                /* attributes            [0] Attributes OPTIONAL */
                /* [[2: publicKey        [1] PublicKey OPTIONAL ]] */
};
enum {
    PKCS8KEYASN_IDX_SEQ = 0,
    PKCS8KEYASN_IDX_VER,
    PKCS8KEYASN_IDX_PKEY_ALGO_SEQ,
    PKCS8KEYASN_IDX_PKEY_ALGO_OID_KEY,
    PKCS8KEYASN_IDX_PKEY_ALGO_OID_CURVE,
    PKCS8KEYASN_IDX_PKEY_ALGO_NULL,
    PKCS8KEYASN_IDX_PKEY_DATA,
};

/* Number of items in ASN.1 template for a PKCS #8 key. */
#define pkcs8KeyASN_Length (sizeof(pkcs8KeyASN) / sizeof(ASNItem))
#endif

/* Remove PKCS #8 header around an RSA, ECDSA, Ed25519, Ed448, or Falcon key.
 *
 * @param [in]       input     Buffer holding BER data.
 * @param [in, out]  inOutIdx  On in, start of PKCS #8 encoding.
 *                             On out, start of encoded key.
 * @param [in]       sz        Size of data in buffer.
 * @param [out]      algId     Key's algorithm id from PKCS #8 header.
 * @return  Length of key data on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 */
int ToTraditionalInline_ex(const byte* input, word32* inOutIdx, word32 sz,
                           word32* algId)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx;
    int    version, length;
    int    ret;
    byte   tag;

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    idx = *inOutIdx;

    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, &idx, &version, sz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &idx, algId, oidKeyType, sz) < 0)
        return ASN_PARSE_E;

    if (GetASNTag(input, &idx, &tag, sz) < 0)
        return ASN_PARSE_E;
    idx = idx - 1; /* reset idx after finding tag */

    if (tag == ASN_OBJECT_ID) {
        if (SkipObjectId(input, &idx, sz) < 0)
            return ASN_PARSE_E;
    }

    ret = GetOctetString(input, &idx, &length, sz);
    if (ret < 0) {
        if (ret == BUFFER_E)
            return ASN_PARSE_E;
        /* Some private keys don't expect an octet string */
        WOLFSSL_MSG("Couldn't find Octet string");
    }

    *inOutIdx = idx;

    return length;
#else
    DECL_ASNGETDATA(dataASN, pkcs8KeyASN_Length);
    int ret = 0;
    word32 oid = 9;
    byte version;
    word32 idx;

    /* Check validity of parameters. */
    if (input == NULL || inOutIdx == NULL) {
        return BAD_FUNC_ARG;
    }

    idx = *inOutIdx;

    CALLOC_ASNGETDATA(dataASN, pkcs8KeyASN_Length, ret, NULL);

    if (ret == 0) {
        /* Get version, check key type and curve type. */
        GetASN_Int8Bit(&dataASN[PKCS8KEYASN_IDX_VER], &version);
        GetASN_OID(&dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_KEY], oidKeyType);
        GetASN_OID(&dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_CURVE], oidCurveType);
        /* Parse data. */
        ret = GetASN_Items(pkcs8KeyASN, dataASN, pkcs8KeyASN_Length, 1, input,
                           &idx, sz);
    }

    if (ret == 0) {
        /* Key type OID. */
        oid = dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_KEY].data.oid.sum;

        /* Version 1 includes an optional public key.
         * If public key is included then the parsing will fail as it did not
         * use all the data.
         */
        if (version > PKCS8v1) {
            ret = ASN_PARSE_E;
        }
    }
    if (ret == 0) {
        switch (oid) {
            case RSAk:
                /* Must have NULL item but not OBJECT_ID item. */
                if ((dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_NULL].tag == 0) ||
                    (dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_CURVE].tag != 0)) {
                    ret = ASN_PARSE_E;
                }
                break;
            case ECDSAk:
                /* Must not have NULL item. */
                if (dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_NULL].tag != 0) {
                    ret = ASN_PARSE_E;
                }
                break;
            /* DSAk not supported. */
            /* Ignore OID lookup failures. */
            default:
                break;
        }
    }
    if (ret == 0) {
        /* Return algorithm id of internal key. */
        *algId = oid;
        /* Return index to start of internal key. */
        *inOutIdx = GetASNItem_DataIdx(dataASN[PKCS8KEYASN_IDX_PKEY_DATA], input);
        /* Return value is length of internal key. */
        ret = dataASN[PKCS8KEYASN_IDX_PKEY_DATA].data.ref.length;
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif
}

/* TODO: test case  */
int ToTraditionalInline(const byte* input, word32* inOutIdx, word32 sz)
{
    word32 oid;

    return ToTraditionalInline_ex(input, inOutIdx, sz, &oid);
}

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)

/* Remove PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditional_ex(byte* input, word32 sz, word32* algId)
{
    word32 inOutIdx = 0;
    int    length;

    if (input == NULL)
        return BAD_FUNC_ARG;

    length = ToTraditionalInline_ex(input, &inOutIdx, sz, algId);
    if (length < 0)
        return length;

    if (length + inOutIdx > sz)
        return BUFFER_E;

    XMEMMOVE(input, input + inOutIdx, length);

    return length;
}

int ToTraditional(byte* input, word32 sz)
{
    word32 oid;

    return ToTraditional_ex(input, sz, &oid);
}

#endif /* HAVE_PKCS8 || HAVE_PKCS12 */

#if defined(HAVE_PKCS8)

int wc_GetPkcs8TraditionalOffset(byte* input, word32* inOutIdx, word32 sz)
{
    int length;
    word32 algId;

    if (input == NULL || inOutIdx == NULL || (*inOutIdx > sz))
        return BAD_FUNC_ARG;

    length = ToTraditionalInline_ex(input, inOutIdx, sz, &algId);

    return length;
}

int wc_CreatePKCS8Key(byte* out, word32* outSz, byte* key, word32 keySz,
        int algoID, const byte* curveOID, word32 oidSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 keyIdx = 0;
    word32 tmpSz  = 0;
    word32 sz;
    word32 tmpAlgId = 0;

    /* If out is NULL then return the max size needed
     * + 2 for ASN_OBJECT_ID and ASN_OCTET_STRING tags */
    if (out == NULL && outSz != NULL) {
        *outSz = keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ
                 + MAX_LENGTH_SZ + MAX_LENGTH_SZ + 2;

        if (curveOID != NULL)
            *outSz += oidSz + MAX_LENGTH_SZ + 1;

        WOLFSSL_MSG("Checking size of PKCS8");

        return LENGTH_ONLY_E;
    }

    WOLFSSL_ENTER("wc_CreatePKCS8Key()");

    if (key == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check the buffer has enough room for largest possible size */
    if (curveOID != NULL) {
        if (*outSz < (keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ
               + MAX_LENGTH_SZ + MAX_LENGTH_SZ + 3 + oidSz + MAX_LENGTH_SZ))
            return BUFFER_E;
    }
    else {
        oidSz = 0; /* with no curveOID oid size must be 0 */
        if (*outSz < (keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ
                  + MAX_LENGTH_SZ + MAX_LENGTH_SZ + 2))
            return BUFFER_E;
    }

    /* sanity check: make sure the key doesn't already have a PKCS 8 header */
    if (ToTraditionalInline_ex(key, &keyIdx, keySz, &tmpAlgId) >= 0) {
        (void)tmpAlgId;
        return ASN_PARSE_E;
    }

    /* PrivateKeyInfo ::= SEQUENCE */
    keyIdx = MAX_SEQ_SZ; /* save room for sequence */

    /*  version Version
     *  no header information just INTEGER */
    sz = SetMyVersion(PKCS8v0, out + keyIdx, 0);
    tmpSz += sz; keyIdx += sz;
    /*  privateKeyAlgorithm PrivateKeyAlgorithmIdentifier */
    sz = 0; /* set sz to 0 and get privateKey oid buffer size needed */
    if (curveOID != NULL && oidSz > 0) {
        byte buf[MAX_LENGTH_SZ];
        sz = SetLength(oidSz, buf);
        sz += 1; /* plus one for ASN object id */
    }
    sz = SetAlgoID(algoID, out + keyIdx, oidKeyType, oidSz + sz);
    tmpSz += sz; keyIdx += sz;

    /*  privateKey          PrivateKey *
     * pkcs8 ecc uses slightly different format. Places curve oid in
     * buffer */
    if (curveOID != NULL && oidSz > 0) {
        sz = SetObjectId(oidSz, out + keyIdx);
        keyIdx += sz; tmpSz += sz;
        XMEMCPY(out + keyIdx, curveOID, oidSz);
        keyIdx += oidSz; tmpSz += oidSz;
    }

    sz = SetOctetString(keySz, out + keyIdx);
    keyIdx += sz; tmpSz += sz;
    XMEMCPY(out + keyIdx, key, keySz);
    tmpSz += keySz;

    /*  attributes          optional
     * No attributes currently added */

    /* rewind and add sequence */
    sz = SetSequence(tmpSz, out);
    XMEMMOVE(out + sz, out + MAX_SEQ_SZ, tmpSz);

    *outSz = tmpSz + sz;
    return tmpSz + sz;
#else
    DECL_ASNSETDATA(dataASN, pkcs8KeyASN_Length);
    int sz;
    int ret = 0;
    word32 keyIdx = 0;
    word32 tmpAlgId = 0;

    WOLFSSL_ENTER("wc_CreatePKCS8Key()");

    /* Check validity of parameters. */
    if (out == NULL && outSz != NULL) {
    }
    else if (key == NULL || out == NULL || outSz == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Sanity check: make sure key doesn't have PKCS #8 header. */
    if (ToTraditionalInline_ex(key, &keyIdx, keySz, &tmpAlgId) >= 0) {
        (void)tmpAlgId;
        ret = ASN_PARSE_E;
    }

    CALLOC_ASNSETDATA(dataASN, pkcs8KeyASN_Length, ret, NULL);

    if (ret == 0) {
        /* Only support default PKCS #8 format - v0. */
        SetASN_Int8Bit(&dataASN[PKCS8KEYASN_IDX_VER], PKCS8v0);
        /* Set key OID that corresponds to key data. */
        SetASN_OID(&dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_KEY], algoID, oidKeyType);
        if (curveOID != NULL && oidSz > 0) {
            /* ECC key and curveOID set to write. */
            SetASN_Buffer(&dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_CURVE], curveOID, oidSz);
        }
        else {
            /* EC curve OID to encode. */
            dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_OID_CURVE].noOut = 1;
        }
        /* Only RSA keys have NULL tagged item after OID. */
        dataASN[PKCS8KEYASN_IDX_PKEY_ALGO_NULL].noOut = (algoID != RSAk);
        /* Set key data to encode. */
        SetASN_Buffer(&dataASN[PKCS8KEYASN_IDX_PKEY_DATA], key, keySz);

        /* Get the size of the DER encoding. */
        ret = SizeASN_Items(pkcs8KeyASN, dataASN, pkcs8KeyASN_Length, &sz);
    }
    if (ret == 0) {
        /* Always return the calculated size. */
        *outSz = sz;
    }
    /* Check for buffer to encoded into. */
    if ((ret == 0) && (out == NULL)) {
        WOLFSSL_MSG("Checking size of PKCS8");
        ret = LENGTH_ONLY_E;
    }
    if (ret == 0) {
        /*  Encode PKCS #8 key into buffer. */
        SetASN_Items(pkcs8KeyASN, dataASN, pkcs8KeyASN_Length, out);
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#endif /* HAVE_PKCS8 && !NO_CERTS */

#if defined(HAVE_PKCS12) || !defined(NO_CHECK_PRIVATE_KEY)
/* check that the private key is a pair for the public key
 * return 1 (true) on match
 * return 0 or negative value on failure/error
 *
 * privKey   : buffer holding DER format private key
 * privKeySz : size of private key buffer
 * pubKey    : buffer holding DER format public key
 * pubKeySz  : size of public key buffer
 * ks        : type of key */
int wc_CheckPrivateKey(const byte* privKey, word32 privKeySz,
                       const byte* pubKey, word32 pubKeySz, enum Key_Sum ks)
{
    int ret;
    (void)privKeySz;
    (void)pubKeySz;
    (void)ks;

    if (privKey == NULL || pubKey == NULL) {
        return BAD_FUNC_ARG;
    }

    #if !defined(NO_ASN_CRYPT)
    /* test if RSA key */
    if (ks == RSAk) {
        RsaKey a[1], b[1];
        word32 keyIdx = 0;


        if ((ret = wc_InitRsaKey(a, NULL)) < 0) {
            return ret;
        }
        if ((ret = wc_InitRsaKey(b, NULL)) < 0) {
            wc_FreeRsaKey(a);
            return ret;
        }
        if ((ret = wc_RsaPrivateKeyDecode(privKey, &keyIdx, a, privKeySz)) == 0) {
            WOLFSSL_MSG("Checking RSA key pair");
            keyIdx = 0; /* reset to 0 for parsing public key */

            if ((ret = wc_RsaPublicKeyDecode(pubKey, &keyIdx, b,
                    pubKeySz)) == 0) {
                /* limit for user RSA crypto because of RsaKey
                 * dereference. */
            #if defined(HAVE_USER_RSA)
                WOLFSSL_MSG("Cannot verify RSA pair with user RSA");
                ret = 1; /* return first RSA cert as match */
            #else
                /* both keys extracted successfully now check n and e
                 * values are the same. This is dereferencing RsaKey */
                if (mp_cmp(&(a->n), &(b->n)) != MP_EQ ||
                    mp_cmp(&(a->e), &(b->e)) != MP_EQ) {
                    ret = MP_CMP_E;
                }
                else
                    ret = 1;
            #endif
            }
        }
        wc_FreeRsaKey(b);
        wc_FreeRsaKey(a);
    }
    else
    #endif /* !NO_RSA && !NO_ASN_CRYPT */

    #if !defined(NO_ASN_CRYPT)
    if (ks == ECDSAk) {
        ecc_key  key_pair[1];
        byte     privDer[MAX_ECC_BYTES];
        word32   privSz = MAX_ECC_BYTES;
        word32   keyIdx = 0;


        if ((ret = wc_ecc_init(key_pair)) < 0) {
            return ret;
        }

        if ((ret = wc_EccPrivateKeyDecode(privKey, &keyIdx, key_pair,
                privKeySz)) == 0) {
            WOLFSSL_MSG("Checking ECC key pair");

            if ((ret = wc_ecc_export_private_only(key_pair, privDer, &privSz))
                                                                         == 0) {
                wc_ecc_free(key_pair);
                ret = wc_ecc_init(key_pair);
                if (ret == 0) {
                    ret = wc_ecc_import_private_key(privDer,
                                            privSz, pubKey,
                                            pubKeySz, key_pair);
                }

                /* public and private extracted successfully now check if is
                 * a pair and also do sanity checks on key. wc_ecc_check_key
                 * checks that private * base generator equals pubkey */
                if (ret == 0) {
                    if ((ret = wc_ecc_check_key(key_pair)) == 0) {
                        ret = 1;
                    }
                }
                ForceZero(privDer, privSz);
            }
        }
        wc_ecc_free(key_pair);
    }
    else
    #endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT && !NO_ASN_CRYPT */


    {
        ret = 0;
    }
    (void)ks;

    return ret;
}

/* check that the private key is a pair for the public key in certificate
 * return 1 (true) on match
 * return 0 or negative value on failure/error
 *
 * key   : buffer holding DER format key
 * keySz : size of key buffer
 * der   : a initialized and parsed DecodedCert holding a certificate */
int wc_CheckPrivateKeyCert(const byte* key, word32 keySz, DecodedCert* der)
{
    if (key == NULL || der == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_CheckPrivateKey(key, keySz, der->publicKey,
            der->pubKeySize, (enum Key_Sum) der->keyOID);
}

#endif /* HAVE_PKCS12 || !NO_CHECK_PRIVATE_KEY */

#ifndef NO_PWDBASED

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
/* Check the PBE algorithm is supported and return wolfSSL id, version and block
 * size of encryption algorithm.
 *
 * When PBES2, version is PKCS5v2, CheckAlgoV2() must be called to get id and
 * blockSz based on encryption algorithm.
 *
 * @param [in]  first    First byte of OID to use in check.
 * @param [in]  second   Second byte of OID to use in check.
 * @param [out] id       wolfSSL id for PBE algorithm.
 * @param [out] version  Version of PBE OID:
 *                       PKCS12v1 (PBE), PKCS5 (PBES1), PKCS5v2 (PBES2).
 * @param [out] blockSz  Block size of encryption algorithm.
 * @return  0 on success.
 * @return  ALGO_ID_E when OID not supported.
 * @return  ASN_INPUT_E when first byte is invalid.
 */
static int CheckAlgo(int first, int second, int* id, int* version, int* blockSz)
{
    int ret = 0;

    (void)id;
    (void)blockSz;

    *version = -1;

    /* pkcs-12 1 = pkcs-12PbeIds */
    if (first == 1) {
        /* PKCS #12: Appendix C */
        switch (second) {
    #ifdef WC_RC2
        case PBE_SHA1_40RC2_CBC:
            *id = PBE_SHA1_40RC2_CBC;
            *version = PKCS12v1;
            if (blockSz != NULL) {
                *blockSz = RC2_BLOCK_SIZE;
            }
            break;
    #endif
        default:
            ret = ALGO_ID_E;
            break;
        }
    }
    else if (first != PKCS5) {
        /* Bad OID. */
        ret = ASN_INPUT_E;
    }
    /* PKCS #5 PBES2: Appendix A.4
     * pkcs-5 13 = id-PBES2 */
    else if (second == PBES2) {
        *version = PKCS5v2;
        /* Id and block size come from CheckAlgoV2() */
    }
    else  {
        /* PKCS #5 PBES1: Appendix A.3 */
        /* see RFC 2898 for ids */
        switch (second) {
        default:
            ret = ALGO_ID_E;
            break;
        }
    }

    /* Return error code. */
    return ret;
}

#endif /* HAVE_PKCS8 || HAVE_PKCS12 */

#ifdef HAVE_PKCS8

/* Check the encryption algorithm with PBES2 is supported and return block size
 * and wolfSSL id for the PBE.
 *
 * @param [in]  oid      Encryption algorithm OID id.
 * @param [out] id       wolfSSL id for PBE algorithm.
 * @param [out] version  Version of PBE OID:
 *                       PKCS12v1 (PBE), PKCS5 (PBES1), PKCS5v2 (PBES2).
 * @return  0 on success.
 * @return  ALGO_ID_E when encryption algorithm is not supported with PBES2.
 */
static int CheckAlgoV2(int oid, int* id, int* blockSz)
{
    int ret = 0;

    (void)id;
    (void)blockSz;

    switch (oid) {
#ifdef WOLFSSL_AES_256
    case AES256CBCb:
        *id = PBE_AES256_CBC;
        if (blockSz != NULL) {
            *blockSz = AES_BLOCK_SIZE;
        }
        break;
#endif
#ifdef WOLFSSL_AES_128
    case AES128CBCb:
        *id = PBE_AES128_CBC;
        if (blockSz != NULL) {
            *blockSz = AES_BLOCK_SIZE;
        }
        break;
#endif
    default:
        WOLFSSL_MSG("No PKCS v2 algo found");
        ret = ALGO_ID_E;
        break;
    }

    /* Return error code. */
    return ret;
}

#endif /* HAVE_PKCS8 */

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)

int wc_GetKeyOID(byte* key, word32 keySz, const byte** curveOID, word32* oidSz,
        int* algoID, void* heap)
{
    word32 tmpIdx = 0;

    if (key == NULL || algoID == NULL)
        return BAD_FUNC_ARG;

    *algoID = 0;

    #if !defined(NO_ASN_CRYPT)
    {
        RsaKey *rsa = (RsaKey *)XMALLOC(sizeof *rsa, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (rsa == NULL)
            return MEMORY_E;

        wc_InitRsaKey(rsa, heap);
        if (wc_RsaPrivateKeyDecode(key, &tmpIdx, rsa, keySz) == 0) {
            *algoID = RSAk;
        }
        else {
            WOLFSSL_MSG("Not RSA DER key");
        }
        wc_FreeRsaKey(rsa);
        XFREE(rsa, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    #endif /* !NO_RSA && !NO_ASN_CRYPT */
    #if !defined(NO_ASN_CRYPT)
    if (*algoID == 0) {
        ecc_key *ecc = (ecc_key *)XMALLOC(sizeof *ecc, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (ecc == NULL)
            return MEMORY_E;

        tmpIdx = 0;
        wc_ecc_init_ex(ecc, heap, INVALID_DEVID);
        if (wc_EccPrivateKeyDecode(key, &tmpIdx, ecc, keySz) == 0) {
            *algoID = ECDSAk;

            /* now find oid */
            if (wc_ecc_get_oid(ecc->dp->oidSum, curveOID, oidSz) < 0) {
                WOLFSSL_MSG("Error getting ECC curve OID");
                wc_ecc_free(ecc);
                XFREE(ecc, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return BAD_FUNC_ARG;
            }
        }
        else {
            WOLFSSL_MSG("Not ECC DER key either");
        }
        wc_ecc_free(ecc);
        XFREE(ecc, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* HAVE_ECC && !NO_ASN_CRYPT */

    /* if flag is not set then this is not a key that we understand. */
    if (*algoID == 0) {
        WOLFSSL_MSG("Bad key DER or compile options");
        return BAD_FUNC_ARG;
    }

    (void)tmpIdx;
    (void)curveOID;
    (void)oidSz;
    (void)keySz;
    (void)heap;

    return 1;
}

#endif /* HAVE_PKCS8 || HAVE_PKCS12 */

#ifdef WOLFSSL_ASN_TEMPLATE
#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
/* ASN.1 template for PBES2 parameters.
 * PKCS #5: RFC 8018, A.4 - PBES2-params without outer SEQUENCE
 *                    A.2 - PBKDF2-params
 *                    B.2 - Encryption schemes
 *                    C   - AlgorithmIdentifier
 */
static const ASNItem pbes2ParamsASN[] = {
/* KDF_SEQ                */ { 0, ASN_SEQUENCE, 1, 1, 0 },
               /* PBKDF2 */
/* KDF_OID                */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* PBKDF2_PARAMS_SEQ      */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                   /* Salt */
/* PBKDF2_PARAMS_SALT     */         { 2, ASN_OCTET_STRING, 0, 0, 0 },
                   /* Iteration count */
/* PBKDF2_PARAMS_ITER     */         { 2, ASN_INTEGER, 0, 0, 0 },
                   /* Key length */
/* PBKDF2_PARAMS_KEYLEN   */         { 2, ASN_INTEGER, 0, 0, 1 },
                   /* PRF - default is HMAC-SHA1 */
/* PBKDF2_PARAMS_PRF      */         { 2, ASN_SEQUENCE, 1, 1, 1 },
/* PBKDF2_PARAMS_PRF_OID  */             { 3, ASN_OBJECT_ID, 0, 0, 0 },
/* PBKDF2_PARAMS_PRF_NULL */             { 3, ASN_TAG_NULL, 0, 0, 1 },
/* ENCS_SEQ               */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                   /* Encryption algorithm */
/* ENCS_OID               */   { 1, ASN_OBJECT_ID, 0, 0, 0 },
                   /* IV for CBC */
/* ENCS_PARAMS            */   { 1, ASN_OCTET_STRING, 0, 0, 0 },
};
enum {
    PBES2PARAMSASN_IDX_KDF_SEQ = 0,
    PBES2PARAMSASN_IDX_KDF_OID,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_SEQ,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_SALT,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_ITER,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_KEYLEN,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_PRF,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_PRF_OID,
    PBES2PARAMSASN_IDX_PBKDF2_PARAMS_PRF_NULL,
    PBES2PARAMSASN_IDX_ENCS_SEQ,
    PBES2PARAMSASN_IDX_ENCS_OID,
    PBES2PARAMSASN_IDX_ENCS_PARAMS,
};

/* Number of items in ASN.1 template for PBES2 parameters. */
#define pbes2ParamsASN_Length (sizeof(pbes2ParamsASN) / sizeof(ASNItem))

/* ASN.1 template for PBES1 parameters.
 * PKCS #5: RFC 8018, A.3. - PBEParameter without outer SEQUENCE
 */
static const ASNItem pbes1ParamsASN[] = {
            /* Salt */
/* SALT */    { 0, ASN_OCTET_STRING, 0, 0, 0 },
            /* Iteration count */
/* ITER */    { 0, ASN_INTEGER, 0, 0, 0 },
};
enum {
    PBES1PARAMSASN_IDX_SALT = 0,
    PBES1PARAMSASN_IDX_ITER,
};

/* Number of items in ASN.1 template for PBES1 parameters. */
#define pbes1ParamsASN_Length (sizeof(pbes1ParamsASN) / sizeof(ASNItem))
#endif /* HAVE_PKCS8 || HAVE_PKCS12 */
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef HAVE_PKCS8

/*
 * Equivalent to calling TraditionalEnc with the same parameters but with
 * encAlgId set to 0. This function must be kept alive because it's sometimes
 * part of the API (WOLFSSL_ASN_API).
 */
int UnTraditionalEnc(byte* key, word32 keySz, byte* out, word32* outSz,
        const char* password, int passwordSz, int vPKCS, int vAlgo,
        byte* salt, word32 saltSz, int itt, WC_RNG* rng, void* heap)
{
    return TraditionalEnc(key, keySz, out, outSz, password, passwordSz,
                vPKCS, vAlgo, 0, salt, saltSz, itt, rng, heap);
}

static int GetAlgoV2(int encAlgId, const byte** oid, int *len, int* id,
                     int *blkSz)
{
    int ret = 0;

    switch (encAlgId) {
#if defined(WOLFSSL_AES_256) && defined(HAVE_AES_CBC)
    case AES256CBCb:
        *len = sizeof(blkAes256CbcOid);
        *oid = blkAes256CbcOid;
        *id = PBE_AES256_CBC;
        *blkSz = 16;
        break;
#endif
    default:
        (void)len;
        (void)oid;
        (void)id;
        (void)blkSz;
        ret = ALGO_ID_E;
    }

    return ret;
}

int wc_EncryptPKCS8Key(byte* key, word32 keySz, byte* out, word32* outSz,
        const char* password, int passwordSz, int vPKCS, int pbeOid,
        int encAlgId, byte* salt, word32 saltSz, int itt, WC_RNG* rng,
        void* heap)
{
    byte saltTmp[MAX_SALT_SIZE];
    int genSalt = 0;
    int ret = 0;
    int version = 0;
    int pbeId = 0;
    int blockSz = 0;
    const byte* encOid = NULL;
    int encOidSz = 0;
    word32 padSz = 0;
    word32 innerLen = 0;
    word32 outerLen = 0;
    const byte* pbeOidBuf = NULL;
    word32 pbeOidBufSz = 0;
    word32 pbeLen = 0;
    word32 kdfLen = 0;
    word32 encLen = 0;
    byte cbcIv[MAX_IV_SIZE];
    word32 idx = 0;
    word32 encIdx = 0;

    (void)heap;

    WOLFSSL_ENTER("wc_EncryptPKCS8Key");

    if (key == NULL || outSz == NULL || password == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = CheckAlgo(vPKCS, pbeOid, &pbeId, &version, &blockSz);
    }
    if (ret == 0 && (salt == NULL || saltSz == 0)) {
        genSalt = 1;
        saltSz = 8;
    }
    if (ret == 0 && version == PKCS5v2) {
        ret = GetAlgoV2(encAlgId, &encOid, &encOidSz, &pbeId, &blockSz);
    }
    if (ret == 0) {
        padSz = (blockSz - (keySz & (blockSz - 1))) & (blockSz - 1);
        /* inner = OCT salt INT itt */
        innerLen = 2 + saltSz + 2 + (itt < 256 ? 1 : 2);

        if (version != PKCS5v2) {
            pbeOidBuf = OidFromId(pbeId, oidPBEType, &pbeOidBufSz);
            /* pbe = OBJ pbse1 SEQ [ inner ] */
            pbeLen = 2 + pbeOidBufSz + 2 + innerLen;
        }
        else {
            pbeOidBuf = pbes2;
            pbeOidBufSz = sizeof(pbes2);
            /* kdf = OBJ pbkdf2 [ SEQ innerLen ] */
            kdfLen = 2 + sizeof(pbkdf2Oid) + 2 + innerLen;
            /* enc = OBJ enc_alg OCT iv */
            encLen = 2 + encOidSz + 2 + blockSz;
            /* pbe = OBJ pbse2 SEQ [ SEQ [ kdf ] SEQ [ enc ] ] */
            pbeLen = 2 + sizeof(pbes2) + 2 + 2 + kdfLen + 2 + encLen;

            ret = wc_RNG_GenerateBlock(rng, cbcIv, blockSz);
        }
    }
    if (ret == 0) {
        /* outerLen = length of PBE encoding + octet string data */
        /* Plus 2 for tag and length for pbe */
        outerLen = 2 + pbeLen;
        /* Octet string tag, length */
        outerLen += 1 + SetLength(keySz + padSz, NULL);
        /* Octet string bytes */
        outerLen += keySz + padSz;
        if (out == NULL) {
            /* Sequence tag, length */
            *outSz = 1 + SetLength(outerLen, NULL) + outerLen;
            return LENGTH_ONLY_E;
        }
        SetOctetString(keySz + padSz, out);

        idx += SetSequence(outerLen, out + idx);

        encIdx = idx + outerLen - keySz - padSz;
        /* Put Encrypted content in place. */
        XMEMCPY(out + encIdx, key, keySz);
        if (padSz > 0) {
            XMEMSET(out + encIdx + keySz, padSz, padSz);
            keySz += padSz;
        }

        if (genSalt == 1) {
            {
                salt = saltTmp;
                if ((ret = wc_RNG_GenerateBlock(rng, saltTmp, saltSz)) != 0) {
                    WOLFSSL_MSG("Error generating random salt");
                }
            }
        }
    }
    if (ret == 0) {
        ret = wc_CryptKey(password, passwordSz, salt, saltSz, itt, pbeId,
                  out + encIdx, keySz, version, cbcIv, 1, 0);
    }
    if (ret == 0) {
        if (version != PKCS5v2) {
            /* PBE algorithm */
            idx += SetSequence(pbeLen, out + idx);
            idx += SetObjectId(pbeOidBufSz, out + idx);
            XMEMCPY(out + idx, pbeOidBuf, pbeOidBufSz);
            idx += pbeOidBufSz;
        }
        else {
            /* PBES2 algorithm identifier */
            idx += SetSequence(pbeLen, out + idx);
            idx += SetObjectId(pbeOidBufSz, out + idx);
            XMEMCPY(out + idx, pbeOidBuf, pbeOidBufSz);
            idx += pbeOidBufSz;
            /* PBES2 Parameters: SEQ [ kdf ] SEQ [ enc ] */
            idx += SetSequence(2 + kdfLen + 2 + encLen, out + idx);
            /* KDF Algorithm Identifier */
            idx += SetSequence(kdfLen, out + idx);
            idx += SetObjectId(sizeof(pbkdf2Oid), out + idx);
            XMEMCPY(out + idx, pbkdf2Oid, sizeof(pbkdf2Oid));
            idx += sizeof(pbkdf2Oid);
        }
        idx += SetSequence(innerLen, out + idx);
        idx += SetOctetString(saltSz, out + idx);
        XMEMCPY(out + idx, salt, saltSz); idx += saltSz;
        ret = SetShortInt(out, &idx, itt, *outSz);
        if (ret > 0)
            ret = 0;
    }
    if (ret == 0) {
        if (version == PKCS5v2) {
            /* Encryption Algorithm Identifier */
            idx += SetSequence(encLen, out + idx);
            idx += SetObjectId(encOidSz, out + idx);
            XMEMCPY(out + idx, encOid, encOidSz);
            idx += encOidSz;
            /* Encryption Algorithm Parameter: CBC IV */
            idx += SetOctetString(blockSz, out + idx);
            XMEMCPY(out + idx, cbcIv, blockSz);
            idx += blockSz;
        }
        idx += SetOctetString(keySz, out + idx);
        /* Default PRF - no need to write out OID */
        idx += keySz;

        ret = idx;
    }


    WOLFSSL_LEAVE("wc_EncryptPKCS8Key", ret);

    return ret;
}

int wc_DecryptPKCS8Key(byte* input, word32 sz, const char* password,
        int passwordSz)
{
    int ret;
    int length;
    word32 inOutIdx = 0;

    if (input == NULL || password == NULL) {
        return BAD_FUNC_ARG;
    }

    if (GetSequence(input, &inOutIdx, &length, sz) < 0) {
        ret = ASN_PARSE_E;
    }
    else {
        ret = DecryptContent(input + inOutIdx, sz - inOutIdx, password,
                passwordSz);
        if (ret > 0) {
            XMEMMOVE(input, input + inOutIdx, ret);
        }
    }

    if (ret > 0) {
        /* DecryptContent will decrypt the data, but it will leave any padding
         * bytes intact. This code calculates the length without the padding
         * and we return that to the user. */
        inOutIdx = 0;
        if (GetSequence(input, &inOutIdx, &length, ret) < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            ret = inOutIdx + length;
        }
    }

    return ret;
}

/* Takes an unencrypted, traditional DER-encoded key and converts it to a PKCS#8
 * encrypted key. If out is not NULL, it will hold the encrypted key. If it's
 * NULL, LENGTH_ONLY_E will be returned and outSz will have the required out
 * buffer size. */
int TraditionalEnc(byte* key, word32 keySz, byte* out, word32* outSz,
        const char* password, int passwordSz, int vPKCS, int vAlgo,
        int encAlgId, byte* salt, word32 saltSz, int itt, WC_RNG* rng,
        void* heap)
{
    int ret = 0;
    byte *pkcs8Key = NULL;
    word32 pkcs8KeySz = 0;
    int algId = 0;
    const byte* curveOid = NULL;
    word32 curveOidSz = 0;

    if (ret == 0) {
        /* check key type and get OID if ECC */
        ret = wc_GetKeyOID(key, keySz, &curveOid, &curveOidSz, &algId, heap);
        if (ret == 1)
            ret = 0;
    }
    if (ret == 0) {
        ret = wc_CreatePKCS8Key(NULL, &pkcs8KeySz, key, keySz, algId, curveOid,
                                                                    curveOidSz);
        if (ret == LENGTH_ONLY_E)
            ret = 0;
    }
    if (ret == 0) {
        pkcs8Key = (byte*)XMALLOC(pkcs8KeySz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pkcs8Key == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_CreatePKCS8Key(pkcs8Key, &pkcs8KeySz, key, keySz, algId,
            curveOid, curveOidSz);
        if (ret >= 0) {
            pkcs8KeySz = ret;
            ret = 0;
        }
    }
    if (ret == 0) {
        ret = wc_EncryptPKCS8Key(pkcs8Key, pkcs8KeySz, out, outSz, password,
            passwordSz, vPKCS, vAlgo, encAlgId, salt, saltSz, itt, rng, heap);
    }

    if (pkcs8Key != NULL) {
        ForceZero(pkcs8Key, pkcs8KeySz);
        XFREE(pkcs8Key, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    (void)rng;

    return ret;
}

/* Same as TraditionalEnc, but in the public API. */
int wc_CreateEncryptedPKCS8Key(byte* key, word32 keySz, byte* out,
        word32* outSz, const char* password, int passwordSz, int vPKCS,
        int pbeOid, int encAlgId, byte* salt, word32 saltSz, int itt,
        WC_RNG* rng, void* heap)
{
    return TraditionalEnc(key, keySz, out, outSz, password, passwordSz, vPKCS,
        pbeOid, encAlgId, salt, saltSz, itt, rng, heap);
}


#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for PKCS #8/#7 encrypted key for decrypting
 * PKCS #8: RFC 5958, 3 - EncryptedPrivateKeyInfo without outer SEQUENCE
 * PKCS #7: RFC 2315, 10.1 - EncryptedContentInfo without outer SEQUENCE
 */
static const ASNItem pkcs8DecASN[] = {
/* ENCALGO_SEQ    */ { 1, ASN_SEQUENCE, 1, 1, 0 },
/* ENCALGO_OID    */     { 2, ASN_OBJECT_ID, 0, 0, 0 },
/* ENCALGO_PARAMS */     { 2, ASN_SEQUENCE, 1, 0, 0 },
            /* PKCS #7 */
/* ENCCONTENT     */ { 1, ASN_CONTEXT_SPECIFIC | ASN_ENC_CONTENT,
                                       0, 0, 2 },
            /* PKCS #8 */
/* ENCDATA        */ { 1, ASN_OCTET_STRING, 0, 0, 2 },
};
enum {
    PKCS8DECASN_IDX_ENCALGO_SEQ = 0,
    PKCS8DECASN_IDX_ENCALGO_OID,
    PKCS8DECASN_IDX_ENCALGO_PARAMS,
    PKCS8DECASN_IDX_ENCCONTENT,
    PKCS8DECASN_IDX_ENCDATA,
};

/* Number of items in ASN.1 template for PKCS #8/#7 encrypted key. */
#define pkcs8DecASN_Length (sizeof(pkcs8DecASN) / sizeof(ASNItem))
#endif

/* Decrypt data using PBE algorithm.
 *
 * PKCS #8: RFC 5958, 3 - EncryptedPrivateKeyInfo without outer SEQUENCE
 * PKCS #7: RFC 2315, 10.1 - EncryptedContentInfo without outer SEQUENCE
 *
 * Note: input buffer is overwritten with decrypted data!
 *
 * Salt is in KDF parameters and IV is PBE parameters when needed.
 *
 * @param [in] input       Data to decrypt and unwrap.
 * @param [in] sz          Size of encrypted data.
 * @param [in] password    Password to derive encryption key with.
 * @param [in] passwordSz  Size of password in bytes.
 * @return  Length of decrypted data on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  Other when decryption fails.
 */
int DecryptContent(byte* input, word32 sz, const char* password, int passwordSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 inOutIdx = 0, seqEnd, oid, shaOid = 0;
    int    ret = 0, first, second, length = 0, version, saltSz, id = 0;
    int    iterations = 0, keySz = 0;
    byte   salt[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
    byte   tag;

    if (passwordSz < 0) {
        WOLFSSL_MSG("Bad password size");
        return BAD_FUNC_ARG;
    }

    if (GetAlgoId(input, &inOutIdx, &oid, oidIgnoreType, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    first  = input[inOutIdx - 2];   /* PKCS version always 2nd to last byte */
    second = input[inOutIdx - 1];   /* version.algo, algo id last byte */

    if (CheckAlgo(first, second, &id, &version, NULL) < 0) {
        ERROR_OUT(ASN_INPUT_E, exit_dc); /* Algo ID error */
    }

    if (version == PKCS5v2) {
        if (GetSequence(input, &inOutIdx, &length, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (GetAlgoId(input, &inOutIdx, &oid, oidKdfType, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (oid != PBKDF2_OID) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }
    }

    if (GetSequence(input, &inOutIdx, &length, sz) <= 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }
    /* Find the end of this SEQUENCE so we can check for the OPTIONAL and
     * DEFAULT items. */
    seqEnd = inOutIdx + length;

    ret = GetOctetString(input, &inOutIdx, &saltSz, sz);
    if (ret < 0)
        goto exit_dc;

    if (saltSz > MAX_SALT_SIZE) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }


    XMEMCPY(salt, &input[inOutIdx], saltSz);
    inOutIdx += saltSz;

    if (GetShortInt(input, &inOutIdx, &iterations, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    /* OPTIONAL key length */
    if (seqEnd > inOutIdx) {
        word32 localIdx = inOutIdx;

        if (GetASNTag(input, &localIdx, &tag, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (tag == ASN_INTEGER &&
                GetShortInt(input, &inOutIdx, &keySz, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }
    }

    /* DEFAULT HMAC is SHA-1 */
    if (seqEnd > inOutIdx) {
        if (GetAlgoId(input, &inOutIdx, &oid, oidHmacType, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        shaOid = oid;
    }


    if (version == PKCS5v2) {
        /* get encryption algo */
        if (GetAlgoId(input, &inOutIdx, &oid, oidBlkType, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (CheckAlgoV2(oid, &id, NULL) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc); /* PKCS v2 algo id error */
        }

        if (shaOid == 0)
            shaOid = oid;

        ret = GetOctetString(input, &inOutIdx, &length, sz);
        if (ret < 0)
            goto exit_dc;

        if (length > MAX_IV_SIZE) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        XMEMCPY(cbcIv, &input[inOutIdx], length);
        inOutIdx += length;
    }

    if (GetASNTag(input, &inOutIdx, &tag, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | 0) && tag != ASN_OCTET_STRING) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    if (GetLength(input, &inOutIdx, &length, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    ret = wc_CryptKey(password, passwordSz, salt, saltSz, iterations, id,
                   input + inOutIdx, length, version, cbcIv, 0, shaOid);

exit_dc:

    if (ret == 0) {
        XMEMMOVE(input, input + inOutIdx, length);
        ret = length;
    }

    return ret;
#else
    /* pbes2ParamsASN longer than pkcs8DecASN_Length/pbes1ParamsASN_Length. */
    DECL_ASNGETDATA(dataASN, pbes2ParamsASN_Length);
    int    ret = 0;
    int    id;
    int    version;
    word32 idx = 0;
    word32 pIdx = 0;
    word32 iterations;
    word32 keySz = 0;
    word32 saltSz;
    word32 shaOid = 0;
    byte*  salt = NULL;
    byte*  key = NULL;
    byte   cbcIv[MAX_IV_SIZE];
    byte*  params;

    WOLFSSL_ENTER("DecryptContent");

    CALLOC_ASNGETDATA(dataASN, pbes2ParamsASN_Length, ret, NULL);

    if (ret == 0) {
        /* Check OID is a PBE Type */
        GetASN_OID(&dataASN[PKCS8DECASN_IDX_ENCALGO_OID], oidPBEType);
        ret = GetASN_Items(pkcs8DecASN, dataASN, pkcs8DecASN_Length, 0, input,
                           &idx, sz);
    }
    if (ret == 0) {
        /* Check the PBE algorithm and get the version and id. */
        idx = dataASN[PKCS8DECASN_IDX_ENCALGO_OID].data.oid.length;
        /* Second last byte: 1 (PKCS #12 PBE Id) or 5 (PKCS #5)
         * Last byte: Alg or PBES2 */
        ret = CheckAlgo(dataASN[PKCS8DECASN_IDX_ENCALGO_OID].data.oid.data[idx - 2],
                  dataASN[PKCS8DECASN_IDX_ENCALGO_OID].data.oid.data[idx - 1],
                  &id, &version, NULL);
    }
    if (ret == 0) {
        /* Get the parameters data. */
        GetASN_GetRef(&dataASN[PKCS8DECASN_IDX_ENCALGO_PARAMS], &params, &sz);
        /* Having a numbered choice means none or both will have errored out. */
        if (dataASN[PKCS8DECASN_IDX_ENCCONTENT].tag != 0)
            GetASN_GetRef(&dataASN[PKCS8DECASN_IDX_ENCCONTENT], &key, &keySz);
        else if (dataASN[PKCS8DECASN_IDX_ENCDATA].tag != 0)
            GetASN_GetRef(&dataASN[PKCS8DECASN_IDX_ENCDATA], &key, &keySz);
        else
            ret = ASN_RSA_KEY_E;
    }

    if (ret == 0) {
        if (version != PKCS5v2) {
            /* Initialize for PBES1 parameters and put iterations in var. */
            XMEMSET(dataASN, 0, sizeof(*dataASN) * pbes1ParamsASN_Length);
            GetASN_Int32Bit(&dataASN[PBES1PARAMSASN_IDX_ITER], &iterations);
            /* Parse the PBES1 parameters. */
            ret = GetASN_Items(pbes1ParamsASN, dataASN, pbes1ParamsASN_Length,
                               0, params, &pIdx, sz);
            if (ret == 0) {
                /* Get the salt data. */
                GetASN_GetRef(&dataASN[PBES1PARAMSASN_IDX_SALT], &salt, &saltSz);
            }
        }
        else {
            word32 ivSz = MAX_IV_SIZE;

            /* Initialize for PBES2 parameters. Put iterations in var; match
             * KDF, HMAC and cipher, and copy CBC into buffer. */
            XMEMSET(dataASN, 0, sizeof(*dataASN) * pbes2ParamsASN_Length);
            GetASN_ExpBuffer(&dataASN[PBES2PARAMSASN_IDX_KDF_OID], pbkdf2Oid, sizeof(pbkdf2Oid));
            GetASN_Int32Bit(&dataASN[PBES2PARAMSASN_IDX_PBKDF2_PARAMS_ITER], &iterations);
            GetASN_OID(&dataASN[PBES2PARAMSASN_IDX_PBKDF2_PARAMS_PRF_OID], oidHmacType);
            GetASN_OID(&dataASN[PBES2PARAMSASN_IDX_ENCS_OID], oidBlkType);
            GetASN_Buffer(&dataASN[PBES2PARAMSASN_IDX_ENCS_PARAMS], cbcIv, &ivSz);
            /* Parse the PBES2 parameters  */
            ret = GetASN_Items(pbes2ParamsASN, dataASN, pbes2ParamsASN_Length,
                               0, params, &pIdx, sz);
            if (ret == 0) {
                /* Get the salt data. */
                GetASN_GetRef(&dataASN[PBES2PARAMSASN_IDX_PBKDF2_PARAMS_SALT], &salt, &saltSz);
                /* Get the digest and encryption algorithm id. */
                shaOid = dataASN[PBES2PARAMSASN_IDX_PBKDF2_PARAMS_PRF_OID].data.oid.sum; /* Default HMAC-SHA1 */
                id     = dataASN[PBES2PARAMSASN_IDX_ENCS_OID].data.oid.sum;
                /* Convert encryption algorithm to a PBE algorithm if needed. */
                CheckAlgoV2(id, &id, NULL);
            }
        }
    }

    if (ret == 0) {
        /* Decrypt the key. */
        ret = wc_CryptKey(password, passwordSz, salt, saltSz, iterations, id,
                          key, keySz, version, cbcIv, 0, shaOid);
    }
    if (ret == 0) {
        /* Copy the decrypted key into the input (inline). */
        XMEMMOVE(input, key, keySz);
        ret = keySz;
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif
}

/* Decrypt data using PBE algorithm and get key from PKCS#8 wrapping.
 *
 * PKCS #8: RFC 5958, 3 - EncryptedPrivateKeyInfo
 * PKCS #7: RFC 2315, 10.1 - EncryptedContentInfo
 *
 * Note: input buffer is overwritten with decrypted key!
 *
 * Salt is in KDF parameters and IV is PBE parameters when needed.
 *
 * @param [in]  input       Data to decrypt and unwrap.
 * @param [in]  sz          Size of encrypted data.
 * @param [in]  password    Password to derive encryption key with.
 * @param [in]  passwordSz  Size of password in bytes.
 * @param [out] algId       Key algorithm from PKCS#8 wrapper.
 * @return  Length of decrypted data on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  Other when decryption fails.
 */
int ToTraditionalEnc(byte* input, word32 sz, const char* password,
                     int passwordSz, word32* algId)
{
    int ret;

    ret = wc_DecryptPKCS8Key(input, sz, password, passwordSz);
    if (ret > 0) {
        ret = ToTraditional_ex(input, ret, algId);
    }

    return ret;
}

#endif /* HAVE_PKCS8 */

#ifdef HAVE_PKCS12

#define PKCS8_MIN_BLOCK_SIZE 8
static int Pkcs8Pad(byte* buf, int sz, int blockSz)
{
    int i, padSz;

    /* calculate pad size */
    padSz = blockSz - (sz & (blockSz - 1));

    /* pad with padSz value */
    if (buf) {
        for (i = 0; i < padSz; i++) {
            buf[sz+i] = (byte)(padSz & 0xFF);
        }
    }

    /* return adjusted length */
    return sz + padSz;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for PKCS #8 encrypted key with PBES1 parameters.
 * PKCS #8: RFC 5958, 3 - EncryptedPrivateKeyInfo
 * PKCS #5: RFC 8018, A.3 - PBEParameter
 */
static const ASNItem p8EncPbes1ASN[] = {
/* SEQ                   */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* ENCALGO_SEQ           */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                    /* PBE algorithm */
/* ENCALGO_OID           */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
/* ENCALGO_PBEPARAM_SEQ  */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                        /* Salt */
/* ENCALGO_PBEPARAM_SALT */             { 3, ASN_OCTET_STRING, 0, 0, 0 },
                        /* Iteration Count */
/* ENCALGO_PBEPARAM_ITER */             { 3, ASN_INTEGER, 0, 0, 0 },
/* ENCDATA               */     { 1, ASN_OCTET_STRING, 0, 0, 0 },
};
enum {
    P8ENCPBES1ASN_IDX_SEQ = 0,
    P8ENCPBES1ASN_IDX_ENCALGO_SEQ,
    P8ENCPBES1ASN_IDX_ENCALGO_OID,
    P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_SEQ,
    P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_SALT,
    P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_ITER,
    P8ENCPBES1ASN_IDX_ENCDATA,
};

#define p8EncPbes1ASN_Length (sizeof(p8EncPbes1ASN) / sizeof(ASNItem))
#endif

/* Wrap a private key in PKCS#8 and encrypt.
 *
 * Used for PKCS#12 and PKCS#7.
 * vPKCS is the version of PKCS to use.
 * vAlgo is the algorithm version to use.
 *
 * When salt is NULL, a random number is generated.
 *
 * data returned is :
 * [ seq - obj [ seq -salt,itt]] , construct with encrypted data
 *
 * @param [in]  input       Data to encrypt.
 * @param [in]  inputSz     Length of data in bytes.
 * @param [out] out         Buffer to write wrapped encrypted data into.
 * @param [out] outSz       Length of encrypted data in bytes.
 * @param [in]  password    Password used to create encryption key.
 * @param [in]  passwordSz  Length of password in bytes.
 * @param [in]  vPKCS       First byte used to determine PBE algorithm.
 * @param [in]  vAlgo       Second byte used to determine PBE algorithm.
 * @param [in]  salt        Salt to use with KDF.
 * @param [in]  saltSz      Length of salt in bytes.
 * @param [in]  itt         Number of iterations to use in KDF.
 * @param [in]  rng         Random number generator to use to generate salt.
 * @param [in]  heap        Dynamic memory allocator hint.
 * @return  The size of encrypted data on success
 * @return  LENGTH_ONLY_E when out is NULL and able to encode.
 * @return  ASN_PARSE_E when the salt size is too large.
 * @return  ASN_VERSION_E when attempting to use a PBES2 algorithm (use
 *          TraditionalEnc).
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other when encryption or random number generation fails.
 */
int EncryptContent(byte* input, word32 inputSz, byte* out, word32* outSz,
        const char* password, int passwordSz, int vPKCS, int vAlgo,
        byte* salt, word32 saltSz, int itt, WC_RNG* rng, void* heap)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 sz;
    word32 inOutIdx = 0;
    word32 tmpIdx   = 0;
    word32 totalSz  = 0;
    word32 seqSz;
    word32 innerSz;
    int    ret;
    int    version, id, blockSz = 0;
    byte   saltTmp[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
    byte   seq[MAX_SEQ_SZ];
    byte   shr[MAX_SHORT_SZ];
    word32 maxShr = MAX_SHORT_SZ;
    word32 algoSz;
    const  byte* algoName;

    (void)heap;

    WOLFSSL_ENTER("EncryptContent()");

    if (CheckAlgo(vPKCS, vAlgo, &id, &version, &blockSz) < 0)
        return ASN_INPUT_E;  /* Algo ID error */

    if (version == PKCS5v2) {
        WOLFSSL_MSG("PKCS#5 version 2 not supported yet");
        return BAD_FUNC_ARG;
    }

    if (saltSz > MAX_SALT_SIZE)
        return ASN_PARSE_E;

    if (outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* calculate size */
    /* size of constructed string at end */
    sz = Pkcs8Pad(NULL, inputSz, blockSz);
    totalSz  = ASN_TAG_SZ;
    totalSz += SetLength(sz, seq);
    totalSz += sz;

    /* size of sequence holding object id and sub sequence of salt and itt */
    algoName = OidFromId(id, oidPBEType, &algoSz);
    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }
    innerSz = SetObjectId(algoSz, seq);
    innerSz += algoSz;

    /* get subsequence of salt and itt */
    if (salt == NULL || saltSz == 0) {
        sz = 8;
    }
    else {
        sz = saltSz;
    }
    seqSz  = SetOctetString(sz, seq);
    seqSz += sz;

    tmpIdx = 0;
    ret = SetShortInt(shr, &tmpIdx, itt, maxShr);
    if (ret >= 0) {
        seqSz += ret;
    }
    else {
        return ret;
    }
    innerSz += seqSz + SetSequence(seqSz, seq);
    totalSz += innerSz + SetSequence(innerSz, seq);

    if (out == NULL) {
        *outSz = totalSz;
        return LENGTH_ONLY_E;
    }

    inOutIdx = 0;
    if (totalSz > *outSz)
        return BUFFER_E;

    inOutIdx += SetSequence(innerSz, out + inOutIdx);
    inOutIdx += SetObjectId(algoSz, out + inOutIdx);
    XMEMCPY(out + inOutIdx, algoName, algoSz);
    inOutIdx += algoSz;
    inOutIdx += SetSequence(seqSz, out + inOutIdx);

    /* create random salt if one not provided */
    if (salt == NULL || saltSz == 0) {
        saltSz = 8;
        salt = saltTmp;

        if ((ret = wc_RNG_GenerateBlock(rng, saltTmp, saltSz)) != 0) {
            WOLFSSL_MSG("Error generating random salt");
            return ret;
        }
    }
    inOutIdx += SetOctetString(saltSz, out + inOutIdx);
    if (saltSz + inOutIdx > *outSz) {
        return BUFFER_E;
    }
    XMEMCPY(out + inOutIdx, salt, saltSz);
    inOutIdx += saltSz;

    /* place iteration setting in buffer */
    ret = SetShortInt(out, &inOutIdx, itt, *outSz);
    if (ret < 0) {
        return ret;
    }

    if (inOutIdx + 1 > *outSz) {
        return BUFFER_E;
    }
    out[inOutIdx++] = ASN_CONTEXT_SPECIFIC | 0;

    /* get pad size and verify buffer room */
    sz = Pkcs8Pad(NULL, inputSz, blockSz);
    if (sz + inOutIdx > *outSz) {
        return BUFFER_E;
    }
    inOutIdx += SetLength(sz, out + inOutIdx);

    /* copy input to output buffer and pad end */
    XMEMCPY(out + inOutIdx, input, inputSz);
    sz = Pkcs8Pad(out + inOutIdx, inputSz, blockSz);

    /* encrypt */
    if ((ret = wc_CryptKey(password, passwordSz, salt, saltSz, itt, id,
                   out + inOutIdx, sz, version, cbcIv, 1, 0)) < 0) {

        return ret;  /* encrypt failure */
    }


    (void)rng;

    return inOutIdx + sz;
#else
    DECL_ASNSETDATA(dataASN, p8EncPbes1ASN_Length);
    int ret = 0;
    int sz = 0;
    int version;
    int id;
    int blockSz = 0;
    byte* pkcs8;
    word32 pkcs8Sz;
    byte cbcIv[MAX_IV_SIZE];

    (void)heap;

    WOLFSSL_ENTER("EncryptContent()");

    /* Must have a output size to return or check. */
    if (outSz == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check salt size is valid. */
    if ((ret == 0) && (saltSz > MAX_SALT_SIZE)) {
        ret = ASN_PARSE_E;
    }
    /* Get algorithm parameters for algorithm identifier. */
    if ((ret == 0) && CheckAlgo(vPKCS, vAlgo, &id, &version, &blockSz) < 0) {
        ret = ASN_INPUT_E;
    }
    /* Check PKCS #5 version - only PBSE1 parameters supported. */
    if ((ret == 0) && (version == PKCS5v2)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, p8EncPbes1ASN_Length, ret, heap);

    if (ret == 0) {
        /* Setup data to go into encoding including PBE algorithm, salt,
         * iteration count, and padded key length. */
        SetASN_OID(&dataASN[P8ENCPBES1ASN_IDX_ENCALGO_OID], id, oidPBEType);
        if (salt == NULL || saltSz == 0) {
            salt = NULL;
            saltSz = PKCS5_SALT_SZ;
            /* Salt generated into encoding below. */
        }
        SetASN_Buffer(&dataASN[P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_SALT],
                salt, saltSz);
        SetASN_Int16Bit(&dataASN[P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_ITER], itt);
        pkcs8Sz = Pkcs8Pad(NULL, inputSz, blockSz);
        SetASN_Buffer(&dataASN[P8ENCPBES1ASN_IDX_ENCDATA], NULL, pkcs8Sz);

        /* Calculate size of encoding. */
        ret = SizeASN_Items(p8EncPbes1ASN + P8ENCPBES1ASN_IDX_ENCALGO_SEQ,
                dataASN + P8ENCPBES1ASN_IDX_ENCALGO_SEQ,
                (int)(p8EncPbes1ASN_Length - P8ENCPBES1ASN_IDX_ENCALGO_SEQ),
                &sz);
    }
    /* Return size when no output buffer. */
    if ((ret == 0) && (out == NULL)) {
        *outSz = sz;
        ret = LENGTH_ONLY_E;
    }
    /* Check output buffer is big enough for encoded data. */
    if ((ret == 0) && (sz > (int)*outSz)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Encode PKCS#8 key. */
        SetASN_Items(p8EncPbes1ASN + P8ENCPBES1ASN_IDX_ENCALGO_SEQ,
                 dataASN + P8ENCPBES1ASN_IDX_ENCALGO_SEQ,
                 (int)(p8EncPbes1ASN_Length - P8ENCPBES1ASN_IDX_ENCALGO_SEQ),
                 out);

        if (salt == NULL) {
            /* Generate salt into encoding. */
            salt = (byte*)dataASN[P8ENCPBES1ASN_IDX_ENCALGO_PBEPARAM_SALT].data.buffer.data;
            ret = wc_RNG_GenerateBlock(rng, salt, saltSz);
        }
    }
    if (ret == 0) {
        /* Store PKCS#8 key in output buffer. */
        pkcs8 = (byte*)dataASN[P8ENCPBES1ASN_IDX_ENCDATA].data.buffer.data;
        XMEMCPY(pkcs8, input, inputSz);
        Pkcs8Pad(pkcs8, inputSz, blockSz);

        /* Encrypt PKCS#8 key inline. */
        ret = wc_CryptKey(password, passwordSz, salt, saltSz, itt, id, pkcs8,
                          pkcs8Sz, version, cbcIv, 1, 0);
    }
    if (ret == 0) {
        /* Returning size on success. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


#endif /* HAVE_PKCS12 */
#endif /* NO_PWDBASED */


#ifndef HAVE_USER_RSA
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
/* This function is to retrieve key position information in a cert.*
 * The information will be used to call TSIP TLS-linked API for    *
 * certificate verification.                                       */
static int RsaPublicKeyDecodeRawIndex(const byte* input, word32* inOutIdx,
                                      word32 inSz, word32* key_n,
                                      word32* key_n_len, word32* key_e,
                                      word32* key_e_len)
{

    int ret = 0;
    int length = 0;
#if defined(RSA_DECODE_EXTRA)
    byte b;
#endif

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(RSA_DECODE_EXTRA)
    if ((*inOutIdx + 1) > inSz)
        return BUFFER_E;

    b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* Option NULL ASN.1 tag */
        if (*inOutIdx  >= inSz) {
            return BUFFER_E;
        }
        if (input[*inOutIdx] == ASN_TAG_NULL) {
            ret = GetASNNull(input, inOutIdx, inSz);
            if (ret != 0)
                return ret;
        }

        /* should have bit tag length and seq next */
        ret = CheckBitString(input, inOutIdx, NULL, inSz, 1, NULL);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }
#endif /* OPENSSL_EXTRA */

    /* Get modulus */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    *key_n += *inOutIdx;
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (key_n_len)
        *key_n_len = length;
    *inOutIdx += length;

    /* Get exponent */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    *key_e += *inOutIdx;
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (key_e_len)
        *key_e_len = length;

    return ret;
}
#endif /* WOLFSSL_RENESAS_TSIP */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for an RSA public key.
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 */
static const ASNItem rsaPublicKeyASN[] = {
/*  SEQ            */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/*  ALGOID_SEQ     */     { 1, ASN_SEQUENCE, 1, 1, 0 },
/*  ALGOID_OID     */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
/*  ALGOID_NULL    */         { 2, ASN_TAG_NULL, 0, 0, 1 },
/*  PUBKEY         */     { 1, ASN_BIT_STRING, 0, 1, 0 },
                                                  /* RSAPublicKey */
/*  PUBKEY_RSA_SEQ */         { 2, ASN_SEQUENCE, 1, 1, 0 },
/*  PUBKEY_RSA_N   */             { 3, ASN_INTEGER, 0, 0, 0 },
/*  PUBKEY_RSA_E   */             { 3, ASN_INTEGER, 0, 0, 0 },
};
enum {
    RSAPUBLICKEYASN_IDX_SEQ = 0,
    RSAPUBLICKEYASN_IDX_ALGOID_SEQ,
    RSAPUBLICKEYASN_IDX_ALGOID_OID,
    RSAPUBLICKEYASN_IDX_ALGOID_NULL,
    RSAPUBLICKEYASN_IDX_PUBKEY,
    RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ,
    RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N,
    RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E,
};

/* Number of items in ASN.1 template for an RSA public key. */
#define rsaPublicKeyASN_Length (sizeof(rsaPublicKeyASN) / sizeof(ASNItem))
#endif

/* Decode RSA public key.
 *
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of RSA public key.
 *                            On out, start of ASN.1 item after RSA public key.
 * @param [in]      inSz      Number of bytes in buffer.
 * @param [out]     n         Pointer to modulus in buffer.
 * @param [out]     nSz       Size of modulus in bytes.
 * @param [out]     e         Pointer to exponent in buffer.
 * @param [out]     eSz       Size of exponent in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int wc_RsaPublicKeyDecode_ex(const byte* input, word32* inOutIdx, word32 inSz,
    const byte** n, word32* nSz, const byte** e, word32* eSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret = 0;
    int length = 0;
#if defined(RSA_DECODE_EXTRA)
    word32 localIdx;
    byte   tag;
#endif

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(RSA_DECODE_EXTRA)
    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) < 0)
        return BUFFER_E;

    if (tag != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* Option NULL ASN.1 tag */
        if (*inOutIdx  >= inSz) {
            return BUFFER_E;
        }

        localIdx = *inOutIdx;
        if (GetASNTag(input, &localIdx, &tag, inSz) < 0)
            return ASN_PARSE_E;

        if (tag == ASN_TAG_NULL) {
            ret = GetASNNull(input, inOutIdx, inSz);
            if (ret != 0)
                return ret;
        }

        /* should have bit tag length and seq next */
        ret = CheckBitString(input, inOutIdx, NULL, inSz, 1, NULL);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }
#endif /* OPENSSL_EXTRA */

    /* Get modulus */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (nSz)
        *nSz = length;
    if (n)
        *n = &input[*inOutIdx];
    *inOutIdx += length;

    /* Get exponent */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (eSz)
        *eSz = length;
    if (e)
        *e = &input[*inOutIdx];
    *inOutIdx += length;

    return ret;
#else
    DECL_ASNGETDATA(dataASN, rsaPublicKeyASN_Length);
    int ret = 0;

    /* Check validity of parameters. */
    if (input == NULL || inOutIdx == NULL) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, rsaPublicKeyASN_Length, ret, NULL);

    if (ret == 0) {
        /* Try decoding PKCS #1 public key by ignoring rest of ASN.1. */
        ret = GetASN_Items(&rsaPublicKeyASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ],
           &dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ],
           (int)(rsaPublicKeyASN_Length - RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ),
           0, input, inOutIdx, inSz);
        if (ret != 0) {
            /* Didn't work - try whole SubjectKeyInfo instead. */
            /* Set the OID to expect. */
            GetASN_ExpBuffer(&dataASN[RSAPUBLICKEYASN_IDX_ALGOID_OID],
                    keyRsaOid, sizeof(keyRsaOid));
            /* Decode SubjectKeyInfo. */
            ret = GetASN_Items(rsaPublicKeyASN, dataASN,
                               rsaPublicKeyASN_Length, 1, input, inOutIdx,
                               inSz);
        }
    }
    if (ret == 0) {
        /* Return the buffers and lengths asked for. */
        if (n != NULL) {
            *n   = dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N].data.ref.data;
        }
        if (nSz != NULL) {
            *nSz = dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N].data.ref.length;
        }
        if (e != NULL) {
            *e   = dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E].data.ref.data;
        }
        if (eSz != NULL) {
            *eSz = dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E].data.ref.length;
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

/* Decode RSA public key.
 *
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of RSA public key.
 *                            On out, start of ASN.1 item after RSA public key.
 * @param [in, out] key       RSA key object.
 * @param [in]      inSz      Number of bytes in buffer.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    const byte *n = NULL, *e = NULL;
    word32 nSz = 0, eSz = 0;

    if (key == NULL)
        return BAD_FUNC_ARG;

    ret = wc_RsaPublicKeyDecode_ex(input, inOutIdx, inSz, &n, &nSz, &e, &eSz);
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
    }

    return ret;
#else
    DECL_ASNGETDATA(dataASN, rsaPublicKeyASN_Length);
    int ret = 0;

    /* Check validity of parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, rsaPublicKeyASN_Length, ret, NULL);

    if (ret == 0) {
        /* Set mp_ints to fill with modulus and exponent data. */
        GetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N], &key->n);
        GetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E], &key->e);
        /* Try decoding PKCS #1 public key by ignoring rest of ASN.1. */
        ret = GetASN_Items(&rsaPublicKeyASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ],
               &dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ],
               (int)(rsaPublicKeyASN_Length - RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ),
               0, input, inOutIdx, inSz);
        if (ret != 0) {
            /* Didn't work - try whole SubjectKeyInfo instead. */
            /* Set the OID to expect. */
            GetASN_ExpBuffer(&dataASN[RSAPUBLICKEYASN_IDX_ALGOID_OID],
                    keyRsaOid, sizeof(keyRsaOid));
            /* Decode SubjectKeyInfo. */
            ret = GetASN_Items(rsaPublicKeyASN, dataASN,
                               rsaPublicKeyASN_Length, 1, input, inOutIdx,
                               inSz);
        }
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif
}

/* import RSA public key elements (n, e) into RsaKey structure (key) */
int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e,
                             word32 eSz, RsaKey* key)
{
    if (n == NULL || e == NULL || key == NULL)
        return BAD_FUNC_ARG;

    key->type = RSA_PUBLIC;

    if (mp_init(&key->n) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&key->n, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }
#ifdef HAVE_WOLF_BIGINT
    if ((int)nSz > 0 && wc_bigint_from_unsigned_bin(&key->n.raw, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

    if (mp_init(&key->e) != MP_OKAY) {
        mp_clear(&key->n);
        return MP_INIT_E;
    }

    if (mp_read_unsigned_bin(&key->e, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }
#ifdef HAVE_WOLF_BIGINT
    if ((int)eSz > 0 && wc_bigint_from_unsigned_bin(&key->e.raw, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

#ifdef WOLFSSL_XILINX_CRYPT
    if (wc_InitRsaHw(key) != 0) {
        return BAD_STATE_E;
    }
#endif

    return 0;
}
#endif /* HAVE_USER_RSA */

#if defined(WOLFSSL_DH_EXTRA)
/*
 * Decodes DH public key to fill specified DhKey.
 *
 * return 0 on success, negative on failure
 */
int wc_DhPublicKeyDecode(const byte* input, word32* inOutIdx,
                DhKey* key, word32 inSz)
{
    int ret = 0;
    int length;
    word32 oid = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    ret = GetObjectId(input, inOutIdx, &oid, oidKeyType, inSz);
    if (oid != DHk || ret < 0)
        return ASN_DH_KEY_E;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p, input, inOutIdx, inSz) < 0)
        return ASN_DH_KEY_E;

    if (GetInt(&key->g, input, inOutIdx, inSz) < 0) {
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }
    ret = (CheckBitString(input, inOutIdx, &length, inSz, 0, NULL) == 0);
    if (ret > 0) {
        /* Found Bit String WOLFSSL_DH_EXTRA is required to access DhKey.pub */
        if (GetInt(&key->pub, input, inOutIdx, inSz) < 0) {
            mp_clear(&key->p);
            mp_clear(&key->g);
            return ASN_DH_KEY_E;
        }
    }
    else {
        mp_clear(&key->p);
        mp_clear(&key->g);
        return ASN_DH_KEY_E;
    }
    return 0;
}
#endif /* WOLFSSL_DH_EXTRA */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for DH key.
 * PKCS #3, 9 - DHParameter.
 * (Also in: RFC 2786, 3)
 */
static const ASNItem dhParamASN[] = {
/* SEQ     */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                /* prime */
/* PRIME   */        { 1, ASN_INTEGER, 0, 0, 0 },
                /* base */
/* BASE    */        { 1, ASN_INTEGER, 0, 0, 0 },
                /* privateValueLength */
/* PRIVLEN */        { 1, ASN_INTEGER, 0, 0, 1 },
};
enum {
    DHPARAMASN_IDX_SEQ = 0,
    DHPARAMASN_IDX_PRIME,
    DHPARAMASN_IDX_BASE,
    DHPARAMASN_IDX_PRIVLEN,
};

/* Number of items in ASN.1 template for DH key. */
#define dhParamASN_Length (sizeof(dhParamASN) / sizeof(ASNItem))

#ifdef WOLFSSL_DH_EXTRA
/* ASN.1 template for DH key wrapped in PKCS #8 or SubjectPublicKeyInfo.
 * PKCS #8: RFC 5208, 5 - PrivateKeyInfo
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * RFC 3279, 2.3.3 - DH in SubjectPublicKeyInfo
 */
static const ASNItem dhKeyPkcs8ASN[] = {
/* SEQ                  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* VER                  */     { 1, ASN_INTEGER, 0, 0, 1 },
/* PKEYALGO_SEQ         */     { 1, ASN_SEQUENCE, 1, 1, 0 },
/* PKEYALGO_OID         */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
                                                     /* DHParameter */
/* PKEYALGO_PARAM_SEQ   */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                         /* p */
/* PKEYALGO_PARAM_P     */             { 3, ASN_INTEGER, 0, 0, 0 },
                                                         /* g */
/* PKEYALGO_PARAM_G     */             { 3, ASN_INTEGER, 0, 0, 0 },
                                                         /* q - factor of p-1 */
/* PKEYALGO_PARAM_Q     */             { 3, ASN_INTEGER, 0, 0, 1 },
                                                         /* j - subgroup factor */
/* PKEYALGO_PARAM_J     */             { 3, ASN_INTEGER, 0, 0, 1 },
                                                         /* ValidationParms */
/* PKEYALGO_PARAM_VALID */             { 3, ASN_SEQUENCE, 0, 0, 1 },
                                                 /* PrivateKey - PKCS #8 */
/* PKEY_STR             */     { 1, ASN_OCTET_STRING, 0, 1, 2 },
/* PKEY_INT             */         { 2, ASN_INTEGER, 0, 0, 0 },
                                                 /* PublicKey - SubjectPublicKeyInfo. */
/* PUBKEY_STR           */     { 1, ASN_BIT_STRING, 0, 1, 2 },
/* PUBKEY_INT           */         { 2, ASN_INTEGER, 0, 0, 0 },
};
enum {
    DHKEYPKCS8ASN_IDX_SEQ = 0,
    DHKEYPKCS8ASN_IDX_VER,
    DHKEYPKCS8ASN_IDX_PKEYALGO_SEQ,
    DHKEYPKCS8ASN_IDX_PKEYALGO_OID,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_SEQ,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_P,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_G,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_Q,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_J,
    DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_VALID,
    DHKEYPKCS8ASN_IDX_PKEY_STR,
    DHKEYPKCS8ASN_IDX_PKEY_INT,
    DHKEYPKCS8ASN_IDX_PUBKEY_STR,
    DHKEYPKCS8ASN_IDX_PUBKEY_INT,
};

#define dhKeyPkcs8ASN_Length (sizeof(dhKeyPkcs8ASN) / sizeof(ASNItem))
#endif
#endif

/* Decodes either PKCS#3 DH parameters or PKCS#8 DH key file (WOLFSSL_DH_EXTRA).
 *
 * See also wc_DhParamsLoad(). Loads directly into buffers rather than key
 * object.
 *
 * @param [in]      input     BER/DER encoded data.
 * @param [in, out] inOutIdx  On in, start of DH key data.
 *                            On out, end of DH key data.
 * @param [in, out] key       DH key object.
 * @param [in]      inSz      Size of data in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIDx or key is NULL.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  MP_INIT_E when the unable to initialize an mp_int.
 * @return  ASN_GETINT_E when the unable to convert data to an mp_int.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret = 0;
    int length;
#ifdef WOLFSSL_DH_EXTRA
    word32 oid = 0, temp = 0;
#endif

    WOLFSSL_ENTER("wc_DhKeyDecode");

    if (inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#ifdef WOLFSSL_DH_EXTRA
    temp = *inOutIdx;
#endif
    /* Assume input started after 1.2.840.113549.1.3.1 dhKeyAgreement */
    if (GetInt(&key->p, input, inOutIdx, inSz) < 0) {
        ret = ASN_DH_KEY_E;
    }
    if (ret == 0 && GetInt(&key->g, input, inOutIdx, inSz) < 0) {
        mp_clear(&key->p);
        ret = ASN_DH_KEY_E;
    }

#ifdef WOLFSSL_DH_EXTRA
    /* If ASN_DH_KEY_E: Check if input started at beginning of key */
    if (ret == ASN_DH_KEY_E) {
        *inOutIdx = temp;

        /* the version (0) - private only (for public skip) */
        if (GetASNInt(input, inOutIdx, &length, inSz) == 0) {
            *inOutIdx += length;
        }

        /* Size of dhKeyAgreement section */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        /* Check for dhKeyAgreement */
        ret = GetObjectId(input, inOutIdx, &oid, oidKeyType, inSz);
        if (oid != DHk || ret < 0)
            return ASN_DH_KEY_E;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (GetInt(&key->p, input, inOutIdx, inSz) < 0) {
            return ASN_DH_KEY_E;
        }
        if (ret == 0 && GetInt(&key->g, input, inOutIdx, inSz) < 0) {
            mp_clear(&key->p);
            return ASN_DH_KEY_E;
        }
    }

    temp = *inOutIdx;
    ret = (CheckBitString(input, inOutIdx, &length, inSz, 0, NULL) == 0);
    if (ret > 0) {
        /* Found Bit String */
        if (GetInt(&key->pub, input, inOutIdx, inSz) == 0) {
            WOLFSSL_MSG("Found Public Key");
            ret = 0;
        }
    } else {
        *inOutIdx = temp;
        ret = (GetOctetString(input, inOutIdx, &length, inSz) >= 0);
        if (ret > 0) {
            /* Found Octet String */
            if (GetInt(&key->priv, input, inOutIdx, inSz) == 0) {
                WOLFSSL_MSG("Found Private Key");

                /* Compute public */
                ret = mp_exptmod(&key->g, &key->priv, &key->p, &key->pub);
            }
        } else {
            /* Don't use length from failed CheckBitString/GetOctetString */
            *inOutIdx = temp;
            ret = 0;
        }
    }
#endif /* WOLFSSL_DH_EXTRA */

    WOLFSSL_LEAVE("wc_DhKeyDecode", ret);

    return ret;
#else
#ifdef WOLFSSL_DH_EXTRA
    DECL_ASNGETDATA(dataASN, dhKeyPkcs8ASN_Length);
#else
    DECL_ASNGETDATA(dataASN, dhParamASN_Length);
#endif
    int ret = 0;

    /* Check input parameters are valid. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_DH_EXTRA
    ALLOC_ASNGETDATA(dataASN, dhKeyPkcs8ASN_Length, ret, key->heap);
#else
    ALLOC_ASNGETDATA(dataASN, dhParamASN_Length, ret, key->heap);
#endif

    if (ret == 0) {
        /* Initialize data and set mp_ints to hold p and g. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * dhParamASN_Length);
        GetASN_MP(&dataASN[DHPARAMASN_IDX_PRIME], &key->p);
        GetASN_MP(&dataASN[DHPARAMASN_IDX_BASE], &key->g);
        /* Try simple PKCS #3 template. */
        ret = GetASN_Items(dhParamASN, dataASN, dhParamASN_Length, 1, input,
                           inOutIdx, inSz);
#ifdef WOLFSSL_DH_EXTRA
        if (ret != 0) {
            /* Initialize data and set mp_ints to hold p, g, q, priv and pub. */
            XMEMSET(dataASN, 0, sizeof(*dataASN) * dhKeyPkcs8ASN_Length);
            GetASN_ExpBuffer(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_OID],
                    keyDhOid, sizeof(keyDhOid));
            GetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_P], &key->p);
            GetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_G], &key->g);
            GetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_Q], &key->q);
            GetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEY_INT], &key->priv);
            GetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PUBKEY_INT], &key->pub);
            /* Try PKCS #8 wrapped template. */
            ret = GetASN_Items(dhKeyPkcs8ASN, dataASN, dhKeyPkcs8ASN_Length, 1,
                               input, inOutIdx, inSz);
            if (ret == 0) {
                /* VERSION only present in PKCS #8 private key structure */
                if ((dataASN[DHKEYPKCS8ASN_IDX_PKEY_INT].length != 0) &&
                        (dataASN[DHKEYPKCS8ASN_IDX_VER].length == 0)) {
                    ret = ASN_PARSE_E;
                }
                else if ((dataASN[DHKEYPKCS8ASN_IDX_PUBKEY_INT].length != 0) &&
                        (dataASN[DHKEYPKCS8ASN_IDX_VER].length != 0)) {
                    ret = ASN_PARSE_E;
                }
            }
        }
#endif
    }

    FREE_ASNGETDATA(dataASN, key->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_DH_EXTRA

/* Export DH Key (private or public) */
int wc_DhKeyToDer(DhKey* key, byte* output, word32* outSz, int exportPriv)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret, privSz = 0, pubSz = 0, keySz;
    word32 idx, len, total;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* determine size */
    if (exportPriv) {
        /* octect string: priv */
        privSz = SetASNIntMP(&key->priv, -1, NULL);
        idx = 1 + SetLength(privSz, NULL) + privSz; /* +1 for ASN_OCTET_STRING */
    }
    else {
        /* bit string: public */
        pubSz = SetASNIntMP(&key->pub, -1, NULL);
        idx = SetBitString(pubSz, 0, NULL) + pubSz;
    }
    keySz = idx;

    /* DH Parameters sequence with P and G */
    total = 0;
    ret = wc_DhParamsToDer(key, NULL, &total);
    if (ret != LENGTH_ONLY_E)
        return ret;
    idx += total;

    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += SetObjectId(sizeof(keyDhOid), NULL);
    idx += sizeof(keyDhOid);
    len = idx - keySz;
    /* sequence - all but pub/priv */
    idx += SetSequence(len, NULL);
    if (exportPriv) {
        /* version: 0 (ASN_INTEGER, 0x01, 0x00) */
        idx += 3;
    }
    /* sequence */
    total = idx + SetSequence(idx, NULL);

    /* if no output, then just getting size */
    if (output == NULL) {
        *outSz = total;
        return LENGTH_ONLY_E;
    }

    /* make sure output fits in buffer */
    if (total > *outSz) {
        return BUFFER_E;
    }
    total = idx;

    /* sequence */
    idx = SetSequence(total, output);
    if (exportPriv) {
        /* version: 0 */
        idx += SetMyVersion(0, output + idx, 0);
    }
    /* sequence - all but pub/priv */
    idx += SetSequence(len, output + idx);
    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += SetObjectId(sizeof(keyDhOid), output + idx);
    XMEMCPY(output + idx, keyDhOid, sizeof(keyDhOid));
    idx += sizeof(keyDhOid);

    /* DH Parameters sequence with P and G */
    total = *outSz - idx;
    ret = wc_DhParamsToDer(key, output + idx, &total);
    if (ret < 0)
        return ret;
    idx += total;

    /* octect string: priv */
    if (exportPriv) {
        idx += SetOctetString(privSz, output + idx);
        idx += SetASNIntMP(&key->priv, -1, output + idx);
    }
    else {
        /* bit string: public */
        idx += SetBitString(pubSz, 0, output + idx);
        idx += SetASNIntMP(&key->pub, -1, output + idx);
    }
    *outSz = idx;

    return idx;
#else
    ASNSetData dataASN[dhKeyPkcs8ASN_Length];
    int ret = 0;
    int sz;

    WOLFSSL_ENTER("wc_DhKeyToDer");

    XMEMSET(dataASN, 0, sizeof(dataASN));
    SetASN_Int8Bit(&dataASN[DHKEYPKCS8ASN_IDX_VER], 0);
    SetASN_OID(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_OID], DHk, oidKeyType);
    /* Set mp_int containing p and g. */
    SetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_P], &key->p);
    SetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_G], &key->g);
    dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_Q].noOut = 1;
    dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_J].noOut = 1;
    dataASN[DHKEYPKCS8ASN_IDX_PKEYALGO_PARAM_VALID].noOut = 1;

    if (exportPriv) {
        SetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PKEY_INT], &key->priv);
        dataASN[DHKEYPKCS8ASN_IDX_PUBKEY_STR].noOut = 1;
        dataASN[DHKEYPKCS8ASN_IDX_PUBKEY_INT].noOut = 1;
    }
    else {
        dataASN[DHKEYPKCS8ASN_IDX_VER].noOut = 1;
        dataASN[DHKEYPKCS8ASN_IDX_PKEY_STR].noOut = 1;
        dataASN[DHKEYPKCS8ASN_IDX_PKEY_INT].noOut = 1;
        SetASN_MP(&dataASN[DHKEYPKCS8ASN_IDX_PUBKEY_INT], &key->pub);
    }

    /* Calculate the size of the DH parameters. */
    ret = SizeASN_Items(dhKeyPkcs8ASN, dataASN, dhKeyPkcs8ASN_Length, &sz);
    if (output == NULL) {
        *outSz = sz;
        ret = LENGTH_ONLY_E;
    }
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && ((int)*outSz < sz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode the DH parameters into buffer. */
        SetASN_Items(dhKeyPkcs8ASN, dataASN, dhKeyPkcs8ASN_Length, output);
        /* Set the actual encoding size. */
        *outSz = sz;
        /* Return the actual encoding size. */
        ret = sz;
    }

    return ret;
#endif
}

int wc_DhPubKeyToDer(DhKey* key, byte* out, word32* outSz)
{
    return wc_DhKeyToDer(key, out, outSz, 0);
}
int wc_DhPrivKeyToDer(DhKey* key, byte* out, word32* outSz)
{
    return wc_DhKeyToDer(key, out, outSz, 1);
}


/* Convert DH key parameters to DER format, write to output (outSz)
 * If output is NULL then max expected size is set to outSz and LENGTH_ONLY_E is
 * returned.
 *
 * Note : static function due to redefinition complications with DhKey and FIPS
 * version 2 build.
 *
 * return bytes written on success */
int wc_DhParamsToDer(DhKey* key, byte* output, word32* outSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx, total;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* determine size */
    /* integer - g */
    idx = SetASNIntMP(&key->g, -1, NULL);
    /* integer - p */
    idx += SetASNIntMP(&key->p, -1, NULL);
    total = idx;
     /* sequence */
    idx += SetSequence(idx, NULL);

    if (output == NULL) {
        *outSz = idx;
        return LENGTH_ONLY_E;
    }
    /* make sure output fits in buffer */
    if (idx > *outSz) {
        return BUFFER_E;
    }


    /* write DH parameters */
    /* sequence - for P and G only */
    idx = SetSequence(total, output);
    /* integer - p */
    idx += SetASNIntMP(&key->p, -1, output + idx);
    /* integer - g */
    idx += SetASNIntMP(&key->g, -1, output + idx);
    *outSz = idx;

    return idx;
#else
    ASNSetData dataASN[dhParamASN_Length];
    int ret = 0;
    int sz = 0;

    WOLFSSL_ENTER("wc_DhParamsToDer");

    if (key == NULL || outSz == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        XMEMSET(dataASN, 0, sizeof(dataASN));
        /* Set mp_int containing p and g. */
        SetASN_MP(&dataASN[DHPARAMASN_IDX_PRIME], &key->p);
        SetASN_MP(&dataASN[DHPARAMASN_IDX_BASE], &key->g);
        /* privateValueLength not encoded. */
        dataASN[DHPARAMASN_IDX_PRIVLEN].noOut = 1;

        /* Calculate the size of the DH parameters. */
        ret = SizeASN_Items(dhParamASN, dataASN, dhParamASN_Length, &sz);
    }
    if ((ret == 0) && (output == NULL)) {
        *outSz = sz;
        ret = LENGTH_ONLY_E;
    }
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && ((int)*outSz < sz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode the DH parameters into buffer. */
        SetASN_Items(dhParamASN, dataASN, dhParamASN_Length, output);
        /* Set the actual encoding size. */
        *outSz = sz;
        /* Return count of bytes written. */
        ret = sz;
    }

    return ret;
#endif
}

#endif /* WOLFSSL_DH_EXTRA */

/* Decode DH parameters.
 *
 * PKCS #3, 9 - DHParameter.
 * (Also in: RFC 2786, 3)
 *
 * @param [in]      input     Buffer holding BER encoded data.
 * @param [in, out] inOutIdx  On in, start of RSA public key.
 *                            On out, start of ASN.1 item after RSA public key.
 * @param [in]      inSz      Number of bytes in buffer.
 * @param [in, out] p         Buffer to hold prime.
 * @param [out]     pInOutSz  On in, size of buffer to hold prime in bytes.
 *                            On out, size of prime in bytes.
 * @param [in, out] g         Buffer to hold base.
 * @param [out]     gInOutSz  On in, size of buffer to hold base in bytes.
 *                            On out, size of base in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set.
 */
int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz,
                 byte* g, word32* gInOutSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int    ret;
    int    length;

    if (GetSequence(input, &idx, &length, inSz) <= 0)
        return ASN_PARSE_E;

    ret = GetASNInt(input, &idx, &length, inSz);
    if (ret != 0)
        return ret;

    if (length <= (int)*pInOutSz) {
        XMEMCPY(p, &input[idx], length);
        *pInOutSz = length;
    }
    else {
        return BUFFER_E;
    }
    idx += length;

    ret = GetASNInt(input, &idx, &length, inSz);
    if (ret != 0)
        return ret;

    if (length <= (int)*gInOutSz) {
        XMEMCPY(g, &input[idx], length);
        *gInOutSz = length;
    }
    else {
        return BUFFER_E;
    }

    return 0;
#else
    DECL_ASNGETDATA(dataASN, dhParamASN_Length);
    word32 idx = 0;
    int ret = 0;

    /* Make sure pointers are valid before use. */
    if ((input == NULL) || (p == NULL) || (pInOutSz == NULL) || (g == NULL) ||
            (gInOutSz == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNGETDATA(dataASN, dhParamASN_Length, ret, NULL);

    if (ret == 0) {
        /* Set the buffers to copy p and g into. */
        GetASN_Buffer(&dataASN[DHPARAMASN_IDX_PRIME], p, pInOutSz);
        GetASN_Buffer(&dataASN[DHPARAMASN_IDX_BASE], g, gInOutSz);
        /* Decode the DH Parameters. */
        ret = GetASN_Items(dhParamASN, dataASN, dhParamASN_Length, 1, input,
                           &idx, inSz);
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}



/* Initialize decoded certificate object with buffer of DER encoding.
 *
 * @param [in, out] cert    Decoded certificate object.
 * @param [in]      source  Buffer containing DER encoded certificate.
 * @param [in]      inSz    Size of DER data in buffer in bytes.
 * @param [in]      heap    Dynamic memory hint.
 */
void InitDecodedCert(DecodedCert* cert,
                     const byte* source, word32 inSz, void* heap)
{
    if (cert != NULL) {
        XMEMSET(cert, 0, sizeof(DecodedCert));

        cert->subjectCNEnc    = CTC_UTF8;
        cert->issuer[0]       = '\0';
        cert->subject[0]      = '\0';
        cert->source          = source;  /* don't own */
        cert->maxIdx          = inSz;    /* can't go over this index */
        cert->heap            = heap;
        cert->maxPathLen      = WOLFSSL_MAX_PATH_LEN;
    #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        cert->subjectSNEnc    = CTC_UTF8;
        cert->subjectCEnc     = CTC_PRINTABLE;
        cert->subjectLEnc     = CTC_UTF8;
        cert->subjectSTEnc    = CTC_UTF8;
        cert->subjectOEnc     = CTC_UTF8;
        cert->subjectOUEnc    = CTC_UTF8;
    #ifdef WOLFSSL_HAVE_ISSUER_NAMES
        cert->issuerSNEnc    = CTC_UTF8;
        cert->issuerCEnc     = CTC_PRINTABLE;
        cert->issuerLEnc     = CTC_UTF8;
        cert->issuerSTEnc    = CTC_UTF8;
        cert->issuerOEnc     = CTC_UTF8;
        cert->issuerOUEnc    = CTC_UTF8;
    #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
    #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */

        InitSignatureCtx(&cert->sigCtx, heap, INVALID_DEVID);
    }
}

void wc_InitDecodedCert(DecodedCert* cert, const byte* source, word32 inSz,
                        void* heap)
{
    InitDecodedCert(cert, source, inSz, heap);
}

/* Free the alternative names object.
 *
 * Frees each linked list items and its name.
 *
 * @param [in, out] altNames  Alternative names.
 * @param [in]      heap      Dynamic memory hint.
 */
void FreeAltNames(DNS_entry* altNames, void* heap)
{
    (void)heap;

    while (altNames) {
        DNS_entry* tmp = altNames->next;

        XFREE(altNames->name, heap, DYNAMIC_TYPE_ALTNAME);
    #if defined(WOLFSSL_IP_ALT_NAME)
        XFREE(altNames->ipString, heap, DYNAMIC_TYPE_ALTNAME);
    #endif
        XFREE(altNames,       heap, DYNAMIC_TYPE_ALTNAME);
        altNames = tmp;
    }
}

/* malloc and initialize a new alt name structure */
DNS_entry* AltNameNew(void* heap)
{
    DNS_entry* ret;
    ret = (DNS_entry*)XMALLOC(sizeof(DNS_entry), heap, DYNAMIC_TYPE_ALTNAME);
    if (ret != NULL) {
        XMEMSET(ret, 0, sizeof(DNS_entry));
    }
    (void)heap;
    return ret;
}


#ifndef IGNORE_NAME_CONSTRAINTS

/* Free the subtree names object.
 *
 * Frees each linked list items and its name.
 *
 * @param [in, out] names  Subtree names.
 * @param [in]      heap   Dynamic memory hint.
 */
void FreeNameSubtrees(Base_entry* names, void* heap)
{
    (void)heap;

    while (names) {
        Base_entry* tmp = names->next;

        XFREE(names->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(names,       heap, DYNAMIC_TYPE_ALTNAME);
        names = tmp;
    }
}

#endif /* IGNORE_NAME_CONSTRAINTS */

/* Free the decoded cert object's dynamic data.
 *
 * @param [in, out] cert  Decoded certificate object.
 */
void FreeDecodedCert(DecodedCert* cert)
{
    if (cert == NULL)
        return;
    if (cert->subjectCNStored == 1) {
        XFREE(cert->subjectCN, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
    }
    if (cert->pubKeyStored == 1) {
        XFREE((void*)cert->publicKey, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    if (cert->weOwnAltNames && cert->altNames)
        FreeAltNames(cert->altNames, cert->heap);
#ifndef IGNORE_NAME_CONSTRAINTS
    if (cert->altEmailNames)
        FreeAltNames(cert->altEmailNames, cert->heap);
    if (cert->altDirNames)
        FreeAltNames(cert->altDirNames, cert->heap);
    if (cert->permittedNames)
        FreeNameSubtrees(cert->permittedNames, cert->heap);
    if (cert->excludedNames)
        FreeNameSubtrees(cert->excludedNames, cert->heap);
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
    XFREE(cert->deviceType, cert->heap, DYNAMIC_TYPE_X509_EXT);
    XFREE(cert->hwType, cert->heap, DYNAMIC_TYPE_X509_EXT);
    XFREE(cert->hwSerialNum, cert->heap, DYNAMIC_TYPE_X509_EXT);
#endif /* WOLFSSL_SEP */
#ifdef WOLFSSL_X509_NAME_AVAILABLE
    if (cert->issuerName != NULL)
        wolfSSL_X509_NAME_free((WOLFSSL_X509_NAME*)cert->issuerName);
    if (cert->subjectName != NULL)
        wolfSSL_X509_NAME_free((WOLFSSL_X509_NAME*)cert->subjectName);
#endif /* WOLFSSL_X509_NAME_AVAILABLE */
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    if (cert->sce_tsip_encRsaKeyIdx != NULL)
        XFREE(cert->sce_tsip_encRsaKeyIdx, cert->heap, DYNAMIC_TYPE_RSA);
#endif
    FreeSignatureCtx(&cert->sigCtx);
}

void wc_FreeDecodedCert(DecodedCert* cert)
{
    FreeDecodedCert(cert);
}

#ifndef WOLFSSL_ASN_TEMPLATE
static int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    /* Reset the max index for the size indicated in the outer wrapper. */
    cert->maxIdx = len + cert->srcIdx;
    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->sigIndex = len + cert->srcIdx;
    if (cert->sigIndex > cert->maxIdx)
        return ASN_PARSE_E;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version,
                                                            cert->sigIndex) < 0)
        return ASN_PARSE_E;

    if (GetSerialNumber(cert->source, &cert->srcIdx, cert->serial,
                                           &cert->serialSz, cert->sigIndex) < 0)
        return ASN_PARSE_E;

    return ret;
}
#endif


#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for header before RSA key in certificate. */
static const ASNItem rsaCertKeyASN[] = {
/* STR */ { 0, ASN_BIT_STRING, 0, 1, 0 },
/* SEQ */     { 1, ASN_SEQUENCE, 1, 0, 0 },
};
enum {
    RSACERTKEYASN_IDX_STR = 0,
    RSACERTKEYASN_IDX_SEQ,
};

/* Number of items in ASN.1 template for header before RSA key in cert. */
#define rsaCertKeyASN_Length (sizeof(rsaCertKeyASN) / sizeof(ASNItem))
#endif

/* Store RSA key pointer and length in certificate object.
 *
 * @param [in, out] cert    Certificate object.
 * @param [in]      source  Buffer containing encoded key.
 * @param [in, out] srcIdx  On in, start of RSA key data.
 *                          On out, start of element after RSA key data.
 * @param [in]      maxIdx  Maximum index of key data.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 */
static int StoreRsaKey(DecodedCert* cert, const byte* source, word32* srcIdx,
                       word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    length;
    int    pubLen;
    word32 pubIdx;

    if (CheckBitString(source, srcIdx, &pubLen, maxIdx, 1, NULL) != 0)
        return ASN_PARSE_E;
    pubIdx = *srcIdx;

    if (GetSequence(source, srcIdx, &length, pubIdx + pubLen) < 0)
        return ASN_PARSE_E;

#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    cert->sigCtx.CertAtt.pubkey_n_start =
            cert->sigCtx.CertAtt.pubkey_e_start = pubIdx;
#endif
    cert->pubKeySize = pubLen;
    cert->publicKey = source + pubIdx;
    *srcIdx += length;

    return 0;
#else
    ASNGetData dataASN[rsaCertKeyASN_Length];
    int ret;

    /* No dynamic data. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    /* Decode the header before the key data. */
    ret = GetASN_Items(rsaCertKeyASN, dataASN, rsaCertKeyASN_Length, 1, source,
                       srcIdx, maxIdx);
    if (ret == 0) {
        /* Store the pointer and length in certificate object starting at
         * SEQUENCE. */
        GetASN_GetConstRef(&dataASN[RSACERTKEYASN_IDX_STR],
                &cert->publicKey, &cert->pubKeySize);

    #if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
        /* Start of SEQUENCE. */
        cert->sigCtx.CertAtt.pubkey_n_start =
            cert->sigCtx.CertAtt.pubkey_e_start = dataASN[RSACERTKEYASN_IDX_SEQ].offset;
    #endif
    }

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for header before ECC key in certificate. */
static const ASNItem eccCertKeyASN[] = {
/* OID        */     { 1, ASN_OBJECT_ID, 0, 0, 2 },
                            /* Algo parameters */
/* PARAMS     */     { 1, ASN_SEQUENCE, 1, 0, 2 },
                            /* Subject public key */
/* SUBJPUBKEY */ { 0, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    ECCCERTKEYASN_IDX_OID = 0,
    ECCCERTKEYASN_IDX_PARAMS,
    ECCCERTKEYASN_IDX_SUBJPUBKEY,
};

/* Number of items in ASN.1 template for header before ECC key in cert. */
#define eccCertKeyASN_Length (sizeof(eccCertKeyASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */

/* Store public ECC key in certificate object.
 *
 * Parse parameters and store public key data.
 *
 * @param [in, out] cert       Certificate object.
 * @param [in]      source     Buffer containing encoded key.
 * @param [in, out] srcIdx     On in, start of ECC key data.
 *                             On out, start of element after ECC key data.
 * @param [in]      maxIdx     Maximum index of key data.
 * @param [in]      pubKey     Buffer holding encoded public key.
 * @param [in]      pubKeyLen  Length of encoded public key in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 */
static int StoreEccKey(DecodedCert* cert, const byte* source, word32* srcIdx,
                       word32 maxIdx, const byte* pubKey, word32 pubKeyLen)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    word32 localIdx;
    byte* publicKey;
    byte  tag;
    int length;

    localIdx = *srcIdx;
    if (GetASNTag(source, &localIdx, &tag, maxIdx) < 0)
        return ASN_PARSE_E;

    if (tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        if (GetObjectId(source, srcIdx, &cert->pkCurveOID, oidCurveType,
                                                                    maxIdx) < 0)
            return ASN_PARSE_E;

        if ((ret = CheckCurve(cert->pkCurveOID)) < 0)
            return ECC_CURVE_OID_E;

    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
        cert->sigCtx.CertAtt.curve_id = ret;
    #else
        (void)ret;
    #endif
        /* key header */
        ret = CheckBitString(source, srcIdx, &length, maxIdx, 1, NULL);
        if (ret != 0)
            return ret;
    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
        cert->sigCtx.CertAtt.pubkey_n_start =
                cert->sigCtx.CertAtt.pubkey_e_start = (*srcIdx + 1);
        cert->sigCtx.CertAtt.pubkey_n_len = ((length - 1) >> 1);
        cert->sigCtx.CertAtt.pubkey_e_start +=
                cert->sigCtx.CertAtt.pubkey_n_len;
        cert->sigCtx.CertAtt.pubkey_e_len   =
                cert->sigCtx.CertAtt.pubkey_n_len;
    #endif
        *srcIdx += length;
    }

    publicKey = (byte*)XMALLOC(pubKeyLen, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (publicKey == NULL)
        return MEMORY_E;
    XMEMCPY(publicKey, pubKey, pubKeyLen);
    cert->publicKey = publicKey;
    cert->pubKeyStored = 1;
    cert->pubKeySize   = pubKeyLen;

    return 0;
#else
    int ret = 0;
    DECL_ASNGETDATA(dataASN, eccCertKeyASN_Length);
    byte* publicKey;

    /* Clear dynamic data and check OID is a curve. */
    CALLOC_ASNGETDATA(dataASN, eccCertKeyASN_Length, ret, cert->heap);
    if (ret == 0) {
        GetASN_OID(&dataASN[ECCCERTKEYASN_IDX_OID], oidCurveType);
        /* Parse ECC public key header. */
        ret = GetASN_Items(eccCertKeyASN, dataASN, eccCertKeyASN_Length, 1,
                source, srcIdx, maxIdx);
    }
    if (ret == 0) {
        if (dataASN[ECCCERTKEYASN_IDX_OID].tag != 0) {
            /* Store curve OID. */
            cert->pkCurveOID = dataASN[ECCCERTKEYASN_IDX_OID].data.oid.sum;
        }
        /* Ignore explicit parameters. */

        /* Store public key data length. */
        cert->pubKeySize = pubKeyLen;
        /* Must allocated space for key.
         * Don't memcpy into constant pointer so use temp. */
        publicKey = (byte*)XMALLOC(cert->pubKeySize, cert->heap,
                                   DYNAMIC_TYPE_PUBLIC_KEY);
        if (publicKey == NULL) {
            ret = MEMORY_E;
        }
        else {
            /* Copy in whole public key and store pointer. */
            XMEMCPY(publicKey, pubKey, cert->pubKeySize);
            cert->publicKey = publicKey;
            /* Indicate publicKey needs to be freed. */
            cert->pubKeyStored = 1;
        }
    }
    FREE_ASNGETDATA(dataASN, cert->heap);

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


/* Decode the SubjectPublicKeyInfo block in a certificate.
 *
 * Stores the public key in fields of the certificate object.
 * Validates the BER/DER items and does not store in a key object.
 *
 * @param [in, out] cert      Decoded certificate oject.
 * @param [in]      source    BER/DER encoded SubjectPublicKeyInfo block.
 * @param [in, out] inOutIdx  On in, start of public key.
 *                            On out, start of ASN.1 item after public key.
 * @param [in]      maxIdx    Maximum index of key data.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 */
static int GetCertKey(DecodedCert* cert, const byte* source, word32* inOutIdx,
                      word32 maxIdx)
{
    word32 srcIdx = *inOutIdx;
    int pubLen;
    int pubIdx = srcIdx;
    int ret = 0;
    int length;

#ifndef WOLFSSL_ASN_TEMPLATE
    if (GetSequence(source, &srcIdx, &length, maxIdx) < 0)
#else
    /* Get SEQUENCE and expect all data to be accounted for. */
    if (GetASN_Sequence(source, &srcIdx, &length, maxIdx, 1) != 0)
#endif
    {
        return ASN_PARSE_E;
    }

    pubLen = srcIdx - pubIdx + length;
    maxIdx = srcIdx + length;

    /* Decode the algorithm identifier for the key. */
    if (GetAlgoId(source, &srcIdx, &cert->keyOID, oidKeyType, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    (void)length;

    /* Parse each type of public key. */
    switch (cert->keyOID) {
        case RSAk:
            ret = StoreRsaKey(cert, source, &srcIdx, maxIdx);
            break;

        case ECDSAk:
            ret = StoreEccKey(cert, source, &srcIdx, maxIdx, source + pubIdx,
                              pubLen);
            break;
        default:
            WOLFSSL_MSG("Unknown or not compiled in key OID");
            ret = ASN_UNKNOWN_OID_E;
    }

    /* Return index after public key. */
    *inOutIdx = srcIdx;

    /* Return error code. */
    return ret;
}



/* Calculate hash of the id using the SHA-1 or SHA-256.
 *
 * @param [in]  data  Data to hash.
 * @param [in]  len   Length of data to hash.
 * @param [out] hash  Buffer to hold hash.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int CalcHashId(const byte* data, word32 len, byte* hash)
{
    int ret;

    ret = wc_ShaHash(data, len, hash);

    return ret;
}

/* Get the hash of the id using the SHA-1 or SHA-256.
 *
 * If the id is not the length of the hash, then hash it.
 *
 * @param [in]  id    Id to get hash for.
 * @param [in]  len   Length of id in bytes.
 * @param [out] hash  Buffer to hold hash.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int GetHashId(const byte* id, int length, byte* hash)
{
    int ret;

    if (length == KEYID_SIZE) {
        XMEMCPY(hash, id, length);
        ret = 0;
    }
    else {
        ret = CalcHashId(id, length, hash);
    }

    return ret;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* Id for email address. */
#define ASN_EMAIL     0x100
/* Id for domain component. */
#define ASN_DC        0x102
/* Id for jurisdiction country. */
#define ASN_JURIS_C   0x203
/* Id for jurisdiction state. */
#define ASN_JURIS_ST  0x203

/* Set the string for a name component into the subject name. */
#define SetCertNameSubject(cert, id, val) \
    *((char**)(((byte *)(cert)) + certNameSubject[(id) - 3].data)) = (val)
/* Set the string length for a name component into the subject name. */
#define SetCertNameSubjectLen(cert, id, val) \
    *((int*)(((byte *)(cert)) + certNameSubject[(id) - 3].len)) = (val)
/* Set the encoding for a name component into the subject name. */
#define SetCertNameSubjectEnc(cert, id, val) \
    *((byte*)(((byte *)(cert)) + certNameSubject[(id) - 3].enc)) = (val)

/* Get the string of a name component from the subject name. */
#define GetCertNameSubjectStr(id) \
    (certNameSubject[(id) - 3].str)
/* Get the string length of a name component from the subject name. */
#define GetCertNameSubjectStrLen(id) \
    (certNameSubject[(id) - 3].strLen)
/* Get the NID of a name component from the subject name. */
#define GetCertNameSubjectNID(id) \
    (certNameSubject[(id) - 3].nid)

#define ValidCertNameSubject(id) \
    (((id) - 3) >= 0 && ((id) - 3) < certNameSubjectSz && \
            (certNameSubject[(id) - 3].strLen > 0))

/* Mapping of certificate name component to useful information. */
typedef struct CertNameData {
    /* Type string of name component. */
    const char* str;
    /* Length of type string of name component. */
    byte        strLen;
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
    /* Offset of data in subject name component. */
    size_t      data;
    /* Offset of length in subject name component. */
    size_t      len;
    /* Offset of encoding in subject name component. */
    size_t      enc;
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
    /* NID of type for subject name component. */
    int         nid;
#endif
} CertNameData;

/* List of data for common name components. */
static const CertNameData certNameSubject[] = {
    /* Common Name */
    {
        "/CN=", 4,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectCN),
        OFFSETOF(DecodedCert, subjectCNLen),
        OFFSETOF(DecodedCert, subjectCNEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_commonName
#endif
    },
    /* Surname */
    {
        "/SN=", 4,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectSN),
        OFFSETOF(DecodedCert, subjectSNLen),
        OFFSETOF(DecodedCert, subjectSNEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_surname
#endif
    },
    /* Serial Number */
    {
        "/serialNumber=", 14,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectSND),
        OFFSETOF(DecodedCert, subjectSNDLen),
        OFFSETOF(DecodedCert, subjectSNDEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_serialNumber
#endif
    },
    /* Country Name */
    {
        "/C=", 3,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectC),
        OFFSETOF(DecodedCert, subjectCLen),
        OFFSETOF(DecodedCert, subjectCEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_countryName
#endif
    },
    /* Locality Name */
    {
        "/L=", 3,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectL),
        OFFSETOF(DecodedCert, subjectLLen),
        OFFSETOF(DecodedCert, subjectLEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_localityName
#endif
    },
    /* State Name */
    {
        "/ST=", 4,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectST),
        OFFSETOF(DecodedCert, subjectSTLen),
        OFFSETOF(DecodedCert, subjectSTEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_stateOrProvinceName
#endif
    },
    /* Street Address */
    {
        "/street=", 8,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectStreet),
        OFFSETOF(DecodedCert, subjectStreetLen),
        OFFSETOF(DecodedCert, subjectStreetEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_streetAddress
#endif
    },
    /* Organization Name */
    {
        "/O=", 3,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectO),
        OFFSETOF(DecodedCert, subjectOLen),
        OFFSETOF(DecodedCert, subjectOEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_organizationName
#endif
    },
    /* Organization Unit Name */
    {
        "/OU=", 4,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectOU),
        OFFSETOF(DecodedCert, subjectOULen),
        OFFSETOF(DecodedCert, subjectOUEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_organizationalUnitName
#endif
    },
    /* Title */
    {
        NULL, 0,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        0,
        0,
        0,
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        0,
#endif
    },
    /* Undefined */
    {
        NULL, 0,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        0,
        0,
        0,
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        0,
#endif
    },
    /* Undefined */
    {
        NULL, 0,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        0,
        0,
        0,
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        0,
#endif
    },
    /* Business Category */
    {
        "/businessCategory=", 18,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectBC),
        OFFSETOF(DecodedCert, subjectBCLen),
        OFFSETOF(DecodedCert, subjectBCEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_businessCategory
#endif
    },
    /* Undefined */
    {
        NULL, 0,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        0,
        0,
        0,
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        0,
#endif
    },
    /* Postal Code */
    {
        "/postalCode=", 12,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectPC),
        OFFSETOF(DecodedCert, subjectPCLen),
        OFFSETOF(DecodedCert, subjectPCEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_postalCode
#endif
    },
    /* User Id */
    {
        "/userid=", 8,
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
        OFFSETOF(DecodedCert, subjectUID),
        OFFSETOF(DecodedCert, subjectUIDLen),
        OFFSETOF(DecodedCert, subjectUIDEnc),
#endif
#ifdef WOLFSSL_X509_NAME_AVAILABLE
        NID_userId
#endif
    },
};

static const int certNameSubjectSz =
        (int) (sizeof(certNameSubject) / sizeof(CertNameData));

/* ASN.1 template for an RDN.
 * X.509: RFC 5280, 4.1.2.4 - RelativeDistinguishedName
 */
static const ASNItem rdnASN[] = {
/* SET       */ { 1, ASN_SET, 1, 1, 0 },
                           /* AttributeTypeAndValue */
/* ATTR_SEQ  */     { 2, ASN_SEQUENCE, 1, 1, 0 },
                                   /* AttributeType */
/* ATTR_TYPE */         { 3, ASN_OBJECT_ID, 0, 0, 0 },
                           /* AttributeValue: Choice of tags - rdnChoice. */
/* ATTR_VAL  */         { 3, 0, 0, 0, 0 },
};
enum {
    RDNASN_IDX_SET = 0,
    RDNASN_IDX_ATTR_SEQ,
    RDNASN_IDX_ATTR_TYPE,
    RDNASN_IDX_ATTR_VAL,
};

/* Number of items in ASN.1 template for an RDN. */
#define rdnASN_Length (sizeof(rdnASN) / sizeof(ASNItem))

/* Supported types of encodings (tags) for RDN strings.
 * X.509: RFC 5280, 4.1.2.4 - DirectoryString
 * (IA5 String not listed in RFC but required for alternative types)
 */
static const byte rdnChoice[] = {
    ASN_PRINTABLE_STRING, ASN_IA5_STRING, ASN_UTF8STRING, ASN_T61STRING,
    ASN_UNIVERSALSTRING, ASN_BMPSTRING, 0
};
#endif

#if defined(WOLFSSL_IP_ALT_NAME)
/* used to set the human readable string for the IP address with a ASN_IP_TYPE
 * DNS entry
 * return 0 on success
 */
static int GenerateDNSEntryIPString(DNS_entry* entry, void* heap)
{
    int ret = 0;
    int nameSz;
    char tmpName[WOLFSSL_MAX_IPSTR] = {0};
    char* ip;

    if (entry == NULL || entry->type != ASN_IP_TYPE) {
        return BAD_FUNC_ARG;
    }

    if (entry->len != WOLFSSL_IP4_ADDR_LEN &&
            entry->len != WOLFSSL_IP6_ADDR_LEN) {
        WOLFSSL_MSG("Unexpected IP size");
        return BAD_FUNC_ARG;
    }
    ip = entry->name;

    /* store IP addresses as a string */
    if (entry->len == WOLFSSL_IP4_ADDR_LEN) {
        XSNPRINTF(tmpName, sizeof(tmpName), "%u.%u.%u.%u", 0xFFU & ip[0],
                0xFFU & ip[1], 0xFFU & ip[2], 0xFFU & ip[3]);
    }

    if (entry->len == WOLFSSL_IP6_ADDR_LEN) {
        int i;
        for (i = 0; i < 8; i++) {
            XSNPRINTF(tmpName + i * 5, sizeof(tmpName) - i * 5,
                    "%02X%02X%s", 0xFF & ip[2 * i], 0xFF & ip[2 * i + 1],
                    (i < 7) ? ":" : "");
        }
    }

    nameSz = (int)XSTRLEN(tmpName);
    entry->ipString = (char*)XMALLOC(nameSz + 1, heap, DYNAMIC_TYPE_ALTNAME);
    if (entry->ipString == NULL) {
        ret = MEMORY_E;
    }

    if (ret == 0) {
        XMEMCPY(entry->ipString, tmpName, nameSz);
        entry->ipString[nameSz] = '\0';
    }

    return ret;
}
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */

#ifdef WOLFSSL_ASN_TEMPLATE
#if defined(WOLFSSL_CERT_GEN) ||  !defined(IGNORE_NAME_CONSTRAINTS)
/* Allocate a DNS entry and set the fields.
 *
 * @param [in]      cert     Certificate object.
 * @param [in]      str      DNS name string.
 * @param [in]      strLen   Length of DNS name string.
 * @param [in]      type     Type of DNS name string.
 * @param [in, out] entries  Linked list of DNS name entries.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int SetDNSEntry(DecodedCert* cert, const char* str, int strLen,
                       int type, DNS_entry** entries)
{
    DNS_entry* dnsEntry;
    int ret = 0;

    /* Only used for heap. */
    (void)cert;

    /* TODO: consider one malloc. */
    /* Allocate DNS Entry object. */
    dnsEntry = AltNameNew(cert->heap);
    if (dnsEntry == NULL) {
        ret = MEMORY_E;
    }
    if (ret == 0) {
        /* Allocate DNS Entry name - length of string plus 1 for NUL. */
        dnsEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                                          DYNAMIC_TYPE_ALTNAME);
        if (dnsEntry->name == NULL) {
            XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Set tag type, name length, name and NUL terminate name. */
        dnsEntry->type = type;
        dnsEntry->len = strLen;
        XMEMCPY(dnsEntry->name, str, strLen);
        dnsEntry->name[strLen] = '\0';

    #if defined(WOLFSSL_IP_ALT_NAME)
        /* store IP addresses as a string */
        if (type == ASN_IP_TYPE) {
            if ((ret = GenerateDNSEntryIPString(dnsEntry, cert->heap)) != 0) {
                XFREE(dnsEntry->name, cert->heap, DYNAMIC_TYPE_ALTNAME);
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
            }
        }
    #endif
    }

    if (ret == 0) {
        /* Prepend entry to linked list. */
        dnsEntry->next = *entries;
        *entries = dnsEntry;
    }

    return ret;
}
#endif

/* Set the details of a subject name component into a certificate.
 *
 * @param [in, out] cert    Certificate object.
 * @param [in]      id      Id of component.
 * @param [in]      str     String for component.
 * @param [in]      strLen  Length of string.
 * @param [in]      tag     BER tag representing encoding of string.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int SetSubject(DecodedCert* cert, int id, byte* str, word32 strLen,
                      byte tag)
{
    int ret = 0;

    /* Put string and encoding into certificate. */
    if (id == ASN_COMMON_NAME) {
        cert->subjectCN = (char *)str;
        cert->subjectCNLen = strLen;
        cert->subjectCNEnc = tag;
    }
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
    else if (id > ASN_COMMON_NAME && id <= ASN_USER_ID) {
        /* Use table and offsets to put data into appropriate fields. */
        SetCertNameSubject(cert, id, (char*)str);
        SetCertNameSubjectLen(cert, id, strLen);
        SetCertNameSubjectEnc(cert, id, tag);
    }
    else if (id == ASN_EMAIL) {
        cert->subjectEmail = (char*)str;
        cert->subjectEmailLen = strLen;
    #if !defined(IGNORE_NAME_CONSTRAINTS)
        ret = SetDNSEntry(cert, cert->subjectEmail, strLen, 0,
                          &cert->altEmailNames);
    #endif
    }
#ifdef WOLFSSL_CERT_EXT
    /* TODO: consider mapping id to an index and using SetCertNameSubect*(). */
    else if (id == ASN_JURIS_C) {
        cert->subjectJC = (char*)str;
        cert->subjectJCLen = strLen;
        cert->subjectJCEnc = tag;
    }
    else if (id == ASN_JURIS_ST) {
        cert->subjectJS = (char*)str;
        cert->subjectJSLen = strLen;
        cert->subjectJSEnc = tag;
    }
#endif
#endif

    return ret;
}

/* Get a RelativeDistinguishedName from the encoding and put in certificate.
 *
 * @param [in, out] cert       Certificate object.
 * @param [in, out] full       Full name string. ([/<type>=<value>]*)
 * @param [in, out] idx        Index int full name to place next component.
 * @param [in, out] nid        NID of component type.
 * @param [in]      isSubject  Whether this data is for a subject name.
 * @param [in]      dataASN    Decoded data of RDN. Expected rdnASN type.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when type not supported.
 */
static int GetRDN(DecodedCert* cert, char* full, word32* idx, int* nid,
                  int isSubject, ASNGetData* dataASN)
{
    int         ret = 0;
    const char* typeStr = NULL;
    byte        typeStrLen = 0;
    byte*       oid;
    word32      oidSz;
    int         id = 0;

    (void)nid;

    /* Get name type OID from data items. */
    GetASN_OIDData(&dataASN[RDNASN_IDX_ATTR_TYPE], &oid, &oidSz);

    /* v1 name types */
    if ((oidSz == 3) && (oid[0] == 0x55) && (oid[1] == 0x04)) {
        id = oid[2];
        /* Check range of supported ids in table. */
        if (ValidCertNameSubject(id)) {
            /* Get the type string, length and NID from table. */
            typeStr = GetCertNameSubjectStr(id);
            typeStrLen = GetCertNameSubjectStrLen(id);
        #ifdef WOLFSSL_X509_NAME_AVAILABLE
            *nid = GetCertNameSubjectNID(id);
        #endif
        }
    }
    else if (oidSz == sizeof(attrEmailOid) && XMEMCMP(oid, attrEmailOid, oidSz) == 0) {
        /* Set the email id, type string, length and NID. */
        id = ASN_EMAIL;
        typeStr =  WOLFSSL_EMAIL_ADDR;
        typeStrLen = sizeof(WOLFSSL_EMAIL_ADDR) - 1;
    #ifdef WOLFSSL_X509_NAME_AVAILABLE
        *nid = NID_emailAddress;
    #endif
    }
    else if (oidSz == sizeof(uidOid) && XMEMCMP(oid, uidOid, oidSz) == 0) {
        /* Set the user id, type string, length and NID. */
        id = ASN_USER_ID;
        typeStr = WOLFSSL_USER_ID;
        typeStrLen = sizeof(WOLFSSL_USER_ID) - 1;
    #ifdef WOLFSSL_X509_NAME_AVAILABLE
        *nid = NID_userId;
    #endif
    }
    else if (oidSz == sizeof(dcOid) && XMEMCMP(oid, dcOid, oidSz) == 0) {
        /* Set the domain component, type string, length and NID. */
        id = ASN_DC;
        typeStr = WOLFSSL_DOMAIN_COMPONENT;
        typeStrLen = sizeof(WOLFSSL_DOMAIN_COMPONENT) - 1;
    #ifdef WOLFSSL_X509_NAME_AVAILABLE
        *nid = NID_domainComponent;
    #endif
    }
    /* Other OIDs that start with the same values. */
    else if (oidSz == sizeof(dcOid) && XMEMCMP(oid, dcOid, oidSz-1) == 0) {
        WOLFSSL_MSG("Unknown pilot attribute type");
        ret = ASN_PARSE_E;
    }
    else if (oidSz == ASN_JOI_PREFIX_SZ + 1 &&
                         XMEMCMP(oid, ASN_JOI_PREFIX, ASN_JOI_PREFIX_SZ) == 0) {
        /* Set the jurisdiction id. */
        id = 0x200 + oid[ASN_JOI_PREFIX_SZ];

        /* Set the jurisdiction type string, length and NID if known. */
        if (oid[ASN_JOI_PREFIX_SZ] == ASN_JOI_C) {
            typeStr = WOLFSSL_JOI_C;
            typeStrLen = sizeof(WOLFSSL_JOI_C) - 1;
        #ifdef WOLFSSL_X509_NAME_AVAILABLE
            *nid = NID_jurisdictionCountryName;
        #endif /* WOLFSSL_X509_NAME_AVAILABLE */
        }
        else if (oid[ASN_JOI_PREFIX_SZ] == ASN_JOI_ST) {
            typeStr = WOLFSSL_JOI_ST;
            typeStrLen = sizeof(WOLFSSL_JOI_ST) - 1;
        #ifdef WOLFSSL_X509_NAME_AVAILABLE
            *nid = NID_jurisdictionStateOrProvinceName;
        #endif /* WOLFSSL_X509_NAME_AVAILABLE */
        }
        else {
            WOLFSSL_MSG("Unknown Jurisdiction, skipping");
        }
    }

    if ((ret == 0) && (typeStr != NULL)) {
        /* OID type to store for subject name and add to full string. */
        byte*  str;
        word32 strLen;
        byte   tag = dataASN[RDNASN_IDX_ATTR_VAL].tag;

        /* Get the string reference and length. */
        GetASN_GetRef(&dataASN[RDNASN_IDX_ATTR_VAL], &str, &strLen);

        if (isSubject) {
            /* Store subject field components. */
            ret = SetSubject(cert, id, str, strLen, tag);
        }
        if (ret == 0) {
            /* Check there is space for this in the full name string and
             * terminating NUL character. */
            if ((typeStrLen + strLen) < (word32)(WC_ASN_NAME_MAX - *idx))
            {
                /* Add RDN to full string. */
                XMEMCPY(&full[*idx], typeStr, typeStrLen);
                *idx += typeStrLen;
                XMEMCPY(&full[*idx], str, strLen);
                *idx += strLen;
            }
            else {
                WOLFSSL_MSG("ASN Name too big, skipping");
            }
        }
    }

    return ret;
}
#endif /* WOLFSSL_ASN_TEMPLATE */

/* Get a certificate name into the certificate object.
 *
 * @param [in, out] cert      Decoded certificate object.
 * @param [out]     full      Buffer to hold full name as a string.
 * @param [out]     hash      Buffer to hold hash of name.
 * @param [in]      nameType  ISSUER or SUBJECT.
 * @param [in]      input     Buffer holding certificate name.
 * @param [in, out] inOutIdx  On in, start of certificate name.
 *                            On out, start of ASN.1 item after cert name.
 * @param [in]      maxIdx    Index of next item after certificate name.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int GetCertName(DecodedCert* cert, char* full, byte* hash, int nameType,
                       const byte* input, word32* inOutIdx, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    length;  /* length of all distinguished names */
    int    dummy;
    int    ret;
    word32 idx;
    word32 srcIdx = *inOutIdx;

    WOLFSSL_MSG("Getting Cert Name");

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    if (CalcHashId(input + *inOutIdx, maxIdx - *inOutIdx, hash) != 0)
        return ASN_PARSE_E;


    if (GetSequence(input, &srcIdx, &length, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

#if defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT)
    /* store pointer to raw issuer */
    if (nameType == ISSUER) {
        cert->issuerRaw = &input[srcIdx];
        cert->issuerRawLen = length;
    }
#endif
#if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
    if (nameType == SUBJECT) {
        cert->subjectRaw = &input[srcIdx];
        cert->subjectRawLen = length;
    }
#endif

    length += srcIdx;
    idx = 0;

    while (srcIdx < (word32)length) {
        byte        b       = 0;
        byte        joint[3];
        byte        tooBig  = FALSE;
        int         oidSz;
        const char* copy    = NULL;
        int         copyLen = 0;
        int         strLen  = 0;
        byte        id      = 0;

        if (GetSet(input, &srcIdx, &dummy, maxIdx) < 0) {
            WOLFSSL_MSG("Cert name lacks set header, trying sequence");
        }

        if (GetSequence(input, &srcIdx, &dummy, maxIdx) <= 0) {
            return ASN_PARSE_E;
        }

        ret = GetASNObjectId(input, &srcIdx, &oidSz, maxIdx);
        if (ret != 0) {
            return ret;
        }

        /* make sure there is room for joint */
        if ((srcIdx + sizeof(joint)) > (word32)maxIdx) {
            return ASN_PARSE_E;
        }

        XMEMCPY(joint, &input[srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            srcIdx += 3;
            id = joint[2];
            if (GetHeader(input, &b, &srcIdx, &strLen, maxIdx, 1) < 0) {
                return ASN_PARSE_E;
            }

            if (id == ASN_COMMON_NAME) {
                if (nameType == SUBJECT) {
                    cert->subjectCN = (char *)&input[srcIdx];
                    cert->subjectCNLen = strLen;
                    cert->subjectCNEnc = b;
                }
            #if (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)) && \
                defined(WOLFSSL_HAVE_ISSUER_NAMES)
                else if (nameType == ISSUER) {
                    cert->issuerCN = (char*)&input[srcIdx];
                    cert->issuerCNLen = strLen;
                    cert->issuerCNEnc = b;
                }
            #endif

                copy = WOLFSSL_COMMON_NAME;
                copyLen = sizeof(WOLFSSL_COMMON_NAME) - 1;
            }
            else if (id == ASN_SUR_NAME) {
                copy = WOLFSSL_SUR_NAME;
                copyLen = sizeof(WOLFSSL_SUR_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectSN = (char*)&input[srcIdx];
                        cert->subjectSNLen = strLen;
                        cert->subjectSNEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerSN = (char*)&input[srcIdx];
                        cert->issuerSNLen = strLen;
                        cert->issuerSNEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_COUNTRY_NAME) {
                copy = WOLFSSL_COUNTRY_NAME;
                copyLen = sizeof(WOLFSSL_COUNTRY_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectC = (char*)&input[srcIdx];
                        cert->subjectCLen = strLen;
                        cert->subjectCEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerC = (char*)&input[srcIdx];
                        cert->issuerCLen = strLen;
                        cert->issuerCEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_LOCALITY_NAME) {
                copy = WOLFSSL_LOCALITY_NAME;
                copyLen = sizeof(WOLFSSL_LOCALITY_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectL = (char*)&input[srcIdx];
                        cert->subjectLLen = strLen;
                        cert->subjectLEnc = b;
                    }
                    #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerL = (char*)&input[srcIdx];
                        cert->issuerLLen = strLen;
                        cert->issuerLEnc = b;
                    }
                    #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_STATE_NAME) {
                copy = WOLFSSL_STATE_NAME;
                copyLen = sizeof(WOLFSSL_STATE_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectST = (char*)&input[srcIdx];
                        cert->subjectSTLen = strLen;
                        cert->subjectSTEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerST = (char*)&input[srcIdx];
                        cert->issuerSTLen = strLen;
                        cert->issuerSTEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT*/
            }
            else if (id == ASN_ORG_NAME) {
                copy = WOLFSSL_ORG_NAME;
                copyLen = sizeof(WOLFSSL_ORG_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectO = (char*)&input[srcIdx];
                        cert->subjectOLen = strLen;
                        cert->subjectOEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerO = (char*)&input[srcIdx];
                        cert->issuerOLen = strLen;
                        cert->issuerOEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_ORGUNIT_NAME) {
                copy = WOLFSSL_ORGUNIT_NAME;
                copyLen = sizeof(WOLFSSL_ORGUNIT_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectOU = (char*)&input[srcIdx];
                        cert->subjectOULen = strLen;
                        cert->subjectOUEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerOU = (char*)&input[srcIdx];
                        cert->issuerOULen = strLen;
                        cert->issuerOUEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_SERIAL_NUMBER) {
                copy = WOLFSSL_SERIAL_NUMBER;
                copyLen = sizeof(WOLFSSL_SERIAL_NUMBER) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectSND = (char*)&input[srcIdx];
                        cert->subjectSNDLen = strLen;
                        cert->subjectSNDEnc = b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerSND = (char*)&input[srcIdx];
                        cert->issuerSNDLen = strLen;
                        cert->issuerSNDEnc = b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_USER_ID) {
                copy = WOLFSSL_USER_ID;
                copyLen = sizeof(WOLFSSL_USER_ID) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectUID = (char*)&input[srcIdx];
                        cert->subjectUIDLen = strLen;
                        cert->subjectUIDEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
        #ifdef WOLFSSL_CERT_EXT
            else if (id == ASN_STREET_ADDR) {
                copy = WOLFSSL_STREET_ADDR_NAME;
                copyLen = sizeof(WOLFSSL_STREET_ADDR_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectStreet = (char*)&input[srcIdx];
                        cert->subjectStreetLen = strLen;
                        cert->subjectStreetEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_BUS_CAT) {
                copy = WOLFSSL_BUS_CAT;
                copyLen = sizeof(WOLFSSL_BUS_CAT) - 1;
            #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                if (nameType == SUBJECT) {
                    cert->subjectBC = (char*)&input[srcIdx];
                    cert->subjectBCLen = strLen;
                    cert->subjectBCEnc = b;
                }
            #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }
            else if (id == ASN_POSTAL_CODE) {
                copy = WOLFSSL_POSTAL_NAME;
                copyLen = sizeof(WOLFSSL_POSTAL_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectPC = (char*)&input[srcIdx];
                        cert->subjectPCLen = strLen;
                        cert->subjectPCEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT*/
            }
        #endif /* WOLFSSL_CERT_EXT */
        }
    #ifdef WOLFSSL_CERT_EXT
        else if ((srcIdx + ASN_JOI_PREFIX_SZ + 2 <= (word32)maxIdx) &&
                 (0 == XMEMCMP(&input[srcIdx], ASN_JOI_PREFIX,
                               ASN_JOI_PREFIX_SZ)) &&
                 ((input[srcIdx+ASN_JOI_PREFIX_SZ] == ASN_JOI_C) ||
                  (input[srcIdx+ASN_JOI_PREFIX_SZ] == ASN_JOI_ST)))
        {
            srcIdx += ASN_JOI_PREFIX_SZ;
            id = input[srcIdx++];
            b = input[srcIdx++]; /* encoding */

            if (GetLength(input, &srcIdx, &strLen,
                          maxIdx) < 0) {
                return ASN_PARSE_E;
            }

            /* Check for jurisdiction of incorporation country name */
            if (id == ASN_JOI_C) {
                copy = WOLFSSL_JOI_C;
                copyLen = sizeof(WOLFSSL_JOI_C) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectJC = (char*)&input[srcIdx];
                        cert->subjectJCLen = strLen;
                        cert->subjectJCEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }

            /* Check for jurisdiction of incorporation state name */
            else if (id == ASN_JOI_ST) {
                copy = WOLFSSL_JOI_ST;
                copyLen = sizeof(WOLFSSL_JOI_ST) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectJS = (char*)&input[srcIdx];
                        cert->subjectJSLen = strLen;
                        cert->subjectJSEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            }

            if ((strLen + copyLen) > (int)(WC_ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN Name too big, skipping");
                tooBig = TRUE;
            }
        }
    #endif /* WOLFSSL_CERT_EXT */
        else {
            /* skip */
            byte email = FALSE;
            byte pilot = FALSE;

            if (joint[0] == 0x2a && joint[1] == 0x86) {  /* email id hdr 42.134.* */
                id = ASN_EMAIL_NAME;
                email = TRUE;
            }

            if (joint[0] == 0x9  && joint[1] == 0x92) { /* uid id hdr 9.146.* */
                /* last value of OID is the type of pilot attribute */
                id    = input[srcIdx + oidSz - 1];
                if (id == 0x01)
                    id = ASN_USER_ID;
                pilot = TRUE;
            }

            srcIdx += oidSz + 1;

            if (GetLength(input, &srcIdx, &strLen, maxIdx) < 0) {
                return ASN_PARSE_E;
            }

            if (strLen > (int)(WC_ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN name too big, skipping");
                tooBig = TRUE;
            }

            if (email) {
                copyLen = sizeof(WOLFSSL_EMAIL_ADDR) - 1;
                if ((copyLen + strLen) > (int)(WC_ASN_NAME_MAX - idx)) {
                    WOLFSSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                else {
                    copy = WOLFSSL_EMAIL_ADDR;
                }

                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == SUBJECT) {
                        cert->subjectEmail = (char*)&input[srcIdx];
                        cert->subjectEmailLen = strLen;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ISSUER) {
                        cert->issuerEmail = (char*)&input[srcIdx];
                        cert->issuerEmailLen = strLen;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #ifndef IGNORE_NAME_CONSTRAINTS
                    {
                        DNS_entry* emailName;

                        emailName = AltNameNew(cert->heap);
                        if (emailName == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            return MEMORY_E;
                        }
                        emailName->type = 0;
                        emailName->name = (char*)XMALLOC(strLen + 1,
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName->name == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            XFREE(emailName, cert->heap, DYNAMIC_TYPE_ALTNAME);
                            return MEMORY_E;
                        }
                        emailName->len = strLen;
                        XMEMCPY(emailName->name, &input[srcIdx], strLen);
                        emailName->name[strLen] = '\0';

                        emailName->next = cert->altEmailNames;
                        cert->altEmailNames = emailName;
                    }
                #endif /* IGNORE_NAME_CONSTRAINTS */
            }

            if (pilot) {
                switch (id) {
                    case ASN_USER_ID:
                        copy = WOLFSSL_USER_ID;
                        copyLen = sizeof(WOLFSSL_USER_ID) - 1;
                        break;

                    case ASN_DOMAIN_COMPONENT:
                        copy = WOLFSSL_DOMAIN_COMPONENT;
                        copyLen = sizeof(WOLFSSL_DOMAIN_COMPONENT) - 1;
                        break;
                    case ASN_FAVOURITE_DRINK:
                        copy = WOLFSSL_FAVOURITE_DRINK;
                        copyLen = sizeof(WOLFSSL_FAVOURITE_DRINK) - 1;
                        break;

                    default:
                        WOLFSSL_MSG("Unknown pilot attribute type");
                        return ASN_PARSE_E;
                }
            }
        }
        if ((copyLen + strLen) > (int)(WC_ASN_NAME_MAX - idx))
        {
            WOLFSSL_MSG("ASN Name too big, skipping");
            tooBig = TRUE;
        }
        if ((copy != NULL) && !tooBig) {
            XMEMCPY(&full[idx], copy, copyLen);
            idx += copyLen;
            XMEMCPY(&full[idx], &input[srcIdx], strLen);
            idx += strLen;
        }
        srcIdx += strLen;
    }
    full[idx++] = 0;


    *inOutIdx = srcIdx;

    return 0;
#else
    DECL_ASNGETDATA(dataASN, rdnASN_Length);
    int    ret = 0;
    word32 idx = 0;
    int    len;
    word32 srcIdx = *inOutIdx;
#ifdef WOLFSSL_X509_NAME_AVAILABLE
    WOLFSSL_X509_NAME* dName = NULL;
#endif /* WOLFSSL_X509_NAME_AVAILABLE */

    WOLFSSL_MSG("Getting Cert Name");

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    if (CalcHashId(input + srcIdx, maxIdx - srcIdx, hash) != 0) {
        ret = ASN_PARSE_E;
    }

    CALLOC_ASNGETDATA(dataASN, rdnASN_Length, ret, cert->heap);

#ifdef WOLFSSL_X509_NAME_AVAILABLE
    if (ret == 0) {
        /* Create an X509_NAME to hold data for OpenSSL compatability APIs. */
        dName = wolfSSL_X509_NAME_new();
        if (dName == NULL) {
            ret = MEMORY_E;
        }
    }
#endif /* WOLFSSL_X509_NAME_AVAILABLE */

    if (ret == 0) {
        /* Expecting a SEQUENCE using up all data. */
        ret = GetASN_Sequence(input, &srcIdx, &len, maxIdx, 1);
    }
    if (ret == 0) {
    #if defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT)
        /* Store pointer and length to raw issuer. */
        if (nameType == ISSUER) {
            cert->issuerRaw = &input[srcIdx];
            cert->issuerRawLen = len;
        }
    #endif
    #if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
        /* Store pointer and length to raw subject. */
        if (nameType == SUBJECT) {
            cert->subjectRaw = &input[srcIdx];
            cert->subjectRawLen = len;
        }
    #endif

        /* Process all RDNs in name. */
        while ((ret == 0) && (srcIdx < maxIdx)) {
            int nid = 0;

            /* Initialize for data and setup RDN choice. */
            GetASN_Choice(&dataASN[RDNASN_IDX_ATTR_VAL], rdnChoice);
            /* Ignore type OID as too many to store in table. */
            GetASN_OID(&dataASN[RDNASN_IDX_ATTR_TYPE], oidIgnoreType);
            /* Parse RDN. */
            ret = GetASN_Items(rdnASN, dataASN, rdnASN_Length, 1, input,
                               &srcIdx, maxIdx);
            if (ret == 0) {
                /* Put RDN data into certificate. */
                ret = GetRDN(cert, full, &idx, &nid, nameType == SUBJECT,
                             dataASN);
            }
        #ifdef WOLFSSL_X509_NAME_AVAILABLE
            /* TODO: push this back up to ssl.c
             * (do parsing for WOLFSSL_X509_NAME on demand) */
            if (ret == 0) {
                int enc;
                byte*  str;
                word32 strLen;
                byte   tag = dataASN[RDNASN_IDX_ATTR_VAL].tag;

                /* Get string reference. */
                GetASN_GetRef(&dataASN[RDNASN_IDX_ATTR_VAL], &str, &strLen);

                /* Convert BER tag to a OpenSSL type. */
                switch (tag) {
                    case CTC_UTF8:
                        enc = MBSTRING_UTF8;
                        break;
                    case CTC_PRINTABLE:
                        enc = V_ASN1_PRINTABLESTRING;
                        break;
                    default:
                        WOLFSSL_MSG("Unknown encoding type, default UTF8");
                        enc = MBSTRING_UTF8;
                }
                if (nid != 0) {
                    /* Add an entry to the X509_NAME. */
                    if (wolfSSL_X509_NAME_add_entry_by_NID(dName, nid, enc, str,
                            strLen, -1, -1) != WOLFSSL_SUCCESS) {
                        ret = ASN_PARSE_E;
                    }
                }
            }
        #endif
        }
    }
    if (ret == 0) {
        /* Terminate string. */
        full[idx] = 0;
        /* Return index into encoding after name. */
        *inOutIdx = srcIdx;

#ifdef WOLFSSL_X509_NAME_AVAILABLE
        /* Store X509_NAME in certificate. */
        if (nameType == ISSUER) {
        #if ( defined(WOLFSSL_NGINX) ||  defined(HAVE_LIGHTY)) &&  (defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT))
            dName->rawLen = min(cert->issuerRawLen, WC_ASN_NAME_MAX);
            XMEMCPY(dName->raw, cert->issuerRaw, dName->rawLen);
        #endif
            cert->issuerName = dName;
        }
        else {
        #if defined(WOLFSSL_NGINX)
            dName->rawLen = min(cert->subjectRawLen, WC_ASN_NAME_MAX);
            XMEMCPY(dName->raw, cert->subjectRaw, dName->rawLen);
        #endif
            cert->subjectName = dName;
        }
    }
    else {
        /* Dispose of unused X509_NAME. */
        wolfSSL_X509_NAME_free(dName);
#endif
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for certificate name. */
static const ASNItem certNameASN[] = {
/* OID  */ { 0, ASN_OBJECT_ID, 0, 0, 1 },
/* NAME */ { 0, ASN_SEQUENCE, 1, 0, 0 },
};
enum {
    CERTNAMEASN_IDX_OID = 0,
    CERTNAMEASN_IDX_NAME,
};

/* Number of items in ASN.1 template for certificate name. */
#define certNameASN_Length (sizeof(certNameASN) / sizeof(ASNItem))
#endif

/* Get a certificate name into the certificate object.
 *
 * Either the issuer or subject name.
 *
 * @param [in, out] cert      Decoded certificate object.
 * @param [in]      nameType  Type of name being decoded: ISSUER or SUBJECT.
 * @param [in]      maxIdx    Index of next item after certificate name.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int GetName(DecodedCert* cert, int nameType, int maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    char*  full;
    byte*  hash;
    int    length;
    word32 localIdx;
    byte   tag;

    WOLFSSL_MSG("Getting Cert Name");

    if (nameType == ISSUER) {
        full = cert->issuer;
        hash = cert->issuerHash;
    }
    else {
        full = cert->subject;
        hash = cert->subjectHash;
    }

    if (cert->srcIdx >= (word32)maxIdx) {
        return BUFFER_E;
    }

    localIdx = cert->srcIdx;
    if (GetASNTag(cert->source, &localIdx, &tag, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    if (tag == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (SkipObjectId(cert->source, &cert->srcIdx, maxIdx) < 0)
            return ASN_PARSE_E;
        WOLFSSL_MSG("Got optional prefix");
    }

    localIdx = cert->srcIdx;
    if (GetASNTag(cert->source, &localIdx, &tag, maxIdx) < 0) {
        return ASN_PARSE_E;
    }
    localIdx = cert->srcIdx + 1;
    if (GetLength(cert->source, &localIdx, &length, maxIdx) < 0) {
        return ASN_PARSE_E;
    }
    length += localIdx - cert->srcIdx;

    return GetCertName(cert, full, hash, nameType, cert->source, &cert->srcIdx,
                       cert->srcIdx + length);
#else
    ASNGetData dataASN[certNameASN_Length];
    word32 idx = cert->srcIdx;
    int    ret = 0;
    char*  full;
    byte*  hash;

    WOLFSSL_MSG("Getting Cert Name");

    XMEMSET(dataASN, 0, sizeof(dataASN));
    /* Initialize for data and don't check optional prefix OID. */
    GetASN_OID(&dataASN[CERTNAMEASN_IDX_OID], oidIgnoreType);
    ret = GetASN_Items(certNameASN, dataASN, certNameASN_Length, 0,
                       cert->source, &idx, maxIdx);
    if (ret == 0) {
        /* Store offset of SEQUENCE that is start of name. */
        cert->srcIdx = dataASN[CERTNAMEASN_IDX_NAME].offset;

        /* Get fields to fill in based on name type. */
        if (nameType == ISSUER) {
            full = cert->issuer;
            hash = cert->issuerHash;
        }
        else {
            full = cert->subject;
            hash = cert->subjectHash;
        }

        /* Parse certificate name. */
        ret = GetCertName(cert, full, hash, nameType, cert->source,
                          &cert->srcIdx, idx);
    }

    return ret;
#endif
}

#ifndef NO_ASN_TIME

/* two byte date/time, add to value */
static WC_INLINE int GetTime(int* value, const byte* date, int* idx)
{
    int i = *idx;

    if (date[i] < 0x30 || date[i] > 0x39 || date[i+1] < 0x30 ||
                                                             date[i+1] > 0x39) {
        return ASN_PARSE_E;
    }

    *value += btoi(date[i++]) * 10;
    *value += btoi(date[i++]);

    *idx = i;

    return 0;
}


int ExtractDate(const unsigned char* date, unsigned char format,
                                                  struct tm* certTime, int* idx)
{
    XMEMSET(certTime, 0, sizeof(struct tm));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[*idx]) >= 5)
            certTime->tm_year = 1900;
        else
            certTime->tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        if (GetTime(&certTime->tm_year, date, idx) != 0) return 0;
        certTime->tm_year *= 100;
    }

#ifdef AVR
    /* Extract the time from the struct tm and adjust tm_year, tm_mon */
    /* AVR libc stores these as uint8_t instead of int */
    /* AVR time_t also offsets from midnight 1 Jan 2000 */
    int tm_year = certTime->tm_year - 2000;
    int tm_mon  = certTime->tm_mon - 1;
    int tm_mday = certTime->tm_mday;
    int tm_hour = certTime->tm_hour;
    int tm_min  = certTime->tm_min;
    int tm_sec  = certTime->tm_sec;

    if (GetTime(&tm_year, date, idx) != 0) return 0;
    if (GetTime(&tm_mon , date, idx) != 0) return 0;
    if (GetTime(&tm_mday, date, idx) != 0) return 0;
    if (GetTime(&tm_hour, date, idx) != 0) return 0;
    if (GetTime(&tm_min , date, idx) != 0) return 0;
    if (GetTime(&tm_sec , date, idx) != 0) return 0;

    /* Re-populate certTime with computed values */
    certTime->tm_year = tm_year;
    certTime->tm_mon  = tm_mon;
    certTime->tm_mday = tm_mday;
    certTime->tm_hour = tm_hour;
    certTime->tm_min  = tm_min;
    certTime->tm_sec  = tm_sec;
#else
    /* adjust tm_year, tm_mon */
    if (GetTime(&certTime->tm_year, date, idx) != 0) return 0;
    certTime->tm_year -= 1900;
    if (GetTime(&certTime->tm_mon , date, idx) != 0) return 0;
    certTime->tm_mon  -= 1;
    if (GetTime(&certTime->tm_mday, date, idx) != 0) return 0;
    if (GetTime(&certTime->tm_hour, date, idx) != 0) return 0;
    if (GetTime(&certTime->tm_min , date, idx) != 0) return 0;
    if (GetTime(&certTime->tm_sec , date, idx) != 0) return 0;
#endif

    return 1;
}


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
int GetTimeString(byte* date, int format, char* buf, int len)
{
    struct tm t;
    int idx = 0;

    if (!ExtractDate(date, (unsigned char)format, &t, &idx)) {
        return 0;
    }

    if (date[idx] != 'Z') {
        WOLFSSL_MSG("UTCtime, not Zulu") ;
        return 0;
    }

    /* place month in buffer */
    buf[0] = '\0';
    switch(t.tm_mon) {
        case 0:  XSTRNCAT(buf, "Jan ", 5); break;
        case 1:  XSTRNCAT(buf, "Feb ", 5); break;
        case 2:  XSTRNCAT(buf, "Mar ", 5); break;
        case 3:  XSTRNCAT(buf, "Apr ", 5); break;
        case 4:  XSTRNCAT(buf, "May ", 5); break;
        case 5:  XSTRNCAT(buf, "Jun ", 5); break;
        case 6:  XSTRNCAT(buf, "Jul ", 5); break;
        case 7:  XSTRNCAT(buf, "Aug ", 5); break;
        case 8:  XSTRNCAT(buf, "Sep ", 5); break;
        case 9:  XSTRNCAT(buf, "Oct ", 5); break;
        case 10: XSTRNCAT(buf, "Nov ", 5); break;
        case 11: XSTRNCAT(buf, "Dec ", 5); break;
        default:
            return 0;

    }
    idx = 4; /* use idx now for char buffer */

    XSNPRINTF(buf + idx, len - idx, "%2d %02d:%02d:%02d %d GMT",
              t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, (int)t.tm_year + 1900);

    return 1;
}
#endif /* OPENSSL_ALL || WOLFSSL_MYSQL_COMPATIBLE || WOLFSSL_NGINX || WOLFSSL_HAPROXY */


#if !defined(NO_ASN_TIME) && !defined(USER_TIME) &&  !defined(TIME_OVERRIDES) && defined(HAVE_PKCS7)
/* Set current time string, either UTC or GeneralizedTime.
 * (void*) tm should be a pointer to time_t, output is placed in buf.
 *
 * Return time string length placed in buf on success, negative on error */
int GetAsnTimeString(void* currTime, byte* buf, word32 len)
{
    byte* data_ptr  = buf;
    byte  uf_time[ASN_GENERALIZED_TIME_SIZE];
    word32 data_len = 0;

    WOLFSSL_ENTER("GetAsnTimeString");

    if (buf == NULL || len == 0)
        return BAD_FUNC_ARG;

    XMEMSET(uf_time, 0, sizeof(uf_time));
    /* GetFormattedTime returns length with null terminator */
    data_len = GetFormattedTime(currTime, uf_time, len);
    if (data_len <= 0) {
        return ASN_TIME_E;
    }
    /* ensure room to add 2 bytes (ASN type and length) before proceeding */
    else if (len < data_len + 2) {
        return BUFFER_E;
    }

    if (data_len == ASN_UTC_TIME_SIZE-1) {
        /* increment data_len for ASN length byte after adding the data_ptr */
        *data_ptr = (byte)ASN_UTC_TIME; data_ptr++; data_len++;
        /* -1 below excludes null terminator */
        *data_ptr = (byte)ASN_UTC_TIME_SIZE - 1; data_ptr++; data_len++;
        XMEMCPY(data_ptr, (byte *)uf_time, ASN_UTC_TIME_SIZE - 1);
        *data_ptr += ASN_UTC_TIME_SIZE - 1;
    }
    else if (data_len == ASN_GENERALIZED_TIME_SIZE-1) {
        /* increment data_len for ASN length byte after adding the data_ptr */
        *data_ptr = (byte)ASN_GENERALIZED_TIME; data_ptr++; data_len++;
        /* -1 below excludes null terminator */
        *data_ptr = (byte)ASN_GENERALIZED_TIME_SIZE - 1; data_ptr++; data_len++;
        XMEMCPY(data_ptr, (byte*)uf_time, ASN_GENERALIZED_TIME_SIZE - 1);
        *data_ptr += ASN_GENERALIZED_TIME_SIZE - 1;
    }
    else {
        WOLFSSL_MSG("Invalid time size returned");
        return ASN_TIME_E;
    }
    /* append null terminator */
    *data_ptr = 0;

    /* return length without null terminator */
    return data_len;
}

/* return just the time string as either UTC or Generalized Time*/
int GetFormattedTime(void* currTime, byte* buf, word32 len)
{
    struct tm* ts      = NULL;
    struct tm* tmpTime = NULL;
    int year, mon, day, hour, mini, sec;
    int ret;
#if defined(NEED_TMP_TIME)
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    (void)tmpTime;
#endif

    WOLFSSL_ENTER("GetFormattedTime");

    if (buf == NULL || len == 0)
        return BAD_FUNC_ARG;

    ts = (struct tm *)XGMTIME((time_t*)currTime, tmpTime);
    if (ts == NULL) {
        WOLFSSL_MSG("failed to get time data.");
        return ASN_TIME_E;
    }

    /* Note ASN_UTC_TIME_SIZE and ASN_GENERALIZED_TIME_SIZE include space for
     * the null terminator. ASN encoded values leave off the terminator. */

    if (ts->tm_year >= 50 && ts->tm_year < 150) {
        /* UTC Time */
        if (ts->tm_year >= 50 && ts->tm_year < 100) {
            year = ts->tm_year;
        }
        else if (ts->tm_year >= 100 && ts->tm_year < 150) {
            year = ts->tm_year - 100;
        }
        else {
            WOLFSSL_MSG("unsupported year range");
            return BAD_FUNC_ARG;
        }
        mon  = ts->tm_mon + 1;
        day  = ts->tm_mday;
        hour = ts->tm_hour;
        mini = ts->tm_min;
        sec  = ts->tm_sec;
        ret = XSNPRINTF((char*)buf, len,
                        "%02d%02d%02d%02d%02d%02dZ", year, mon, day,
                        hour, mini, sec);
    }
    else {
        /* GeneralizedTime */
        year = ts->tm_year + 1900;
        mon  = ts->tm_mon + 1;
        day  = ts->tm_mday;
        hour = ts->tm_hour;
        mini = ts->tm_min;
        sec  = ts->tm_sec;
        ret = XSNPRINTF((char*)buf, len,
                        "%4d%02d%02d%02d%02d%02dZ", year, mon, day,
                        hour, mini, sec);
    }

    return ret;
}

#endif /* !NO_ASN_TIME && !USER_TIME && !TIME_OVERRIDES &&
        * (OPENSSL_EXTRA || HAVE_PKCS7) */

#if defined(USE_WOLF_VALIDDATE)

/* to the second */
int DateGreaterThan(const struct tm* a, const struct tm* b)
{
    if (a->tm_year > b->tm_year)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
           a->tm_mday > b->tm_mday)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min > b->tm_min)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min  == b->tm_min  && a->tm_sec > b->tm_sec)
        return 1;

    return 0; /* false */
}


static WC_INLINE int DateLessThan(const struct tm* a, const struct tm* b)
{
    return DateGreaterThan(b,a);
}

/* like atoi but only use first byte */
/* Make sure before and after dates are valid */
int wc_ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime;
    struct tm  certTime;
    struct tm* localTime;
    struct tm* tmpTime;
    int    i = 0;
    int    timeDiff = 0 ;
    int    diffHH = 0 ; int diffMM = 0 ;
    int    diffSign = 0 ;

#if defined(NEED_TMP_TIME)
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    tmpTime = NULL;
#endif
    (void)tmpTime;

    ltime = wc_Time(0);

#ifdef WOLFSSL_BEFORE_DATE_CLOCK_SKEW
    if (dateType == BEFORE) {
        WOLFSSL_MSG("Skewing local time for before date check");
        ltime += WOLFSSL_BEFORE_DATE_CLOCK_SKEW;
    }
#endif

#ifdef WOLFSSL_AFTER_DATE_CLOCK_SKEW
    if (dateType == AFTER) {
        WOLFSSL_MSG("Skewing local time for after date check");
        ltime -= WOLFSSL_AFTER_DATE_CLOCK_SKEW;
    }
#endif

    if (!ExtractDate(date, format, &certTime, &i)) {
        WOLFSSL_MSG("Error extracting the date");
        return 0;
    }

    if ((date[i] == '+') || (date[i] == '-')) {
        WOLFSSL_MSG("Using time differential, not Zulu") ;
        diffSign = date[i++] == '+' ? 1 : -1 ;
        if (GetTime(&diffHH, date, &i) != 0)
            return 0;
        if (GetTime(&diffMM, date, &i) != 0)
            return 0;
        timeDiff = diffSign * (diffHH*60 + diffMM) * 60 ;
    } else if (date[i] != 'Z') {
        WOLFSSL_MSG("UTCtime, neither Zulu or time differential") ;
        return 0;
    }

    ltime -= (time_t)timeDiff ;
    localTime = XGMTIME(&ltime, tmpTime);

    if (localTime == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;
    }

    if (dateType == BEFORE) {
        if (DateLessThan(localTime, &certTime)) {
            WOLFSSL_MSG("Date BEFORE check failed");
            return 0;
        }
    }
    else {  /* dateType == AFTER */
        if (DateGreaterThan(localTime, &certTime)) {
            WOLFSSL_MSG("Date AFTER check failed");
            return 0;
        }
    }

    return 1;
}
#endif /* USE_WOLF_VALIDDATE */

int wc_GetTime(void* timePtr, word32 timeSize)
{
    time_t* ltime = (time_t*)timePtr;

    if (timePtr == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((word32)sizeof(time_t) > timeSize) {
        return BUFFER_E;
    }

    *ltime = wc_Time(0);

    return 0;
}

#ifdef TIME_OVERRIDES
    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t* t);
#endif

static wc_time_cb timeFunc = NULL;

int wc_SetTimeCb(wc_time_cb f)
{
    timeFunc = f;
    return 0;
}

time_t wc_Time(time_t* t)
{
    if (timeFunc != NULL) {
        return timeFunc(t);
    }
    return XTIME(t);
}

#endif /* !NO_ASN_TIME */


#ifdef WOLFSSL_ASN_TEMPLATE
/* TODO: use a CHOICE instead of two items? */
/* ASN.1 template for a date - either UTC or Generalized Time. */
static const ASNItem dateASN[] = {
/* UTC */ { 0, ASN_UTC_TIME, 0, 0, 2 },
/* GT  */ { 0, ASN_GENERALIZED_TIME, 0, 0, 2 },
};
enum {
    DATEASN_IDX_UTC = 0,
    DATEASN_IDX_GT,
};

/* Number of items in ASN.1 template for a date. */
#define dateASN_Length (sizeof(dateASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */

/* Get date buffer, format and length. Returns 0=success or error */
/* Decode a DateInfo - choice of UTC TIME or GENERALIZED TIME.
 *
 * @param [in]      source   Buffer containing encoded date.
 * @param [in, out] idx      On in, the index of the date.
 *                           On out, index after date.
 * @param [out]     pDate    Pointer into buffer of data bytes.
 * @param [out]     pFormat  Format of date - BER/DER tag.
 * @param [out]     pLength  Length of date bytes.
 * @param [in]      maxIdx   Index of next item after date.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when source or idx is NULL.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 */
static int GetDateInfo(const byte* source, word32* idx, const byte** pDate,
                        byte* pFormat, int* pLength, word32 maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int length;
    byte format;

    if (source == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    /* get ASN format header */
    if (*idx+1 > maxIdx)
        return BUFFER_E;
    format = source[*idx];
    *idx += 1;
    if (format != ASN_UTC_TIME && format != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    /* get length */
    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    /* return format, date and length */
    if (pFormat)
        *pFormat = format;
    if (pDate)
        *pDate = &source[*idx];
    if (pLength)
        *pLength = length;

    *idx += length;

    return 0;
#else
    ASNGetData dataASN[dateASN_Length];
    int i;
    int ret = 0;

    if ((source == NULL) || (idx == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Initialize data. */
        XMEMSET(dataASN, 0, sizeof(dataASN));
        /* Parse date. */
        ret = GetASN_Items(dateASN, dataASN, dateASN_Length, 0, source, idx,
                           maxIdx);
    }
    if (ret == 0) {
        /* Determine which tag was seen. */
        i = (dataASN[DATEASN_IDX_UTC].tag != 0) ? DATEASN_IDX_UTC
                                                : DATEASN_IDX_GT;
        /* Return data from seen item. */
        if (pFormat != NULL) {
            *pFormat = dataASN[i].tag;
        }
        if (pDate != NULL) {
            *pDate = dataASN[i].data.ref.data;
        }
        if (pLength != NULL) {
            *pLength = dataASN[i].data.ref.length;
        }
    }

    return ret;
#endif
}

#ifndef WOLFSSL_ASN_TEMPLATE
static int GetDate(DecodedCert* cert, int dateType, int verify, int maxIdx)
{
    int    ret, length;
    const byte *datePtr = NULL;
    byte   date[MAX_DATE_SIZE];
    byte   format;
    word32 startIdx = 0;

    if (dateType == BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    ret = GetDateInfo(cert->source, &cert->srcIdx, &datePtr, &format,
                      &length, maxIdx);
    if (ret < 0)
        return ret;

    XMEMSET(date, 0, MAX_DATE_SIZE);
    XMEMCPY(date, datePtr, length);

    if (dateType == BEFORE)
        cert->beforeDateLen = cert->srcIdx - startIdx;
    else
        cert->afterDateLen  = cert->srcIdx - startIdx;

#ifndef NO_ASN_TIME
    if (verify != NO_VERIFY && verify != VERIFY_SKIP_DATE &&
            !XVALIDATE_DATE(date, format, dateType)) {
        if (dateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }
#else
    (void)verify;
#endif

    return 0;
}

static int GetValidity(DecodedCert* cert, int verify, int maxIdx)
{
    int length;
    int badDate = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    maxIdx = cert->srcIdx + length;

    if (GetDate(cert, BEFORE, verify, maxIdx) < 0)
        badDate = ASN_BEFORE_DATE_E; /* continue parsing */

    if (GetDate(cert, AFTER, verify, maxIdx) < 0)
        return ASN_AFTER_DATE_E;

    if (badDate != 0)
        return badDate;

    return 0;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */


int wc_GetDateInfo(const byte* certDate, int certDateSz, const byte** date,
    byte* format, int* length)
{
    int ret;
    word32 idx = 0;

    ret = GetDateInfo(certDate, &idx, date, format, length, certDateSz);

    return ret;
}

#ifndef NO_ASN_TIME
int wc_GetDateAsCalendarTime(const byte* date, int length, byte format,
    struct tm* timearg)
{
    int idx = 0;
    (void)length;
    if (!ExtractDate(date, format, timearg, &idx))
        return ASN_TIME_E;
    return 0;
}

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES)
int wc_GetCertDates(Cert* cert, struct tm* before, struct tm* after)
{
    int ret = 0;
    const byte* date;
    byte format;
    int length;

    if (cert == NULL)
        return BAD_FUNC_ARG;

    if (before && cert->beforeDateSz > 0) {
        ret = wc_GetDateInfo(cert->beforeDate, cert->beforeDateSz, &date,
                             &format, &length);
        if (ret == 0)
            ret = wc_GetDateAsCalendarTime(date, length, format, before);
    }
    if (after && cert->afterDateSz > 0) {
        ret = wc_GetDateInfo(cert->afterDate, cert->afterDateSz, &date,
                             &format, &length);
        if (ret == 0)
            ret = wc_GetDateAsCalendarTime(date, length, format, after);
    }

    return ret;
}
#endif /* WOLFSSL_CERT_GEN && WOLFSSL_ALT_NAMES */
#endif /* !NO_ASN_TIME */

#ifdef WOLFSSL_ASN_TEMPLATE
/* TODO: move code around to not require this. */
static int DecodeCertInternal(DecodedCert* cert, int verify, int* criticalExt,
                              int* badDateRet, int stopAtPubKey,
                              int stopAfterPubKey);
#endif

/* Parse the certificate up to the X.509 public key.
 *
 * If cert data is invalid then badDate get set to error value.
 *
 * @param [in, out] cert     Decoded certificate object.
 * @param [in]      verify   Whether to verify dates.
 * @param [out]     badDate  Error code when verify dates.
 * @return  0 on success.
 * @return  ASN_TIME_E when date BER tag is nor UTC or GENERALIZED time.
 * @return  ASN_DATE_SZ_E when time data is not supported.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set.
 */
int wc_GetPubX509(DecodedCert* cert, int verify, int* badDate)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;

    if (cert == NULL || badDate == NULL)
        return BAD_FUNC_ARG;

    *badDate = 0;
    if ( (ret = GetCertHeader(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Cert Header");

#ifdef WOLFSSL_CERT_REQ
    if (!cert->isCSR) {
#endif
        /* Using the sigIndex as the upper bound because that's where the
         * actual certificate data ends. */
        if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID,
                              oidSigType, cert->sigIndex)) < 0)
            return ret;

        WOLFSSL_MSG("Got Algo ID");

        if ( (ret = GetName(cert, ISSUER, cert->sigIndex)) < 0)
            return ret;

        if ( (ret = GetValidity(cert, verify, cert->sigIndex)) < 0)
            *badDate = ret;
#ifdef WOLFSSL_CERT_REQ
    }
#endif

    if ( (ret = GetName(cert, SUBJECT, cert->sigIndex)) < 0)
        return ret;

    WOLFSSL_MSG("Got Subject Name");
    return ret;
#else
    /* Use common decode routine and stop at public key. */
    int ret;

    *badDate = 0;

    ret = DecodeCertInternal(cert, verify, NULL, badDate, 1, 0);
    if (ret >= 0) {
        /* Store current index: public key. */
        cert->srcIdx = ret;
    }
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

/* Parse the certificate up to and including X.509 public key.
 *
 * @param [in, out] cert     Decoded certificate object.
 * @param [in]      verify   Whether to verify dates.
 * @return  0 on success.
 * @return  ASN_TIME_E when date BER tag is nor UTC or GENERALIZED time.
 * @return  ASN_DATE_SZ_E when time data is not supported.
 * @return  ASN_BEFORE_DATE_E when BEFORE date is invalid.
 * @return  ASN_AFTER_DATE_E when AFTER date is invalid.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set.
 */
int DecodeToKey(DecodedCert* cert, int verify)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int badDate = 0;
    int ret;

    if ( (ret = wc_GetPubX509(cert, verify, &badDate)) < 0)
        return ret;

    /* Determine if self signed */
    cert->selfSigned = XMEMCMP(cert->issuerHash,
                               cert->subjectHash,
                               KEYID_SIZE) == 0 ? 1 : 0;

    ret = GetCertKey(cert, cert->source, &cert->srcIdx, cert->maxIdx);
    if (ret != 0)
        return ret;

    WOLFSSL_MSG("Got Key");

    if (badDate != 0)
        return badDate;

    return ret;
#else
    int ret;
    int badDate = 0;

    /* Call internal version and stop after public key. */
    ret = DecodeCertInternal(cert, verify, NULL, &badDate, 0, 1);
    /* Always return date errors. */
    if (ret == 0) {
        ret = badDate;
    }
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#if !defined(WOLFSSL_ASN_TEMPLATE)
static int GetSignature(DecodedCert* cert)
{
    int length;
    int ret;

    ret = CheckBitString(cert->source, &cert->srcIdx, &length, cert->maxIdx, 1,
                         NULL);
    if (ret != 0)
        return ret;

    cert->sigLength = length;
    cert->signature = &cert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    if (cert->srcIdx != cert->maxIdx)
        return ASN_PARSE_E;

    return 0;
}
#endif /* !NO_CERTS && !WOLFSSL_ASN_TEMPLATE */

#ifndef WOLFSSL_ASN_TEMPLATE
static word32 SetOctetString8Bit(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)len;
    return 2;
}
static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    word32 idx = SetOctetString8Bit(digSz, output);
    XMEMCPY(&output[idx], digest, digSz);

    return idx + digSz;
}
#endif


/* Encode a length for DER.
 *
 * @param [in]  length  Value to encode.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetLength(word32 length, byte* output)
{
    /* Start encoding at start of buffer. */
    word32 i = 0;

    if (length < ASN_LONG_LENGTH) {
        /* Only one byte needed to encode. */
        if (output) {
            /* Write out length value. */
            output[i] = (byte)length;
        }
        /* Skip over length. */
        i++;
    }
    else {
        /* Calculate the number of bytes required to encode value. */
        byte j = (byte)BytePrecision(length);

        if (output) {
            /* Encode count byte. */
            output[i] = j | ASN_LONG_LENGTH;
        }
        /* Skip over count byte. */
        i++;

        /* Encode value as a big-endian byte array. */
        for (; j > 0; --j) {
            if (output) {
                /* Encode next most-significant byte. */
                output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            }
            /* Skip over byte. */
            i++;
        }
    }

    /* Return number of bytes in encoded length. */
    return i;
}

/* Encode a DER header - type/tag and length.
 *
 * @param [in]  tag     DER tag of ASN.1 item.
 * @param [in]  len     Length of data in ASN.1 item.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
static word32 SetHeader(byte tag, word32 len, byte* output)
{
    if (output) {
        /* Encode tag first. */
        output[0] = tag;
    }
    /* Encode the length. */
    return SetLength(len, output ? output + ASN_TAG_SZ : NULL) + ASN_TAG_SZ;
}

/* Encode a SEQUENCE header in DER.
 *
 * @param [in]  len     Length of data in SEQUENCE.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetSequence(word32 len, byte* output)
{
    return SetHeader(ASN_SEQUENCE | ASN_CONSTRUCTED, len, output);
}

/* Encode an OCTET STRING header in DER.
 *
 * @param [in]  len     Length of data in OCTET STRING.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetOctetString(word32 len, byte* output)
{
    return SetHeader(ASN_OCTET_STRING, len, output);
}

/* Encode a SET header in DER.
 *
 * @param [in]  len     Length of data in SET.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetSet(word32 len, byte* output)
{
    return SetHeader(ASN_SET | ASN_CONSTRUCTED, len, output);
}

/* Encode an implicit context specific header in DER.
 *
 * Implicit means that it is constructed only if the included ASN.1 item is.
 *
 * @param [in]  tag     Tag for the implicit ASN.1 item.
 * @param [in]  number  Context specific number.
 * @param [in]  len     Length of data in SET.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetImplicit(byte tag, byte number, word32 len, byte* output)
{
    tag = ((tag == ASN_SEQUENCE || tag == ASN_SET) ? ASN_CONSTRUCTED : 0)
                    | ASN_CONTEXT_SPECIFIC | number;
    return SetHeader(tag, len, output);
}

/* Encode an explicit context specific header in DER.
 *
 * Explicit means that there will be an ASN.1 item underneath.
 *
 * @param [in]  number  Context specific number.
 * @param [in]  len     Length of data in SET.
 * @param [out] output  Buffer to encode into.
 * @return  Number of bytes encoded.
 */
word32 SetExplicit(byte number, word32 len, byte* output)
{
    return SetHeader(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | number, len,
                     output);
}



#ifndef WOLFSSL_ASN_TEMPLATE
static int SetCurve(ecc_key* key, byte* output)
{
#ifdef HAVE_OID_ENCODING
    int ret;
#endif
    int idx;
    word32 oidSz = 0;

    /* validate key */
    if (key == NULL || key->dp == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_OID_ENCODING
    ret = EncodeObjectId(key->dp->oid, key->dp->oidSz, NULL, &oidSz);
    if (ret != 0) {
        return ret;
    }
#else
    oidSz = key->dp->oidSz;
#endif

    idx = SetObjectId(oidSz, output);

    /* length only */
    if (output == NULL) {
        return idx + oidSz;
    }

#ifdef HAVE_OID_ENCODING
    ret = EncodeObjectId(key->dp->oid, key->dp->oidSz, output+idx, &oidSz);
    if (ret != 0) {
        return ret;
    }
#else
    XMEMCPY(output+idx, key->dp->oid, oidSz);
#endif
    idx += oidSz;

    return idx;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */



/* Determines whether the signature algorithm is using ECDSA.
 *
 * @param [in] algoOID  Signature algorithm identifier.
 * @return  1 when algorithm is using ECDSA.
 * @return  0 otherwise.
 */
static WC_INLINE int IsSigAlgoECDSA(int algoOID)
{
    /* ECDSA sigAlgo must not have ASN1 NULL parameters */
    if (algoOID == CTC_SHAwECDSA || algoOID == CTC_SHA256wECDSA ||
        algoOID == CTC_SHA384wECDSA || algoOID == CTC_SHA512wECDSA) {
        return 1;
    }

    return 0;
}

/* Determines if OID is for an EC signing algorithm including ECDSA and EdDSA.
 *
 * @param [in] algoOID  Algorithm OID.
 * @return  1 when is EC signing algorithm.
 * @return  0 otherwise.
 */
static WC_INLINE int IsSigAlgoECC(int algoOID)
{
    (void)algoOID;

    return (0
              || IsSigAlgoECDSA(algoOID)
    );
}

/* Encode an algorithm identifier.
 *
 * [algoOID, type] is unique.
 *
 * @param [in]  algoOID   Algorithm identifier.
 * @param [out] output    Buffer to hold encoding.
 * @param [in]  type      Type of OID being encoded.
 * @param [in]  curveSz   Add extra space for curve data.
 * @return  Encoded data size on success.
 * @return  0 when dynamic memory allocation fails.
 */
word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 tagSz, idSz, seqSz, algoSz = 0;
    const  byte* algoName = 0;
    byte   ID_Length[1 + MAX_LENGTH_SZ];
    byte   seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */
    int    length = 0;

    tagSz = (type == oidHashType ||
             (type == oidSigType && !IsSigAlgoECC(algoOID)) ||
             (type == oidKeyType && algoOID == RSAk)) ? 2 : 0;

    algoName = OidFromId(algoOID, type, &algoSz);
    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }

    idSz  = SetObjectId(algoSz, ID_Length);
    seqSz = SetSequence(idSz + algoSz + tagSz + curveSz, seqArray);

    /* Copy only algo to output for DSA keys */
    if (algoOID == DSAk && output) {
        XMEMCPY(output, ID_Length, idSz);
        XMEMCPY(output + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }
    else if (output) {
        XMEMCPY(output, seqArray, seqSz);
        XMEMCPY(output + seqSz, ID_Length, idSz);
        XMEMCPY(output + seqSz + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }

    if (algoOID == DSAk)
        length = idSz + algoSz + tagSz;
    else
        length = seqSz + idSz + algoSz + tagSz;

    return length;
#else
    DECL_ASNSETDATA(dataASN, algoIdASN_Length);
    int sz;
    int ret = 0;
    int o = 0;

    CALLOC_ASNSETDATA(dataASN, algoIdASN_Length, ret, NULL);

    /* Set the OID and OID type to encode. */
    SetASN_OID(&dataASN[ALGOIDASN_IDX_OID], algoOID, type);
    /* Hashes, signatures not ECC and keys not RSA put put NULL tag. */
    if (!(type == oidHashType ||
             (type == oidSigType && !IsSigAlgoECC(algoOID)) ||
             (type == oidKeyType && algoOID == RSAk))) {
        /* Don't put out NULL DER item. */
        dataASN[ALGOIDASN_IDX_NULL].noOut = 1;
    }
    if (algoOID == DSAk) {
        /* Don't include SEQUENCE for DSA keys. */
        o = 1;
    }
    else if (curveSz > 0) {
        /* Don't put out NULL DER item. */
        dataASN[ALGOIDASN_IDX_NULL].noOut = 0;
        /* Include space for extra data of length curveSz.
         * Subtract 1 for sequence and 1 for length encoding. */
        SetASN_Buffer(&dataASN[ALGOIDASN_IDX_NULL], NULL, curveSz - 2);
    }

    /* Calculate size of encoding. */
    ret = SizeASN_Items(algoIdASN + o, dataASN + o, algoIdASN_Length - o, &sz);
    if (ret == 0 && output != NULL) {
        /* Encode into buffer. */
        SetASN_Items(algoIdASN + o, dataASN + o, algoIdASN_Length - o, output);
        if (curveSz > 0) {
            /* Return size excluding curve data. */
            sz = dataASN[o].offset - dataASN[ALGOIDASN_IDX_NULL].offset;
        }
    }

    if (ret == 0) {
        /* Return encoded size. */
        ret = sz;
    }
    else {
        /* Unsigned return type so 0 indicates error. */
        ret = 0;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* Always encode PKCS#1 v1.5 RSA signature and compare to encoded data. */
/* ASN.1 template for DigestInfo for a PKCS#1 v1.5 RSA signature.
 * PKCS#1 v2.2: RFC 8017, A.2.4 - DigestInfo
 */
static const ASNItem digestInfoASN[] = {
/* SEQ          */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                         /* digestAlgorithm */
/* DIGALGO_SEQ  */     { 1, ASN_SEQUENCE, 1, 1, 0 },
/* DIGALGO_OID  */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
/* DIGALGO_NULL */         { 2, ASN_TAG_NULL, 0, 0, 0 },
                                         /* digest */
/* DIGEST       */     { 1, ASN_OCTET_STRING, 0, 0, 0 }
};
enum {
    DIGESTINFOASN_IDX_SEQ = 0,
    DIGESTINFOASN_IDX_DIGALGO_SEQ,
    DIGESTINFOASN_IDX_DIGALGO_OID,
    DIGESTINFOASN_IDX_DIGALGO_NULL,
    DIGESTINFOASN_IDX_DIGEST,
};

/* Number of items in ASN.1 template for DigestInfo for RSA. */
#define digestInfoASN_Length (sizeof(digestInfoASN) / sizeof(ASNItem))
#endif

/* Encode signature.
 *
 * @param [out] out     Buffer to hold encoding.
 * @param [in]  digest  Buffer holding digest.
 * @param [in]  digSz   Length of digest in bytes.
 * @return  Encoded data size on success.
 * @return  0 when dynamic memory allocation fails.
 */
word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz,
                          int hashOID)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz;

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, oidHashType, 0);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    XMEMCPY(out, seqArray, seqSz);
    XMEMCPY(out + seqSz, algoArray, algoSz);
    XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
#else
    DECL_ASNSETDATA(dataASN, digestInfoASN_Length);
    int ret = 0;
    int sz;

    CALLOC_ASNSETDATA(dataASN, digestInfoASN_Length, ret, NULL);

    if (ret == 0) {
        /* Set hash OID and type. */
        SetASN_OID(&dataASN[DIGESTINFOASN_IDX_DIGALGO_OID], hashOID, oidHashType);
        /* Set digest. */
        SetASN_Buffer(&dataASN[DIGESTINFOASN_IDX_DIGEST], digest, digSz);

        /* Calculate size of encoding. */
        ret = SizeASN_Items(digestInfoASN, dataASN, digestInfoASN_Length, &sz);
    }
    if (ret == 0) {
        /* Encode PKCS#1 v1.5 RSA signature. */
        SetASN_Items(digestInfoASN, dataASN, digestInfoASN_Length, out);
        ret = sz;
    }
    else {
        /* Unsigned return type so 0 indicates error. */
        ret = 0;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
#endif
}



int wc_GetCTC_HashOID(int type)
{
    int ret;
    enum wc_HashType hType;

    hType = wc_HashTypeConvert(type);
    ret = wc_HashGetOID(hType);
    if (ret < 0) {
        ret = 0; /* backwards compatibility */
    }

    return ret;
}

/* Initialize a signature context object.
 *
 * Object used for signing and verifying a certificate signature.
 *
 * @param [in, out] sigCtx  Signature context object.
 * @param [in]      heap    Dynamic memory hint.
 * @param [in]      devId   Hardware device identifier.
 */
void InitSignatureCtx(SignatureCtx* sigCtx, void* heap, int devId)
{
    if (sigCtx) {
        XMEMSET(sigCtx, 0, sizeof(SignatureCtx));
        sigCtx->devId = devId;
        sigCtx->heap = heap;
    }
}

/* Free dynamic data in a signature context object.
 *
 * @param [in, out] sigCtx  Signature context object.
 */
void FreeSignatureCtx(SignatureCtx* sigCtx)
{
    if (sigCtx == NULL)
        return;

    if (sigCtx->digest) {
        XFREE(sigCtx->digest, sigCtx->heap, DYNAMIC_TYPE_DIGEST);
        sigCtx->digest = NULL;
    }
    if (sigCtx->sigCpy) {
        XFREE(sigCtx->sigCpy, sigCtx->heap, DYNAMIC_TYPE_SIGNATURE);
        sigCtx->sigCpy = NULL;
    }
#ifndef NO_ASN_CRYPT
    if (sigCtx->key.ptr) {
        switch (sigCtx->keyOID) {
            case RSAk:
                wc_FreeRsaKey(sigCtx->key.rsa);
                XFREE(sigCtx->key.rsa, sigCtx->heap, DYNAMIC_TYPE_RSA);
                sigCtx->key.rsa = NULL;
                break;
            case ECDSAk:
                wc_ecc_free(sigCtx->key.ecc);
                XFREE(sigCtx->key.ecc, sigCtx->heap, DYNAMIC_TYPE_ECC);
                sigCtx->key.ecc = NULL;
                break;
            default:
                break;
        } /* switch (keyOID) */
        sigCtx->key.ptr = NULL;
    }
#endif

    /* reset state, we are done */
    sigCtx->state = SIG_STATE_BEGIN;
}

#ifndef NO_ASN_CRYPT
static int HashForSignature(const byte* buf, word32 bufSz, word32 sigOID,
                            byte* digest, int* typeH, int* digestSz, int verify)
{
    int ret = 0;

    switch (sigOID) {
    #if defined(WOLFSSL_MD2)
        case CTC_MD2wRSA:
            if (!verify) {
                ret = HASH_TYPE_E;
                WOLFSSL_MSG("MD2 not supported for signing");
            }
            else if ((ret = wc_Md2Hash(buf, bufSz, digest)) == 0) {
                *typeH    = MD2h;
                *digestSz = MD2_DIGEST_SIZE;
            }
        break;
    #endif
    #ifndef NO_MD5
        case CTC_MD5wRSA:
            if ((ret = wc_Md5Hash(buf, bufSz, digest)) == 0) {
                *typeH    = MD5h;
                *digestSz = WC_MD5_DIGEST_SIZE;
            }
            break;
    #endif
        case CTC_SHAwRSA:
        case CTC_SHAwDSA:
        case CTC_SHAwECDSA:
            if ((ret = wc_ShaHash(buf, bufSz, digest)) == 0) {
                *typeH    = SHAh;
                *digestSz = WC_SHA_DIGEST_SIZE;
            }
            break;
        case CTC_SHA224wRSA:
        case CTC_SHA224wECDSA:
            if ((ret = wc_Sha224Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA224h;
                *digestSz = WC_SHA224_DIGEST_SIZE;
            }
            break;
        case CTC_SHA256wRSA:
        case CTC_SHA256wECDSA:
        case CTC_SHA256wDSA:
            if ((ret = wc_Sha256Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA256h;
                *digestSz = WC_SHA256_DIGEST_SIZE;
            }
            break;
        case CTC_SHA384wRSA:
        case CTC_SHA384wECDSA:
            if ((ret = wc_Sha384Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA384h;
                *digestSz = WC_SHA384_DIGEST_SIZE;
            }
            break;
        case CTC_SHA512wRSA:
        case CTC_SHA512wECDSA:
            if ((ret = wc_Sha512Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA512h;
                *digestSz = WC_SHA512_DIGEST_SIZE;
            }
            break;
    #ifndef WOLFSSL_NOSHA3_224
        case CTC_SHA3_224wRSA:
        case CTC_SHA3_224wECDSA:
            if ((ret = wc_Sha3_224Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA3_224h;
                *digestSz = WC_SHA3_224_DIGEST_SIZE;
            }
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case CTC_SHA3_256wRSA:
        case CTC_SHA3_256wECDSA:
            if ((ret = wc_Sha3_256Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA3_256h;
                *digestSz = WC_SHA3_256_DIGEST_SIZE;
            }
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case CTC_SHA3_384wRSA:
        case CTC_SHA3_384wECDSA:
            if ((ret = wc_Sha3_384Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA3_384h;
                *digestSz = WC_SHA3_384_DIGEST_SIZE;
            }
            break;
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case CTC_SHA3_512wRSA:
        case CTC_SHA3_512wECDSA:
            if ((ret = wc_Sha3_512Hash(buf, bufSz, digest)) == 0) {
                *typeH    = SHA3_512h;
                *digestSz = WC_SHA3_512_DIGEST_SIZE;
            }
            break;
    #endif

        default:
            ret = HASH_TYPE_E;
            WOLFSSL_MSG("Hash for Signature has unsupported type");
    }

    (void)buf;
    (void)bufSz;
    (void)sigOID;
    (void)digest;
    (void)digestSz;
    (void)typeH;
    (void)verify;

    return ret;
}
#endif /* !NO_ASN_CRYPT */

/* Return codes: 0=Success, Negative (see error-crypt.h), ASN_SIG_CONFIRM_E */
static int ConfirmSignature(SignatureCtx* sigCtx,
    const byte* buf, word32 bufSz,
    const byte* key, word32 keySz, word32 keyOID,
    const byte* sig, word32 sigSz, word32 sigOID, byte* rsaKeyIdx)
{
    int ret = 0;

    if (sigCtx == NULL || buf == NULL || bufSz == 0 || key == NULL ||
        keySz == 0 || sig == NULL || sigSz == 0) {
        return BAD_FUNC_ARG;
    }

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;

    WOLFSSL_ENTER("ConfirmSignature");

#if !defined(WOLFSSL_RENESAS_TSIP_TLS) && !defined(WOLFSSL_RENESAS_SCEPROTECT)
    (void)rsaKeyIdx;
#else
    CertAttribute* certatt = NULL;

    certatt = (CertAttribute*)&sigCtx->CertAtt;
    if(certatt) {
        certatt->keyIndex = rsaKeyIdx;
        certatt->cert = buf;
        certatt->certSz = bufSz;
    }
#endif

#ifndef NO_ASN_CRYPT
    switch (sigCtx->state) {
        case SIG_STATE_BEGIN:
        {
            sigCtx->keyOID = keyOID; /* must set early for cleanup */

            sigCtx->digest = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, sigCtx->heap,
                                                    DYNAMIC_TYPE_DIGEST);
            if (sigCtx->digest == NULL) {
                ERROR_OUT(MEMORY_E, exit_cs);
            }

            sigCtx->state = SIG_STATE_HASH;
        } /* SIG_STATE_BEGIN */
        FALL_THROUGH;

        case SIG_STATE_HASH:
        {
            ret = HashForSignature(buf, bufSz, sigOID, sigCtx->digest,
                                   &sigCtx->typeH, &sigCtx->digestSz, 1);
            if (ret != 0) {
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_KEY;
        } /* SIG_STATE_HASH */
        FALL_THROUGH;

        case SIG_STATE_KEY:
        {
            switch (keyOID) {
                case RSAk:
                {
                    word32 idx = 0;

                    sigCtx->key.rsa = (RsaKey*)XMALLOC(sizeof(RsaKey),
                                                sigCtx->heap, DYNAMIC_TYPE_RSA);
                    sigCtx->sigCpy = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ,
                                         sigCtx->heap, DYNAMIC_TYPE_SIGNATURE);
                    if (sigCtx->key.rsa == NULL || sigCtx->sigCpy == NULL) {
                        ERROR_OUT(MEMORY_E, exit_cs);
                    }
                    if ((ret = wc_InitRsaKey_ex(sigCtx->key.rsa, sigCtx->heap,
                                                        sigCtx->devId)) != 0) {
                        goto exit_cs;
                    }
                    if (sigSz > MAX_ENCODED_SIG_SZ) {
                        WOLFSSL_MSG("Verify Signature is too big");
                        ERROR_OUT(BUFFER_E, exit_cs);
                    }
                    if ((ret = wc_RsaPublicKeyDecode(key, &idx, sigCtx->key.rsa,
                                                                 keySz)) != 0) {
                        WOLFSSL_MSG("ASN Key decode error RSA");
                        goto exit_cs;
                    }
                    XMEMCPY(sigCtx->sigCpy, sig, sigSz);
                    sigCtx->out = NULL;

                    break;
                }
                case ECDSAk:
                {
                    word32 idx = 0;

                    sigCtx->verify = 0;
                    sigCtx->key.ecc = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                sigCtx->heap, DYNAMIC_TYPE_ECC);
                    if (sigCtx->key.ecc == NULL) {
                        ERROR_OUT(MEMORY_E, exit_cs);
                    }
                    if ((ret = wc_ecc_init_ex(sigCtx->key.ecc, sigCtx->heap,
                                                          sigCtx->devId)) < 0) {
                        goto exit_cs;
                    }
                    ret = wc_EccPublicKeyDecode(key, &idx, sigCtx->key.ecc,
                                                                         keySz);
                    if (ret < 0) {
                        WOLFSSL_MSG("ASN Key import error ECC");
                        goto exit_cs;
                    }
                    break;
                }
                default:
                    WOLFSSL_MSG("Verify Key type unknown");
                    ret = ASN_UNKNOWN_OID_E;
                    break;
            } /* switch (keyOID) */

            if (ret != 0) {
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_DO;

        } /* SIG_STATE_KEY */
        FALL_THROUGH;

        case SIG_STATE_DO:
        {
            switch (keyOID) {
                case RSAk:
                {
                    {
                        ret = wc_RsaSSL_VerifyInline(sigCtx->sigCpy, sigSz,
                                                 &sigCtx->out, sigCtx->key.rsa);
                    }
                    break;
                }
                case ECDSAk:
                {
                    {
                        ret = wc_ecc_verify_hash(sig, sigSz, sigCtx->digest,
                                            sigCtx->digestSz, &sigCtx->verify,
                                            sigCtx->key.ecc);
                    }
                    break;
                }
                default:
                    break;
            }  /* switch (keyOID) */


            if (ret < 0) {
                /* treat all RSA errors as ASN_SIG_CONFIRM_E */
                ret = ASN_SIG_CONFIRM_E;
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_CHECK;
        } /* SIG_STATE_DO */
        FALL_THROUGH;

        case SIG_STATE_CHECK:
        {
            switch (keyOID) {
                case RSAk:
                {
                    int encodedSigSz, verifySz;
                #if defined(WOLFSSL_RENESAS_TSIP_TLS) || \
                                            defined(WOLFSSL_RENESAS_SCEPROTECT)
                    if (sigCtx->CertAtt.verifyByTSIP_SCE == 1) break;
                #endif
                    byte encodedSig[MAX_ENCODED_SIG_SZ];

                    verifySz = ret;

                    /* make sure we're right justified */
                    encodedSigSz = wc_EncodeSignature(encodedSig,
                            sigCtx->digest, sigCtx->digestSz, sigCtx->typeH);
                    if (encodedSigSz == verifySz && sigCtx->out != NULL &&
                        XMEMCMP(sigCtx->out, encodedSig, encodedSigSz) == 0) {
                        ret = 0;
                    }
                    else {
                        WOLFSSL_MSG("RSA SSL verify match encode error");
                        ret = ASN_SIG_CONFIRM_E;
                    }

                    break;
                }
                case ECDSAk:
                {
                    if (sigCtx->verify == 1) {
                        ret = 0;
                    }
                    else {
                        WOLFSSL_MSG("ECC Verify didn't match");
                        ret = ASN_SIG_CONFIRM_E;
                    }
                    break;
                }
                default:
                    break;
            }  /* switch (keyOID) */

            break;
        } /* SIG_STATE_CHECK */

        default:
            break;
    } /* switch (sigCtx->state) */

exit_cs:

#endif /* !NO_ASN_CRYPT */

    (void)keyOID;
    (void)sigOID;

    WOLFSSL_LEAVE("ConfirmSignature", ret);


    FreeSignatureCtx(sigCtx);

    return ret;
}


#ifndef IGNORE_NAME_CONSTRAINTS

static int MatchBaseName(int type, const char* name, int nameSz,
                         const char* base, int baseSz)
{
    if (base == NULL || baseSz <= 0 || name == NULL || nameSz <= 0 ||
            name[0] == '.' || nameSz < baseSz ||
            (type != ASN_RFC822_TYPE && type != ASN_DNS_TYPE &&
             type != ASN_DIR_TYPE)) {
        return 0;
    }

    if (type == ASN_DIR_TYPE)
        return XMEMCMP(name, base, baseSz) == 0;

    /* If an email type, handle special cases where the base is only
     * a domain, or is an email address itself. */
    if (type == ASN_RFC822_TYPE) {
        const char* p = NULL;
        int count = 0;

        if (base[0] != '.') {
            p = base;
            count = 0;

            /* find the '@' in the base */
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            /* No '@' in base, reset p to NULL */
            if (count >= baseSz)
                p = NULL;
        }

        if (p == NULL) {
            /* Base isn't an email address, it is a domain name,
             * wind the name forward one character past its '@'. */
            p = name;
            count = 0;
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            if (count < baseSz && *p == '@') {
                name = p + 1;
                nameSz -= count + 1;
            }
        }
    }

    /* RFC 5280 section 4.2.1.10
     * "...Any DNS name that can be constructed by simply adding zero or more
     *  labels to the left-hand side of the name satisfies the name constraint."
     * i.e www.host.example.com works for host.example.com name constraint and
     * host1.example.com does not. */
    if (type == ASN_DNS_TYPE || (type == ASN_RFC822_TYPE && base[0] == '.')) {
        int szAdjust = nameSz - baseSz;
        name += szAdjust;
        nameSz -= szAdjust;
    }

    while (nameSz > 0) {
        if (XTOLOWER((unsigned char)*name++) !=
                                               XTOLOWER((unsigned char)*base++))
            return 0;
        nameSz--;
    }

    return 1;
}


static int ConfirmNameConstraints(Signer* signer, DecodedCert* cert)
{
    const byte nameTypes[] = {ASN_RFC822_TYPE, ASN_DNS_TYPE, ASN_DIR_TYPE};
    int i;

    if (signer == NULL || cert == NULL)
        return 0;

    if (signer->excludedNames == NULL && signer->permittedNames == NULL)
        return 1;

    for (i=0; i < (int)sizeof(nameTypes); i++) {
        byte nameType = nameTypes[i];
        DNS_entry* name = NULL;
        DNS_entry  subjectDnsName;
        Base_entry* base;

        switch (nameType) {
            case ASN_DNS_TYPE:
                /* Should it also consider CN in subject? It could use
                 * subjectDnsName too */
                name = cert->altNames;
                break;
            case ASN_RFC822_TYPE:
                /* Shouldn't it validade E= in subject as well? */
                name = cert->altEmailNames;
                break;
            case ASN_DIR_TYPE:
                if (cert->subjectRaw != NULL) {
                    subjectDnsName.next = NULL;
                    subjectDnsName.type = ASN_DIR_TYPE;
                    subjectDnsName.len = cert->subjectRawLen;
                    subjectDnsName.name = (char *)cert->subjectRaw;
                    name = &subjectDnsName;
                }

                #ifndef WOLFSSL_NO_ASN_STRICT
                /* RFC 5280 section 4.2.1.10
                    "Restrictions of the form directoryName MUST be
                    applied to the subject field .... and to any names
                    of type directoryName in the subjectAltName
                    extension"
                */
                if (name != NULL)
                    name->next = cert->altDirNames;
                else
                    name = cert->altDirNames;
                #endif
                break;
            default:
                /* Other types of names are ignored for now.
                 * Shouldn't it be rejected if it there is a altNamesByType[nameType]
                 * and signer->extNameConstraintCrit is set? */
                return 0;
        }

        while (name != NULL) {
            int match = 0;
            int need = 0;

            base = signer->excludedNames;
            /* Check against the excluded list */
            while (base != NULL) {
                if (base->type == nameType) {
                    if (name->len >= base->nameSz &&
                        MatchBaseName(nameType,
                                      name->name, name->len,
                                      base->name, base->nameSz)) {
                            return 0;
                    }
                }
                base = base->next;
            }

            /* Check against the permitted list */
            base = signer->permittedNames;
            while (base != NULL) {
                if (base->type == nameType) {
                    need = 1;
                    if (name->len >= base->nameSz &&
                        MatchBaseName(nameType,
                                      name->name, name->len,
                                      base->name, base->nameSz)) {
                            match = 1;
                            break;
                    }
                }
                base = base->next;
            }

            if (need && !match)
                return 0;

            name = name->next;
        }
    }

    return 1;
}

#endif /* IGNORE_NAME_CONSTRAINTS */

#ifndef WOLFSSL_ASN_TEMPLATE
static void AddAltName(DecodedCert* cert, DNS_entry* dnsEntry)
{
    dnsEntry->next = cert->altNames;
    cert->altNames = dnsEntry;
}
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
#ifdef WOLFSSL_SEP
/* ASN.1 template for OtherName of an X.509 certificate.
 * X.509: RFC 5280, 4.2.1.6 - OtherName (without implicit outer SEQUENCE).
 * HW Name: RFC 4108, 5 - Hardware Module Name
 * Only support HW Name where the type is a HW serial number.
 */
static const ASNItem otherNameASN[] = {
/* TYPEID   */ { 0, ASN_OBJECT_ID, 0, 0, 0 },
/* VALUE    */ { 0, ASN_CONTEXT_SPECIFIC | ASN_OTHERNAME_VALUE, 1, 0, 0 },
/* HWN_SEQ  */     { 1, ASN_SEQUENCE, 1, 0, 0 },
/* HWN_TYPE */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
/* HWN_NUM  */         { 2, ASN_OCTET_STRING, 0, 0, 0 }
};
enum {
    OTHERNAMEASN_IDX_TYPEID = 0,
    OTHERNAMEASN_IDX_VALUE,
    OTHERNAMEASN_IDX_HWN_SEQ,
    OTHERNAMEASN_IDX_HWN_TYPE,
    OTHERNAMEASN_IDX_HWN_NUM,
};

/* Number of items in ASN.1 template for OtherName of an X.509 certificate. */
#define otherNameASN_Length (sizeof(otherNameASN) / sizeof(ASNItem))

/* Decode data with OtherName format from after implicit SEQUENCE.
 *
 * @param [in, out] cert      Certificate object.
 * @param [in]      input     Buffer containing encoded OtherName.
 * @param [in, out] inOutIdx  On in, the index of the start of the OtherName.
 *                            On out, index after OtherName.
 * @param [in]      maxIdx    Maximum index of data in buffer.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  ASN_PARSE_E when OID does is not HW Name.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  BUFFER_E when data in buffer is too small.
 */
static int DecodeOtherName(DecodedCert* cert, const byte* input,
                           word32* inOutIdx, word32 maxIdx)
{
    DECL_ASNGETDATA(dataASN, otherNameASN_Length);
    int ret = 0;
    word32 oidLen, serialLen;

    CALLOC_ASNGETDATA(dataASN, otherNameASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Check the first OID is a recognized Alt Cert Name type. */
        GetASN_OID(&dataASN[OTHERNAMEASN_IDX_TYPEID], oidCertAltNameType);
        /* Only support HW serial number. */
        GetASN_OID(&dataASN[OTHERNAMEASN_IDX_HWN_TYPE], oidIgnoreType);
        /* Parse OtherName. */
        ret = GetASN_Items(otherNameASN, dataASN, otherNameASN_Length, 1, input,
                           inOutIdx, maxIdx);
    }
    if (ret == 0) {
        /* Ensure expected OID. */
        if (dataASN[OTHERNAMEASN_IDX_TYPEID].data.oid.sum != HW_NAME_OID) {
            WOLFSSL_MSG("\tunsupported OID");
            ret = ASN_PARSE_E;
        }
    }

    if (ret == 0) {
        oidLen = dataASN[OTHERNAMEASN_IDX_HWN_TYPE].data.oid.length;
        serialLen = dataASN[OTHERNAMEASN_IDX_HWN_NUM].data.ref.length;

        /* Allocate space for HW type OID. */
        cert->hwType = (byte*)XMALLOC(oidLen, cert->heap,
                                      DYNAMIC_TYPE_X509_EXT);
        if (cert->hwType == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        /* Copy, into cert HW type OID */
        XMEMCPY(cert->hwType,
                dataASN[OTHERNAMEASN_IDX_HWN_TYPE].data.oid.data, oidLen);
        cert->hwTypeSz = oidLen;
        /* TODO: check this is the HW serial number OID - no test data. */

        /* Allocate space for HW serial number. */
        cert->hwSerialNum = (byte*)XMALLOC(serialLen, cert->heap,
                                           DYNAMIC_TYPE_X509_EXT);
        if (cert->hwSerialNum == NULL) {
            WOLFSSL_MSG("\tOut of Memory");
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Copy into cert HW serial number. */
        XMEMCPY(cert->hwSerialNum,
                dataASN[OTHERNAMEASN_IDX_HWN_NUM].data.ref.data, serialLen);
        cert->hwSerialNum[serialLen] = '\0';
        cert->hwSerialNumSz = serialLen;
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
}
#endif /* WOLFSSL_SEP */

/* Decode a GeneralName.
 *
 * @param [in]      input     Buffer containing encoded OtherName.
 * @param [in, out] inOutIdx  On in, the index of the start of the OtherName.
 *                            On out, index after OtherName.
 * @param [in]      len       Length of data in buffer.
 * @param [in]      cert      Decoded certificate object.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int DecodeGeneralName(const byte* input, word32* inOutIdx, byte tag,
                             int len, DecodedCert* cert)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    /* GeneralName choice: dnsName */
    if (tag == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) {
        ret = SetDNSEntry(cert, (const char*)(input + idx), len, ASN_DNS_TYPE,
                &cert->altNames);
        if (ret == 0) {
            idx += len;
        }
    }
#ifndef IGNORE_NAME_CONSTRAINTS
    /* GeneralName choice: directoryName */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {
        int strLen;
        word32 idxDir = idx;

        /* Expecting a SEQUENCE using up all data. */
        if (GetASN_Sequence(input, &idxDir, &strLen, idx + len, 1) < 0) {
            WOLFSSL_MSG("\tfail: seq length");
            return ASN_PARSE_E;
        }

        ret = SetDNSEntry(cert, (const char*)(input + idxDir), strLen,
                ASN_DIR_TYPE, &cert->altDirNames);
        if (ret == 0) {
            idx += len;
        }
    }
    /* GeneralName choice: rfc822Name */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) {
        ret = SetDNSEntry(cert, (const char*)(input + idx), len,
                ASN_RFC822_TYPE, &cert->altEmailNames);
        if (ret == 0) {
            idx += len;
        }
    }
    /* GeneralName choice: uniformResourceIdentifier */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE)) {
        WOLFSSL_MSG("\tPutting URI into list but not using");

    #ifndef WOLFSSL_NO_ASN_STRICT
        /* Verify RFC 5280 Sec 4.2.1.6 rule:
            "The name MUST NOT be a relative URI" */
        {
            int i;

            /* skip past scheme (i.e http,ftp,...) finding first ':' char */
            for (i = 0; i < len; i++) {
                if (input[idx + i] == ':') {
                    break;
                }
                if (input[idx + i] == '/') {
                    i = len; /* error, found relative path since '/' was
                              * encountered before ':'. Returning error
                              * value in next if statement. */
                }
            }

            /* test if no ':' char was found and test that the next two
             * chars are "//" to match the pattern "://" */
            if (i >= len - 2 || (input[idx + i + 1] != '/' ||
                                 input[idx + i + 2] != '/')) {
                WOLFSSL_MSG("\tAlt Name must be absolute URI");
                return ASN_ALT_NAME_E;
            }
        }
    #endif

        ret = SetDNSEntry(cert, (const char*)(input + idx), len, ASN_URI_TYPE,
                &cert->altNames);
        if (ret == 0) {
            idx += len;
        }
    }
    #if  defined(WOLFSSL_IP_ALT_NAME)
    /* GeneralName choice: iPAddress */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_IP_TYPE)) {
        ret = SetDNSEntry(cert, (const char*)(input + idx), len, ASN_IP_TYPE,
                &cert->altNames);
        if (ret == 0) {
            idx += len;
        }
    }
    #endif /* WOLFSSL_QT || OPENSSL_ALL */
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
    /* GeneralName choice: otherName */
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE)) {
        /* TODO: test data for code path */
        ret = DecodeOtherName(cert, input, &idx, idx + len);
    }
#endif
    /* GeneralName choice: dNSName, x400Address, ediPartyName,
     *                     registeredID */
    else {
        WOLFSSL_MSG("\tUnsupported name type, skipping");
        idx += len;
    }

    if (ret == 0) {
        /* Return index of next encoded byte. */
        *inOutIdx = idx;
    }
    return ret;
}

/* ASN.1 choices for GeneralName.
 * X.509: RFC 5280, 4.2.1.6 - GeneralName.
 */
static const byte generalNameChoice[] = {
    ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0,
    ASN_CONTEXT_SPECIFIC                   | 1,
    ASN_CONTEXT_SPECIFIC                   | 2,
    ASN_CONTEXT_SPECIFIC                   | 3,
    ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 4,
    ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 5,
    ASN_CONTEXT_SPECIFIC                   | 6,
    ASN_CONTEXT_SPECIFIC                   | 7,
    ASN_CONTEXT_SPECIFIC                   | 8,
    0
};

/* ASN.1 template for GeneralName.
 * X.509: RFC 5280, 4.2.1.6 - GeneralName.
 */
static const ASNItem altNameASN[] = {
    { 0, ASN_CONTEXT_SPECIFIC | 0, 0, 1, 0 }
};
enum {
    ALTNAMEASN_IDX_GN = 0,
};

/* Number of items in ASN.1 template for GeneralName. */
#define altNameASN_Length (sizeof(altNameASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */

/* Decode subject alternative names extension.
 *
 * RFC 5280 4.2.1.6.  Subject Alternative Name
 *
 * @param [in]      input  Buffer holding encoded data.
 * @param [in]      sz     Size of encoded data in bytes.
 * @param [in, out] cert   Decoded certificate object.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int DecodeAltNames(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeAltNames");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tBad Sequence");
        return ASN_PARSE_E;
    }

    if (length == 0) {
        /* RFC 5280 4.2.1.6.  Subject Alternative Name
           If the subjectAltName extension is present, the sequence MUST
           contain at least one entry. */
        return ASN_PARSE_E;
    }


    cert->weOwnAltNames = 1;

    while (length > 0) {
        byte b = input[idx++];

        length--;

        /* Save DNS Type names in the altNames list. */
        /* Save Other Type names in the cert's OidMap */
        if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) {
            DNS_entry* dnsEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            dnsEntry = AltNameNew(cert->heap);
            if (dnsEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            dnsEntry->type = ASN_DNS_TYPE;
            dnsEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            dnsEntry->len = strLen;
            XMEMCPY(dnsEntry->name, &input[idx], strLen);
            dnsEntry->name[strLen] = '\0';

            AddAltName(cert, dnsEntry);

            length -= strLen;
            idx    += strLen;
        }
    #ifndef IGNORE_NAME_CONSTRAINTS
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {
            DNS_entry* dirEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }

            if (GetSequence(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: seq length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            dirEntry = AltNameNew(cert->heap);
            if (dirEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            dirEntry->type = ASN_DIR_TYPE;
            dirEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dirEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dirEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            dirEntry->len = strLen;
            XMEMCPY(dirEntry->name, &input[idx], strLen);
            dirEntry->name[strLen] = '\0';

            dirEntry->next = cert->altDirNames;
            cert->altDirNames = dirEntry;

            length -= strLen;
            idx    += strLen;
        }
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) {
            DNS_entry* emailEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            emailEntry = AltNameNew(cert->heap);
            if (emailEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            emailEntry->type = ASN_RFC822_TYPE;
            emailEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (emailEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(emailEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            emailEntry->len = strLen;
            XMEMCPY(emailEntry->name, &input[idx], strLen);
            emailEntry->name[strLen] = '\0';

            emailEntry->next = cert->altEmailNames;
            cert->altEmailNames = emailEntry;

            length -= strLen;
            idx    += strLen;
        }
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE)) {
            DNS_entry* uriEntry;
            int strLen;
            word32 lenStartIdx = idx;

            WOLFSSL_MSG("\tPutting URI into list but not using");
            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            /* check that strLen at index is not past input buffer */
            if (strLen + (int)idx > sz) {
                return BUFFER_E;
            }

        #ifndef WOLFSSL_NO_ASN_STRICT
            /* Verify RFC 5280 Sec 4.2.1.6 rule:
                "The name MUST NOT be a relative URI" */

            {
                int i;

                /* skip past scheme (i.e http,ftp,...) finding first ':' char */
                for (i = 0; i < strLen; i++) {
                    if (input[idx + i] == ':') {
                        break;
                    }
                    if (input[idx + i] == '/') {
                        WOLFSSL_MSG("\tAlt Name must be absolute URI");
                        return ASN_ALT_NAME_E;
                    }
                }

                /* test if no ':' char was found and test that the next two
                 * chars are "//" to match the pattern "://" */
                if (i >= strLen - 2 || (input[idx + i + 1] != '/' ||
                                        input[idx + i + 2] != '/')) {
                    WOLFSSL_MSG("\tAlt Name must be absolute URI");
                    return ASN_ALT_NAME_E;
                }
            }
        #endif

            uriEntry = AltNameNew(cert->heap);
            if (uriEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            uriEntry->type = ASN_URI_TYPE;
            uriEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (uriEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(uriEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            uriEntry->len = strLen;
            XMEMCPY(uriEntry->name, &input[idx], strLen);
            uriEntry->name[strLen] = '\0';

            AddAltName(cert, uriEntry);

            length -= strLen;
            idx    += strLen;
        }
#if defined(WOLFSSL_IP_ALT_NAME)
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_IP_TYPE)) {
            DNS_entry* ipAddr;
            int strLen;
            word32 lenStartIdx = idx;
            WOLFSSL_MSG("Decoding Subject Alt. Name: IP Address");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);
            /* check that strLen at index is not past input buffer */
            if (strLen + (int)idx > sz) {
                return BUFFER_E;
            }

            ipAddr = AltNameNew(cert->heap);
            if (ipAddr == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            ipAddr->type = ASN_IP_TYPE;
            ipAddr->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (ipAddr->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(ipAddr, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            ipAddr->len = strLen;
            XMEMCPY(ipAddr->name, &input[idx], strLen);
            ipAddr->name[strLen] = '\0';

        #if defined(WOLFSSL_IP_ALT_NAME)
            if (GenerateDNSEntryIPString(ipAddr, cert->heap) != 0) {
                WOLFSSL_MSG("\tOut of Memory for IP string");
                XFREE(ipAddr->name, cert->heap, DYNAMIC_TYPE_ALTNAME);
                XFREE(ipAddr, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
        #endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
            AddAltName(cert, ipAddr);

            length -= strLen;
            idx    += strLen;
        }
#endif /* WOLFSSL_QT || OPENSSL_ALL */
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE))
        {
            int strLen;
            word32 lenStartIdx = idx;
            word32 oid = 0;
            int    ret;
            byte   tag;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: other name length");
                return ASN_PARSE_E;
            }
            /* Consume the rest of this sequence. */
            length -= (strLen + idx - lenStartIdx);

            if (GetObjectId(input, &idx, &oid, oidCertAltNameType, sz) < 0) {
                WOLFSSL_MSG("\tbad OID");
                return ASN_PARSE_E;
            }

            if (oid != HW_NAME_OID) {
                WOLFSSL_MSG("\tincorrect OID");
                return ASN_PARSE_E;
            }

            /* Certificates issued with this OID in the subject alt name are for
             * verifying signatures created on a module.
             * RFC 4108 Section 5. */
            if (cert->hwType != NULL) {
                WOLFSSL_MSG("\tAlready seen Hardware Module Name");
                return ASN_PARSE_E;
            }

            if (GetASNTag(input, &idx, &tag, sz) < 0) {
                return ASN_PARSE_E;
            }

            if (tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
                WOLFSSL_MSG("\twrong type");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str len");
                return ASN_PARSE_E;
            }

            if (GetSequence(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tBad Sequence");
                return ASN_PARSE_E;
            }

            ret = GetASNObjectId(input, &idx, &strLen, sz);
            if (ret != 0) {
                WOLFSSL_MSG("\tbad OID");
                return ret;
            }

            cert->hwType = (byte*)XMALLOC(strLen, cert->heap,
                                          DYNAMIC_TYPE_X509_EXT);
            if (cert->hwType == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwType, &input[idx], strLen);
            cert->hwTypeSz = strLen;
            idx += strLen;

            ret = GetOctetString(input, &idx, &strLen, sz);
            if (ret < 0)
                return ret;

            cert->hwSerialNum = (byte*)XMALLOC(strLen + 1, cert->heap,
                                               DYNAMIC_TYPE_X509_EXT);
            if (cert->hwSerialNum == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwSerialNum, &input[idx], strLen);
            cert->hwSerialNum[strLen] = '\0';
            cert->hwSerialNumSz = strLen;
            idx += strLen;
        }
    #endif /* WOLFSSL_SEP */
        else {
            int strLen;
            word32 lenStartIdx = idx;

            WOLFSSL_MSG("\tUnsupported name type, skipping");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: unsupported name length");
                return ASN_PARSE_E;
            }
            length -= (strLen + idx - lenStartIdx);
            idx += strLen;
        }
    }

    return 0;
#else
    word32 idx = 0;
    int length = 0;
    int ret = 0;

    WOLFSSL_ENTER("DecodeAltNames");

    /* Get SEQUENCE and expect all data to be accounted for. */
    if (GetASN_Sequence(input, &idx, &length, sz, 1) != 0) {
        WOLFSSL_MSG("\tBad Sequence");
        ret = ASN_PARSE_E;
    }

    if ((ret == 0) && (length == 0)) {
        /* RFC 5280 4.2.1.6.  Subject Alternative Name
           If the subjectAltName extension is present, the sequence MUST
           contain at least one entry. */
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {

        cert->weOwnAltNames = 1;

        if (length + (int)idx != sz) {
            ret = ASN_PARSE_E;
        }
    }

    while ((ret == 0) && ((int)idx < sz)) {
        ASNGetData dataASN[altNameASN_Length];

        /* Clear dynamic data items. */
        XMEMSET(dataASN, 0, sizeof(dataASN));
        /* Parse GeneralName with the choices supported. */
        GetASN_Choice(&dataASN[ALTNAMEASN_IDX_GN], generalNameChoice);
        /* Decode a GeneralName choice. */
        ret = GetASN_Items(altNameASN, dataASN, altNameASN_Length, 0, input,
                           &idx, sz);
        if (ret == 0) {
            ret = DecodeGeneralName(input, &idx, dataASN[ALTNAMEASN_IDX_GN].tag,
                dataASN[ALTNAMEASN_IDX_GN].length, cert);
        }
    }

    return ret;
#endif
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for BasicContraints.
 * X.509: RFC 5280, 4.2.1.9 - BasicConstraints.
 */
static const ASNItem basicConsASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* CA   */     { 1, ASN_BOOLEAN, 0, 0, 1 },
/* PLEN */     { 1, ASN_INTEGER, 0, 0, 1 }
};
enum {
    BASICCONSASN_IDX_SEQ = 0,
    BASICCONSASN_IDX_CA,
    BASICCONSASN_IDX_PLEN,
};

/* Number of items in ASN.1 template for BasicContraints. */
#define basicConsASN_Length (sizeof(basicConsASN) / sizeof(ASNItem))
#endif

/* Decode basic constraints extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.1.9 - BasicConstraints.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  ASN_PARSE_E when CA boolean is present and false (default is false).
 * @return  ASN_PARSE_E when CA boolean is not present unless
 *          WOLFSSL_X509_BASICCONS_INT is defined. Only a CA extension.
 * @return  ASN_PARSE_E when path length more than 7 bits.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 */
static int DecodeBasicCaConstraint(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length = 0;
    int ret;

    WOLFSSL_ENTER("DecodeBasicCaConstraint");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return 0;

    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    ret = GetBoolean(input, &idx, sz);

    /* Removed logic for WOLFSSL_X509_BASICCONS_INT which was mistreating the
     * pathlen value as if it were the CA Boolean value 7/2/2021 - KH.
     * When CA Boolean not asserted use the default value "False" */
    if (ret < 0) {
        WOLFSSL_MSG("\tfail: constraint not valid BOOLEAN, set default FALSE");
        ret = 0;
    }

    cert->isCA = (byte)ret;

    /* If there isn't any more data, return. */
    if (idx >= (word32)sz) {
        return 0;
    }

    ret = GetInteger7Bit(input, &idx, sz);
    if (ret < 0)
        return ret;
    cert->pathLength = (byte)ret;
    cert->pathLengthSet = 1;

    return 0;
#else
    DECL_ASNGETDATA(dataASN, basicConsASN_Length);
    int ret = 0;
    word32 idx = 0;
    byte isCA = 0;

    WOLFSSL_ENTER("DecodeBasicCaConstraints");

    CALLOC_ASNGETDATA(dataASN, basicConsASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Get the CA boolean and path length when present. */
        GetASN_Boolean(&dataASN[BASICCONSASN_IDX_CA], &isCA);
        GetASN_Int8Bit(&dataASN[BASICCONSASN_IDX_PLEN], &cert->pathLength);

        ret = GetASN_Items(basicConsASN, dataASN, basicConsASN_Length, 1, input,
                           &idx, sz);
    }

    /* Empty SEQUENCE is OK - nothing to store. */
    if ((ret == 0) && (dataASN[BASICCONSASN_IDX_SEQ].length != 0)) {
        /* Bad encoding when CA Boolean is false
         * (default when not present). */
        if ((dataASN[BASICCONSASN_IDX_CA].length != 0) && (!isCA)) {
            ret = ASN_PARSE_E;
        }
        /* Path length must be a 7-bit value. */
        if ((ret == 0) && (cert->pathLength >= (1 << 7))) {
            ret = ASN_PARSE_E;
        }
        /* Store CA boolean and whether a path length was seen. */
        if (ret == 0) {
            /* isCA in certificate is a 1 bit of a byte. */
            cert->isCA = isCA;
            cert->pathLengthSet = (dataASN[BASICCONSASN_IDX_PLEN].length > 0);
        }
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
#endif
}


static int DecodePolicyConstraints(const byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;
    int skipLength = 0;
    int ret;
    byte tag;

    WOLFSSL_ENTER("DecodePolicyConstraints");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return ASN_PARSE_E;

    if (GetASNTag(input, &idx, &tag, sz) < 0) {
        WOLFSSL_MSG("\tfail: bad TAG");
        return ASN_PARSE_E;
    }

    if (tag == (ASN_CONTEXT_SPECIFIC | 0)) {
        /* requireExplicitPolicy */
        cert->extPolicyConstRxpSet = 1;
    }
    else if (tag == (ASN_CONTEXT_SPECIFIC | 1)) {
        /* inhibitPolicyMapping */
        cert->extPolicyConstIpmSet = 1;
    }
    else {
        WOLFSSL_MSG("\tfail: invalid TAG");
        return ASN_PARSE_E;
    }

    ret = GetLength(input, &idx, &skipLength, sz);
    if (ret < 0) {
        WOLFSSL_MSG("\tfail: invalid length");
        return ret;
    }
    if (skipLength > 1) {
        WOLFSSL_MSG("\tfail: skip value too big");
        return BUFFER_E;
    }
    if (idx >= (word32)sz) {
        WOLFSSL_MSG("\tfail: no policy const skip to read");
        return BUFFER_E;
    }
    cert->policyConstSkip = input[idx];

    return 0;
}


/* Context-Specific value for: DistributionPoint.distributionPoint
 * From RFC5280 SS4.2.1.13, Distribution Point */
#define DISTRIBUTION_POINT  (ASN_CONTEXT_SPECIFIC | 0)
/* Context-Specific value for: DistributionPoint.DistributionPointName.fullName
 *  From RFC3280 SS4.2.1.13, Distribution Point Name */
#define CRLDP_FULL_NAME     (ASN_CONTEXT_SPECIFIC | 0)
/* Context-Specific value for choice: GeneralName.uniformResourceIdentifier
 * From RFC3280 SS4.2.1.7, GeneralName */
#define GENERALNAME_URI     (ASN_CONTEXT_SPECIFIC | 6)

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for CRL distribution points.
 * X.509: RFC 5280, 4.2.1.13 - CRL Distribution Points.
 */
static const ASNItem crlDistASN[] = {
/* SEQ                */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* DP_SEQ             */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                /* Distribution point name */
/* DP_DISTPOINT       */         { 2, DISTRIBUTION_POINT, 1, 1, 1 },
                                                    /* fullName */
/* DP_DISTPOINT_FN    */             { 3, CRLDP_FULL_NAME, 1, 1, 2 },
/* DP_DISTPOINT_FN_GN */                 { 4, GENERALNAME_URI, 0, 0, 0 },
                                                    /* nameRelativeToCRLIssuer */
/* DP_DISTPOINT_RN    */             { 3, ASN_CONTEXT_SPECIFIC | 1, 1, 0, 2 },
                                                /* reasons: IMPLICIT BIT STRING */
/* DP_REASONS         */         { 2, ASN_CONTEXT_SPECIFIC | 1, 1, 0, 1 },
                                                /* cRLIssuer */
/* DP_CRLISSUER       */         { 2, ASN_CONTEXT_SPECIFIC | 2, 1, 0, 1 },
};
enum {
    CRLDISTASN_IDX_SEQ = 0,
    CRLDISTASN_IDX_DP_SEQ,
    CRLDISTASN_IDX_DP_DISTPOINT,
    CRLDISTASN_IDX_DP_DISTPOINT_FN,
    CRLDISTASN_IDX_DP_DISTPOINT_FN_GN,
    CRLDISTASN_IDX_DP_DISTPOINT_RN, /* Relative name */
    CRLDISTASN_IDX_DP_REASONS,
    CRLDISTASN_IDX_DP_CRLISSUER,
};

/* Number of items in ASN.1 template for CRL distribution points. */
#define crlDistASN_Length (sizeof(crlDistASN) / sizeof(ASNItem))
#endif

/* Decode CRL distribution point extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.1.13 - CRL Distribution Points.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  ASN_PARSE_E when invalid bits of reason are set.
 * @return  ASN_PARSE_E when BITSTRING value is more than 2 bytes.
 * @return  ASN_PARSE_E when unused bits of BITSTRING is invalid.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 */
static int DecodeCrlDist(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0, localIdx;
    int length = 0;
    byte tag   = 0;

    WOLFSSL_ENTER("DecodeCrlDist");

    cert->extCrlInfoRaw = input;
    cert->extCrlInfoRawSz = sz;

    /* Unwrap the list of Distribution Points*/
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* Unwrap a single Distribution Point */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* The Distribution Point has three explicit optional members
     *  First check for a DistributionPointName
     */
    localIdx = idx;
    if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
            tag == (ASN_CONSTRUCTED | DISTRIBUTION_POINT))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        localIdx = idx;
        if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
                tag == (ASN_CONSTRUCTED | CRLDP_FULL_NAME))
        {
            idx++;
            if (GetLength(input, &idx, &length, sz) < 0)
                return ASN_PARSE_E;

            localIdx = idx;
            if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
                    tag == GENERALNAME_URI)
            {
                idx++;
                if (GetLength(input, &idx, &length, sz) < 0)
                    return ASN_PARSE_E;

                cert->extCrlInfoSz = length;
                cert->extCrlInfo = input + idx;
                idx += length;
            }
            else
                /* This isn't a URI, skip it. */
                idx += length;
        }
        else {
            /* This isn't a FULLNAME, skip it. */
            idx += length;
        }
    }

    /* Check for reasonFlags */
    localIdx = idx;
    if (idx < (word32)sz &&
        GetASNTag(input, &localIdx, &tag, sz) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    /* Check for cRLIssuer */
    localIdx = idx;
    if (idx < (word32)sz &&
        GetASNTag(input, &localIdx, &tag, sz) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    if (idx < (word32)sz)
    {
        WOLFSSL_MSG("\tThere are more CRL Distribution Point records, "
                   "but we only use the first one.");
    }

    return 0;
#else
    DECL_ASNGETDATA(dataASN, crlDistASN_Length);
    word32 idx = 0;
    int ret = 0;
#ifdef CRLDP_VALIDATE_DATA
    word16 reason;
#endif

    WOLFSSL_ENTER("DecodeCrlDist");

    CALLOC_ASNGETDATA(dataASN, crlDistASN_Length, ret, cert->heap);

    cert->extCrlInfoRaw = input;
    cert->extCrlInfoRawSz = sz;

    if  (ret == 0) {
        /* Get the GeneralName choice */
        GetASN_Choice(&dataASN[CRLDISTASN_IDX_DP_DISTPOINT_FN_GN], generalNameChoice);
        /* Parse CRL distribtion point. */
        ret = GetASN_Items(crlDistASN, dataASN, crlDistASN_Length, 0, input,
                           &idx, sz);
    }
    if (ret == 0) {
        /* If the choice was a URI, store it in certificate. */
        if (dataASN[CRLDISTASN_IDX_DP_DISTPOINT_FN_GN].tag == GENERALNAME_URI) {
            word32 sz32;
            GetASN_GetConstRef(&dataASN[CRLDISTASN_IDX_DP_DISTPOINT_FN_GN],
                    &cert->extCrlInfo, &sz32);
            cert->extCrlInfoSz = sz32;
        }

    #ifdef CRLDP_VALIDATE_DATA
        if (dataASN[CRLDISTASN_IDX_DP_REASONS].data.ref.data != NULL) {
             /* TODO: test case */
             /* Validate ReasonFlags. */
             ret = GetASN_BitString_Int16Bit(&dataASN[CRLDISTASN_IDX_DP_REASONS],
                     &reason);
             /* First bit (LSB) unused and eight other bits defined. */
             if ((ret == 0) && ((reason >> 9) || (reason & 0x01))) {
                ret = ASN_PARSE_E;
             }
        }
    #endif
    }

    /* Only parsing the first one. */
    if (ret == 0 && idx < (word32)sz) {
        WOLFSSL_MSG("\tThere are more CRL Distribution Point records, "
                    "but we only use the first one.");
    }
    /* TODO: validate other points. */

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for the access description.
 * X.509: RFC 5280, 4.2.2.1 - Authority Information Access.
 */
static const ASNItem accessDescASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                 /* accessMethod */
/* METH */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                                 /* accessLocation: GeneralName */
/* LOC  */     { 1, ASN_CONTEXT_SPECIFIC | 0, 0, 0, 0 },
};
enum {
    ACCESSDESCASN_IDX_SEQ = 0,
    ACCESSDESCASN_IDX_METH,
    ACCESSDESCASN_IDX_LOC,
};

/* Number of items in ASN.1 template for the access description. */
#define accessDescASN_Length (sizeof(accessDescASN) / sizeof(ASNItem))
#endif

/* Decode authority information access extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.2.1 - Authority Information Access.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
static int DecodeAuthInfo(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length = 0;
    int count  = 0;
    byte b = 0;
    word32 oid;

    WOLFSSL_ENTER("DecodeAuthInfo");

    /* Unwrap the list of AIAs */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    while ((idx < (word32)sz) && (count < MAX_AIA_SZ)) {
        /* Unwrap a single AIA */
        if (GetSequence(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        oid = 0;
        if (GetObjectId(input, &idx, &oid, oidCertAuthInfoType, sz) < 0) {
            return ASN_PARSE_E;
        }

        /* Only supporting URIs right now. */
        if (GetASNTag(input, &idx, &b, sz) < 0)
            return ASN_PARSE_E;

        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        /* Set ocsp entry */
        if (b == GENERALNAME_URI && oid == AIA_OCSP_OID)
        {
            cert->extAuthInfoSz = length;
            cert->extAuthInfo = input + idx;
            break;
        }
        idx += length;
    }

    return 0;
#else
    word32 idx = 0;
    int length = 0;
    int count  = 0;
    int ret    = 0;

    WOLFSSL_ENTER("DecodeAuthInfo");

    /* Unwrap the list of AIAs */
    if (GetASN_Sequence(input, &idx, &length, sz, 1) < 0) {
        ret = ASN_PARSE_E;
    }

    while ((ret == 0) && (idx < (word32)sz) && (count < MAX_AIA_SZ)) {
        ASNGetData dataASN[accessDescASN_Length];
        word32 sz32;

        /* Clear dynamic data and retrieve OID and name. */
        XMEMSET(dataASN, 0, sizeof(dataASN));
        GetASN_OID(&dataASN[ACCESSDESCASN_IDX_METH], oidCertAuthInfoType);
        GetASN_Choice(&dataASN[ACCESSDESCASN_IDX_LOC], generalNameChoice);
        /* Parse AccessDescription. */
        ret = GetASN_Items(accessDescASN, dataASN, accessDescASN_Length, 0,
                           input, &idx, sz);
        if (ret == 0) {
            /* Check we have OCSP and URI. */
            if ((dataASN[ACCESSDESCASN_IDX_METH].data.oid.sum == AIA_OCSP_OID) &&
                    (dataASN[ACCESSDESCASN_IDX_LOC].tag == GENERALNAME_URI)) {
                /* Store URI for OCSP lookup. */
                GetASN_GetConstRef(&dataASN[ACCESSDESCASN_IDX_LOC],
                        &cert->extAuthInfo, &sz32);
                cert->extAuthInfoSz = sz32;
                count++;
                break;
            }
            /* Otherwise skip. */
        }
    }

    return ret;
#endif
}


#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for AuthorityKeyIdentifier.
 * X.509: RFC 5280, 4.2.1.1 - Authority Key Identifier.
 */
static const ASNItem authKeyIdASN[] = {
/* SEQ    */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                                     /* keyIdentifier */
/* KEYID  */        { 1, ASN_CONTEXT_SPECIFIC | ASN_AUTHKEYID_KEYID, 0, 0, 1 },
                                     /* authorityCertIssuer */
/* ISSUER */        { 1, ASN_CONTEXT_SPECIFIC | ASN_AUTHKEYID_ISSUER, 1, 0, 1 },
                                     /* authorityCertSerialNumber */
/* SERIAL */        { 1, ASN_CONTEXT_SPECIFIC | ASN_AUTHKEYID_SERIAL, 0, 0, 1 },
};
enum {
    AUTHKEYIDASN_IDX_SEQ = 0,
    AUTHKEYIDASN_IDX_KEYID,
    AUTHKEYIDASN_IDX_ISSUER,
    AUTHKEYIDASN_IDX_SERIAL,
};

/* Number of items in ASN.1 template for AuthorityKeyIdentifier. */
#define authKeyIdASN_Length (sizeof(authKeyIdASN) / sizeof(ASNItem))
#endif

/* Decode authority information access extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.2.1 - Authority Information Access.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 */
static int DecodeAuthKeyId(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length = 0;
    byte tag;

    WOLFSSL_ENTER("DecodeAuthKeyId");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    if (GetASNTag(input, &idx, &tag, sz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | 0)) {
        WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available");
        cert->extAuthKeyIdSet = 0;
        return 0;
    }

    if (GetLength(input, &idx, &length, sz) <= 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }


    return GetHashId(input + idx, length, cert->extAuthKeyId);
#else
    DECL_ASNGETDATA(dataASN, authKeyIdASN_Length);
    int ret = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("DecodeAuthKeyId");

    CALLOC_ASNGETDATA(dataASN, authKeyIdASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Parse an authority key identifier. */
        ret = GetASN_Items(authKeyIdASN, dataASN, authKeyIdASN_Length, 1, input,
                           &idx, sz);
    }
    if (ret == 0) {
        /* Key id is optional. */
        if (dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.data == NULL) {
            WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available");
        }
        else {

            /* Get the hash or hash of the hash if wrong size. */
            ret = GetHashId(dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.data,
                        dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.length,
                        cert->extAuthKeyId);
        }
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

/* Decode subject key id extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.2.1 - Authority Information Access.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  ASN_PARSE_E when the OCTET_STRING tag is not found or length is
 *          invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int DecodeSubjKeyId(const byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;
    int ret = 0;

    WOLFSSL_ENTER("DecodeSubjKeyId");

    if (sz <= 0) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        ret = GetOctetString(input, &idx, &length, sz);
    }
    if (ret > 0) {

        /* Get the hash or hash of the hash if wrong size. */
        ret = GetHashId(input + idx, length, cert->extSubjKeyId);
    }

    return ret;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for KeyUsage.
 * X.509: RFC 5280, 4.2.1.3 - Key Usage.
 */
static const ASNItem keyUsageASN[] = {
/* STR */ { 0, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    KEYUSAGEASN_IDX_STR = 0,
};

/* Number of items in ASN.1 template for KeyUsage. */
#define keyUsageASN_Length (sizeof(keyUsageASN) / sizeof(ASNItem))
#endif

/* Decode key usage extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.2.1 - Authority Information Access.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int DecodeKeyUsage(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length;
    int ret;
    WOLFSSL_ENTER("DecodeKeyUsage");

    ret = CheckBitString(input, &idx, &length, sz, 0, NULL);
    if (ret != 0)
        return ret;

    if (length == 0 || length > 2)
        return ASN_PARSE_E;

    cert->extKeyUsage = (word16)(input[idx]);
    if (length == 2)
        cert->extKeyUsage |= (word16)(input[idx+1] << 8);

    return 0;
#else
    ASNGetData dataASN[keyUsageASN_Length];
    word32 idx = 0;
    WOLFSSL_ENTER("DecodeKeyUsage");

    /* Clear dynamic data and set where to store extended key usage. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_Int16Bit(&dataASN[KEYUSAGEASN_IDX_STR], &cert->extKeyUsage);
    /* Parse key usage. */
    return GetASN_Items(keyUsageASN, dataASN, keyUsageASN_Length, 0, input,
                        &idx, sz);
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for KeyPurposeId.
 * X.509: RFC 5280, 4.2.1.12 - Extended Key Usage.
 */
static const ASNItem keyPurposeIdASN[] = {
/* OID */ { 0, ASN_OBJECT_ID, 0, 0, 0 },
};
enum {
    KEYPURPOSEIDASN_IDX_OID = 0,
};

/* Number of items in ASN.1 template for KeyPurposeId. */
#define keyPurposeIdASN_Length (sizeof(keyPurposeIdASN) / sizeof(ASNItem))
#endif

/* Decode extended key usage extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.1.12 - Extended Key Usage.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int DecodeExtKeyUsage(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0, oid;
    int length, ret;

    WOLFSSL_ENTER("DecodeExtKeyUsage");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }


    while (idx < (word32)sz) {
        ret = GetObjectId(input, &idx, &oid, oidCertKeyUseType, sz);
        if (ret == ASN_UNKNOWN_OID_E)
            continue;
        else if (ret < 0)
            return ret;

        switch (oid) {
            case EKU_ANY_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_ANY;
                break;
            case EKU_SERVER_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_SERVER_AUTH;
                break;
            case EKU_CLIENT_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
                break;
            case EKU_CODESIGNING_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_CODESIGN;
                break;
            case EKU_EMAILPROTECT_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_EMAILPROT;
                break;
            case EKU_TIMESTAMP_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_TIMESTAMP;
                break;
            case EKU_OCSP_SIGN_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_OCSP_SIGN;
                break;
            default:
                break;
        }

    }

    return 0;
#else
    word32 idx = 0;
    int length;
    int ret = 0;

    WOLFSSL_ENTER("DecodeExtKeyUsage");

    /* Strip SEQUENCE OF and expect to account for all the data. */
    if (GetASN_Sequence(input, &idx, &length, sz, 1) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        ret = ASN_PARSE_E;
    }

    if (ret == 0) {
    }

    /* Check all OIDs. */
    while ((ret == 0) && (idx < (word32)sz)) {
        ASNGetData dataASN[keyPurposeIdASN_Length];

        /* Clear dynamic data items and set OID type expected. */
        XMEMSET(dataASN, 0, sizeof(dataASN));
        GetASN_OID(&dataASN[KEYPURPOSEIDASN_IDX_OID], oidCertKeyUseType);
        /* Decode KeyPurposeId. */
        ret = GetASN_Items(keyPurposeIdASN, dataASN, keyPurposeIdASN_Length, 0,
                           input, &idx, sz);
        /* Skip unknown OIDs. */
        if (ret == ASN_UNKNOWN_OID_E) {
            ret = 0;
        }
        else if (ret == 0) {
            /* Store the bit for the OID. */
            switch (dataASN[KEYPURPOSEIDASN_IDX_OID].data.oid.sum) {
                case EKU_ANY_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_ANY;
                    break;
                case EKU_SERVER_AUTH_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_SERVER_AUTH;
                    break;
                case EKU_CLIENT_AUTH_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
                    break;
                case EKU_CODESIGNING_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_CODESIGN;
                    break;
                case EKU_EMAILPROTECT_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_EMAILPROT;
                    break;
                case EKU_TIMESTAMP_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_TIMESTAMP;
                    break;
                case EKU_OCSP_SIGN_OID:
                    cert->extExtKeyUsage |= EXTKEYUSE_OCSP_SIGN;
                    break;
            }

        }
    }

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifndef IGNORE_NETSCAPE_CERT_TYPE

static int DecodeNsCertType(const byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int len = 0;

    WOLFSSL_ENTER("DecodeNsCertType");

    if (CheckBitString(input, &idx, &len, (word32)sz, 0, NULL) < 0)
        return ASN_PARSE_E;

    /* Don't need to worry about unused bits as CheckBitString makes sure
     * they're zero. */
    if (idx < (word32)sz)
        cert->nsCertType = input[idx];
    else
        return ASN_PARSE_E;

    return 0;
}
#endif


#ifndef IGNORE_NAME_CONSTRAINTS
#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for GeneralSubtree.
 * X.509: RFC 5280, 4.2.1.10 - Name Constraints.
 */
static const ASNItem subTreeASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                              /* base     GeneralName */
/* BASE */     { 1, ASN_CONTEXT_SPECIFIC | 0, 0, 0, 0 },
                              /* minimum  BaseDistance DEFAULT 0*/
/* MIN  */     { 1, ASN_CONTEXT_SPECIFIC | ASN_SUBTREE_MIN, 0, 0, 1 },
                              /* maximum  BaseDistance OPTIONAL  */
/* MAX  */     { 1, ASN_CONTEXT_SPECIFIC | ASN_SUBTREE_MAX, 0, 0, 1 },
};
enum {
    SUBTREEASN_IDX_SEQ = 0,
    SUBTREEASN_IDX_BASE,
    SUBTREEASN_IDX_MIN,
    SUBTREEASN_IDX_MAX,
};

/* Number of items in ASN.1 template for GeneralSubtree. */
#define subTreeASN_Length (sizeof(subTreeASN) / sizeof(ASNItem))
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
/* Decode the Subtree's GeneralName.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in]      tag    BER tag on GeneralName.
 * @param [in, out] head   Linked list of subtree names.
 * @param [in]      heap   Dynamic memory hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when SEQUENCE is not found as expected.
 */
static int DecodeSubtreeGeneralName(const byte* input, int sz, byte tag,
                                    Base_entry** head, void* heap)
{
    Base_entry* entry;
    word32 nameIdx = 0;
    word32 len = sz;
    int strLen;
    int ret = 0;

    (void)heap;

    /* if constructed has leading sequence */
    if ((tag & ASN_CONSTRUCTED) == ASN_CONSTRUCTED) {
        ret = GetASN_Sequence(input, &nameIdx, &strLen, sz, 0);
        if (ret < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            len = strLen;
            ret = 0;
        }
    }
    if (ret == 0) {
        /* TODO: consider one malloc. */
        /* Allocate Base Entry object. */
        entry = (Base_entry*)XMALLOC(sizeof(Base_entry), heap,
                                     DYNAMIC_TYPE_ALTNAME);
        if (entry == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Allocate name. */
        entry->name = (char*)XMALLOC(len + 1, heap, DYNAMIC_TYPE_ALTNAME);
        if (entry->name == NULL) {
            XFREE(entry, heap, DYNAMIC_TYPE_ALTNAME);
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Store name, size and tag in object. */
        XMEMCPY(entry->name, &input[nameIdx], len);
        entry->name[len] = '\0';
        entry->nameSz = len;
        entry->type = tag & ASN_TYPE_MASK;

        /* Put entry at front of linked list. */
        entry->next = *head;
        *head = entry;
    }

    return ret;
}
#endif

/* Decode a subtree of a name contraint in a certificate.
 *
 * X.509: RFC 5280, 4.2.1.10 - Name Contraints.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] head   Linked list of subtree names.
 * @param [in]      heap   Dynamic memory hint.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_PARSE_E when SEQUENCE is not found as expected.
 */
static int DecodeSubtree(const byte* input, int sz, Base_entry** head,
                         void* heap)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int ret = 0;

    (void)heap;

    while (idx < (word32)sz) {
        int seqLength, strLength;
        word32 nameIdx;
        byte b, bType;

        if (GetSequence(input, &idx, &seqLength, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        if (idx >= (word32)sz) {
            WOLFSSL_MSG("\tfail: expecting tag");
            return ASN_PARSE_E;
        }

        nameIdx = idx;
        b = input[nameIdx++];

        if (GetLength(input, &nameIdx, &strLength, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        /* Get type, LSB 4-bits */
        bType = (b & ASN_TYPE_MASK);

        if (bType == ASN_DNS_TYPE || bType == ASN_RFC822_TYPE ||
                                                        bType == ASN_DIR_TYPE) {
            Base_entry* entry;

            /* if constructed has leading sequence */
            if (b & ASN_CONSTRUCTED) {
                if (GetSequence(input, &nameIdx, &strLength, sz) < 0) {
                    WOLFSSL_MSG("\tfail: constructed be a SEQUENCE");
                    return ASN_PARSE_E;
                }
            }

            entry = (Base_entry*)XMALLOC(sizeof(Base_entry), heap,
                                                          DYNAMIC_TYPE_ALTNAME);
            if (entry == NULL) {
                WOLFSSL_MSG("allocate error");
                return MEMORY_E;
            }

            entry->name = (char*)XMALLOC(strLength+1, heap, DYNAMIC_TYPE_ALTNAME);
            if (entry->name == NULL) {
                WOLFSSL_MSG("allocate error");
                XFREE(entry, heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }

            XMEMCPY(entry->name, &input[nameIdx], strLength);
            entry->name[strLength] = '\0';
            entry->nameSz = strLength;
            entry->type = bType;

            entry->next = *head;
            *head = entry;
        }

        idx += seqLength;
    }

    return ret;
#else
    DECL_ASNGETDATA(dataASN, subTreeASN_Length);
    word32 idx = 0;
    int ret = 0;

    (void)heap;

    ALLOC_ASNGETDATA(dataASN, subTreeASN_Length, ret, heap);

    /* Process all subtrees. */
    while ((ret == 0) && (idx < (word32)sz)) {
        byte minVal = 0;
        byte maxVal = 0;

        /* Clear dynamic data and set choice for GeneralName and location to
         * store minimum and maximum.
         */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * subTreeASN_Length);
        GetASN_Choice(&dataASN[SUBTREEASN_IDX_BASE], generalNameChoice);
        GetASN_Int8Bit(&dataASN[SUBTREEASN_IDX_MIN], &minVal);
        GetASN_Int8Bit(&dataASN[SUBTREEASN_IDX_MAX], &maxVal);
        /* Parse GeneralSubtree. */
        ret = GetASN_Items(subTreeASN, dataASN, subTreeASN_Length, 0, input,
                           &idx, sz);
        if (ret == 0) {
            byte t = dataASN[SUBTREEASN_IDX_BASE].tag;

            /* Check GeneralName tag is one of the types we can handle. */
            if (t == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE) ||
                t == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE) ||
                t == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {
                /* Parse the general name and store a new entry. */
                ret = DecodeSubtreeGeneralName(input +
                    GetASNItem_DataIdx(dataASN[SUBTREEASN_IDX_BASE], input),
                    dataASN[SUBTREEASN_IDX_BASE].length, t, head, heap);
            }
            /* Skip entry. */
        }
    }

    FREE_ASNGETDATA(dataASN, heap);
    return ret;
#endif
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for NameConstraints.
 * X.509: RFC 5280, 4.2.1.10 - Name Contraints.
 */
static const ASNItem nameConstraintsASN[] = {
/* SEQ     */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                         /* permittedSubtrees */
/* PERMIT  */     { 1, ASN_CONTEXT_SPECIFIC | 0, 1, 0, 1 },
                                         /* excludededSubtrees */
/* EXCLUDE */     { 1, ASN_CONTEXT_SPECIFIC | 1, 1, 0, 1 },
};
enum {
    NAMECONSTRAINTSASN_IDX_SEQ = 0,
    NAMECONSTRAINTSASN_IDX_PERMIT,
    NAMECONSTRAINTSASN_IDX_EXCLUDE,
};

/* Number of items in ASN.1 template for NameConstraints. */
#define nameConstraintsASN_Length (sizeof(nameConstraintsASN) / sizeof(ASNItem))
#endif

/* Decode name constraints extension in a certificate.
 *
 * X.509: RFC 5280, 4.2.1.10 - Name Constraints.
 *
 * @param [in]      input  Buffer holding data.
 * @param [in]      sz     Size of data in buffer.
 * @param [in, out] cert   Certificate object.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int DecodeNameConstraints(const byte* input, int sz, DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeNameConstraints");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        byte b = input[idx++];
        Base_entry** subtree = NULL;

        if (GetLength(input, &idx, &length, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
            subtree = &cert->permittedNames;
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
            subtree = &cert->excludedNames;
        else {
            WOLFSSL_MSG("\tinvalid subtree");
            return ASN_PARSE_E;
        }

        if (DecodeSubtree(input + idx, length, subtree, cert->heap) < 0) {
            WOLFSSL_MSG("\terror parsing subtree");
            return ASN_PARSE_E;
        }

        idx += length;
    }

    return 0;
#else
    DECL_ASNGETDATA(dataASN, nameConstraintsASN_Length);
    word32 idx = 0;
    int    ret = 0;

    CALLOC_ASNGETDATA(dataASN, nameConstraintsASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Parse NameConstraints. */
        ret = GetASN_Items(nameConstraintsASN, dataASN,
                           nameConstraintsASN_Length, 1, input, &idx, sz);
    }
    if (ret == 0) {
        /* If there was a permittedSubtrees then parse it. */
        if (dataASN[NAMECONSTRAINTSASN_IDX_PERMIT].data.ref.data != NULL) {
            ret = DecodeSubtree(
                    dataASN[NAMECONSTRAINTSASN_IDX_PERMIT].data.ref.data,
                    dataASN[NAMECONSTRAINTSASN_IDX_PERMIT].data.ref.length,
                    &cert->permittedNames, cert->heap);
        }
    }
    if (ret == 0) {
        /* If there was a excludedSubtrees then parse it. */
        if (dataASN[NAMECONSTRAINTSASN_IDX_EXCLUDE].data.ref.data != NULL) {
            ret = DecodeSubtree(
                    dataASN[NAMECONSTRAINTSASN_IDX_EXCLUDE].data.ref.data,
                    dataASN[NAMECONSTRAINTSASN_IDX_EXCLUDE].data.ref.length,
                    &cert->excludedNames, cert->heap);
        }
    }

    FREE_ASNGETDATA(dataASN, cert->heap);

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}
#endif /* IGNORE_NAME_CONSTRAINTS */

#if defined(WOLFSSL_CERT_EXT) && !defined(WOLFSSL_SEP)

/* Decode ITU-T X.690 OID format to a string representation
 * return string length */
int DecodePolicyOID(char *out, word32 outSz, const byte *in, word32 inSz)
{
    word32 val, inIdx = 0, outIdx = 0;
    int w = 0;

    if (out == NULL || in == NULL || outSz < 4 || inSz < 2)
        return BAD_FUNC_ARG;

    /* The first byte expands into b/40 dot b%40. */
    val = in[inIdx++];

    w = XSNPRINTF(out, outSz, "%u.%u", val / 40, val % 40);
    if (w < 0) {
        w = BUFFER_E;
        goto exit;
    }
    outIdx += w;
    val = 0;

    while (inIdx < inSz && outIdx < outSz) {
        /* extract the next OID digit from in to val */
        /* first bit is used to set if value is coded on 1 or multiple bytes */
        if (in[inIdx] & 0x80) {
            val += in[inIdx] & 0x7F;
            val *= 128;
        }
        else {
            /* write val as text into out */
            val += in[inIdx];
            w = XSNPRINTF(out + outIdx, outSz - outIdx, ".%u", val);
            if (w < 0 || (word32)w > outSz - outIdx) {
                w = BUFFER_E;
                goto exit;
            }
            outIdx += w;
            val = 0;
        }
        inIdx++;
    }
    if (outIdx == outSz)
        outIdx--;
    out[outIdx] = 0;

    w = (int)outIdx;

exit:
    return w;
}
#endif /* WOLFSSL_CERT_EXT && !WOLFSSL_SEP */

#if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
    #ifdef WOLFSSL_ASN_TEMPLATE
    /* ASN.1 template for PolicyInformation.
     * X.509: RFC 5280, 4.2.1.4 - Certificate Policies.
     */
    static const ASNItem policyInfoASN[] = {
    /* SEQ   */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                      /* policyIdentifier */
    /* ID    */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                                      /* policyQualifiers */
    /* QUALI */     { 1, ASN_SEQUENCE, 1, 0, 1 },
    };
    enum {
        POLICYINFOASN_IDX_SEQ = 0,
        POLICYINFOASN_IDX_ID,
        POLICYINFOASN_IDX_QUALI,
    };

    /* Number of items in ASN.1 template for PolicyInformation. */
    #define policyInfoASN_Length (sizeof(policyInfoASN) / sizeof(ASNItem))
    #endif

    /* Reference: https://tools.ietf.org/html/rfc5280#section-4.2.1.4 */
    static int DecodeCertPolicy(const byte* input, int sz, DecodedCert* cert)
    {
    #ifndef WOLFSSL_ASN_TEMPLATE
        word32 idx = 0;
        word32 oldIdx;
        int policy_length = 0;
        int ret;
        int total_length = 0;
    #if !defined(WOLFSSL_SEP) && defined(WOLFSSL_CERT_EXT) && \
        !defined(WOLFSSL_DUP_CERTPOL)
        int i;
    #endif

        WOLFSSL_ENTER("DecodeCertPolicy");

    #if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
        /* Check if cert is null before dereferencing below */
        if (cert == NULL)
            return BAD_FUNC_ARG;
    #else
        (void)cert;
    #endif

    #if defined(WOLFSSL_CERT_EXT)
         cert->extCertPoliciesNb = 0;
    #endif

        if (GetSequence(input, &idx, &total_length, sz) < 0) {
            WOLFSSL_MSG("\tGet CertPolicy total seq failed");
            return ASN_PARSE_E;
        }

        /* Validate total length */
        if (total_length > (sz - (int)idx)) {
            WOLFSSL_MSG("\tCertPolicy length mismatch");
            return ASN_PARSE_E;
        }

        /* Unwrap certificatePolicies */
        do {
            int length = 0;

            if (GetSequence(input, &idx, &policy_length, sz) < 0) {
                WOLFSSL_MSG("\tGet CertPolicy seq failed");
                return ASN_PARSE_E;
            }

            oldIdx = idx;
            ret = GetASNObjectId(input, &idx, &length, sz);
            if (ret != 0)
                return ret;
            policy_length -= idx - oldIdx;

            if (length > 0) {
                /* Verify length won't overrun buffer */
                if (length > (sz - (int)idx)) {
                    WOLFSSL_MSG("\tCertPolicy length exceeds input buffer");
                    return ASN_PARSE_E;
                }

        #if defined(WOLFSSL_SEP)
                cert->deviceType = (byte*)XMALLOC(length, cert->heap,
                                                         DYNAMIC_TYPE_X509_EXT);
                if (cert->deviceType == NULL) {
                    WOLFSSL_MSG("\tCouldn't alloc memory for deviceType");
                    return MEMORY_E;
                }
                cert->deviceTypeSz = length;
                XMEMCPY(cert->deviceType, input + idx, length);
                break;
        #elif defined(WOLFSSL_CERT_EXT)
                /* decode cert policy */
                if (DecodePolicyOID(cert->extCertPolicies[
                                       cert->extCertPoliciesNb], MAX_CERTPOL_SZ,
                                       input + idx, length) <= 0) {
                    WOLFSSL_MSG("\tCouldn't decode CertPolicy");
                    return ASN_PARSE_E;
                }
            #ifndef WOLFSSL_DUP_CERTPOL
                /* From RFC 5280 section 4.2.1.3 "A certificate policy OID MUST
                 * NOT appear more than once in a certificate policies
                 * extension". This is a sanity check for duplicates.
                 * extCertPolicies should only have OID values, additional
                 * qualifiers need to be stored in a separate array. */
                for (i = 0; i < cert->extCertPoliciesNb; i++) {
                    if (XMEMCMP(cert->extCertPolicies[i],
                            cert->extCertPolicies[cert->extCertPoliciesNb],
                            MAX_CERTPOL_SZ) == 0) {
                            WOLFSSL_MSG("Duplicate policy OIDs not allowed");
                            WOLFSSL_MSG("Use WOLFSSL_DUP_CERTPOL if wanted");
                            return CERTPOLICIES_E;
                    }
                }
            #endif /* !WOLFSSL_DUP_CERTPOL */
                cert->extCertPoliciesNb++;
        #else
                WOLFSSL_LEAVE("DecodeCertPolicy : unsupported mode", 0);
                return 0;
        #endif
            }
            idx += policy_length;
        } while((int)idx < total_length
    #if defined(WOLFSSL_CERT_EXT)
            && cert->extCertPoliciesNb < MAX_CERTPOL_NB
    #endif
        );

        WOLFSSL_LEAVE("DecodeCertPolicy", 0);
        return 0;
    #else /* WOLFSSL_ASN_TEMPLATE */
        word32 idx = 0;
        int ret = 0;
        int total_length = 0;
    #if !defined(WOLFSSL_SEP) && defined(WOLFSSL_CERT_EXT) && \
        !defined(WOLFSSL_DUP_CERTPOL)
        int i;
    #endif

        WOLFSSL_ENTER("DecodeCertPolicy");
        #if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
        /* Check if cert is null before dereferencing below */
        if (cert == NULL)
            ret = BAD_FUNC_ARG;
        #endif

        if (ret == 0) {
        #if defined(WOLFSSL_CERT_EXT)
             cert->extCertPoliciesNb = 0;
        #endif

            /* Strip SEQUENCE OF and check using all data. */
            if (GetASN_Sequence(input, &idx, &total_length, sz, 1) < 0) {
                ret = ASN_PARSE_E;
            }
        }

        /* Unwrap certificatePolicies */
        while ((ret == 0) && ((int)idx < total_length)
        #if defined(WOLFSSL_CERT_EXT)
            && (cert->extCertPoliciesNb < MAX_CERTPOL_NB)
        #endif
               ) {
            ASNGetData dataASN[policyInfoASN_Length];
            byte* data;
            word32 length = 0;

            /* Clear dynamic data and check OID is a cert policy type. */
            XMEMSET(dataASN, 0, sizeof(dataASN));
            GetASN_OID(&dataASN[POLICYINFOASN_IDX_ID], oidCertPolicyType);
            ret = GetASN_Items(policyInfoASN, dataASN, policyInfoASN_Length, 1,
                               input, &idx, sz);
            if (ret == 0) {
                /* Get the OID. */
                GetASN_OIDData(&dataASN[POLICYINFOASN_IDX_ID], &data, &length);
                if (length == 0) {
                    ret = ASN_PARSE_E;
                }
            }
            #if defined(WOLFSSL_SEP)
            /* Store OID in device type. */
            if (ret == 0) {
                cert->deviceType = (byte*)XMALLOC(length, cert->heap,
                                                  DYNAMIC_TYPE_X509_EXT);
                if (cert->deviceType == NULL) {
                    WOLFSSL_MSG("\tCouldn't alloc memory for deviceType");
                    ret = MEMORY_E;
                }
            }
            if (ret == 0) {
                /* Store device type data and length. */
                cert->deviceTypeSz = length;
                XMEMCPY(cert->deviceType, data, length);
                break;
            }
            #elif defined(WOLFSSL_CERT_EXT)
            if (ret == 0) {
                /* Decode cert policy. */
                if (DecodePolicyOID(
                                 cert->extCertPolicies[cert->extCertPoliciesNb],
                                 MAX_CERTPOL_SZ, data, length) <= 0) {
                    WOLFSSL_MSG("\tCouldn't decode CertPolicy");
                    ret = ASN_PARSE_E;
                }
            }
            #ifndef WOLFSSL_DUP_CERTPOL
            /* From RFC 5280 section 4.2.1.3 "A certificate policy OID MUST
             * NOT appear more than once in a certificate policies
             * extension". This is a sanity check for duplicates.
             * extCertPolicies should only have OID values, additional
             * qualifiers need to be stored in a seperate array. */
            for (i = 0; (ret == 0) && (i < cert->extCertPoliciesNb); i++) {
                if (XMEMCMP(cert->extCertPolicies[i],
                            cert->extCertPolicies[cert->extCertPoliciesNb],
                            MAX_CERTPOL_SZ) == 0) {
                    WOLFSSL_MSG("Duplicate policy OIDs not allowed");
                    WOLFSSL_MSG("Use WOLFSSL_DUP_CERTPOL if wanted");
                    ret = CERTPOLICIES_E;
                }
            }
            #endif /* !defined(WOLFSSL_DUP_CERTPOL) */
            if (ret == 0) {
                /* Keep count of policies seen. */
                cert->extCertPoliciesNb++;
            }
            #else
                (void)data;
                WOLFSSL_LEAVE("DecodeCertPolicy : unsupported mode", 0);
                break;
            #endif
        }

        WOLFSSL_LEAVE("DecodeCertPolicy", 0);
        return ret;
    #endif /* WOLFSSL_ASN_TEMPLATE */
    }
#endif /* WOLFSSL_SEP */

/* Macro to check if bit is set, if not sets and return success.
    Otherwise returns failure */
/* Macro required here because bit-field operation */
#ifndef WOLFSSL_NO_ASN_STRICT
    #define VERIFY_AND_SET_OID(bit) \
        if ((bit) == 0) \
            (bit) = 1; \
        else \
            return ASN_OBJECT_ID_E;
#else
    /* With no strict defined, the verify is skipped */
#define VERIFY_AND_SET_OID(bit) bit = 1;
#endif

/* Parse extension type specific data based on OID sum.
 *
 * Supported extensions:
 *   Basic Constraints - BASIC_CA_OID
 *   CRL Distribution Points - CRL_DIST_OID
 *   Authority Information Access - AUTH_INFO_OID
 *   Subject Alternative Name - ALT_NAMES_OID
 *   Authority Key Identifier - AUTH_KEY_OID
 *   Subject Key Identifier - SUBJ_KEY_OID
 *   Certificate Policies - CERT_POLICY_OID (conditional parsing)
 *   Key Usage - KEY_USAGE_OID
 *   Extended Key Usage - EXT_KEY_USAGE_OID
 *   Name Constraints - NAME_CONS_OID
 *   Inhibit anyPolicy - INHIBIT_ANY_OID
 *   Netscape Certificate Type - NETSCAPE_CT_OID (able to be excluded)
 *   OCSP no check - OCSP_NOCHECK_OID (when compiling OCSP)
 * Unsupported extensions from RFC 5280:
 *   4.2.1.5 - Policy mappings
 *   4.2.1.7 - Issuer Alternative Name
 *   4.2.1.8 - Subject Directory Attributes
 *   4.2.1.11 - Policy Constraints
 *   4.2.1.15 - Freshest CRL
 *   4.2.2.2 - Subject Information Access
 *
 * @param [in]      input     Buffer containing extension type specific data.
 * @param [in]      length    Length of data.
 * @param [in]      oid       OID sum for extension.
 * @param [in]      critical  Whether extension is critical.
 * @param [in, out] cert      Certificate object.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoding is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  Other -ve value on error.
 */
static int DecodeExtensionType(const byte* input, int length, word32 oid,
                               byte critical, DecodedCert* cert,
                               int *isUnknownExt)
{
    int ret = 0;
    word32 idx = 0;

    if (isUnknownExt != NULL)
        *isUnknownExt = 0;

    switch (oid) {
        /* Basic Constraints. */
        case BASIC_CA_OID:
            VERIFY_AND_SET_OID(cert->extBasicConstSet);
            if (DecodeBasicCaConstraint(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;

        /* CRL Distribution point. */
        case CRL_DIST_OID:
            VERIFY_AND_SET_OID(cert->extCRLdistSet);
            if (DecodeCrlDist(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;

        /* Authority information access. */
        case AUTH_INFO_OID:
            VERIFY_AND_SET_OID(cert->extAuthInfoSet);
            if (DecodeAuthInfo(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;

        /* Subject alternative name. */
        case ALT_NAMES_OID:
            VERIFY_AND_SET_OID(cert->extSubjAltNameSet);
            ret = DecodeAltNames(input, length, cert);
            break;

        /* Authority Key Identifier. */
        case AUTH_KEY_OID:
            VERIFY_AND_SET_OID(cert->extAuthKeyIdSet);
            #ifndef WOLFSSL_ALLOW_CRIT_SKID
                /* This check is added due to RFC 5280 section 4.2.1.1
                 * stating that conforming CA's must mark this extension
                 * as non-critical. When parsing extensions check that
                 * certificate was made in compliance with this. */
                if (critical) {
                    WOLFSSL_MSG("Critical Auth Key ID is not allowed");
                    WOLFSSL_MSG("Use macro WOLFSSL_ALLOW_CRIT_SKID if wanted");
                    ret = ASN_CRIT_EXT_E;
                }
            #endif
            if ((ret == 0) && (DecodeAuthKeyId(input, length, cert) < 0)) {
                ret = ASN_PARSE_E;
            }
            break;

        /* Subject Key Identifier. */
        case SUBJ_KEY_OID:
            VERIFY_AND_SET_OID(cert->extSubjKeyIdSet);
            #ifndef WOLFSSL_ALLOW_CRIT_SKID
                /* This check is added due to RFC 5280 section 4.2.1.2
                 * stating that conforming CA's must mark this extension
                 * as non-critical. When parsing extensions check that
                 * certificate was made in compliance with this. */
                if (critical) {
                    WOLFSSL_MSG("Critical Subject Key ID is not allowed");
                    WOLFSSL_MSG("Use macro WOLFSSL_ALLOW_CRIT_SKID if wanted");
                    ret = ASN_CRIT_EXT_E;
                }
            #endif

            if ((ret == 0) && (DecodeSubjKeyId(input, length, cert) < 0)) {
                ret = ASN_PARSE_E;
            }
            break;

        /* Certificate policies. */
        case CERT_POLICY_OID:
            #if defined(WOLFSSL_SEP)
                VERIFY_AND_SET_OID(cert->extCertPolicySet);
            #endif
            #if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
                if (DecodeCertPolicy(input, length, cert) < 0) {
                    ret = ASN_PARSE_E;
                }
            #else
                WOLFSSL_MSG("Certificate Policy extension not supported yet.");
            #endif
            break;

        /* Key usage. */
        case KEY_USAGE_OID:
            VERIFY_AND_SET_OID(cert->extKeyUsageSet);
            if (DecodeKeyUsage(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;

        /* Extended key usage. */
        case EXT_KEY_USAGE_OID:
            VERIFY_AND_SET_OID(cert->extExtKeyUsageSet);
            if (DecodeExtKeyUsage(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;

        #ifndef IGNORE_NAME_CONSTRAINTS
        /* Name constraints. */
        case NAME_CONS_OID:
        #ifndef WOLFSSL_NO_ASN_STRICT
            /* Verify RFC 5280 Sec 4.2.1.10 rule:
                "The name constraints extension,
                which MUST be used only in a CA certificate" */
            if (!cert->isCA) {
                WOLFSSL_MSG("Name constraints allowed only for CA certs");
                ret = ASN_NAME_INVALID_E;
            }
        #endif
            VERIFY_AND_SET_OID(cert->extNameConstraintSet);
            if (DecodeNameConstraints(input, length, cert) < 0) {
                ret = ASN_PARSE_E;
            }
            break;
        #endif /* IGNORE_NAME_CONSTRAINTS */

        /* Inhibit anyPolicy. */
        case INHIBIT_ANY_OID:
            VERIFY_AND_SET_OID(cert->inhibitAnyOidSet);
            WOLFSSL_MSG("Inhibit anyPolicy extension not supported yet.");
            break;

   #ifndef IGNORE_NETSCAPE_CERT_TYPE
        /* Netscape's certificate type. */
        case NETSCAPE_CT_OID:
            if (DecodeNsCertType(input, length, cert) < 0)
                ret = ASN_PARSE_E;
            break;
    #endif
        case POLICY_CONST_OID:
            VERIFY_AND_SET_OID(cert->extPolicyConstSet);
            if (DecodePolicyConstraints(&input[idx], length, cert) < 0)
                return ASN_PARSE_E;
            break;
        default:
            if (isUnknownExt != NULL)
                *isUnknownExt = 1;
        #ifndef WOLFSSL_NO_ASN_STRICT
            /* While it is a failure to not support critical extensions,
             * still parse the certificate ignoring the unsupported
             * extension to allow caller to accept it with the verify
             * callback. */
            if (critical)
                ret = ASN_CRIT_EXT_E;
        #endif
            break;
    }

    return ret;
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for extensions.
 * X.509: RFC 5280, 4.1 - Basic Certificate Fields.
 */
static const ASNItem certExtHdrASN[] = {
/* EXTTAG */ { 0, ASN_CONTEXT_SPECIFIC | 3, 1, 1, 0 },
/* EXTSEQ */     { 1, ASN_SEQUENCE, 1, 1, 0 },
};
enum {
    CERTEXTHDRASN_IDX_EXTTAG = 0,
    CERTEXTHDRASN_IDX_EXTSEQ,
};

/* Number of itesm in ASN.1 template for extensions. */
#define certExtHdrASN_Length (sizeof(certExtHdrASN) / sizeof(ASNItem))

/* ASN.1 template for Extension.
 * X.509: RFC 5280, 4.1 - Basic Certificate Fields.
 */
static const ASNItem certExtASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                              /* Extension object id */
/* OID  */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                              /* critical - when true, must be parseable. */
/* CRIT */     { 1, ASN_BOOLEAN, 0, 0, 1 },
                              /* Data for extension - leave index at start of data. */
/* VAL  */     { 1, ASN_OCTET_STRING, 0, 1, 0 },
};
enum {
    CERTEXTASN_IDX_SEQ = 0,
    CERTEXTASN_IDX_OID,
    CERTEXTASN_IDX_CRIT,
    CERTEXTASN_IDX_VAL,
};

/* Number of items in ASN.1 template for Extension. */
#define certExtASN_Length (sizeof(certExtASN) / sizeof(ASNItem))
#endif

#if defined(WOLFSSL_CUSTOM_OID) && defined(WOLFSSL_ASN_TEMPLATE) \
    && defined(HAVE_OID_DECODING)
int wc_SetUnknownExtCallback(DecodedCert* cert,
                             wc_UnknownExtCallback cb) {
    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

    cert->unknownExtCallback = cb;
    return 0;
}
#endif

/*
 *  Processing the Certificate Extensions. This does not modify the current
 *  index. It is works starting with the recorded extensions pointer.
 */
static int DecodeCertExtensions(DecodedCert* cert)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret = 0;
    word32 idx = 0;
    int sz = cert->extensionsSz;
    const byte* input = cert->extensions;
    int length;
    word32 oid;
    byte critical = 0;
    byte criticalFail = 0;
    byte tag = 0;

    WOLFSSL_ENTER("DecodeCertExtensions");

    if (input == NULL || sz == 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_CERT_REQ
    if (!cert->isCSR)
#endif
    { /* Not included in CSR */
        if (GetASNTag(input, &idx, &tag, sz) < 0) {
            return ASN_PARSE_E;
        }

        if (tag != ASN_EXTENSIONS) {
            WOLFSSL_MSG("\tfail: should be an EXTENSIONS");
            return ASN_PARSE_E;
        }

        if (GetLength(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: invalid length");
            return ASN_PARSE_E;
        }
    }

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE (1)");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        word32 localIdx;

        if (GetSequence(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if ((ret = GetObjectId(input, &idx, &oid, oidCertExtType, sz)) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ret;
        }

        /* check for critical flag */
        critical = 0;
        if ((idx + 1) > (word32)sz) {
            WOLFSSL_MSG("\tfail: malformed buffer");
            return BUFFER_E;
        }

        localIdx = idx;
        if (GetASNTag(input, &localIdx, &tag, sz) == 0) {
            if (tag == ASN_BOOLEAN) {
                ret = GetBoolean(input, &idx, sz);
                if (ret < 0) {
                    WOLFSSL_MSG("\tfail: critical boolean");
                    return ret;
                }

                critical = (byte)ret;
            }
        }

        /* process the extension based on the OID */
        ret = GetOctetString(input, &idx, &length, sz);
        if (ret < 0) {
            WOLFSSL_MSG("\tfail: bad OCTET STRING");
            return ret;
        }

        ret = DecodeExtensionType(input + idx, length, oid, critical, cert,
                                  NULL);
        if (ret == ASN_CRIT_EXT_E) {
            ret = 0;
            criticalFail = 1;
        }
        if (ret < 0)
            goto end;
        idx += length;
    }

    ret = criticalFail ? ASN_CRIT_EXT_E : 0;
end:
    return ret;
#else
    DECL_ASNGETDATA(dataASN, certExtASN_Length);
    ASNGetData dataExtsASN[certExtHdrASN_Length];
    int ret = 0;
    const byte* input = cert->extensions;
    int sz = cert->extensionsSz;
    word32 idx = 0;
    int criticalRet = 0;
    int offset = 0;

    WOLFSSL_ENTER("DecodeCertExtensions");

    if (input == NULL || sz == 0)
        ret = BAD_FUNC_ARG;

    ALLOC_ASNGETDATA(dataASN, certExtASN_Length, ret, cert->heap);

#ifdef WOLFSSL_CERT_REQ
    if (cert->isCSR) {
        offset = CERTEXTHDRASN_IDX_EXTSEQ;
    }
#endif
    if (ret == 0) {
        /* Clear dynamic data. */
        XMEMSET(dataExtsASN, 0, sizeof(dataExtsASN));
        /* Parse extensions header. */
        ret = GetASN_Items(certExtHdrASN + offset, dataExtsASN + offset,
                           certExtHdrASN_Length - offset, 0, input, &idx, sz);
    }
    /* Parse each extension. */
    while ((ret == 0) && (idx < (word32)sz)) {
        byte critical = 0;
        int isUnknownExt = 0;

        /* Clear dynamic data. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * certExtASN_Length);
        /* Ensure OID is an extention type. */
        GetASN_OID(&dataASN[CERTEXTASN_IDX_OID], oidCertExtType);
        /* Set criticality variable. */
        GetASN_Int8Bit(&dataASN[CERTEXTASN_IDX_CRIT], &critical);
        /* Parse extension wrapper. */
        ret = GetASN_Items(certExtASN, dataASN, certExtASN_Length, 0, input,
                           &idx, sz);
        if (ret == 0) {
            word32 oid = dataASN[CERTEXTASN_IDX_OID].data.oid.sum;
            int length = dataASN[CERTEXTASN_IDX_VAL].length;

            /* Decode the extension by type. */
            ret = DecodeExtensionType(input + idx, length, oid, critical, cert,
                                      &isUnknownExt);
#if defined(WOLFSSL_CUSTOM_OID) && defined(HAVE_OID_DECODING)
            if (isUnknownExt && (cert->unknownExtCallback != NULL)) {
                word16 decOid[MAX_OID_SZ];
                word32 decOidSz = sizeof(decOid);
                ret = DecodeObjectId(
                          dataASN[CERTEXTASN_IDX_OID].data.oid.data,
                          dataASN[CERTEXTASN_IDX_OID].data.oid.length,
                          decOid, &decOidSz);
                if (ret != 0) {
                    /* Should never get here as the extension was successfully
                     * decoded earlier. Something might be corrupted. */
                    WOLFSSL_MSG("DecodeObjectId() failed. Corruption?");
                    WOLFSSL_ERROR(ret);
                }

                ret = cert->unknownExtCallback(decOid, decOidSz, critical,
                          dataASN[CERTEXTASN_IDX_VAL].data.buffer.data,
                          dataASN[CERTEXTASN_IDX_VAL].length);
            }
#endif
            (void)isUnknownExt;

            /* Move index on to next extension. */
            idx += length;
        }
        /* Don't fail criticality until all other extensions have been checked.
         */
        if (ret == ASN_CRIT_EXT_E) {
            criticalRet = ASN_CRIT_EXT_E;
            ret = 0;
        }
    }

    if (ret == 0) {
        /* Use criticality return. */
        ret = criticalRet;
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
#endif
}

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN template for an X509 certificate.
 * X.509: RFC 5280, 4.1 - Basic Certificate Fields.
 */
static const ASNItem x509CertASN[] = {
        /* Certificate ::= SEQUENCE */
/* SEQ                           */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* tbsCertificate       TBSCertificate */
                                                   /* TBSCertificate ::= SEQUENCE */
/* TBS_SEQ                       */        { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* version         [0]  EXPLICT Version DEFAULT v1 */
/* TBS_VER                       */            { 2, ASN_CONTEXT_SPECIFIC | ASN_X509_CERT_VERSION, 1, 1, 1 },
                                                   /* Version ::= INTEGER { v1(0), v2(1), v3(2) */
/* TBS_VER_INT                   */                { 3, ASN_INTEGER, 0, 0, 0 },
                                                   /* serialNumber         CertificateSerialNumber */
                                                   /* CetificateSerialNumber ::= INTEGER */
/* TBS_SERIAL                    */            { 2, ASN_INTEGER, 0, 0, 0 },
                                                   /* signature            AlgorithmIdentifier */
                                                   /* AlgorithmIdentifier ::= SEQUENCE */
/* TBS_ALGOID_SEQ                */            { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* Algorithm    OBJECT IDENTIFIER */
/* TBS_ALGOID_OID                */                { 3, ASN_OBJECT_ID, 0, 0, 0 },
                                                   /* parameters   ANY defined by algorithm OPTIONAL */
/* TBS_ALGOID_PARAMS             */                { 3, ASN_TAG_NULL, 0, 0, 1 },
                                                   /* issuer               Name */
/* TBS_ISSUER_SEQ                */            { 2, ASN_SEQUENCE, 1, 0, 0 },
                                                   /* validity             Validity */
                                                   /* Validity ::= SEQUENCE */
/* TBS_VALIDITY_SEQ              */            { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* notBefore   Time */
                                                   /* Time :: CHOICE { UTCTime, GeneralizedTime } */
/* TBS_VALIDITY_NOTB_UTC         */                { 3, ASN_UTC_TIME, 0, 0, 2 },
/* TBS_VALIDITY_NOTB_GT          */                { 3, ASN_GENERALIZED_TIME, 0, 0, 2 },
                                                   /* notAfter   Time */
                                                   /* Time :: CHOICE { UTCTime, GeneralizedTime } */
/* TBS_VALIDITY_NOTA_UTC         */                { 3, ASN_UTC_TIME, 0, 0, 3 },
/* TBS_VALIDITY_NOTA_GT          */                { 3, ASN_GENERALIZED_TIME, 0, 0, 3 },
                                                   /* subject              Name */
/* TBS_SUBJECT_SEQ               */            { 2, ASN_SEQUENCE, 1, 0, 0 },
                                                   /* subjectPublicKeyInfo SubjectPublicKeyInfo */
/* TBS_SPUBKEYINFO_SEQ           */            { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* algorithm          AlgorithmIdentifier */
                                                   /* AlgorithmIdentifier ::= SEQUENCE */
/* TBS_SPUBKEYINFO_ALGO_SEQ      */                { 3, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* Algorithm    OBJECT IDENTIFIER */
/* TBS_SPUBKEYINFO_ALGO_OID      */                    { 4, ASN_OBJECT_ID, 0, 0, 0 },
                                                   /* parameters   ANY defined by algorithm OPTIONAL */
/* TBS_SPUBKEYINFO_ALGO_NOPARAMS */                    { 4, ASN_TAG_NULL, 0, 0, 1 },
/* TBS_SPUBKEYINFO_ALGO_CURVEID  */                    { 4, ASN_OBJECT_ID, 0, 0, 1 },
                                                   /* subjectPublicKey   BIT STRING */
/* TBS_SPUBKEYINFO_PUBKEY        */                { 3, ASN_BIT_STRING, 0, 0, 0 },
                                                   /* issuerUniqueID       UniqueIdentfier OPTIONAL */
/* TBS_ISSUERUID                 */            { 2, ASN_CONTEXT_SPECIFIC | 1, 0, 0, 1 },
                                                   /* subjectUniqueID      UniqueIdentfier OPTIONAL */
/* TBS_SUBJECTUID                */            { 2, ASN_CONTEXT_SPECIFIC | 2, 0, 0, 1 },
                                                   /* extensions           Extensions OPTIONAL */
/* TBS_EXT                       */            { 2, ASN_CONTEXT_SPECIFIC | 3, 1, 1, 1 },
/* TBS_EXT_SEQ                   */                { 3, ASN_SEQUENCE, 1, 0, 0 },
                                                   /* signatureAlgorithm   AlgorithmIdentifier */
                                                   /* AlgorithmIdentifier ::= SEQUENCE */
/* SIGALGO_SEQ                   */        { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* Algorithm    OBJECT IDENTIFIER */
/* SIGALGO_OID                   */            { 2, ASN_OBJECT_ID, 0, 0, 0 },
                                                   /* parameters   ANY defined by algorithm OPTIONAL */
/* SIGALGO_PARAMS                */            { 2, ASN_TAG_NULL, 0, 0, 1 },
                                                   /* signature            BIT STRING */
/* SIGNATURE                     */        { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    X509CERTASN_IDX_SEQ = 0,
    X509CERTASN_IDX_TBS_SEQ,
    X509CERTASN_IDX_TBS_VER,
    X509CERTASN_IDX_TBS_VER_INT,
    X509CERTASN_IDX_TBS_SERIAL,
    X509CERTASN_IDX_TBS_ALGOID_SEQ,
    X509CERTASN_IDX_TBS_ALGOID_OID,
    X509CERTASN_IDX_TBS_ALGOID_PARAMS,
    X509CERTASN_IDX_TBS_ISSUER_SEQ,
    X509CERTASN_IDX_TBS_VALIDITY_SEQ,
    X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC,
    X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT,
    X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC,
    X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT,
    X509CERTASN_IDX_TBS_SUBJECT_SEQ,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_SEQ,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_OID,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_NOPARAMS,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_CURVEID,
    X509CERTASN_IDX_TBS_SPUBKEYINFO_PUBKEY,
    X509CERTASN_IDX_TBS_ISSUERUID,
    X509CERTASN_IDX_TBS_SUBJECTUID,
    X509CERTASN_IDX_TBS_EXT,
    X509CERTASN_IDX_TBS_EXT_SEQ,
    X509CERTASN_IDX_SIGALGO_SEQ,
    X509CERTASN_IDX_SIGALGO_OID,
    X509CERTASN_IDX_SIGALGO_PARAMS,
    X509CERTASN_IDX_SIGNATURE,
};

/* Number of items in ASN template for an X509 certificate. */
#define x509CertASN_Length (sizeof(x509CertASN) / sizeof(ASNItem))

/* Check the data data.
 *
 * @param [in] dataASN   ASN template dynamic data item.
 * @param [in] dataType  BEFORE or AFTER date.
 * @return  0 on success.
 * @return  ASN_TIME_E when BER tag is nor UTC or GENERALIZED time.
 * @return  ASN_DATE_SZ_E when time data is not supported.
 * @return  ASN_BEFORE_DATE_E when BEFORE date is invalid.
 * @return  ASN_AFTER_DATE_E when AFTER date is invalid.
 */
static int CheckDate(ASNGetData *dataASN, int dateType)
{
    int ret = 0;

    /* Check BER tag is valid. */
    if ((dataASN->tag != ASN_UTC_TIME) &&
            (dataASN->tag != ASN_GENERALIZED_TIME)) {
        ret = ASN_TIME_E;
    }
    /* Check date length is valid. */
    if ((ret == 0) && ((dataASN->length > MAX_DATE_SIZE) ||
                       (dataASN->length < MIN_DATE_SIZE))) {
        ret = ASN_DATE_SZ_E;
    }

#ifndef NO_ASN_TIME
    /* Check date is a valid string and BEFORE or AFTER now. */
    if ((ret == 0) &&
            (!XVALIDATE_DATE(dataASN->data.ref.data, dataASN->tag, dateType))) {
        if (dateType == BEFORE) {
            ret = ASN_BEFORE_DATE_E;
        }
        else {
            ret = ASN_AFTER_DATE_E;
        }
    }
#endif
    (void)dateType;

    return ret;
}

/* Decode a certificate. Internal/non-public API.
 *
 * @param [in]  cert             Certificate object.
 * @param [in]  verify           Whether to verify dates before and after now.
 * @param [out] criticalExt      Critical extension return code.
 * @param [out] badDateRet       Bad date return code.
 * @param [in]  stopAtPubKey     Stop parsing before subkectPublicKeyInfo.
 * @param [in]  stopAfterPubKey  Stop parsing after subkectPublicKeyInfo.
 * @return  0 on success.
 * @return  ASN_CRIT_EXT_E when a critical extension was not recognized.
 * @return  ASN_TIME_E when date BER tag is nor UTC or GENERALIZED time.
 * @return  ASN_DATE_SZ_E when time data is not supported.
 * @return  ASN_BEFORE_DATE_E when BEFORE date is invalid.
 * @return  ASN_AFTER_DATE_E when AFTER date is invalid.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
static int DecodeCertInternal(DecodedCert* cert, int verify, int* criticalExt,
                              int* badDateRet, int stopAtPubKey,
                              int stopAfterPubKey)
{
    DECL_ASNGETDATA(dataASN, x509CertASN_Length);
    int ret = 0;
    int badDate = 0;
    int i;
    byte version;
    word32 idx;
    word32 serialSz;
    int done = 0;

    CALLOC_ASNGETDATA(dataASN, x509CertASN_Length, ret, cert->heap);

    if (ret == 0) {
        version = 0;
        serialSz = EXTERNAL_SERIAL_SIZE;

        /* Get the version and put the serial number into the buffer. */
        GetASN_Int8Bit(&dataASN[X509CERTASN_IDX_TBS_VER_INT], &version);
        GetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_SERIAL], cert->serial,
                &serialSz);
        /* Check OID types for signature, algorithm, ECC curve and sigAlg. */
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_ALGOID_OID], oidSigType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_OID],
                oidKeyType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_CURVEID],
                oidCurveType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_SIGALGO_OID], oidSigType);
        /* Parse the X509 certificate. */
        ret = GetASN_Items(x509CertASN, dataASN, x509CertASN_Length, 1,
                           cert->source, &cert->srcIdx, cert->maxIdx);
    }
    /* Check version is valid/supported - can't be negative. */
    if ((ret == 0) && (version > MAX_X509_VERSION)) {
        WOLFSSL_MSG("Unexpected certificate version");
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* Set fields extracted from data. */
        cert->version = version;
        cert->serialSz = serialSz;
        cert->signatureOID = dataASN[X509CERTASN_IDX_TBS_ALGOID_OID].data.oid.sum;
        cert->keyOID = dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_OID].data.oid.sum;
        cert->certBegin = dataASN[X509CERTASN_IDX_TBS_SEQ].offset;

        /* No bad date error - don't always care. */
        badDate = 0;
        /* Find the item with the BEFORE date and check it. */
        i = (dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC].tag != 0)
                ? X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC
                : X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT;
        if ((CheckDate(&dataASN[i], BEFORE) < 0) && verify) {
            badDate = ASN_BEFORE_DATE_E;
        }
        /* Store reference to BEFOREdate. */
        cert->beforeDate = GetASNItem_Addr(dataASN[i], cert->source);
        cert->beforeDateLen = GetASNItem_Length(dataASN[i], cert->source);

        /* Find the item with the AFTER date and check it. */
        i = (dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC].tag != 0)
                ? X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC
                : X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT;
        if ((CheckDate(&dataASN[i], AFTER) < 0) && verify) {
            badDate = ASN_AFTER_DATE_E;
        }
        /* Store reference to AFTER date. */
        cert->afterDate = GetASNItem_Addr(dataASN[i], cert->source);
        cert->afterDateLen = GetASNItem_Length(dataASN[i], cert->source);

        /* Get the issuer name and calculate hash. */
        idx = dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ].offset;
        ret = GetCertName(cert, cert->issuer, cert->issuerHash, ISSUER,
                          cert->source, &idx,
                          dataASN[X509CERTASN_IDX_TBS_VALIDITY_SEQ].offset);
    }
    if (ret == 0) {
        /* Get the subject name and calculate hash. */
        idx = dataASN[X509CERTASN_IDX_TBS_SUBJECT_SEQ].offset;
        ret = GetCertName(cert, cert->subject, cert->subjectHash, SUBJECT,
                          cert->source, &idx,
                          dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ].offset);
    }
    if (ret == 0) {
        /* Determine if self signed by comparing issuer and subject hashes. */
        cert->selfSigned = XMEMCMP(cert->issuerHash, cert->subjectHash,
                                   KEYID_SIZE) == 0 ? 1 : 0;

        if (stopAtPubKey) {
            /* Return any bad date error through badDateRet and return offset of
             * subjectPublicKeyInfo.
             */
            if (badDateRet != NULL) {
                *badDateRet = badDate;
            }
            ret = dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ].offset;
            done = 1;
        }
    }

    if ((ret == 0) && (!done)) {
        /* Parse the public key. */
        idx = dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ].offset;
        ret = GetCertKey(cert, cert->source, &idx,
                dataASN[X509CERTASN_IDX_TBS_ISSUERUID].offset);
        if ((ret == 0) && stopAfterPubKey) {
            /* Return any bad date error through badDateRed and return offset
             * after subjectPublicKeyInfo.
             */
            if (badDateRet != NULL) {
                *badDateRet = badDate;
            }
            done = 1;
        }
    }
    if ((ret == 0) && (!done) &&
            (dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.ref.data != NULL)) {
    #ifndef ALLOW_V1_EXTENSIONS
        /* Certificate extensions were only defined in version 2. */
        if (cert->version < 2) {
            WOLFSSL_MSG("\tv1 and v2 certs not allowed extensions");
            ret = ASN_VERSION_E;
        }
    #endif
        if (ret == 0) {
            /* Save references to extension data. */
            cert->extensions    = GetASNItem_Addr(
                    dataASN[X509CERTASN_IDX_TBS_EXT], cert->source);
            cert->extensionsSz  = GetASNItem_Length(
                    dataASN[X509CERTASN_IDX_TBS_EXT], cert->source);
            cert->extensionsIdx = dataASN[X509CERTASN_IDX_TBS_EXT].offset;

            /* Decode the extension data starting at [3]. */
            ret = DecodeCertExtensions(cert);
            if (criticalExt != NULL) {
                if (ret == ASN_CRIT_EXT_E) {
                    /* Return critical extension not recognized. */
                    *criticalExt = ret;
                    ret = 0;
                }
                else {
                    /* No critical extension error. */
                    *criticalExt = 0;
                }
            }
        }
        if (ret == 0) {
            /* Advance past extensions. */
            cert->srcIdx = dataASN[X509CERTASN_IDX_SIGALGO_SEQ].offset;
        }
    }

    if ((ret == 0) && (!done)) {
        /* Store the signature information. */
        cert->sigIndex = dataASN[X509CERTASN_IDX_SIGALGO_SEQ].offset;
        GetASN_GetConstRef(&dataASN[X509CERTASN_IDX_SIGNATURE],
                &cert->signature, &cert->sigLength);
        /* Make sure 'signature' and 'signatureAlgorithm' are the same. */
        if (dataASN[X509CERTASN_IDX_SIGALGO_OID].data.oid.sum
                != cert->signatureOID) {
            ret = ASN_SIG_OID_E;
        }
        /* NULL tagged item not allowed after ECDSA or EdDSA algorithm OID. */
        if (IsSigAlgoECC(cert->signatureOID) &&
                (dataASN[X509CERTASN_IDX_SIGALGO_PARAMS].tag != 0)) {
            ret = ASN_PARSE_E;
        }
    }
    if ((ret == 0) && (!done) && (badDate != 0)) {
        /* Parsed whole certificate fine but return any date errors. */
        ret = badDate;
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
}

/* Decode BER/DER data into certificate object.
 *
 * BER/DER data information held in source, srcIdx and maxIdx fields of
 * certificate object.
 *
 * @param [in] cert         Decoded certificate object.
 * @param [in] verify       Whether to find CA and verify certificate.
 * @param [in] criticalExt  Any error for critical extensions not recognized.
 * @return  0 on success.
 * @return  ASN_CRIT_EXT_E when a critical extension was not recognized.
 * @return  ASN_TIME_E when date BER tag is nor UTC or GENERALIZED time.
 * @return  ASN_DATE_SZ_E when time data is not supported.
 * @return  ASN_BEFORE_DATE_E when BEFORE date is invalid.
 * @return  ASN_AFTER_DATE_E when AFTER date is invalid.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_BITSTR_E when the expected BIT_STRING tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
int DecodeCert(DecodedCert* cert, int verify, int* criticalExt)
{
    return DecodeCertInternal(cert, verify, criticalExt, NULL, 0, 0);
}

#ifdef WOLFSSL_CERT_REQ
/* ASN.1 template for certificate request Attribute.
 * PKCS #10: RFC 2986, 4.1 - CertificationRequestInfo
 */
static const ASNItem reqAttrASN[] = {
/* SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                              /* type */
/* TYPE */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                              /* values */
/* VALS */     { 1, ASN_SET, 1, 0, 0 },
};
enum {
    REQATTRASN_IDX_SEQ = 0,
    REQATTRASN_IDX_TYPE,
    REQATTRASN_IDX_VALS,
};

/* Number of items in ASN.1 template for certificate request Attribute. */
#define reqAttrASN_Length (sizeof(reqAttrASN) / sizeof(ASNItem))

/* ASN.1 template for a string choice. */
static const ASNItem strAttrASN[] = {
    { 0, 0, 0, 0, 0 },
};
enum {
    STRATTRASN_IDX_STR = 0,
};

/* Number of items in ASN.1 template for a string choice. */
#define strAttrASN_Length (sizeof(strAttrASN) / sizeof(ASNItem))

/* ASN.1 choices for types for a string in an attribute. */
static const byte strAttrChoice[] = {
    ASN_PRINTABLE_STRING, ASN_IA5_STRING, ASN_UTF8STRING, 0
};

/* Decode a certificate request attribute's value.
 *
 * @param [in]  cert         Certificate request object.
 * @param [out] criticalExt  Critical extension return code.
 * @param [in]  oid          OID decribing which attribute was found.
 * @param [in]  aIdx         Index into certificate source to start parsing.
 * @param [in]  input        Attribute value data.
 * @param [in]  maxIdx       Maximum index to parse to.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 */
static int DecodeCertReqAttrValue(DecodedCert* cert, int* criticalExt,
    word32 oid, word32 aIdx, const byte* input, word32 maxIdx)
{
    int ret = 0;
    word32 idx = 0;
    ASNGetData strDataASN[strAttrASN_Length];

    switch (oid) {
        case PKCS9_CONTENT_TYPE_OID:
            /* Clear dynamic data and specify choices acceptable. */
            XMEMSET(strDataASN, 0, sizeof(strDataASN));
            GetASN_Choice(&strDataASN[STRATTRASN_IDX_STR], strAttrChoice);
            /* Parse a string. */
            ret = GetASN_Items(strAttrASN, strDataASN, strAttrASN_Length,
                               1, input, &idx, maxIdx);
            if (ret == 0) {
                /* Store references to password data. */
                cert->contentType =
                        (char*)strDataASN[STRATTRASN_IDX_STR].data.ref.data;
                cert->contentTypeLen =
                        strDataASN[STRATTRASN_IDX_STR].data.ref.length;
            }
            break;

        /* A password by which the entity may request certificate revocation.
         * PKCS#9: RFC 2985, 5.4.1 - Challenge password
         */
        case CHALLENGE_PASSWORD_OID:
            /* Clear dynamic data and specify choices acceptable. */
            XMEMSET(strDataASN, 0, sizeof(strDataASN));
            GetASN_Choice(&strDataASN[STRATTRASN_IDX_STR], strAttrChoice);
            /* Parse a string. */
            ret = GetASN_Items(strAttrASN, strDataASN, strAttrASN_Length,
                               1, input, &idx, maxIdx);
            if (ret == 0) {
                /* Store references to password data. */
                cert->cPwd =
                        (char*)strDataASN[STRATTRASN_IDX_STR].data.ref.data;
                cert->cPwdLen = strDataASN[STRATTRASN_IDX_STR].data.ref.length;
            }
            break;

        /* Requested serial number to issue with.
         * PKCS#9: RFC 2985, 5.2.10 - Serial Number
         * (References: ISO/IEC 9594-6:1997)
         */
        case SERIAL_NUMBER_OID:
            /* Clear dynamic data and specify choices acceptable. */
            XMEMSET(strDataASN, 0, sizeof(strDataASN));
            GetASN_Choice(&strDataASN[STRATTRASN_IDX_STR], strAttrChoice);
            /* Parse a string. */
            ret = GetASN_Items(strAttrASN, strDataASN, strAttrASN_Length,
                               1, input, &idx, maxIdx);
            if (ret == 0) {
                /* Store references to serial number. */
                cert->sNum =
                        (char*)strDataASN[STRATTRASN_IDX_STR].data.ref.data;
                cert->sNumLen = strDataASN[STRATTRASN_IDX_STR].data.ref.length;
                /* Store serial number if small enough. */
                if (cert->sNumLen <= EXTERNAL_SERIAL_SIZE) {
                    XMEMCPY(cert->serial, cert->sNum, cert->sNumLen);
                    cert->serialSz = cert->sNumLen;
                }
            }
            break;

        /* Certificate extensions to be included in generated certificate.
         * PKCS#9: RFC 2985, 5.4.2 - Extension request
         */
        case EXTENSION_REQUEST_OID:
            /* Store references to all extensions. */
            cert->extensions    = input;
            cert->extensionsSz  = maxIdx;
            cert->extensionsIdx = aIdx;

            /* Decode and validate extensions. */
            ret = DecodeCertExtensions(cert);
            if (ret == ASN_CRIT_EXT_E) {
                /* Return critical extension not recognized. */
                *criticalExt = ret;
                ret = 0;
            }
            else {
                /* No critical extension error. */
                *criticalExt = 0;
            }
            break;

        default:
            ret = ASN_PARSE_E;
            break;
    }

    return ret;
}

/* Decode attributes of a BER encoded certificate request.
 *
 * RFC 2986 - PKCS #10: Certification Request Syntax Specification Version 1.7
 *
 * Outer sequence has been removed.
 *
 * @param [in]  cert         Certificate request object.
 * @param [out] criticalExt  Critical extension return code.
 * @param [in]  idx          Index into certificate source to start parsing.
 * @param [in]  maxIdx       Maximum index to parse to.
 * @return  0 on success.
 * @return  ASN_CRIT_EXT_E when a critical extension was not recognized.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 */
static int DecodeCertReqAttributes(DecodedCert* cert, int* criticalExt,
                                   word32 idx, word32 maxIdx)
{
    DECL_ASNGETDATA(dataASN, reqAttrASN_Length);
    int ret = 0;

    WOLFSSL_ENTER("DecodeCertReqAttributes");

    ALLOC_ASNGETDATA(dataASN, reqAttrASN_Length, ret, cert->heap);

    /* Parse each attribute until all data used up. */
    while ((ret == 0) && (idx < maxIdx)) {
        /* Clear dynamic data. */
        XMEMSET(dataASN, 0, sizeof(ASNGetData) * reqAttrASN_Length);
        GetASN_OID(&dataASN[REQATTRASN_IDX_TYPE], oidIgnoreType);

        /* Parse an attribute. */
        ret = GetASN_Items(reqAttrASN, dataASN, reqAttrASN_Length, 0,
                           cert->source, &idx, maxIdx);
        /* idx is now at end of attribute data. */
        if (ret == 0) {
            ret = DecodeCertReqAttrValue(cert, criticalExt,
                dataASN[REQATTRASN_IDX_TYPE].data.oid.sum,
                GetASNItem_DataIdx(dataASN[REQATTRASN_IDX_VALS], cert->source),
                dataASN[REQATTRASN_IDX_VALS].data.ref.data,
                dataASN[REQATTRASN_IDX_VALS].data.ref.length);
        }
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
}

/* ASN.1 template for a certificate request.
 * PKCS#10: RFC 2986, 4.1 - CertificationRequestInfo
 * PKCS#10: RFC 2986, 4.2 - CertificationRequest
 */
static const ASNItem certReqASN[] = {
            /* CertificationRequest */
/* SEQ                              */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                                          /* CertificationRequestInfo */
/* INFO_SEQ                         */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                              /* version              INTEGER { v1(0), v2(1), v3(2) */
/* INFO_VER                         */         { 2, ASN_INTEGER, 0, 0, 0 },
                                                              /* subject              Name */
/* INFO_SUBJ_SEQ                    */         { 2, ASN_SEQUENCE, 1, 0, 0 },
                                                              /* subjectPublicKeyInfo SubjectPublicKeyInfo */
/* INFO_SPUBKEYINFO_SEQ             */         { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                                  /* algorithm          AlgorithmIdentifier */
/* INFO_SPUBKEYINFO_ALGOID_SEQ      */             { 3, ASN_SEQUENCE, 1, 1, 0 },
                                                                      /* Algorithm    OBJECT IDENTIFIER */
/* INFO_SPUBKEYINFO_ALGOID_OID      */                 { 4, ASN_OBJECT_ID, 0, 0, 0 },
                                                                      /* parameters   ANY defined by algorithm OPTIONAL */
/* INFO_SPUBKEYINFO_ALGOID_NOPARAMS */                 { 4, ASN_TAG_NULL, 0, 0, 1 },
/* INFO_SPUBKEYINFO_ALGOID_CURVEID  */                 { 4, ASN_OBJECT_ID, 0, 0, 1 },
/* INFO_SPUBKEYINFO_ALGOID_PARAMS   */                 { 4, ASN_SEQUENCE, 1, 0, 1 },
                                                                  /* subjectPublicKey   BIT STRING */
/* INFO_SPUBKEYINFO_PUBKEY          */             { 3, ASN_BIT_STRING, 0, 0, 0 },
                                                              /* attributes       [0] Attributes */
/* INFO_ATTRS                       */         { 2, ASN_CONTEXT_SPECIFIC | 0, 1, 0, 1 },
                                                          /* signatureAlgorithm   AlgorithmIdentifier */
/* INFO_SIGALGO_SEQ                 */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                              /* Algorithm    OBJECT IDENTIFIER */
/* INFO_SIGALGO_OID                 */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
                                                              /* parameters   ANY defined by algorithm OPTIONAL */
/* INFO_SIGALGO_NOPARAMS            */         { 2, ASN_TAG_NULL, 0, 0, 1 },
                                                          /* signature            BIT STRING */
/* INFO_SIGNATURE                   */     { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    CERTREQASN_IDX_SEQ = 0,
    CERTREQASN_IDX_INFO_SEQ,
    CERTREQASN_IDX_INFO_VER,
    CERTREQASN_IDX_INFO_SUBJ_SEQ,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_SEQ,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_SEQ,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_OID,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_NOPARAMS,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_CURVEID,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_PARAMS,
    CERTREQASN_IDX_INFO_SPUBKEYINFO_PUBKEY,
    CERTREQASN_IDX_INFO_ATTRS,
    CERTREQASN_IDX_INFO_SIGALGO_SEQ,
    CERTREQASN_IDX_INFO_SIGALGO_OID,
    CERTREQASN_IDX_INFO_SIGALGO_NOPARAMS,
    CERTREQASN_IDX_INFO_SIGNATURE,
};

/* Number of items in ASN.1 template for a certificate request. */
#define certReqASN_Length (sizeof(certReqASN) / sizeof(ASNItem))

/* Parse BER encoded certificate request.
 *
 * RFC 2986 - PKCS #10: Certification Request Syntax Specification Version 1.7
 *
 * @param [in]  cert         Certificate request object.
 * @param [out] criticalExt  Critical extension return code.
 * @return  0 on success.
 * @return  ASN_CRIT_EXT_E when a critical extension was not recognized.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  BUFFER_E when data in buffer is too small.
 * @return  ASN_OBJECT_ID_E when the expected OBJECT_ID tag is not found.
 * @return  ASN_EXPECT_0_E when the INTEGER has the MSB set or NULL has a
 *          non-zero length.
 * @return  ASN_UNKNOWN_OID_E when the OID cannot be verified.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int DecodeCertReq(DecodedCert* cert, int* criticalExt)
{
    DECL_ASNGETDATA(dataASN, certReqASN_Length);
    int ret = 0;
    byte version;
    word32 idx;

    CALLOC_ASNGETDATA(dataASN, certReqASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Default version is 0. */
        version = 0;

        /* Set version var and OID types to expect. */
        GetASN_Int8Bit(&dataASN[CERTREQASN_IDX_INFO_VER], &version);
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_OID],
                oidKeyType);
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_CURVEID],
                oidCurveType);
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SIGALGO_OID], oidSigType);
        /* Parse a certificate request. */
        ret = GetASN_Items(certReqASN, dataASN, certReqASN_Length, 1,
                           cert->source, &cert->srcIdx, cert->maxIdx);
    }
    /* Check version is valid/supported - can't be negative. */
    if ((ret == 0) && (version > MAX_X509_VERSION)) {
        WOLFSSL_MSG("Unexpected certificate request version");
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* Set fields of certificate request. */
        cert->version = version;
        cert->signatureOID =
              dataASN[CERTREQASN_IDX_INFO_SIGALGO_OID].data.oid.sum;
        cert->keyOID =
              dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_OID].data.oid.sum;
        cert->certBegin = dataASN[CERTREQASN_IDX_INFO_SEQ].offset;

        /* Parse the subject name. */
        idx = dataASN[CERTREQASN_IDX_INFO_SUBJ_SEQ].offset;
        ret = GetCertName(cert, cert->subject, cert->subjectHash, SUBJECT,
                          cert->source, &idx,
                          dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_SEQ].offset);
    }
    if (ret == 0) {
        /* Parse the certificate request Attributes. */
        ret = DecodeCertReqAttributes(cert, criticalExt,
                GetASNItem_DataIdx(dataASN[CERTREQASN_IDX_INFO_ATTRS],
                        cert->source),
                dataASN[CERTREQASN_IDX_INFO_SIGALGO_SEQ].offset);
    }
    if (ret == 0) {
        /* Parse the certificate request's key. */
        idx = dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_SEQ].offset;
        ret = GetCertKey(cert, cert->source, &idx,
                dataASN[CERTREQASN_IDX_INFO_ATTRS].offset);
    }
    if (ret == 0) {
        /* Store references to signature. */
        cert->sigIndex = dataASN[CERTREQASN_IDX_INFO_SIGALGO_SEQ].offset;
        GetASN_GetConstRef(&dataASN[CERTREQASN_IDX_INFO_SIGNATURE],
                &cert->signature, &cert->sigLength);
    }

    FREE_ASNGETDATA(dataASN, cert->heap);
    return ret;
}

#endif /* WOLFSSL_CERT_REQ */

#endif

int ParseCert(DecodedCert* cert, int type, int verify, void* cm)
{
    int   ret;
    char* ptr;

    ret = ParseCertRelative(cert, type, verify, cm);
    if (ret < 0)
        return ret;

    /* cert->subjectCN not stored as copy of WOLFSSL_NO_MALLOC defind */
    if (cert->subjectCNLen > 0) {
        ptr = (char*) XMALLOC(cert->subjectCNLen + 1, cert->heap,
                              DYNAMIC_TYPE_SUBJECT_CN);
        if (ptr == NULL)
            return MEMORY_E;
        XMEMCPY(ptr, cert->subjectCN, cert->subjectCNLen);
        ptr[cert->subjectCNLen] = '\0';
        cert->subjectCN = ptr;
        cert->subjectCNStored = 1;
    }

    /* cert->publicKey not stored as copy if WOLFSSL_NO_MALLOC defined */
    if (cert->keyOID == RSAk &&
                          cert->publicKey != NULL  && cert->pubKeySize > 0) {
        ptr = (char*) XMALLOC(cert->pubKeySize, cert->heap,
                              DYNAMIC_TYPE_PUBLIC_KEY);
        if (ptr == NULL)
            return MEMORY_E;
        XMEMCPY(ptr, cert->publicKey, cert->pubKeySize);
        cert->publicKey = (byte *)ptr;
        cert->pubKeyStored = 1;
    }

    return ret;
}

int wc_ParseCert(DecodedCert* cert, int type, int verify, void* cm)
{
    return ParseCert(cert, type, verify, cm);
}

#if  !defined(GetCA)
/* from SSL proper, for locking can't do find here anymore.
 * brought in from internal.h if built with compat layer.
 * if defined(GetCA), it's a predefined macro and these prototypes
 * would conflict.
 */
#ifdef __cplusplus
    extern "C" {
#endif
    Signer* GetCA(void* signers, byte* hash);
    #ifndef NO_SKID
        Signer* GetCAByName(void* signers, byte* hash);
    #endif
#ifdef __cplusplus
    }
#endif

#endif /* !OPENSSL_EXTRA && !OPENSSL_EXTRA_X509_SMALL && !GetCA */

#if defined(WOLFCRYPT_ONLY)

/* dummy functions, not using wolfSSL so don't need actual ones */
Signer* GetCA(void* signers, byte* hash)
{
    (void)hash;

    return (Signer*)signers;
}

#ifndef NO_SKID
Signer* GetCAByName(void* signers, byte* hash)
{
    (void)hash;

    return (Signer*)signers;
}
#endif /* NO_SKID */

#endif /* WOLFCRYPT_ONLY */

#if defined(WOLFSSL_NO_TRUSTED_CERTS_VERIFY) && !defined(NO_SKID)
static Signer* GetCABySubjectAndPubKey(DecodedCert* cert, void* cm)
{
    Signer* ca = NULL;
    if (cert->extSubjKeyIdSet)
        ca = GetCA(cm, cert->extSubjKeyId);
    if (ca == NULL)
        ca = GetCAByName(cm, cert->subjectHash);
    if (ca) {
        if ((ca->pubKeySize == cert->pubKeySize) &&
               (XMEMCMP(ca->publicKey, cert->publicKey, ca->pubKeySize) == 0)) {
            return ca;
        }
    }
    return NULL;
}
#endif

#if defined(WOLFSSL_SMALL_CERT_VERIFY)
#ifdef WOLFSSL_ASN_TEMPLATE
/* Get the Hash of the Authority Key Identifier from the list of extensions.
 *
 * @param [in]  input   Input data.
 * @param [in]  maxIdx  Maximum index for data.
 * @param [out] hash    Hash of AKI.
 * @param [out] set     Whether the hash buffer was set.
 * @param [in]  heap    Dynamic memory allocation hint.
 * @return  0 on success.
 * @return  ASN_PARSE_E when BER encoded data does not match ASN.1 items or
 *          is invalid.
 * @return  MEMORY_E on dynamic memory allocation failure.
 */
static int GetAKIHash(const byte* input, word32 maxIdx, byte* hash, int* set,
                      void* heap)
{
    /* AKI and Certificate Extenion ASN.1 templates are the same length. */
    DECL_ASNGETDATA(dataASN, certExtASN_Length);
    int ret = 0;
    word32 idx = 0;
    word32 extEndIdx;
    byte* extData;
    word32 extDataSz;
    byte critical;

    ALLOC_ASNGETDATA(dataASN, certExtASN_Length, ret, heap);
    (void)heap;

    extEndIdx = idx + maxIdx;

    /* Step through each extension looking for AKI. */
    while ((ret == 0) && (idx < extEndIdx)) {
        /* Clear dynamic data and check for certificate extension type OIDs. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * certExtASN_Length);
        GetASN_OID(&dataASN[CERTEXTASN_IDX_OID], oidCertExtType);
        /* Set criticality variable. */
        GetASN_Int8Bit(&dataASN[CERTEXTASN_IDX_CRIT], &critical);
        /* Parse an extension. */
        ret = GetASN_Items(certExtASN, dataASN, certExtASN_Length, 0, input,
                &idx, extEndIdx);
        if (ret == 0) {
            /* Get reference to extension data and move index on past this
             * extension. */
            GetASN_GetRef(&dataASN[CERTEXTASN_IDX_VAL], &extData, &extDataSz);
            idx += extDataSz;

            /* Check whether we have the AKI extension. */
            if (dataASN[CERTEXTASN_IDX_OID].data.oid.sum == AUTH_KEY_OID) {
                /* Clear dynamic data. */
                XMEMSET(dataASN, 0, sizeof(*dataASN) * authKeyIdASN_Length);
                /* Start parsing extension data from the start. */
                idx = 0;
                /* Parse AKI extension data. */
                ret = GetASN_Items(authKeyIdASN, dataASN, authKeyIdASN_Length,
                        1, extData, &idx, extDataSz);
                if ((ret == 0) &&
                        (dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.data
                                != NULL)) {
                    /* We parsed successfully and have data. */
                    *set = 1;
                    /* Get the hash or hash of the hash if wrong size. */
                    ret = GetHashId(
                            dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.data,
                            dataASN[AUTHKEYIDASN_IDX_KEYID].data.ref.length,
                            hash);
                }
                break;
            }
        }
    }

    FREE_ASNGETDATA(dataASN, heap);
    return ret;
}
#endif

/* Only quick step through the certificate to find fields that are then used
 * in certificate signature verification.
 * Must use the signature OID from the signed part of the certificate.
 * Works also on certificate signing requests.
 *
 * This is only for minimizing dynamic memory usage during TLS certificate
 * chain processing.
 * Doesn't support:
 *   OCSP Only: alt lookup using subject and pub key w/o sig check
 */
static int CheckCertSignature_ex(const byte* cert, word32 certSz, void* heap,
        void* cm, const byte* pubKey, word32 pubKeySz, int pubKeyOID, int req)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    SignatureCtx  sigCtx[1];
    byte          hash[KEYID_SIZE];
    Signer*       ca = NULL;
    word32        idx = 0;
    int           len;
    word32        tbsCertIdx = 0;
    word32        sigIndex   = 0;
    word32        signatureOID = 0;
    word32        oid = 0;
    word32        issuerIdx = 0;
    word32        issuerSz  = 0;
#ifndef NO_SKID
    int           extLen = 0;
    word32        extIdx = 0;
    word32        extEndIdx = 0;
    int           extAuthKeyIdSet = 0;
#endif
    int           ret = 0;
    word32        localIdx;
    byte          tag;


    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

    InitSignatureCtx(sigCtx, heap, INVALID_DEVID);

    /* Certificate SEQUENCE */
    if (GetSequence(cert, &idx, &len, certSz) < 0)
        ret = ASN_PARSE_E;
    if (ret == 0) {
        tbsCertIdx = idx;

        /* TBSCertificate SEQUENCE */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        sigIndex = len + idx;

        if ((idx + 1) > certSz)
            ret = BUFFER_E;
    }
    if (ret == 0) {
        /* version - optional */
        localIdx = idx;
        if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
            if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
                idx++;
                if (GetLength(cert, &idx, &len, certSz) < 0)
                    ret = ASN_PARSE_E;
                idx += len;
            }
        }
    }

    if (ret == 0) {
        /* serialNumber */
        if (GetASNHeader(cert, ASN_INTEGER, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        idx += len;

        /* signature */
        if (!req &&
                GetAlgoId(cert, &idx, &signatureOID, oidSigType, certSz) < 0)
            ret = ASN_PARSE_E;
    }

    if (ret == 0) {
        issuerIdx = idx;
        /* issuer for cert or subject for csr */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        issuerSz = len + idx - issuerIdx;
    }
#ifndef NO_SKID
    if (!req && ret == 0) {
        idx += len;

        /* validity */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (!req && ret == 0) {
        idx += len;

        /* subject */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        idx += len;

        /* subjectPublicKeyInfo */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (req && ret == 0) {
        idx += len;

        /* attributes */
        if (GetASNHeader_ex(cert,
                ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED, &idx,
                &len, certSz, 1) < 0)
            ret = ASN_PARSE_E;
    }
    if (!req) {
        if (ret == 0) {
            idx += len;

            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        if (ret == 0) {
            /* issuerUniqueID - optional */
            localIdx = idx;
            if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
                if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
                    idx++;
                    if (GetLength(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    idx += len;
                }
            }
        }
        if (ret == 0) {
            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        if (ret == 0) {
            /* subjectUniqueID - optional */
            localIdx = idx;
            if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
                if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2)) {
                    idx++;
                    if (GetLength(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    idx += len;
                }
            }
        }

        if (ret == 0) {
            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        /* extensions - optional */
        localIdx = idx;
        if (ret == 0 && GetASNTag(cert, &localIdx, &tag, certSz) == 0 &&
                tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3)) {
            idx++;
            if (GetLength(cert, &idx, &extLen, certSz) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0) {
                if (GetSequence(cert, &idx, &extLen, certSz) < 0)
                    ret = ASN_PARSE_E;
            }
            if (ret == 0) {
                extEndIdx = idx + extLen;

                /* Check each extension for the ones we want. */
                while (ret == 0 && idx < extEndIdx) {
                    if (GetSequence(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    if (ret == 0) {
                        extIdx = idx;
                        if (GetObjectId(cert, &extIdx, &oid, oidCertExtType,
                                                                  certSz) < 0) {
                            ret = ASN_PARSE_E;
                        }

                        if (ret == 0) {
                            if ((extIdx + 1) > certSz)
                                ret = BUFFER_E;
                        }
                    }

                    if (ret == 0) {
                        localIdx = extIdx;
                        if (GetASNTag(cert, &localIdx, &tag, certSz) == 0 &&
                                tag == ASN_BOOLEAN) {
                            if (GetBoolean(cert, &extIdx, certSz) < 0)
                                ret = ASN_PARSE_E;
                        }
                    }
                    if (ret == 0) {
                        if (GetOctetString(cert, &extIdx, &extLen, certSz) < 0)
                            ret = ASN_PARSE_E;
                    }

                    if (ret == 0) {
                        switch (oid) {
                        case AUTH_KEY_OID:
                            if (GetSequence(cert, &extIdx, &extLen, certSz) < 0)
                                ret = ASN_PARSE_E;

                            if (ret == 0 && (extIdx + 1) >= certSz)
                                ret = BUFFER_E;

                            if (ret == 0 &&
                                    GetASNTag(cert, &extIdx, &tag, certSz) == 0 &&
                                    tag == (ASN_CONTEXT_SPECIFIC | 0)) {
                                if (GetLength(cert, &extIdx, &extLen, certSz) <= 0)
                                    ret = ASN_PARSE_E;
                                if (ret == 0) {
                                    extAuthKeyIdSet = 1;
                                    /* Get the hash or hash of the hash if wrong
                                     * size. */
                                    ret = GetHashId(cert + extIdx, extLen,
                                                    hash);
                                }
                            }
                            break;

                        default:
                            break;
                        }
                    }
                    idx += len;
                }
            }
        }
    }
    else if (ret == 0) {
        idx += len;
    }

    if (ret == 0 && pubKey == NULL) {
        if (extAuthKeyIdSet)
            ca = GetCA(cm, hash);
        if (ca == NULL) {
            ret = CalcHashId(cert + issuerIdx, issuerSz, hash);
            if (ret == 0)
                ca = GetCAByName(cm, hash);
        }
    }
#else
    if (ret == 0 && pubKey == NULL) {
        ret = CalcHashId(cert + issuerIdx, issuerSz, hash);
        if (ret == 0)
            ca = GetCA(cm, hash);
    }
#endif /* !NO_SKID */
    if (ca == NULL && pubKey == NULL)
        ret = ASN_NO_SIGNER_E;

    if (ret == 0) {
        idx = sigIndex;
        /* signatureAlgorithm */
        if (GetAlgoId(cert, &idx, &oid, oidSigType, certSz) < 0)
            ret = ASN_PARSE_E;
        /* In CSR signature data is not present in body */
        if (req)
            signatureOID = oid;
    }
    if (ret == 0) {
        if (oid != signatureOID)
            ret = ASN_SIG_OID_E;
    }
    if (ret == 0) {
        /* signatureValue */
        if (CheckBitString(cert, &idx, &len, certSz, 1, NULL) < 0)
            ret = ASN_PARSE_E;
    }

    if (ret == 0) {
        if (pubKey != NULL) {
            ret = ConfirmSignature(sigCtx, cert + tbsCertIdx,
                               sigIndex - tbsCertIdx,
                               pubKey, pubKeySz, pubKeyOID,
                               cert + idx, len, signatureOID, NULL);
        }
        else {
            ret = ConfirmSignature(sigCtx, cert + tbsCertIdx,
                               sigIndex - tbsCertIdx,
                               ca->publicKey, ca->pubKeySize, ca->keyOID,
                               cert + idx, len, signatureOID, NULL);
        }
        if (ret != 0) {
            WOLFSSL_MSG("Confirm signature failed");
        }
    }

    FreeSignatureCtx(sigCtx);
    return ret;
#else /* WOLFSSL_ASN_TEMPLATE */
    /* X509 ASN.1 template longer than Certificate Request template. */
    DECL_ASNGETDATA(dataASN, x509CertASN_Length);
    SignatureCtx  sigCtx[1];
    byte hash[KEYID_SIZE];
    Signer* ca = NULL;
    int ret = 0;
    word32 idx = 0;
#ifndef NO_SKID
    int extAuthKeyIdSet = 0;
#endif
    const byte* tbs = NULL;
    word32 tbsSz = 0;
    const byte* sig = NULL;
    word32 sigSz = 0;
    word32 sigOID = 0;
    const byte* caName = NULL;
    word32 caNameLen = 0;

    (void)req;
    (void)heap;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }

    ALLOC_ASNGETDATA(dataASN, x509CertASN_Length, ret, heap);

    InitSignatureCtx(sigCtx, heap, INVALID_DEVID);

    if ((ret == 0) && (!req)) {
        /* Clear dynamic data for certificate items. */
        XMEMSET(dataASN, 0, sizeof(ASNGetData) * x509CertASN_Length);
        /* Set OID types expected for signature and public key. */
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_ALGOID_OID], oidSigType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_OID],
                oidKeyType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_CURVEID],
                oidCurveType);
        GetASN_OID(&dataASN[X509CERTASN_IDX_SIGALGO_OID], oidSigType);
        /* Parse certificate. */
        ret = GetASN_Items(x509CertASN, dataASN, x509CertASN_Length, 1, cert,
                           &idx, certSz);

        /* Check signature OIDs match. */
        if ((ret == 0) && dataASN[X509CERTASN_IDX_TBS_ALGOID_OID].data.oid.sum
                != dataASN[X509CERTASN_IDX_SIGALGO_OID].data.oid.sum) {
            ret = ASN_SIG_OID_E;
        }
        /* Store the data for verification in the certificate. */
        if (ret == 0) {
            tbs = GetASNItem_Addr(dataASN[X509CERTASN_IDX_TBS_SEQ], cert);
            tbsSz = GetASNItem_Length(dataASN[X509CERTASN_IDX_TBS_SEQ], cert);
            caName = GetASNItem_Addr(dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ],
                    cert);
            caNameLen = GetASNItem_Length(dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ],
                    cert);
            sigOID = dataASN[X509CERTASN_IDX_SIGALGO_OID].data.oid.sum;
            GetASN_GetConstRef(&dataASN[X509CERTASN_IDX_SIGNATURE], &sig, &sigSz);
        }
    }
    else if (ret == 0) {
#ifndef WOLFSSL_CERT_REQ
        ret = NOT_COMPILED_IN;
#else
        /* Clear dynamic data for certificate request items. */
        XMEMSET(dataASN, 0, sizeof(ASNGetData) * certReqASN_Length);
        /* Set OID types expected for signature and public key. */
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_OID],
                oidKeyType);
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SPUBKEYINFO_ALGOID_CURVEID],
                oidCurveType);
        GetASN_OID(&dataASN[CERTREQASN_IDX_INFO_SIGALGO_OID], oidSigType);
        /* Parse certificate request. */
        ret = GetASN_Items(certReqASN, dataASN, certReqASN_Length, 1, cert,
                           &idx, certSz);
        if (ret == 0) {
            /* Store the data for verification in the certificate. */
            tbs = GetASNItem_Addr(dataASN[CERTREQASN_IDX_INFO_SEQ], cert);
            tbsSz = GetASNItem_Length(dataASN[CERTREQASN_IDX_INFO_SEQ], cert);
            caName = GetASNItem_Addr(
                    dataASN[CERTREQASN_IDX_INFO_SUBJ_SEQ], cert);
            caNameLen = GetASNItem_Length(
                    dataASN[CERTREQASN_IDX_INFO_SUBJ_SEQ], cert);
            sigOID = dataASN[CERTREQASN_IDX_INFO_SIGALGO_OID].data.oid.sum;
            GetASN_GetConstRef(&dataASN[CERTREQASN_IDX_INFO_SIGNATURE], &sig,
                    &sigSz);
        }
#endif
    }

    /* If no public passed, then find the CA. */
    if ((ret == 0) && (pubKey == NULL)) {
#ifndef NO_SKID
        /* Find the AKI extension in list of extensions and get hash. */
        if ((!req) &&
                (dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.ref.data != NULL)) {
            /* TODO: test case */
            ret = GetAKIHash(dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.ref.data,
                             dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.ref.length,
                             hash, &extAuthKeyIdSet, heap);
        }

        /* Get the CA by hash one was found. */
        if (extAuthKeyIdSet) {
            ca = GetCA(cm, hash);
        }
        if (ca == NULL)
#endif
        {
            /* Try hash of issuer name. */
            ret = CalcHashId(caName, caNameLen, hash);
            if (ret == 0) {
                ca = GetCAByName(cm, hash);
            }
        }

        if (ca != NULL) {
            /* Extract public key information. */
            pubKey = ca->publicKey;
            pubKeySz = ca->pubKeySize;
            pubKeyOID = ca->keyOID;
        }
        else {
            /* No public key to verify with. */
            ret = ASN_NO_SIGNER_E;
        }
    }

    if (ret == 0) {
        /* Check signature. */
        ret = ConfirmSignature(sigCtx, tbs, tbsSz, pubKey, pubKeySz, pubKeyOID,
                sig, sigSz, sigOID, NULL);
        if (ret != 0) {
            WOLFSSL_MSG("Confirm signature failed");
        }
    }

    FreeSignatureCtx(sigCtx);
    FREE_ASNGETDATA(dataASN, heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifdef WOLFSSL_SMALL_CERT_VERIFY
/* Call CheckCertSignature_ex using a certificate manager (cm)
 */
int CheckCertSignature(const byte* cert, word32 certSz, void* heap, void* cm)
{
    return CheckCertSignature_ex(cert, certSz, heap, cm, NULL, 0, 0, 0);
}
#endif /* WOLFSSL_SMALL_CERT_VERIFY */
#endif /* WOLFSSL_SMALL_CERT_VERIFY || OPENSSL_EXTRA */

int ParseCertRelative(DecodedCert* cert, int type, int verify, void* cm)
{
    int    ret = 0;
    int    checkPathLen = 0;
    int    decrementMaxPathLen = 0;
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 confirmOID = 0;
#ifdef WOLFSSL_CERT_REQ
    int    len = 0;
#endif
#endif
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    int    idx = 0;
#endif
    byte*  sce_tsip_encRsaKeyIdx;

    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_CERT_REQ
    if (type == CERTREQ_TYPE)
        cert->isCSR = 1;
#endif

    if (cert->sigCtx.state == SIG_STATE_BEGIN) {
#ifndef WOLFSSL_ASN_TEMPLATE
        cert->badDate = 0;
        cert->criticalExt = 0;
        if ((ret = DecodeToKey(cert, verify)) < 0) {
            if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
                cert->badDate = ret;
            else
                return ret;
        }

        WOLFSSL_MSG("Parsed Past Key");


#ifdef WOLFSSL_CERT_REQ
        /* Read attributes */
        if (cert->isCSR) {
            if (GetASNHeader_ex(cert->source,
                    ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED, &cert->srcIdx,
                    &len, cert->maxIdx, 1) < 0) {
                WOLFSSL_MSG("GetASNHeader_ex error");
                return ASN_PARSE_E;
            }

            if (len) {
                word32 attrMaxIdx = cert->srcIdx + len;
                word32 oid;
                byte   tag;

                if (attrMaxIdx > cert->maxIdx) {
                    WOLFSSL_MSG("Attribute length greater than CSR length");
                    return ASN_PARSE_E;
                }

                while (cert->srcIdx < attrMaxIdx) {
                    /* Attributes have the structure:
                     * SEQ -> OID -> SET -> ATTRIBUTE */
                    if (GetSequence(cert->source, &cert->srcIdx, &len,
                            attrMaxIdx) < 0) {
                        WOLFSSL_MSG("attr GetSequence error");
                        return ASN_PARSE_E;
                    }
                    if (GetObjectId(cert->source, &cert->srcIdx, &oid,
                            oidCsrAttrType, attrMaxIdx) < 0) {
                        WOLFSSL_MSG("attr GetObjectId error");
                        return ASN_PARSE_E;
                    }
                    if (GetSet(cert->source, &cert->srcIdx, &len,
                            attrMaxIdx) < 0) {
                        WOLFSSL_MSG("attr GetSet error");
                        return ASN_PARSE_E;
                    }
                    switch (oid) {
                    case PKCS9_CONTENT_TYPE_OID:
                        if (GetHeader(cert->source, &tag,
                                &cert->srcIdx, &len, attrMaxIdx, 1) < 0) {
                            WOLFSSL_MSG("attr GetHeader error");
                            return ASN_PARSE_E;
                        }
                        if (tag != ASN_PRINTABLE_STRING && tag != ASN_UTF8STRING &&
                                tag != ASN_IA5_STRING) {
                            WOLFSSL_MSG("Unsupported attribute value format");
                            return ASN_PARSE_E;
                        }
                        cert->contentType = (char*)cert->source + cert->srcIdx;
                        cert->contentTypeLen = len;
                        cert->srcIdx += len;
                        break;
                    case CHALLENGE_PASSWORD_OID:
                        if (GetHeader(cert->source, &tag,
                                &cert->srcIdx, &len, attrMaxIdx, 1) < 0) {
                            WOLFSSL_MSG("attr GetHeader error");
                            return ASN_PARSE_E;
                        }
                        if (tag != ASN_PRINTABLE_STRING && tag != ASN_UTF8STRING &&
                                tag != ASN_IA5_STRING) {
                            WOLFSSL_MSG("Unsupported attribute value format");
                            return ASN_PARSE_E;
                        }
                        cert->cPwd = (char*)cert->source + cert->srcIdx;
                        cert->cPwdLen = len;
                        cert->srcIdx += len;
                        break;
                    case SERIAL_NUMBER_OID:
                        if (GetHeader(cert->source, &tag,
                                &cert->srcIdx, &len, attrMaxIdx, 1) < 0) {
                            WOLFSSL_MSG("attr GetHeader error");
                            return ASN_PARSE_E;
                        }
                        if (tag != ASN_PRINTABLE_STRING && tag != ASN_UTF8STRING &&
                                tag != ASN_IA5_STRING) {
                            WOLFSSL_MSG("Unsupported attribute value format");
                            return ASN_PARSE_E;
                        }
                        cert->sNum = (char*)cert->source + cert->srcIdx;
                        cert->sNumLen = len;
                        cert->srcIdx += len;
                        if (cert->sNumLen <= EXTERNAL_SERIAL_SIZE) {
                            XMEMCPY(cert->serial, cert->sNum, cert->sNumLen);
                            cert->serialSz = cert->sNumLen;
                        }
                        break;
                    case EXTENSION_REQUEST_OID:
                        /* save extensions */
                        cert->extensions    = &cert->source[cert->srcIdx];
                        cert->extensionsSz  = len;
                        cert->extensionsIdx = cert->srcIdx; /* for potential later use */

                        if ((ret = DecodeCertExtensions(cert)) < 0) {
                            if (ret == ASN_CRIT_EXT_E)
                                cert->criticalExt = ret;
                            else
                                return ret;
                        }
                        cert->srcIdx += len;
                        break;
                    default:
                        WOLFSSL_MSG("Unsupported attribute type");
                        return ASN_PARSE_E;
                    }
                }
            }
        }
#endif

        if (cert->srcIdx < cert->sigIndex) {
        #ifndef ALLOW_V1_EXTENSIONS
            if (cert->version < 2) {
                WOLFSSL_MSG("\tv1 and v2 certs not allowed extensions");
                return ASN_VERSION_E;
            }
        #endif

            /* save extensions */
            cert->extensions    = &cert->source[cert->srcIdx];
            cert->extensionsSz  = cert->sigIndex - cert->srcIdx;
            cert->extensionsIdx = cert->srcIdx;   /* for potential later use */

            if ((ret = DecodeCertExtensions(cert)) < 0) {
                if (ret == ASN_CRIT_EXT_E)
                    cert->criticalExt = ret;
                else
                    return ret;
            }

            /* advance past extensions */
            cert->srcIdx = cert->sigIndex;
        }

        if ((ret = GetAlgoId(cert->source, &cert->srcIdx,
#ifdef WOLFSSL_CERT_REQ
                !cert->isCSR ? &confirmOID : &cert->signatureOID,
#else
                &confirmOID,
#endif
                oidSigType, cert->maxIdx)) < 0)
            return ret;

        if ((ret = GetSignature(cert)) < 0)
            return ret;

        if (confirmOID != cert->signatureOID
#ifdef WOLFSSL_CERT_REQ
                && !cert->isCSR
#endif
                )
            return ASN_SIG_OID_E;
#else
#ifdef WOLFSSL_CERT_REQ
        if (cert->isCSR) {
            ret = DecodeCertReq(cert, &cert->criticalExt);
            if (ret < 0) {
                return ret;
            }
        }
        else
#endif
        {
            ret = DecodeCert(cert, verify, &cert->criticalExt);
            if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
                cert->badDate = ret;
            else if (ret < 0)
                return ret;
        }
#endif

    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet == 0 && cert->publicKey != NULL &&
                                                         cert->pubKeySize > 0) {
            ret = CalcHashId(cert->publicKey, cert->pubKeySize,
                                                            cert->extSubjKeyId);
            if (ret != 0)
                return ret;
        }
    #endif /* !NO_SKID */

        if (!cert->selfSigned || (verify != NO_VERIFY && type != CA_TYPE &&
                                                   type != TRUSTED_PEER_TYPE)) {
            cert->ca = NULL;
    #ifndef NO_SKID
            if (cert->extAuthKeyIdSet) {
                cert->ca = GetCA(cm, cert->extAuthKeyId);
            }
            if (cert->ca == NULL && cert->extSubjKeyIdSet
                                 && verify != VERIFY_OCSP) {
                cert->ca = GetCA(cm, cert->extSubjKeyId);
            }
            if (cert->ca != NULL && XMEMCMP(cert->issuerHash,
                                  cert->ca->subjectNameHash, KEYID_SIZE) != 0) {
                cert->ca = NULL;
            }
            if (cert->ca == NULL) {
                cert->ca = GetCAByName(cm, cert->issuerHash);
                /* If AKID is available then this CA doesn't have the public
                 * key required */
                if (cert->ca && cert->extAuthKeyIdSet) {
                    WOLFSSL_MSG("CA SKID doesn't match AKID");
                    cert->ca = NULL;
                }
            }

            /* OCSP Only: alt lookup using subject and pub key w/o sig check */
        #ifdef WOLFSSL_NO_TRUSTED_CERTS_VERIFY
            if (cert->ca == NULL && verify == VERIFY_OCSP) {
                cert->ca = GetCABySubjectAndPubKey(cert, cm);
                if (cert->ca) {
                    ret = 0; /* success */
                    goto exit_pcr;
                }
            }
        #endif /* WOLFSSL_NO_TRUSTED_CERTS_VERIFY */
    #else
            cert->ca = GetCA(cm, cert->issuerHash);
    #endif /* !NO_SKID */

            if (cert->ca) {
                WOLFSSL_MSG("CA found");
            }
        }

        if (cert->selfSigned) {
            cert->maxPathLen = WOLFSSL_MAX_PATH_LEN;
        } else {
            /* RFC 5280 Section 4.2.1.9:
             *
             * load/receive check
             *
             * 1) Is CA boolean set?
             *      No  - SKIP CHECK
             *      Yes - Check key usage
             * 2) Is Key usage extension present?
             *      No  - goto 3
             *      Yes - check keyCertSign assertion
             *     2.a) Is keyCertSign asserted?
             *          No  - goto 4
             *          Yes - goto 3
             * 3) Is pathLen set?
             *      No  - goto 4
             *      Yes - check pathLen against maxPathLen.
             *      3.a) Is pathLen less than maxPathLen?
             *           No - goto 4
             *           Yes - set maxPathLen to pathLen and EXIT
             * 4) Is maxPathLen > 0?
             *      Yes - Reduce by 1
             *      No  - ERROR
             */

            if (cert->ca && cert->pathLengthSet) {
                cert->maxPathLen = cert->pathLength;
                if (cert->isCA) {
                    WOLFSSL_MSG("\tCA boolean set");
                    if (cert->extKeyUsageSet) {
                         WOLFSSL_MSG("\tExtension Key Usage Set");
                         if ((cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) != 0) {
                            checkPathLen = 1;
                         } else {
                            decrementMaxPathLen = 1;
                         }
                    } else {
                        checkPathLen = 1;
                    } /* !cert->ca check */
                } /* cert is not a CA (assuming entity cert) */

                if (checkPathLen && cert->pathLengthSet) {
                    if (cert->pathLength < cert->ca->maxPathLen) {
                        WOLFSSL_MSG("\tmaxPathLen status: set to pathLength");
                        cert->maxPathLen = cert->pathLength;
                    } else {
                        decrementMaxPathLen = 1;
                    }
                }

                if (decrementMaxPathLen && cert->ca->maxPathLen > 0) {
                    WOLFSSL_MSG("\tmaxPathLen status: reduce by 1");
                    cert->maxPathLen = cert->ca->maxPathLen - 1;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tmaxPathLen status: OK");
                    }
                } else if (decrementMaxPathLen && cert->ca->maxPathLen == 0) {
                    cert->maxPathLen = 0;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tNon-entity cert, maxPathLen is 0");
                        WOLFSSL_MSG("\tmaxPathLen status: ERROR");
                        return ASN_PATHLEN_INV_E;
                    }
                }
            } else if (cert->ca && cert->isCA) {
                /* case where cert->pathLength extension is not set */
                if (cert->ca->maxPathLen > 0) {
                    cert->maxPathLen = cert->ca->maxPathLen - 1;
                } else {
                    cert->maxPathLen = 0;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tNon-entity cert, maxPathLen is 0");
                        WOLFSSL_MSG("\tmaxPathLen status: ERROR");
                        return ASN_PATHLEN_INV_E;
                    }
                }
            }
        }

    }
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    /* prepare for TSIP TLS cert verification API use */
    if (cert->keyOID == RSAk) {
        /* to call TSIP API, it needs keys position info in bytes */
        if ((ret = RsaPublicKeyDecodeRawIndex(cert->publicKey, (word32*)&idx,
                                   cert->pubKeySize,
                                   &cert->sigCtx.CertAtt.pubkey_n_start,
                                   &cert->sigCtx.CertAtt.pubkey_n_len,
                                   &cert->sigCtx.CertAtt.pubkey_e_start,
                                   &cert->sigCtx.CertAtt.pubkey_e_len)) != 0) {
            WOLFSSL_MSG("Decoding index from cert failed.");
            return ret;
        }
        cert->sigCtx.CertAtt.certBegin = cert->certBegin;
    } else if (cert->keyOID == ECDSAk) {
        cert->sigCtx.CertAtt.certBegin = cert->certBegin;
    }
    /* check if we can use TSIP for cert verification */
    /* if the ca is verified as tsip root ca.         */
    /* TSIP can only handle 2048 bits(256 byte) key.  */
    if (cert->ca && Renesas_cmn_checkCA(cert->ca->cm_idx) != 0 &&
        (cert->sigCtx.CertAtt.pubkey_n_len == 256 ||
         cert->sigCtx.CertAtt.curve_id == ECC_SECP256R1)) {

        /* assign memory to encrypted tsip Rsa key index */
        if (!cert->sce_tsip_encRsaKeyIdx)
            cert->sce_tsip_encRsaKeyIdx =
                            (byte*)XMALLOC(TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY,
                             cert->heap, DYNAMIC_TYPE_RSA);
        if (cert->sce_tsip_encRsaKeyIdx == NULL)
                return MEMORY_E;
    } else {
        if (cert->ca) {
            /* TSIP isn't usable */
            if (Renesas_cmn_checkCA(cert->ca->cm_idx) == 0)
                WOLFSSL_MSG("SCE-TSIP isn't usable because the ca isn't verified "
                            "by TSIP.");
            else if (cert->sigCtx.CertAtt.pubkey_n_len != 256)
                WOLFSSL_MSG("SCE-TSIP isn't usable because the ca isn't signed by "
                            "RSA 2048.");
            else
                WOLFSSL_MSG("SCE-TSIP isn't usable");
        }
        cert->sce_tsip_encRsaKeyIdx = NULL;
    }

    sce_tsip_encRsaKeyIdx = cert->sce_tsip_encRsaKeyIdx;

#else
    sce_tsip_encRsaKeyIdx = NULL;
#endif

    if (verify != NO_VERIFY && type != CA_TYPE && type != TRUSTED_PEER_TYPE) {
        if (cert->ca) {
            if (verify == VERIFY || verify == VERIFY_OCSP ||
                                                 verify == VERIFY_SKIP_DATE) {
                /* try to confirm/verify signature */
                if ((ret = ConfirmSignature(&cert->sigCtx,
                        cert->source + cert->certBegin,
                        cert->sigIndex - cert->certBegin,
                        cert->ca->publicKey, cert->ca->pubKeySize,
                        cert->ca->keyOID, cert->signature,
                        cert->sigLength, cert->signatureOID,
                        sce_tsip_encRsaKeyIdx)) != 0) {
                    if (ret != WC_PENDING_E) {
                        WOLFSSL_MSG("Confirm signature failed");
                    }
                    return ret;
                }
            }
        #ifndef IGNORE_NAME_CONSTRAINTS
            if (verify == VERIFY || verify == VERIFY_OCSP ||
                        verify == VERIFY_NAME || verify == VERIFY_SKIP_DATE) {
                /* check that this cert's name is permitted by the signer's
                 * name constraints */
                if (!ConfirmNameConstraints(cert->ca, cert)) {
                    WOLFSSL_MSG("Confirm name constraint failed");
                    return ASN_NAME_INVALID_E;
                }
            }
        #endif /* IGNORE_NAME_CONSTRAINTS */
        }
        else {
            /* no signer */
            WOLFSSL_MSG("No CA signer to verify with");
            return ASN_NO_SIGNER_E;
        }
    }

#if defined(WOLFSSL_NO_TRUSTED_CERTS_VERIFY) && !defined(NO_SKID)
exit_pcr:
#endif

    if (cert->badDate != 0) {
        if (verify != VERIFY_SKIP_DATE) {
            return cert->badDate;
        }
        WOLFSSL_MSG("Date error: Verify option is skipping");
    }

    if (cert->criticalExt != 0)
        return cert->criticalExt;

    return ret;
}

/* Create and init an new signer */
Signer* MakeSigner(void* heap)
{
    Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap,
                                       DYNAMIC_TYPE_SIGNER);
    if (signer) {
        XMEMSET(signer, 0, sizeof(Signer));
    }
    (void)heap;

    return signer;
}


/* Free an individual signer.
 *
 * Used by Certificate Manager.
 *
 * @param [in, out] signer  On in, signer object.
 *                          On out, pointer is no longer valid.
 * @param [in]      heap    Dynamic memory hint.
 */
void FreeSigner(Signer* signer, void* heap)
{
    XFREE(signer->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE((void*)signer->publicKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
#ifndef IGNORE_NAME_CONSTRAINTS
    if (signer->permittedNames)
        FreeNameSubtrees(signer->permittedNames, heap);
    if (signer->excludedNames)
        FreeNameSubtrees(signer->excludedNames, heap);
#endif
#ifdef WOLFSSL_SIGNER_DER_CERT
    FreeDer(&signer->derCert);
#endif
    XFREE(signer, heap, DYNAMIC_TYPE_SIGNER);

    (void)heap;
}


/* Free the whole singer table with number of rows.
 *
 * Each table entry is a linked list of signers.
 * Used by Certificate Manager.
 *
 * @param [in, out] table   Array of signer objects.
 * @param [in]      rows    Number of entries in table.
 * @param [in]      heap    Dynamic memory hint.
 */
void FreeSignerTable(Signer** table, int rows, void* heap)
{
    int i;

    for (i = 0; i < rows; i++) {
        Signer* signer = table[i];
        while (signer) {
            Signer* next = signer->next;
            FreeSigner(signer, heap);
            signer = next;
        }
        table[i] = NULL;
    }
}

#ifdef WOLFSSL_TRUST_PEER_CERT
/* Free an individual trusted peer cert.
 *
 * @param [in, out] tp    Trusted peer certificate object.
 * @param [in]      heap  Dynamic memory hint.
 */
void FreeTrustedPeer(TrustedPeerCert* tp, void* heap)
{
    if (tp == NULL) {
        return;
    }

    if (tp->name) {
        XFREE(tp->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
    }

    if (tp->sig) {
        XFREE(tp->sig, heap, DYNAMIC_TYPE_SIGNATURE);
    }
#ifndef IGNORE_NAME_CONSTRAINTS
    if (tp->permittedNames)
        FreeNameSubtrees(tp->permittedNames, heap);
    if (tp->excludedNames)
        FreeNameSubtrees(tp->excludedNames, heap);
#endif
    XFREE(tp, heap, DYNAMIC_TYPE_CERT);

    (void)heap;
}

/* Free the whole Trusted Peer linked list.
 *
 * Each table entry is a linked list of trusted peer certificates.
 * Used by Certificate Manager.
 *
 * @param [in, out] table   Array of trusted peer certificate objects.
 * @param [in]      rows    Number of entries in table.
 * @param [in]      heap    Dynamic memory hint.
 */
void FreeTrustedPeerTable(TrustedPeerCert** table, int rows, void* heap)
{
    int i;

    for (i = 0; i < rows; i++) {
        TrustedPeerCert* tp = table[i];
        while (tp) {
            TrustedPeerCert* next = tp->next;
            FreeTrustedPeer(tp, heap);
            tp = next;
        }
        table[i] = NULL;
    }
}
#endif /* WOLFSSL_TRUST_PEER_CERT */

int SetMyVersion(word32 version, byte* output, int header)
{
    int i = 0;

    if (output == NULL)
        return BAD_FUNC_ARG;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = 3;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}

#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS7)
int SetSerialNumber(const byte* sn, word32 snSz, byte* output,
    word32 outputSz, int maxSnSz)
{
    int i;
    int snSzInt = (int)snSz;

    if (sn == NULL || output == NULL || snSzInt < 0)
        return BAD_FUNC_ARG;

    /* remove leading zeros */
    while (snSzInt > 0 && sn[0] == 0) {
        snSzInt--;
        sn++;
    }
    /* RFC 5280 - 4.1.2.2:
     *   Serial numbers must be a positive value (and not zero) */
    if (snSzInt == 0)
        return BAD_FUNC_ARG;

    if (sn[0] & 0x80)
        maxSnSz--;
    /* truncate if input is too long */
    if (snSzInt > maxSnSz)
        snSzInt = maxSnSz;

    i = SetASNInt(snSzInt, sn[0], NULL);
    /* truncate if input is too long */
    if (snSzInt > (int)outputSz - i)
        snSzInt = (int)outputSz - i;
    /* sanity check number of bytes to copy */
    if (snSzInt <= 0) {
        return BUFFER_E;
    }

    /* write out ASN.1 Integer */
    (void)SetASNInt(snSzInt, sn[0], output);
    XMEMCPY(output + i, sn, snSzInt);

    /* compute final length */
    i += snSzInt;

    return i;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */


#ifndef WOLFSSL_ASN_TEMPLATE
int GetSerialNumber(const byte* input, word32* inOutIdx,
    byte* serial, int* serialSz, word32 maxIdx)
{
    int result = 0;
    int ret;

    WOLFSSL_ENTER("GetSerialNumber");

    if (serial == NULL || input == NULL || serialSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* First byte is ASN type */
    if ((*inOutIdx+1) > maxIdx) {
        WOLFSSL_MSG("Bad idx first");
        return BUFFER_E;
    }

    ret = GetASNInt(input, inOutIdx, serialSz, maxIdx);
    if (ret != 0)
        return ret;

    if (*serialSz > EXTERNAL_SERIAL_SIZE || *serialSz <= 0) {
        WOLFSSL_MSG("Serial size bad");
        return ASN_PARSE_E;
    }

    /* return serial */
    XMEMCPY(serial, &input[*inOutIdx], (size_t)*serialSz);
    *inOutIdx += *serialSz;

    return result;
}
#endif


/* TODO: consider moving PEM code out to a different file. */

int AllocDer(DerBuffer** pDer, word32 length, int type, void* heap)
{
    int ret = BAD_FUNC_ARG;
    if (pDer) {
        int dynType = 0;
        DerBuffer* der;

        /* Determine dynamic type */
        switch (type) {
            case CA_TYPE:   dynType = DYNAMIC_TYPE_CA;   break;
            case CERT_TYPE: dynType = DYNAMIC_TYPE_CERT; break;
            case CRL_TYPE:  dynType = DYNAMIC_TYPE_CRL;  break;
            case DSA_TYPE:  dynType = DYNAMIC_TYPE_DSA;  break;
            case ECC_TYPE:  dynType = DYNAMIC_TYPE_ECC;  break;
            case RSA_TYPE:  dynType = DYNAMIC_TYPE_RSA;  break;
            default:        dynType = DYNAMIC_TYPE_KEY;  break;
        }

        /* Setup new buffer */
        *pDer = (DerBuffer*)XMALLOC(sizeof(DerBuffer) + length, heap, dynType);
        if (*pDer == NULL) {
            return MEMORY_E;
        }
        XMEMSET(*pDer, 0, sizeof(DerBuffer) + length);

        der = *pDer;
        der->type = type;
        der->dynType = dynType; /* Cache this for FreeDer */
        der->heap = heap;
        der->buffer = (byte*)der + sizeof(DerBuffer);
        der->length = length;
        ret = 0; /* Success */
    }
    return ret;
}

void FreeDer(DerBuffer** pDer)
{
    if (pDer && *pDer)
    {
        DerBuffer* der = (DerBuffer*)*pDer;

        /* ForceZero private keys */
        if (der->type == PRIVATEKEY_TYPE && der->buffer != NULL) {
            ForceZero(der->buffer, der->length);
        }
        der->buffer = NULL;
        der->length = 0;
        XFREE(der, der->heap, der->dynType);

        *pDer = NULL;
    }
}

int wc_AllocDer(DerBuffer** pDer, word32 length, int type, void* heap)
{
    return AllocDer(pDer, length, type, heap);
}
void wc_FreeDer(DerBuffer** pDer)
{
    FreeDer(pDer);
}


#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)

/* Note: If items added make sure MAX_X509_HEADER_SZ is
    updated to reflect maximum length and pem_struct_min_sz
    to reflect minimum size */
wcchar BEGIN_CERT           = "-----BEGIN CERTIFICATE-----";
wcchar END_CERT             = "-----END CERTIFICATE-----";
#ifdef WOLFSSL_CERT_REQ
    wcchar BEGIN_CERT_REQ   = "-----BEGIN CERTIFICATE REQUEST-----";
    wcchar END_CERT_REQ     = "-----END CERTIFICATE REQUEST-----";
#endif
    wcchar BEGIN_DH_PARAM   = "-----BEGIN DH PARAMETERS-----";
    wcchar END_DH_PARAM     = "-----END DH PARAMETERS-----";
    wcchar BEGIN_X942_PARAM = "-----BEGIN X9.42 DH PARAMETERS-----";
    wcchar END_X942_PARAM   = "-----END X9.42 DH PARAMETERS-----";
wcchar BEGIN_X509_CRL       = "-----BEGIN X509 CRL-----";
wcchar END_X509_CRL         = "-----END X509 CRL-----";
wcchar BEGIN_RSA_PRIV       = "-----BEGIN RSA PRIVATE KEY-----";
wcchar END_RSA_PRIV         = "-----END RSA PRIVATE KEY-----";
wcchar BEGIN_RSA_PUB        = "-----BEGIN RSA PUBLIC KEY-----";
wcchar END_RSA_PUB          = "-----END RSA PUBLIC KEY-----";
wcchar BEGIN_PRIV_KEY       = "-----BEGIN PRIVATE KEY-----";
wcchar END_PRIV_KEY         = "-----END PRIVATE KEY-----";
wcchar BEGIN_ENC_PRIV_KEY   = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
wcchar END_ENC_PRIV_KEY     = "-----END ENCRYPTED PRIVATE KEY-----";
    wcchar BEGIN_EC_PRIV    = "-----BEGIN EC PRIVATE KEY-----";
    wcchar END_EC_PRIV      = "-----END EC PRIVATE KEY-----";
    wcchar BEGIN_DSA_PRIV   = "-----BEGIN DSA PRIVATE KEY-----";
    wcchar END_DSA_PRIV     = "-----END DSA PRIVATE KEY-----";
wcchar BEGIN_PUB_KEY        = "-----BEGIN PUBLIC KEY-----";
wcchar END_PUB_KEY          = "-----END PUBLIC KEY-----";

const int pem_struct_min_sz = XSTR_SIZEOF("-----BEGIN X509 CRL-----"
                                             "-----END X509 CRL-----");

static WC_INLINE const char* SkipEndOfLineChars(const char* line,
                                                const char* endOfLine)
{
    /* eat end of line characters */
    while (line < endOfLine &&
              (line[0] == '\r' || line[0] == '\n')) {
        line++;
    }
    return line;
}

int wc_PemGetHeaderFooter(int type, const char** header, const char** footer)
{
    int ret = BAD_FUNC_ARG;

    switch (type) {
        case CA_TYPE:       /* same as below */
        case TRUSTED_PEER_TYPE:
        case CERT_TYPE:
            if (header) *header = BEGIN_CERT;
            if (footer) *footer = END_CERT;
            ret = 0;
            break;

        case CRL_TYPE:
            if (header) *header = BEGIN_X509_CRL;
            if (footer) *footer = END_X509_CRL;
            ret = 0;
            break;
        case DH_PARAM_TYPE:
            if (header) *header = BEGIN_DH_PARAM;
            if (footer) *footer = END_DH_PARAM;
            ret = 0;
            break;
        case X942_PARAM_TYPE:
            if (header) *header = BEGIN_X942_PARAM;
            if (footer) *footer = END_X942_PARAM;
            ret = 0;
            break;
    #ifdef WOLFSSL_CERT_REQ
        case CERTREQ_TYPE:
            if (header) *header = BEGIN_CERT_REQ;
            if (footer) *footer = END_CERT_REQ;
            ret = 0;
            break;
    #endif
        case ECC_TYPE:
        case ECC_PRIVATEKEY_TYPE:
            if (header) *header = BEGIN_EC_PRIV;
            if (footer) *footer = END_EC_PRIV;
            ret = 0;
            break;
        case RSA_TYPE:
        case PRIVATEKEY_TYPE:
            if (header) *header = BEGIN_RSA_PRIV;
            if (footer) *footer = END_RSA_PRIV;
            ret = 0;
            break;
        case PUBLICKEY_TYPE:
        case ECC_PUBLICKEY_TYPE:
            if (header) *header = BEGIN_PUB_KEY;
            if (footer) *footer = END_PUB_KEY;
            ret = 0;
            break;
        case DH_PRIVATEKEY_TYPE:
        case PKCS8_PRIVATEKEY_TYPE:
            if (header) *header = BEGIN_PRIV_KEY;
            if (footer) *footer = END_PRIV_KEY;
            ret = 0;
            break;
        case PKCS8_ENC_PRIVATEKEY_TYPE:
            if (header) *header = BEGIN_ENC_PRIV_KEY;
            if (footer) *footer = END_ENC_PRIV_KEY;
            ret = 0;
            break;
        default:
            break;
    }
    return ret;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS

static wcchar kProcTypeHeader = "Proc-Type";
static wcchar kDecInfoHeader = "DEK-Info";

#ifdef WOLFSSL_PEM_TO_DER
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    static wcchar kEncTypeAesCbc128 = "AES-128-CBC";
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_192)
    static wcchar kEncTypeAesCbc192 = "AES-192-CBC";
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    static wcchar kEncTypeAesCbc256 = "AES-256-CBC";
#endif

int wc_EncryptedInfoGet(EncryptedInfo* info, const char* cipherInfo)
{
    int ret = 0;

    if (info == NULL || cipherInfo == NULL)
        return BAD_FUNC_ARG;

    /* determine cipher information */
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    if (XSTRCMP(cipherInfo, kEncTypeAesCbc128) == 0) {
        info->cipherType = WC_CIPHER_AES_CBC;
        info->keySz = AES_128_KEY_SIZE;
        if (info->ivSz == 0) info->ivSz  = AES_IV_SIZE;
    }
    else
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_192)
    if (XSTRCMP(cipherInfo, kEncTypeAesCbc192) == 0) {
        info->cipherType = WC_CIPHER_AES_CBC;
        info->keySz = AES_192_KEY_SIZE;
        if (info->ivSz == 0) info->ivSz  = AES_IV_SIZE;
    }
    else
#endif
#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_256)
    if (XSTRCMP(cipherInfo, kEncTypeAesCbc256) == 0) {
        info->cipherType = WC_CIPHER_AES_CBC;
        info->keySz = AES_256_KEY_SIZE;
        if (info->ivSz == 0) info->ivSz  = AES_IV_SIZE;
    }
    else
#endif
    {
        ret = NOT_COMPILED_IN;
    }
    return ret;
}

int wc_EncryptedInfoParse(EncryptedInfo* info, const char** pBuffer,
                          size_t bufSz)
{
    int         err = 0;
    const char* bufferStart;
    const char* bufferEnd;
    char*       line;
    word32      lineSz;
    char*       finish;
    word32      finishSz;
    char*       start = NULL;
    word32      startSz;
    const char* newline = NULL;

    if (info == NULL || pBuffer == NULL || bufSz == 0)
        return BAD_FUNC_ARG;

    bufferStart = *pBuffer;
    bufferEnd = bufferStart + bufSz;

    /* find encrypted info marker */
    line = XSTRNSTR(bufferStart, kProcTypeHeader,
                    min((word32)bufSz, PEM_LINE_LEN));
    if (line != NULL) {
        if (line >= bufferEnd) {
            return BUFFER_E;
        }

        lineSz = (word32)(bufferEnd - line);

        /* find DEC-Info marker */
        start = XSTRNSTR(line, kDecInfoHeader, min(lineSz, PEM_LINE_LEN));

        if (start == NULL)
            return BUFFER_E;

        /* skip dec-info and ": " */
        start += XSTRLEN(kDecInfoHeader);
        if (start >= bufferEnd)
            return BUFFER_E;

        if (start[0] == ':') {
            start++;
            if (start >= bufferEnd)
                return BUFFER_E;
        }
        if (start[0] == ' ')
            start++;

        startSz = (word32)(bufferEnd - start);
        finish = XSTRNSTR(start, ",", min(startSz, PEM_LINE_LEN));

        if ((start != NULL) && (finish != NULL) && (start < finish)) {
            if (finish >= bufferEnd) {
                return BUFFER_E;
            }

            finishSz = (word32)(bufferEnd - finish);
            newline = XSTRNSTR(finish, "\r", min(finishSz, PEM_LINE_LEN));

            /* get cipher name */
            if (NAME_SZ < (finish - start)) /* buffer size of info->name */
                return BUFFER_E;
            if (XMEMCPY(info->name, start, finish - start) == NULL)
                return BUFFER_E;
            info->name[finish - start] = '\0'; /* null term */

            /* populate info */
            err = wc_EncryptedInfoGet(info, info->name);
            if (err != 0)
                return err;

            /* get IV */
            if (finishSz < info->ivSz + 1)
                return BUFFER_E;

            if (newline == NULL) {
                newline = XSTRNSTR(finish, "\n", min(finishSz,
                                                     PEM_LINE_LEN));
            }
            if ((newline != NULL) && (newline > finish)) {
                finish++;
                info->ivSz = (word32)(newline - finish);
                if (info->ivSz > IV_SZ)
                    return BUFFER_E;
                if (XMEMCPY(info->iv, finish, info->ivSz) == NULL)
                    return BUFFER_E;
                info->set = 1;
            }
            else
                return BUFFER_E;
        }
        else
            return BUFFER_E;

        /* eat end of line characters */
        newline = SkipEndOfLineChars(newline, bufferEnd);

        /* return new headerEnd */

        *pBuffer = newline;
    }

    return err;
}
#endif /* WOLFSSL_PEM_TO_DER */

#ifdef WOLFSSL_DER_TO_PEM
static int wc_EncryptedInfoAppend(char* dest, int destSz, char* cipherInfo)
{
    if (cipherInfo != NULL) {
        int cipherInfoStrLen = (int)XSTRLEN((char*)cipherInfo);

        if (cipherInfoStrLen > HEADER_ENCRYPTED_KEY_SIZE - (9+14+10+3))
            cipherInfoStrLen = HEADER_ENCRYPTED_KEY_SIZE - (9+14+10+3);

        if (destSz - (int)XSTRLEN(dest) >= cipherInfoStrLen + (9+14+8+2+2+1)) {
            /* strncat's src length needs to include the NULL */
            XSTRNCAT(dest, kProcTypeHeader, 10);
            XSTRNCAT(dest, ": 4,ENCRYPTED\n", 15);
            XSTRNCAT(dest, kDecInfoHeader, 9);
            XSTRNCAT(dest, ": ", 3);
            XSTRNCAT(dest, cipherInfo, destSz - (int)XSTRLEN(dest) - 1);
            XSTRNCAT(dest, "\n\n", 4);
        }
    }
    return 0;
}
#endif /* WOLFSSL_DER_TO_PEM */
#endif /* WOLFSSL_ENCRYPTED_KEYS */

#ifdef WOLFSSL_DER_TO_PEM

/* Used for compatibility API */
int wc_DerToPem(const byte* der, word32 derSz,
                byte* output, word32 outSz, int type)
{
    return wc_DerToPemEx(der, derSz, output, outSz, NULL, type);
}

/* convert der buffer to pem into output, can't do inplace, der and output
   need to be different */
int wc_DerToPemEx(const byte* der, word32 derSz, byte* output, word32 outSz,
             byte *cipher_info, int type)
{
    const char* headerStr = NULL;
    const char* footerStr = NULL;
    char header[MAX_X509_HEADER_SZ + HEADER_ENCRYPTED_KEY_SIZE];
    char footer[MAX_X509_HEADER_SZ];
    int headerLen = MAX_X509_HEADER_SZ + HEADER_ENCRYPTED_KEY_SIZE;
    int footerLen = MAX_X509_HEADER_SZ;
    int i;
    int err;
    int outLen;   /* return length or error */

    (void)cipher_info;

    if (der == output)      /* no in place conversion */
        return BAD_FUNC_ARG;

    err = wc_PemGetHeaderFooter(type, &headerStr, &footerStr);
    if (err != 0)
        return err;


    /* build header and footer based on type */
    XSTRNCPY(header, headerStr, headerLen - 1);
    header[headerLen - 2] = 0;
    XSTRNCPY(footer, footerStr, footerLen - 1);
    footer[footerLen - 2] = 0;

    /* add new line to end */
    XSTRNCAT(header, "\n", 2);
    XSTRNCAT(footer, "\n", 2);

#ifdef WOLFSSL_ENCRYPTED_KEYS
    err = wc_EncryptedInfoAppend(header, headerLen, (char*)cipher_info);
    if (err != 0) {
        return err;
    }
#endif

    headerLen = (int)XSTRLEN(header);
    footerLen = (int)XSTRLEN(footer);

    /* if null output and 0 size passed in then return size needed */
    if (!output && outSz == 0) {
        outLen = 0;
        if ((err = Base64_Encode(der, derSz, NULL, (word32*)&outLen))
                != LENGTH_ONLY_E) {
            return err;
        }
        return headerLen + footerLen + outLen;
    }

    if (!der || !output) {
        return BAD_FUNC_ARG;
    }

    /* don't even try if outSz too short */
    if (outSz < headerLen + footerLen + derSz) {
        return BAD_FUNC_ARG;
    }

    /* header */
    XMEMCPY(output, header, headerLen);
    i = headerLen;


    /* body */
    outLen = outSz - (headerLen + footerLen);  /* input to Base64_Encode */
    if ( (err = Base64_Encode(der, derSz, output + i, (word32*)&outLen)) < 0) {
        return err;
    }
    i += outLen;

    /* footer */
    if ( (i + footerLen) > (int)outSz) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(output + i, footer, footerLen);


    return outLen + headerLen + footerLen;
}

#endif /* WOLFSSL_DER_TO_PEM */

#ifdef WOLFSSL_PEM_TO_DER

/* Remove PEM header/footer, convert to ASN1, store any encrypted data
   info->consumed tracks of PEM bytes consumed in case multiple parts */
int PemToDer(const unsigned char* buff, long longSz, int type,
              DerBuffer** pDer, void* heap, EncryptedInfo* info, int* keyFormat)
{
    const char* header      = NULL;
    const char* footer      = NULL;
    const char* headerEnd;
    const char* footerEnd;
    const char* consumedEnd;
    const char* bufferEnd   = (const char*)(buff + longSz);
    long        neededSz;
    int         ret         = 0;
    int         sz          = (int)longSz;
    int         encrypted_key = 0;
    DerBuffer*  der;
    word32      algId = 0;
    word32      idx;
#if defined(WOLFSSL_ENCRYPTED_KEYS)
    #if (  defined(HAVE_AES_CBC) &&  defined(HAVE_AES_DECRYPT)) &&  !defined(NO_WOLFSSL_SKIP_TRAILING_PAD)
        int     padVal = 0;
    #endif
#endif

    WOLFSSL_ENTER("PemToDer");

    /* get PEM header and footer based on type */
    ret = wc_PemGetHeaderFooter(type, &header, &footer);
    if (ret != 0)
        return ret;

    /* map header if not found for type */
    for (;;) {
        headerEnd = XSTRNSTR((char*)buff, header, sz);
        if (headerEnd) {
            break;
        }

        if (type == PRIVATEKEY_TYPE) {
            if (header == BEGIN_RSA_PRIV) {
                header = BEGIN_PRIV_KEY;
                footer = END_PRIV_KEY;
            }
            else if (header == BEGIN_PRIV_KEY) {
                header = BEGIN_ENC_PRIV_KEY;
                footer = END_ENC_PRIV_KEY;
            }
            else if (header == BEGIN_ENC_PRIV_KEY) {
                header = BEGIN_EC_PRIV;
                footer = END_EC_PRIV;
            }
            else if (header == BEGIN_EC_PRIV) {
                header = BEGIN_DSA_PRIV;
                footer = END_DSA_PRIV;
            }
            else {
                break;
            }
        }
        else if (type == PUBLICKEY_TYPE) {
            if (header == BEGIN_PUB_KEY) {
                header = BEGIN_RSA_PUB;
                footer = END_RSA_PUB;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }

    if (!headerEnd) {
        WOLFSSL_MSG("Couldn't find PEM header");
        return ASN_NO_PEM_HEADER;
    } else {
        headerEnd += XSTRLEN(header);
    }

    /* eat end of line characters */
    headerEnd = SkipEndOfLineChars(headerEnd, bufferEnd);

    if (keyFormat) {
        /* keyFormat is Key_Sum enum */
        if (type == PRIVATEKEY_TYPE) {
            if (header == BEGIN_RSA_PRIV)
                *keyFormat = RSAk;
            if (header == BEGIN_EC_PRIV)
                *keyFormat = ECDSAk;
        }
    }

#ifdef WOLFSSL_ENCRYPTED_KEYS
    if (info) {
        ret = wc_EncryptedInfoParse(info, &headerEnd, bufferEnd - headerEnd);
        if (ret < 0)
            return ret;
        if (info->set)
            encrypted_key = 1;
    }
#endif /* WOLFSSL_ENCRYPTED_KEYS */

    /* find footer */
    footerEnd = XSTRNSTR(headerEnd, footer, (unsigned int)((char*)buff +
        sz - headerEnd));
    if (!footerEnd) {
        if (info)
            info->consumed = longSz; /* No more certs if no footer */
        return BUFFER_E;
    }

    consumedEnd = footerEnd + XSTRLEN(footer);

    if (consumedEnd < bufferEnd) { /* handle no end of line on last line */
        /* eat end of line characters */
        consumedEnd = SkipEndOfLineChars(consumedEnd, bufferEnd);
        /* skip possible null term */
        if (consumedEnd < bufferEnd && consumedEnd[0] == '\0')
            consumedEnd++;
    }

    if (info)
        info->consumed = (long)(consumedEnd - (const char*)buff);

    /* set up der buffer */
    neededSz = (long)(footerEnd - headerEnd);
    if (neededSz > sz || neededSz <= 0)
        return BUFFER_E;

    ret = AllocDer(pDer, (word32)neededSz, type, heap);
    if (ret < 0) {
        return ret;
    }
    der = *pDer;

    if (Base64_Decode((byte*)headerEnd, (word32)neededSz,
                      der->buffer, &der->length) < 0) {
        WOLFSSL_ERROR(BUFFER_E);
        return BUFFER_E;
    }

    if ((header == BEGIN_PRIV_KEY
         || header == BEGIN_EC_PRIV
        ) && !encrypted_key)
    {
        /* detect pkcs8 key and get alg type */
        /* keep PKCS8 header */
        idx = 0;
        ret = ToTraditionalInline_ex(der->buffer, &idx, der->length, &algId);
        if (ret > 0) {
            if (keyFormat)
                *keyFormat = algId;
        }
        else {
            /* ignore failure here and assume key is not pkcs8 wrapped */
        }
        return 0;
    }

#ifdef WOLFSSL_ENCRYPTED_KEYS
    if (encrypted_key || header == BEGIN_ENC_PRIV_KEY) {
        int   passwordSz = NAME_SZ;
        char  password[NAME_SZ];

        if (!info || !info->passwd_cb) {
            WOLFSSL_MSG("No password callback set");
            return NO_PASSWORD;
        }


        /* get password */
        ret = info->passwd_cb(password, passwordSz, PEM_PASS_READ,
            info->passwd_userdata);
        if (ret >= 0) {
            passwordSz = ret;

            /* convert and adjust length */
            if (header == BEGIN_ENC_PRIV_KEY) {
            #ifndef NO_PWDBASED
                ret = wc_DecryptPKCS8Key(der->buffer, der->length,
                    password, passwordSz);
                if (ret > 0) {
                    /* update length by decrypted content */
                    der->length = ret;
                    idx = 0;
                    /* detect pkcs8 key and get alg type */
                    /* keep PKCS8 header */
                    ret = ToTraditionalInline_ex(der->buffer, &idx, der->length,
                        &algId);
                    if (ret >= 0) {
                        if (keyFormat)
                            *keyFormat = algId;
                        ret = 0;
                    }
                }
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
            /* decrypt the key */
            else {
                if (passwordSz == 0) {
                    /* The key is encrypted but does not have a password */
                    WOLFSSL_MSG("No password for encrypted key");
                    ret = NO_PASSWORD;
                }
                else {
                    ret = wc_BufferKeyDecrypt(info, der->buffer, der->length,
                        (byte*)password, passwordSz, WC_MD5);

#ifndef NO_WOLFSSL_SKIP_TRAILING_PAD
                #if defined(HAVE_AES_CBC) &&  defined(HAVE_AES_DECRYPT)
                    if (info->cipherType == WC_CIPHER_AES_CBC) {
                        if (der->length > AES_BLOCK_SIZE) {
                            padVal = der->buffer[der->length-1];
                            if (padVal <= AES_BLOCK_SIZE) {
                                der->length -= padVal;
                            }
                        }
                    }
                #endif
#endif /* !NO_WOLFSSL_SKIP_TRAILING_PAD */
                }
            }
            ForceZero(password, passwordSz);
        }

    }
#endif /* WOLFSSL_ENCRYPTED_KEYS */

    return ret;
}

int wc_PemToDer(const unsigned char* buff, long longSz, int type,
              DerBuffer** pDer, void* heap, EncryptedInfo* info, int* keyFormat)
{
    int ret = PemToDer(buff, longSz, type, pDer, heap, info, keyFormat);
#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    if (ret == 0 && type == PRIVATEKEY_TYPE) {
        DerBuffer* der = *pDer;
        /* if a PKCS8 key header exists remove it */
        ret = ToTraditional(der->buffer, der->length);
        if (ret > 0) {
            der->length = ret;
        }
        ret = 0; /* ignore error removing PKCS8 header */
    }
#endif
    return ret;
}


/* our KeyPemToDer password callback, password in userData */
static int KeyPemToDerPassCb(char* passwd, int sz, int rw, void* userdata)
{
    (void)rw;

    if (userdata == NULL)
        return 0;

    XSTRNCPY(passwd, (char*)userdata, sz);
    return min((word32)sz, (word32)XSTRLEN((char*)userdata));
}

/* Return bytes written to buff or < 0 for error */
int wc_KeyPemToDer(const unsigned char* pem, int pemSz,
                        unsigned char* buff, int buffSz, const char* pass)
{
    int ret;
    DerBuffer* der = NULL;
    EncryptedInfo  info[1];

    WOLFSSL_ENTER("wc_KeyPemToDer");

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        WOLFSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }


    XMEMSET(info, 0, sizeof(EncryptedInfo));
    info->passwd_cb = KeyPemToDerPassCb;
    info->passwd_userdata = (void*)pass;

    ret = PemToDer(pem, pemSz, PRIVATEKEY_TYPE, &der, NULL, info, NULL);


    if (ret < 0 || der == NULL) {
        WOLFSSL_MSG("Bad Pem To Der");
    }
    else {
        if (der->length <= (word32)buffSz) {
            XMEMCPY(buff, der->buffer, der->length);
            ret = der->length;
        }
        else {
            WOLFSSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    FreeDer(&der);
    return ret;
}


/* Return bytes written to buff or < 0 for error */
int wc_CertPemToDer(const unsigned char* pem, int pemSz,
                        unsigned char* buff, int buffSz, int type)
{
    int ret;
    DerBuffer* der = NULL;

    WOLFSSL_ENTER("wc_CertPemToDer");

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        WOLFSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

    if (type != CERT_TYPE && type != CA_TYPE && type != CERTREQ_TYPE) {
        WOLFSSL_MSG("Bad cert type");
        return BAD_FUNC_ARG;
    }


    ret = PemToDer(pem, pemSz, type, &der, NULL, NULL, NULL);
    if (ret < 0 || der == NULL) {
        WOLFSSL_MSG("Bad Pem To Der");
    }
    else {
        if (der->length <= (word32)buffSz) {
            XMEMCPY(buff, der->buffer, der->length);
            ret = der->length;
        }
        else {
            WOLFSSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    FreeDer(&der);
    return ret;
}

#endif /* WOLFSSL_PEM_TO_DER */
#endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */


#ifdef WOLFSSL_PEM_TO_DER
#if defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_PUB_PEM_TO_DER)
/* Return bytes written to buff or < 0 for error */
int wc_PubKeyPemToDer(const unsigned char* pem, int pemSz,
                           unsigned char* buff, int buffSz)
{
    int ret;
    DerBuffer* der = NULL;

    WOLFSSL_ENTER("wc_PubKeyPemToDer");

    if (pem == NULL || buff == NULL || buffSz <= 0) {
        WOLFSSL_MSG("Bad pem der args");
        return BAD_FUNC_ARG;
    }

    ret = PemToDer(pem, pemSz, PUBLICKEY_TYPE, &der, NULL, NULL, NULL);
    if (ret < 0 || der == NULL) {
        WOLFSSL_MSG("Bad Pem To Der");
    }
    else {
        if (der->length <= (word32)buffSz) {
            XMEMCPY(buff, der->buffer, der->length);
            ret = der->length;
        }
        else {
            WOLFSSL_MSG("Bad der length");
            ret = BAD_FUNC_ARG;
        }
    }

    FreeDer(&der);
    return ret;
}
#endif /* WOLFSSL_CERT_EXT || WOLFSSL_PUB_PEM_TO_DER */
#endif /* WOLFSSL_PEM_TO_DER */

#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_PEM_TO_DER)

#ifdef WOLFSSL_CERT_GEN
int wc_PemCertToDer_ex(const char* fileName, DerBuffer** der)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  fileBuf = staticBuffer;
    int    dynamic = 0;
    int    ret     = 0;
    long   sz      = 0;
    XFILE  file    = NULL;

    WOLFSSL_ENTER("wc_PemCertToDer");

    if (fileName == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        file = XFOPEN(fileName, "rb");
        if (file == XBADFILE) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        if (XFSEEK(file, 0, XSEEK_END) != 0) {
            ret = BUFFER_E;
        }
        sz = XFTELL(file);
        XREWIND(file);

        if (sz <= 0) {
            ret = BUFFER_E;
        }
        else if (sz > (long)sizeof(staticBuffer)) {
            fileBuf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE);
            if (fileBuf == NULL)
                ret = MEMORY_E;
            else
                dynamic = 1;
        }

        if (ret == 0) {
            if ((size_t)XFREAD(fileBuf, 1, sz, file) != (size_t)sz) {
                ret = BUFFER_E;
            }
            else {
                ret = PemToDer(fileBuf, sz, CA_TYPE, der,  0, NULL,NULL);
            }
        }

        XFCLOSE(file);
        if (dynamic)
            XFREE(fileBuf, NULL, DYNAMIC_TYPE_FILE);
    }

    return ret;
}
/* load pem cert from file into der buffer, return der size or error */
int wc_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz)
{
    int ret;
    DerBuffer* converted = NULL;
    ret = wc_PemCertToDer_ex(fileName, &converted);
    if (ret == 0) {
        if (converted->length < (word32)derSz) {
            XMEMCPY(derBuf, converted->buffer, converted->length);
            ret = converted->length;
        }
        else
            ret = BUFFER_E;

        FreeDer(&converted);
    }
    return ret;
}
#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_PUB_PEM_TO_DER)
/* load pem public key from file into der buffer, return der size or error */
int wc_PemPubKeyToDer_ex(const char* fileName, DerBuffer** der)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  fileBuf = staticBuffer;
    int    dynamic = 0;
    int    ret     = 0;
    long   sz      = 0;
    XFILE  file;

    WOLFSSL_ENTER("wc_PemPubKeyToDer");

    if (fileName == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        file = XFOPEN(fileName, "rb");
        if (file == XBADFILE) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        if (XFSEEK(file, 0, XSEEK_END) != 0) {
            ret = BUFFER_E;
        }
        sz = XFTELL(file);
        XREWIND(file);

        if (sz <= 0) {
            ret = BUFFER_E;
        }
        else if (sz > (long)sizeof(staticBuffer)) {
            fileBuf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE);
            if (fileBuf == NULL)
                ret = MEMORY_E;
            else
                dynamic = 1;
        }
        if (ret == 0) {
            if ((size_t)XFREAD(fileBuf, 1, sz, file) != (size_t)sz) {
                ret = BUFFER_E;
            }
            else {
                ret = PemToDer(fileBuf, sz, PUBLICKEY_TYPE, der,
                               0, NULL, NULL);
            }
        }

        XFCLOSE(file);
        if (dynamic) {
            XFREE(fileBuf, NULL, DYNAMIC_TYPE_FILE);
        }
    }

    return ret;
}
/* load pem public key from file into der buffer, return der size or error */
int wc_PemPubKeyToDer(const char* fileName,
                           unsigned char* derBuf, int derSz)
{
    int ret;
    DerBuffer* converted = NULL;
    ret = wc_PemPubKeyToDer_ex(fileName, &converted);
    if (ret == 0) {
        if (converted->length < (word32)derSz) {
            XMEMCPY(derBuf, converted->buffer, converted->length);
            ret = converted->length;
        }
        else
            ret = BUFFER_E;

        FreeDer(&converted);
    }
    return ret;
}
#endif /* WOLFSSL_CERT_EXT || WOLFSSL_PUB_PEM_TO_DER */

#endif /* !NO_FILESYSTEM && WOLFSSL_PEM_TO_DER */

/* Get public key in DER format from a populated DecodedCert struct.
 *
 * Users must call wc_InitDecodedCert() and wc_ParseCert() before calling
 * this API. wc_InitDecodedCert() accepts a DER/ASN.1 encoded certificate.
 * To convert a PEM cert to DER first use wc_CertPemToDer() before calling
 * wc_InitDecodedCert().
 *
 * cert   - populated DecodedCert struct holding X.509 certificate
 * derKey - output buffer to place DER/ASN.1 encoded public key
 * derKeySz [IN/OUT] - size of derKey buffer on input, size of public key
 *                     on return. If derKey is passed in as NULL, derKeySz
 *                     will be set to required buffer size for public key
 *                     and LENGTH_ONLY_E will be returned from function.
 * Returns 0 on success, or negative error code on failure. LENGTH_ONLY_E
 * if derKey is NULL and returning length only.
 */
int wc_GetPubKeyDerFromCert(struct DecodedCert* cert,
                            byte* derKey, word32* derKeySz)
{
    int ret = 0;

    /* derKey may be NULL to return length only */
    if (cert == NULL || derKeySz == NULL ||
        (derKey != NULL && *derKeySz == 0)) {
        return BAD_FUNC_ARG;
    }

    if (cert->publicKey == NULL) {
        WOLFSSL_MSG("DecodedCert does not contain public key\n");
        return BAD_FUNC_ARG;
    }

    /* if derKey is NULL, return required output buffer size in derKeySz */
    if (derKey == NULL) {
        *derKeySz = cert->pubKeySize;
        ret = LENGTH_ONLY_E;
    }

    if (ret == 0) {
        if (cert->pubKeySize > *derKeySz) {
            WOLFSSL_MSG("Output buffer not large enough for public key DER");
            ret = BAD_FUNC_ARG;
        }
        else {
            XMEMCPY(derKey, cert->publicKey, cert->pubKeySize);
            *derKeySz = cert->pubKeySize;
        }
    }

    return ret;
}

#if (defined(WOLFSSL_CERT_GEN) ||  defined(WOLFSSL_KCAPI_RSA) ||  (defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)))
/* USER RSA ifdef portions used instead of refactor in consideration for
   possible fips build */
/* Encode a public RSA key to output.
 *
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 *
 * Encoded data can either be SubjectPublicKeyInfo (with header) or just the key
 * (RSAPublicKey).
 *
 * @param [out] output       Buffer to put encoded data in.
 * @param [in]  key          RSA key object.
 * @param [in]  outLen       Size of the output buffer in bytes.
 * @param [in]  with_header  Whether to include SubjectPublicKeyInfo around key.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when output or key is NULL, or outLen is less than
 *          minimum length (5 bytes).
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int SetRsaPublicKey(byte* output, RsaKey* key, int outLen,
                           int with_header)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int  idx, nSz, eSz, seqSz, headSz = 0, bitStringSz = 0, algoSz = 0;
    byte seq[MAX_SEQ_SZ];
    byte headSeq[MAX_SEQ_SZ];
    byte bitString[1 + MAX_LENGTH_SZ + 1];
    byte algo[MAX_ALGO_SZ]; /* 20 bytes */

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_USER_RSA
    nSz = SetASNIntRSA(key->n, NULL);
#else
    nSz = SetASNIntMP(&key->n, MAX_RSA_INT_SZ, NULL);
#endif
    if (nSz < 0)
        return nSz;

#ifdef HAVE_USER_RSA
    eSz = SetASNIntRSA(key->e, NULL);
#else
    eSz = SetASNIntMP(&key->e, MAX_RSA_INT_SZ, NULL);
#endif
    if (eSz < 0)
        return eSz;
    seqSz = SetSequence(nSz + eSz, seq);

    /* headers */
    if (with_header) {
        algoSz = SetAlgoID(RSAk, algo, oidKeyType, 0);
        bitStringSz = SetBitString(seqSz + nSz + eSz, 0, bitString);
        headSz = SetSequence(nSz + eSz + seqSz + bitStringSz + algoSz, headSeq);
    }

    /* if getting length only */
    if (output == NULL) {
        return headSz + algoSz + bitStringSz + seqSz + nSz + eSz;
    }

    /* check output size */
    if ((headSz + algoSz + bitStringSz + seqSz + nSz + eSz) > outLen) {
        return BUFFER_E;
    }

    /* write output */
    idx = 0;
    if (with_header) {
        /* header size */
        XMEMCPY(output + idx, headSeq, headSz);
        idx += headSz;
        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* bit string */
        XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }

    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
#ifdef HAVE_USER_RSA
    nSz = SetASNIntRSA(key->n, output + idx);
#else
    nSz = SetASNIntMP(&key->n, nSz, output + idx);
#endif
    idx += nSz;
    /* e */
#ifdef HAVE_USER_RSA
    eSz = SetASNIntRSA(key->e, output + idx);
#else
    eSz = SetASNIntMP(&key->e, eSz, output + idx);
#endif
    idx += eSz;

    return idx;
#else
    DECL_ASNSETDATA(dataASN, rsaPublicKeyASN_Length);
    int sz = 0;
    int ret = 0;
    int o = 0;

    /* Check parameter validity. */
    if ((key == NULL) || ((output != NULL) && (outLen < MAX_SEQ_SZ))) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, rsaPublicKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        if (!with_header) {
            /* Start encoding with items after header. */
            o = RSAPUBLICKEYASN_IDX_PUBKEY_RSA_SEQ;
        }
        /* Set OID for RSA key. */
        SetASN_OID(&dataASN[RSAPUBLICKEYASN_IDX_ALGOID_OID], RSAk, oidKeyType);
        /* Set public key mp_ints. */
    #ifdef HAVE_USER_RSA
        SetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N], key->n);
        SetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E], key->e);
    #else
        SetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_N], &key->n);
        SetASN_MP(&dataASN[RSAPUBLICKEYASN_IDX_PUBKEY_RSA_E], &key->e);
    #endif
        /* Calculate size of RSA public key. */
        ret = SizeASN_Items(rsaPublicKeyASN + o, dataASN + o,
                            rsaPublicKeyASN_Length - o, &sz);
    }
    /* Check output buffer is big enough for encoding. */
    if ((ret == 0) && (output != NULL) && (sz > outLen)) {
        ret = BUFFER_E;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Encode RSA public key. */
        SetASN_Items(rsaPublicKeyASN + o, dataASN + o,
                     rsaPublicKeyASN_Length - o, output);
    }
    if (ret == 0) {
        /* Return size of encoding. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, key->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#endif /* !NO_RSA && (WOLFSSL_CERT_GEN || (WOLFSSL_KEY_GEN &&
                                           !HAVE_USER_RSA))) */

#if defined(WOLFSSL_CERT_GEN)
/* Calculate size of encoded public RSA key in bytes.
 *
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 *
 * Encoded data can either be SubjectPublicKeyInfo (with header) or just the key
 * (RSAPublicKey).
 *
 * @param [in]  key          RSA key object.
 * @param [in]  with_header  Whether to include SubjectPublicKeyInfo around key.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_RsaPublicKeyDerSize(RsaKey* key, int with_header)
{
    return SetRsaPublicKey(NULL, key, 0, with_header);
}

#endif /* !NO_RSA && WOLFSSL_CERT_GEN */

#if (defined(WOLFSSL_KEY_GEN) ||  defined(WOLFSSL_KCAPI_RSA)) && !defined(HAVE_USER_RSA)

/* Encode private RSA key in DER format.
 *
 * PKCS #1: RFC 8017, A.1.2 - RSAPrivateKey
 *
 * @param [in]  key     RSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL or not a private key.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret = 0, i, j, outLen = 0, mpSz;
    word32 seqSz = 0, verSz = 0, rawLen, intTotalLen = 0;
    word32 sizes[RSA_INTS];
    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    byte* tmps[RSA_INTS];

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (key->type != RSA_PRIVATE)
        return BAD_FUNC_ARG;

    for (i = 0; i < RSA_INTS; i++)
        tmps[i] = NULL;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < RSA_INTS; i++) {
        mp_int* keyInt = GetRsaInt(key, (byte)i);

        rawLen = mp_unsigned_bin_size(keyInt) + 1;
        if (output != NULL) {
            tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                 DYNAMIC_TYPE_RSA);
            if (tmps[i] == NULL) {
                ret = MEMORY_E;
                break;
            }
        }

        mpSz = SetASNIntMP(keyInt, MAX_RSA_INT_SZ, tmps[i]);
        if (mpSz < 0) {
            ret = mpSz;
            break;
        }
        intTotalLen += (sizes[i] = mpSz);
    }

    if (ret == 0) {
        /* make headers */
        verSz = SetMyVersion(0, ver, FALSE);
        seqSz = SetSequence(verSz + intTotalLen, seq);

        outLen = seqSz + verSz + intTotalLen;
        if (output != NULL && outLen > (int)inLen)
            ret = BUFFER_E;
    }
    if (ret == 0 && output != NULL) {
        /* write to output */
        XMEMCPY(output, seq, seqSz);
        j = seqSz;
        XMEMCPY(output + j, ver, verSz);
        j += verSz;

        for (i = 0; i < RSA_INTS; i++) {
            XMEMCPY(output + j, tmps[i], sizes[i]);
            j += sizes[i];
        }
    }

    for (i = 0; i < RSA_INTS; i++) {
        if (tmps[i])
            XFREE(tmps[i], key->heap, DYNAMIC_TYPE_RSA);
    }

    if (ret == 0)
        ret = outLen;
    return ret;
#else
    DECL_ASNSETDATA(dataASN, rsaKeyASN_Length);
    int i;
    int sz = 0;
    int ret = 0;

    if ((key == NULL) || (key->type != RSA_PRIVATE)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, rsaKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Set the version. */
        SetASN_Int8Bit(&dataASN[RSAKEYASN_IDX_VER], 0);
        /* Set all the mp_ints in private key. */
        for (i = 0; i < RSA_INTS; i++) {
            SetASN_MP(&dataASN[(byte)RSAKEYASN_IDX_N + i], GetRsaInt(key, i));
        }

        /* Calculate size of RSA private key encoding. */
        ret = SizeASN_Items(rsaKeyASN, dataASN, rsaKeyASN_Length, &sz);
    }
    /* Check output buffer has enough space for encoding. */
    if ((ret == 0) && (output != NULL) && (sz > (int)inLen)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Encode RSA private key. */
        SetASN_Items(rsaKeyASN, dataASN, rsaKeyASN_Length, output);
    }

    if (ret == 0) {
        /* Return size of encoding. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, key->heap);
    return ret;
#endif
}


/* Encode public RSA key in DER format.
 *
 * X.509: RFC 5280, 4.1 - SubjectPublicKeyInfo
 * PKCS #1: RFC 8017, A.1.1 - RSAPublicKey
 *
 * @param [in]  key     RSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key or output is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen)
{
    return SetRsaPublicKey(output, key, inLen, 1);
}

/* Returns public DER version of the RSA key. If with_header is 0 then only a
 * seq + n + e is returned in ASN.1 DER format */
int wc_RsaKeyToPublicDer_ex(RsaKey* key, byte* output, word32 inLen,
    int with_header)
{
    return SetRsaPublicKey(output, key, inLen, with_header);
}
#endif /* (WOLFSSL_KEY_GEN || OPENSSL_EXTRA) && !NO_RSA && !HAVE_USER_RSA */


#ifdef WOLFSSL_CERT_GEN

/* Initialize and Set Certificate defaults:
   version    = 3 (0x2)
   serial     = 0
   sigType    = SHA_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
*/
int wc_InitCert_ex(Cert* cert, void* heap, int devId)
{
#ifdef WOLFSSL_MULTI_ATTRIB
    int i = 0;
#endif
    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(cert, 0, sizeof(Cert));

    cert->version    = 2;   /* version 3 is hex 2 */
    cert->sigType    = CTC_SHAwRSA;
    cert->daysValid  = 500;
    cert->selfSigned = 1;
    cert->keyType    = RSA_KEY;

    cert->issuer.countryEnc = CTC_PRINTABLE;
    cert->issuer.stateEnc = CTC_UTF8;
    cert->issuer.localityEnc = CTC_UTF8;
    cert->issuer.surEnc = CTC_UTF8;
    cert->issuer.orgEnc = CTC_UTF8;
    cert->issuer.unitEnc = CTC_UTF8;
    cert->issuer.commonNameEnc = CTC_UTF8;

    cert->subject.countryEnc = CTC_PRINTABLE;
    cert->subject.stateEnc = CTC_UTF8;
    cert->subject.localityEnc = CTC_UTF8;
    cert->subject.surEnc = CTC_UTF8;
    cert->subject.orgEnc = CTC_UTF8;
    cert->subject.unitEnc = CTC_UTF8;
    cert->subject.commonNameEnc = CTC_UTF8;

#ifdef WOLFSSL_MULTI_ATTRIB
    for (i = 0; i < CTC_MAX_ATTRIB; i++) {
        cert->issuer.name[i].type   = CTC_UTF8;
        cert->subject.name[i].type  = CTC_UTF8;
    }
#endif /* WOLFSSL_MULTI_ATTRIB */

    cert->heap = heap;
    (void)devId; /* future */

    return 0;
}

int wc_InitCert(Cert* cert)
{
    return wc_InitCert_ex(cert, NULL, INVALID_DEVID);
}

/* DER encoded x509 Certificate */
typedef struct DerCert {
    byte size[MAX_LENGTH_SZ];          /* length encoded */
    byte version[MAX_VERSION_SZ];      /* version encoded */
    byte serial[(int)CTC_SERIAL_SIZE + (int)MAX_LENGTH_SZ]; /* serial number encoded */
    byte sigAlgo[MAX_ALGO_SZ];         /* signature algo encoded */
    byte issuer[WC_ASN_NAME_MAX];         /* issuer  encoded */
    byte subject[WC_ASN_NAME_MAX];        /* subject encoded */
    byte validity[MAX_DATE_SIZE*2 + MAX_SEQ_SZ*2];  /* before and after dates */
    byte publicKey[MAX_PUBLIC_KEY_SZ]; /* rsa public key encoded */
    byte ca[MAX_CA_SZ];                /* basic constraint CA true size */
    byte extensions[MAX_EXTENSIONS_SZ]; /* all extensions */
#ifdef WOLFSSL_CERT_EXT
    byte skid[MAX_KID_SZ];             /* Subject Key Identifier extension */
    byte akid[MAX_KID_SZ
#ifdef WOLFSSL_AKID_NAME
              + sizeof(CertName) + CTC_SERIAL_SIZE
#endif
              ]; /* Authority Key Identifier extension */
    byte keyUsage[MAX_KEYUSAGE_SZ];    /* Key Usage extension */
    byte extKeyUsage[MAX_EXTKEYUSAGE_SZ]; /* Extended Key Usage extension */
#ifndef IGNORE_NETSCAPE_CERT_TYPE
    byte nsCertType[MAX_NSCERTTYPE_SZ]; /* Extended Key Usage extension */
#endif
    byte certPolicies[MAX_CERTPOL_NB*MAX_CERTPOL_SZ]; /* Certificate Policies */
    byte crlInfo[CTC_MAX_CRLINFO_SZ];  /* CRL Distribution Points */
#endif
#ifdef WOLFSSL_CERT_REQ
    byte attrib[MAX_ATTRIB_SZ];        /* Cert req attributes encoded */
    #ifdef WOLFSSL_CUSTOM_OID
    byte extCustom[MAX_ATTRIB_SZ];     /* Encoded user oid and value */
    #endif
#endif
#ifdef WOLFSSL_ALT_NAMES
    byte altNames[CTC_MAX_ALT_SIZE];   /* Alternative Names encoded */
#endif
    int  sizeSz;                       /* encoded size length */
    int  versionSz;                    /* encoded version length */
    int  serialSz;                     /* encoded serial length */
    int  sigAlgoSz;                    /* encoded sig algo length */
    int  issuerSz;                     /* encoded issuer length */
    int  subjectSz;                    /* encoded subject length */
    int  validitySz;                   /* encoded validity length */
    int  publicKeySz;                  /* encoded public key length */
    int  caSz;                         /* encoded CA extension length */
#ifdef WOLFSSL_CERT_EXT
    int  skidSz;                       /* encoded SKID extension length */
    int  akidSz;                       /* encoded SKID extension length */
    int  keyUsageSz;                   /* encoded KeyUsage extension length */
    int  extKeyUsageSz;                /* encoded ExtendedKeyUsage extension length */
#ifndef IGNORE_NETSCAPE_CERT_TYPE
    int  nsCertTypeSz;                 /* encoded Netscape Certifcate Type
                                        * extension length */
#endif
    int  certPoliciesSz;               /* encoded CertPolicies extension length*/
    int  crlInfoSz;                    /* encoded CRL Dist Points length */
#endif
#ifdef WOLFSSL_ALT_NAMES
    int  altNamesSz;                   /* encoded AltNames extension length */
#endif
    int  extensionsSz;                 /* encoded extensions total length */
    int  total;                        /* total encoded lengths */
#ifdef WOLFSSL_CERT_REQ
    int  attribSz;
    #ifdef WOLFSSL_CUSTOM_OID
    int  extCustomSz;
    #endif
#endif
} DerCert;


#ifdef WOLFSSL_CERT_REQ
#ifndef WOLFSSL_ASN_TEMPLATE

/* Write a set header to output */
static word32 SetPrintableString(word32 len, byte* output)
{
    output[0] = ASN_PRINTABLE_STRING;
    return SetLength(len, output + 1) + 1;
}

static word32 SetUTF8String(word32 len, byte* output)
{
    output[0] = ASN_UTF8STRING;
    return SetLength(len, output + 1) + 1;
}

#endif
#endif /* WOLFSSL_CERT_REQ */


#ifndef WOLFSSL_CERT_GEN_CACHE
/* wc_SetCert_Free is only public when WOLFSSL_CERT_GEN_CACHE is not defined */
static
#endif
void wc_SetCert_Free(Cert* cert)
{
    if (cert != NULL) {
        cert->der = NULL;
        if (cert->decodedCert) {
            FreeDecodedCert((DecodedCert*)cert->decodedCert);

            XFREE(cert->decodedCert, cert->heap, DYNAMIC_TYPE_DCERT);
            cert->decodedCert = NULL;
        }
    }
}

static int wc_SetCert_LoadDer(Cert* cert, const byte* der, word32 derSz)
{
    int ret;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Allocate DecodedCert struct and Zero */
        cert->decodedCert = (void*)XMALLOC(sizeof(DecodedCert), cert->heap,
            DYNAMIC_TYPE_DCERT);

        if (cert->decodedCert == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMSET(cert->decodedCert, 0, sizeof(DecodedCert));

            InitDecodedCert((DecodedCert*)cert->decodedCert, der, derSz,
                    cert->heap);
            ret = ParseCertRelative((DecodedCert*)cert->decodedCert,
                    CERT_TYPE, 0, NULL);
            if (ret >= 0) {
                cert->der = (byte*)der;
            }
            else {
                wc_SetCert_Free(cert);
            }
        }
    }

    return ret;
}

#endif /* WOLFSSL_CERT_GEN */

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for ECC public key (SubjectPublicKeyInfo).
 * RFC 5480, 2 - Subject Public Key Information Fields
 *           2.1.1 - Unrestricted Algorithm Identifier and Parameters
 * X9.62 ECC point format.
 * See ASN.1 template 'eccSpecifiedASN' for specifiedCurve.
 */
static const ASNItem eccPublicKeyASN[] = {
/* SEQ            */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                             /* AlgorithmIdentifier */
/* ALGOID_SEQ     */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                                 /* algorithm */
/* ALGOID_OID     */         { 2, ASN_OBJECT_ID, 0, 0, 0 },
                                                 /* namedCurve */
/* ALGOID_CURVEID */         { 2, ASN_OBJECT_ID, 0, 0, 2 },
                                                 /* specifiedCurve - explicit parameters */
/* ALGOID_PARAMS  */         { 2, ASN_SEQUENCE, 1, 0, 2 },
                                             /* Public Key */
/* PUBKEY         */     { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    ECCPUBLICKEYASN_IDX_SEQ = 0,
    ECCPUBLICKEYASN_IDX_ALGOID_SEQ,
    ECCPUBLICKEYASN_IDX_ALGOID_OID,
    ECCPUBLICKEYASN_IDX_ALGOID_CURVEID,
    ECCPUBLICKEYASN_IDX_ALGOID_PARAMS,
    ECCPUBLICKEYASN_IDX_PUBKEY,
};

/* Number of items in ASN.1 template for ECC public key. */
#define eccPublicKeyASN_Length (sizeof(eccPublicKeyASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */


/* Encode public ECC key in DER format.
 *
 * RFC 5480, 2 - Subject Public Key Information Fields
 *           2.1.1 - Unrestricted Algorithm Identifier and Parameters
 * X9.62 ECC point format.
 * SEC 1 Ver. 2.0, C.2 - Syntax for Elliptic Curve Domain Parameters
 *
 * @param [out] output       Buffer to put encoded data in.
 * @param [in]  key          ECC key object.
 * @param [in]  outLen       Size of buffer in bytes.
 * @param [in]  with_header  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int SetEccPublicKey(byte* output, ecc_key* key, int outLen,
                           int with_header)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret, idx = 0, algoSz, curveSz, bitStringSz;
    word32 pubSz;
    byte bitString[1 + MAX_LENGTH_SZ + 1]; /* 6 */
    byte algo[MAX_ALGO_SZ];  /* 20 */

    /* public size */
    pubSz = key->dp ? key->dp->size : MAX_ECC_BYTES;
    pubSz = 1 + 2 * pubSz;

    /* check for buffer overflow */
    if (output != NULL && pubSz > (word32)outLen) {
        return BUFFER_E;
    }

    /* headers */
    if (with_header) {
        curveSz = SetCurve(key, NULL);
        if (curveSz <= 0) {
            return curveSz;
        }

        /* calculate size */
        algoSz  = SetAlgoID(ECDSAk, algo, oidKeyType, curveSz);
        bitStringSz = SetBitString(pubSz, 0, bitString);
        idx = SetSequence(pubSz + curveSz + bitStringSz + algoSz, NULL);

        /* check for buffer overflow */
        if (output != NULL &&
                curveSz + algoSz + bitStringSz + idx + pubSz > (word32)outLen) {
            return BUFFER_E;
        }

        idx = SetSequence(pubSz + curveSz + bitStringSz + algoSz, output);
        /* algo */
        if (output)
            XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* curve */
        if (output)
            (void)SetCurve(key, output + idx);
        idx += curveSz;
        /* bit string */
        if (output)
            XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }

    /* pub */
    if (output) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, output + idx, &pubSz);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            return ret;
        }
    }
    idx += pubSz;

    return idx;
#else
    word32 pubSz = 0;
    int sz = 0;
    int ret = 0;

    /* Check key validity. */
    if ((key == NULL) || (key->dp == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Calculate the size of the encoded public point. */
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, NULL, &pubSz);
        PRIVATE_KEY_LOCK();
        /* LENGTH_ONLY_E on success. */
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }
    }
    if ((ret == 0) && with_header) {
        /* Including SubjectPublicKeyInfo header. */
        DECL_ASNSETDATA(dataASN, eccPublicKeyASN_Length);

        CALLOC_ASNSETDATA(dataASN, eccPublicKeyASN_Length, ret, key->heap);

        /* Set the key type OID. */
        SetASN_OID(&dataASN[ECCPUBLICKEYASN_IDX_ALGOID_OID], ECDSAk,
                oidKeyType);
        /* Set the curve OID. */
        SetASN_Buffer(&dataASN[ECCPUBLICKEYASN_IDX_ALGOID_CURVEID],
                (const byte *)key->dp->oid, key->dp->oidSz);
        /* Don't try to write out explicit parameters. */
        dataASN[ECCPUBLICKEYASN_IDX_ALGOID_PARAMS].noOut = 1;
        /* Set size of public point to ensure space is made for it. */
        SetASN_Buffer(&dataASN[ECCPUBLICKEYASN_IDX_PUBKEY], NULL, pubSz);
        /* Calculate size of ECC public key. */
        ret = SizeASN_Items(eccPublicKeyASN, dataASN,
                            eccPublicKeyASN_Length, &sz);

        /* Check buffer, if passed in, is big enough for encoded data. */
        if ((ret == 0) && (output != NULL) && (sz > outLen)) {
            ret = BUFFER_E;
        }
        if ((ret == 0) && (output != NULL)) {
            /* Encode ECC public key. */
            SetASN_Items(eccPublicKeyASN, dataASN, eccPublicKeyASN_Length,
                         output);
            /* Skip to where public point is to be encoded. */
            output += sz - pubSz;
        }

        FREE_ASNSETDATA(dataASN, key->heap);
    }
    else if ((ret == 0) && (output != NULL) && (pubSz > (word32)outLen)) {
        ret = BUFFER_E;
    }
    else {
        /* Total size is the public point size. */
        sz = pubSz;
    }

    if ((ret == 0) && (output != NULL)) {
        /* Encode public point. */
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, output, &pubSz);
        PRIVATE_KEY_LOCK();
    }
    if (ret == 0) {
        /* Return the size of the encoding. */
        ret = sz;
    }

    return ret;
#endif
}


/* Encode the public part of an ECC key in a DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key            ECC key object.
 * @param [out] output         Buffer to hold DER encoding.
 * @param [in]  inLen          Size of buffer in bytes.
 * @param [in]  with_AlgCurve  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key or key's parameters is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_EccPublicKeyToDer(ecc_key* key, byte* output, word32 inLen,
                                                              int with_AlgCurve)
{
    return SetEccPublicKey(output, key, inLen, with_AlgCurve);
}

int wc_EccPublicKeyDerSize(ecc_key* key, int with_AlgCurve)
{
    return SetEccPublicKey(NULL, key, 0, with_AlgCurve);
}


#ifdef WOLFSSL_ASN_TEMPLATE
#if defined(WC_ENABLE_ASYM_KEY_EXPORT) || defined(WC_ENABLE_ASYM_KEY_IMPORT)
/* ASN.1 template for Ed25519 and Ed448 public key (SubkectPublicKeyInfo).
 * RFC 8410, 4 - Subject Public Key Fields
 */
static const ASNItem edPubKeyASN[] = {
            /* SubjectPublicKeyInfo */
/* SEQ        */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                     /* AlgorithmIdentifier */
/* ALGOID_SEQ */     { 1, ASN_SEQUENCE, 1, 1, 0 },
                                         /* Ed25519/Ed448 OID */
/* ALGOID_OID */         { 2, ASN_OBJECT_ID, 0, 0, 1 },
                                     /* Public key stream */
/* PUBKEY     */     { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    EDPUBKEYASN_IDX_SEQ = 0,
    EDPUBKEYASN_IDX_ALGOID_SEQ,
    EDPUBKEYASN_IDX_ALGOID_OID,
    EDPUBKEYASN_IDX_PUBKEY,
};

/* Number of items in ASN.1 template for Ed25519 and Ed448 public key. */
#define edPubKeyASN_Length (sizeof(edPubKeyASN) / sizeof(ASNItem))
#endif /* WC_ENABLE_ASYM_KEY_EXPORT || WC_ENABLE_ASYM_KEY_IMPORT */
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifdef WC_ENABLE_ASYM_KEY_EXPORT

/* Build ASN.1 formatted public key based on RFC 8410
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  pubKey       public key buffer
 * @param [in]  pubKeyLen    public ket buffer length
 * @param [out] output       Buffer to put encoded data in (optional)
 * @param [in]  outLen       Size of buffer in bytes
 * @param [in]  keyType      is "enum Key_Sum" like ED25519k
 * @param [in]  withHeader   Whether to include SubjectPublicKeyInfo around key.
 * @return  Size of encoded data in bytes on success
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int SetAsymKeyDerPublic(const byte* pubKey, word32 pubKeyLen,
    byte* output, word32 outLen, int keyType, int withHeader)
{
    int ret = 0;
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    word32 seqDataSz = 0;
    word32 sz;
#else
    int sz = 0;
    DECL_ASNSETDATA(dataASN, edPubKeyASN_Length);
#endif

    if (pubKey == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef WOLFSSL_ASN_TEMPLATE
    /* calculate size */
    if (withHeader) {
        word32 algoSz      = SetAlgoID(keyType, NULL, oidKeyType, 0);
        word32 bitStringSz = SetBitString(pubKeyLen, 0, NULL);

        seqDataSz = algoSz + bitStringSz + pubKeyLen;
        sz = SetSequence(seqDataSz, NULL) + seqDataSz;
    }
    else {
        sz = pubKeyLen;
    }

    /* checkout output size */
    if (output != NULL && sz > outLen) {
        ret = BUFFER_E;
    }

    /* headers */
    if (ret == 0 && output != NULL && withHeader) {
        /* sequence */
        idx = SetSequence(seqDataSz, output);
        /* algo */
        idx += SetAlgoID(keyType, output + idx, oidKeyType, 0);
        /* bit string */
        idx += SetBitString(pubKeyLen, 0, output + idx);
    }

    if (ret == 0 && output != NULL) {
        /* pub */
        XMEMCPY(output + idx, pubKey, pubKeyLen);
        idx += pubKeyLen;

        sz = idx;
    }

    if (ret == 0) {
        ret = sz;
    }
#else
    if (withHeader) {
        CALLOC_ASNSETDATA(dataASN, edPubKeyASN_Length, ret, NULL);

        if (ret == 0) {
            /* Set the OID. */
            SetASN_OID(&dataASN[EDPUBKEYASN_IDX_ALGOID_OID], keyType,
                    oidKeyType);
            /* Leave space for public point. */
            SetASN_Buffer(&dataASN[EDPUBKEYASN_IDX_PUBKEY], NULL, pubKeyLen);
            /* Calculate size of public key encoding. */
            ret = SizeASN_Items(edPubKeyASN, dataASN, edPubKeyASN_Length, &sz);
        }
        if ((ret == 0) && (output != NULL) && (sz > (int)outLen)) {
            ret = BUFFER_E;
        }
        if ((ret == 0) && (output != NULL)) {
            /* Encode public key. */
            SetASN_Items(edPubKeyASN, dataASN, edPubKeyASN_Length, output);
            /* Set location to encode public point. */
            output = (byte*)dataASN[EDPUBKEYASN_IDX_PUBKEY].data.buffer.data;
        }

        FREE_ASNSETDATA(dataASN, NULL);
    }
    else if ((output != NULL) && (pubKeyLen > outLen)) {
        ret = BUFFER_E;
    }
    else if (ret == 0) {
        sz = pubKeyLen;
    }

    if ((ret == 0) && (output != NULL)) {
        /* Put public key into space provided. */
        XMEMCPY(output, pubKey, pubKeyLen);
    }
    if (ret == 0) {
        ret = sz;
    }
#endif /* WOLFSSL_ASN_TEMPLATE */
    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */




#ifdef WOLFSSL_CERT_GEN

#ifndef NO_ASN_TIME
static WC_INLINE byte itob(int number)
{
    return (byte)number + 0x30;
}


/* write time to output, format */
static void SetTime(struct tm* date, byte* output)
{
    int i = 0;

    output[i++] = itob((date->tm_year % 10000) / 1000);
    output[i++] = itob((date->tm_year % 1000)  /  100);
    output[i++] = itob((date->tm_year % 100)   /   10);
    output[i++] = itob( date->tm_year % 10);

    output[i++] = itob(date->tm_mon / 10);
    output[i++] = itob(date->tm_mon % 10);

    output[i++] = itob(date->tm_mday / 10);
    output[i++] = itob(date->tm_mday % 10);

    output[i++] = itob(date->tm_hour / 10);
    output[i++] = itob(date->tm_hour % 10);

    output[i++] = itob(date->tm_min / 10);
    output[i++] = itob(date->tm_min % 10);

    output[i++] = itob(date->tm_sec / 10);
    output[i++] = itob(date->tm_sec % 10);

    output[i] = 'Z';  /* Zulu profile */
}
#endif

#ifdef WOLFSSL_ALT_NAMES
#ifndef WOLFSSL_ASN_TEMPLATE

/* Copy Dates from cert, return bytes written */
static int CopyValidity(byte* output, Cert* cert)
{
    int seqSz;

    WOLFSSL_ENTER("CopyValidity");

    /* headers and output */
    seqSz = SetSequence(cert->beforeDateSz + cert->afterDateSz, output);
    if (output) {
        XMEMCPY(output + seqSz, cert->beforeDate, cert->beforeDateSz);
        XMEMCPY(output + seqSz + cert->beforeDateSz, cert->afterDate,
                                                     cert->afterDateSz);
    }
    return seqSz + cert->beforeDateSz + cert->afterDateSz;
}

#endif /* !WOLFSSL_ASN_TEMPLATE */
#endif


/* Simple name OID size. */
#define NAME_OID_SZ     3

/* Domain name OIDs. */
static const byte nameOid[][NAME_OID_SZ] = {
    { 0x55, 0x04, ASN_COUNTRY_NAME },
    { 0x55, 0x04, ASN_STATE_NAME },
    { 0x55, 0x04, ASN_STREET_ADDR },
    { 0x55, 0x04, ASN_LOCALITY_NAME },
    { 0x55, 0x04, ASN_SUR_NAME },
    { 0x55, 0x04, ASN_ORG_NAME },
    { 0x00, 0x00, ASN_DOMAIN_COMPONENT}, /* not actual OID - see dcOid */
                                         /* list all DC values before OUs */
    { 0x55, 0x04, ASN_ORGUNIT_NAME },
    { 0x55, 0x04, ASN_COMMON_NAME },
    { 0x55, 0x04, ASN_SERIAL_NUMBER },
#ifdef WOLFSSL_CERT_EXT
    { 0x55, 0x04, ASN_BUS_CAT },
#endif
    { 0x55, 0x04, ASN_POSTAL_CODE },
    { 0x00, 0x00, ASN_EMAIL_NAME},       /* not actual OID - see attrEmailOid */
    { 0x00, 0x00, ASN_USER_ID},          /* not actual OID - see uidOid */
#ifdef WOLFSSL_CUSTOM_OID
    { 0x00, 0x00, ASN_CUSTOM_NAME} /* OID comes from CertOidField */
#endif
};
#define NAME_ENTRIES (int)(sizeof(nameOid)/NAME_OID_SZ)


/* Get ASN Name from index */
byte GetCertNameId(int idx)
{
    if (idx < NAME_ENTRIES)
        return nameOid[idx][2];
    return 0;
}

/* Get Which Name from index */
const char* GetOneCertName(CertName* name, int idx)
{
    byte type = GetCertNameId(idx);
    switch (type) {
    case ASN_COUNTRY_NAME:
       return name->country;
    case ASN_STATE_NAME:
       return name->state;
    case ASN_STREET_ADDR:
       return name->street;
    case ASN_LOCALITY_NAME:
       return name->locality;
    case ASN_SUR_NAME:
       return name->sur;
    case ASN_ORG_NAME:
       return name->org;
    case ASN_ORGUNIT_NAME:
       return name->unit;
    case ASN_COMMON_NAME:
       return name->commonName;
    case ASN_SERIAL_NUMBER:
       return name->serialDev;
    case ASN_USER_ID:
       return name->userId;
    case ASN_POSTAL_CODE:
       return name->postalCode;
    case ASN_EMAIL_NAME:
       return name->email;
#ifdef WOLFSSL_CERT_EXT
    case ASN_BUS_CAT:
       return name->busCat;
#endif
#ifdef WOLFSSL_CUSTOM_OID
    case ASN_CUSTOM_NAME:
        return (const char*)name->custom.val;
#endif
    default:
       return NULL;
    }
}


/* Get Which Name Encoding from index */
static char GetNameType(CertName* name, int idx)
{
    byte type = GetCertNameId(idx);
    switch (type) {
    case ASN_COUNTRY_NAME:
       return name->countryEnc;
    case ASN_STATE_NAME:
       return name->stateEnc;
    case ASN_STREET_ADDR:
       return name->streetEnc;
    case ASN_LOCALITY_NAME:
       return name->localityEnc;
    case ASN_SUR_NAME:
       return name->surEnc;
    case ASN_ORG_NAME:
       return name->orgEnc;
    case ASN_ORGUNIT_NAME:
       return name->unitEnc;
    case ASN_COMMON_NAME:
       return name->commonNameEnc;
    case ASN_SERIAL_NUMBER:
       return name->serialDevEnc;
    case ASN_USER_ID:
       return name->userIdEnc;
    case ASN_POSTAL_CODE:
       return name->postalCodeEnc;
    case ASN_EMAIL_NAME:
       return 0; /* special */
#ifdef WOLFSSL_CERT_EXT
    case ASN_BUS_CAT:
       return name->busCatEnc;
#endif
#ifdef WOLFSSL_CUSTOM_OID
    case ASN_CUSTOM_NAME:
        return name->custom.enc;
#endif
    default:
       return 0;
    }
}

#ifndef WOLFSSL_ASN_TEMPLATE
/*
 Extensions ::= SEQUENCE OF Extension

 Extension ::= SEQUENCE {
 extnId     OBJECT IDENTIFIER,
 critical   BOOLEAN DEFAULT FALSE,
 extnValue  OCTET STRING }
 */

/* encode all extensions, return total bytes written */
static int SetExtensions(byte* out, word32 outSz, int *IdxInOut,
                         const byte* ext, int extSz)
{
    if (out == NULL || IdxInOut == NULL || ext == NULL)
        return BAD_FUNC_ARG;

    if (outSz < (word32)(*IdxInOut+extSz))
        return BUFFER_E;

    XMEMCPY(&out[*IdxInOut], ext, extSz);  /* extensions */
    *IdxInOut += extSz;

    return *IdxInOut;
}

/* encode extensions header, return total bytes written */
static int SetExtensionsHeader(byte* out, word32 outSz, int extSz)
{
    byte sequence[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ];
    int seqSz, lenSz, idx = 0;

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    seqSz = SetSequence(extSz, sequence);

    /* encode extensions length provided */
    lenSz = SetLength(extSz+seqSz, len);

    if (outSz < (word32)(lenSz+seqSz+1))
        return BUFFER_E;

    out[idx++] = ASN_EXTENSIONS; /* extensions id */
    XMEMCPY(&out[idx], len, lenSz);  /* length */
    idx += lenSz;

    XMEMCPY(&out[idx], sequence, seqSz);  /* sequence */
    idx += seqSz;

    return idx;
}


/* encode CA basic constraint true, return total bytes written */
static int SetCa(byte* out, word32 outSz)
{
    const byte ca[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
                               0x05, 0x30, 0x03, 0x01, 0x01, 0xff };

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < sizeof(ca))
        return BUFFER_E;

    XMEMCPY(out, ca, sizeof(ca));

    return (int)sizeof(ca);
}
#endif


#ifdef WOLFSSL_CERT_EXT
#ifndef WOLFSSL_ASN_TEMPLATE
/* encode OID and associated value, return total bytes written */
static int SetOidValue(byte* out, word32 outSz, const byte *oid, word32 oidSz,
                       byte *in, word32 inSz)
{
    int idx = 0;

    if (out == NULL || oid == NULL || in == NULL)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    /* sequence,  + 1 => byte to put value size */
    idx = SetSequence(inSz + oidSz + 1, out);

    if ((idx + inSz + oidSz + 1) > outSz)
        return BUFFER_E;

    XMEMCPY(out+idx, oid, oidSz);
    idx += oidSz;
    out[idx++] = (byte)inSz;
    XMEMCPY(out+idx, in, inSz);

    return (idx+inSz);
}

/* encode Subject Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetSKID(byte* output, word32 outSz, const byte *input, word32 length)
{
    byte skid_len[1 + MAX_LENGTH_SZ];
    byte skid_enc_len[MAX_LENGTH_SZ];
    int idx = 0, skid_lenSz, skid_enc_lenSz;
    const byte skid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04 };

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    /* Octet String header */
    skid_lenSz = SetOctetString(length, skid_len);

    /* length of encoded value */
    skid_enc_lenSz = SetLength(length + skid_lenSz, skid_enc_len);

    if (outSz < 3)
        return BUFFER_E;

    idx = SetSequence(length + sizeof(skid_oid) + skid_lenSz + skid_enc_lenSz,
                      output);

    if ((length + sizeof(skid_oid) + skid_lenSz + skid_enc_lenSz) > outSz)
        return BUFFER_E;

    /* put oid */
    XMEMCPY(output+idx, skid_oid, sizeof(skid_oid));
    idx += sizeof(skid_oid);

    /* put encoded len */
    XMEMCPY(output+idx, skid_enc_len, skid_enc_lenSz);
    idx += skid_enc_lenSz;

    /* put octet header */
    XMEMCPY(output+idx, skid_len, skid_lenSz);
    idx += skid_lenSz;

    /* put value */
    XMEMCPY(output+idx, input, length);
    idx += length;

    return idx;
}

/* encode Authority Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetAKID(byte* output, word32 outSz, byte *input, word32 length,
                   byte rawAkid)
{
    int     enc_valSz, inSeqSz;
    byte enc_val_buf[MAX_KID_SZ];
    byte* enc_val;
    const byte akid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x23 };
    const byte akid_cs[] = { 0x80 };
    word32 idx;

    (void)rawAkid;

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_AKID_NAME
    if (rawAkid) {
        enc_val = input;
        enc_valSz = length;
    }
    else
#endif
    {
        enc_val = enc_val_buf;
        enc_valSz = length + 3 + sizeof(akid_cs);
        if (enc_valSz > (int)sizeof(enc_val_buf))
            return BAD_FUNC_ARG;

        /* sequence for ContentSpec & value */
        enc_valSz = SetOidValue(enc_val, enc_valSz, akid_cs, sizeof(akid_cs),
                          input, length);
        if (enc_valSz <= 0)
            return enc_valSz;
    }

    /* The size of the extension sequence contents */
    inSeqSz = sizeof(akid_oid) + SetOctetString(enc_valSz, NULL) +
            enc_valSz;

    if (SetSequence(inSeqSz, NULL) + inSeqSz > outSz)
        return BAD_FUNC_ARG;

    /* Write out the sequence header */
    idx = SetSequence(inSeqSz, output);

    /* Write out OID */
    XMEMCPY(output + idx, akid_oid, sizeof(akid_oid));
    idx += sizeof(akid_oid);

    /* Write out AKID */
    idx += SetOctetString(enc_valSz, output + idx);
    XMEMCPY(output + idx, enc_val, enc_valSz);

    return idx + enc_valSz;
}

/* encode Key Usage, return total bytes written
 * RFC5280 : critical */
static int SetKeyUsage(byte* output, word32 outSz, word16 input)
{
    byte ku[5];
    int  idx;
    const byte keyusage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f,
                                         0x01, 0x01, 0xff, 0x04};
    if (output == NULL)
        return BAD_FUNC_ARG;

    idx = SetBitString16Bit(input, ku);
    return SetOidValue(output, outSz, keyusage_oid, sizeof(keyusage_oid),
                       ku, idx);
}

static int SetOjectIdValue(byte* output, word32 outSz, int* idx,
    const byte* oid, word32 oidSz)
{
    /* verify room */
    if (*idx + 2 + oidSz >= outSz)
        return ASN_PARSE_E;

    *idx += SetObjectId(oidSz, &output[*idx]);
    XMEMCPY(&output[*idx], oid, oidSz);
    *idx += oidSz;

    return 0;
}
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for extended key usage.
 * X.509: RFC 5280, 4.2.12 - Extended Key Usage
 * Dynamic creation of template for encoding.
 */
static const ASNItem ekuASN[] = {
/* SEQ */ { 0, ASN_SEQUENCE, 1, 1, 0 },
/* OID */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
};
enum {
    EKUASN_IDX_SEQ = 0,
    EKUASN_IDX_OID,
};

/* OIDs corresponding to extended key usage. */
struct {
    const byte* oid;
    word32 oidSz;
} ekuOid[] = {
    { extExtKeyUsageServerAuthOid,   sizeof(extExtKeyUsageServerAuthOid) },
    { extExtKeyUsageClientAuthOid,   sizeof(extExtKeyUsageClientAuthOid) },
    { extExtKeyUsageCodeSigningOid,  sizeof(extExtKeyUsageCodeSigningOid) },
    { extExtKeyUsageEmailProtectOid, sizeof(extExtKeyUsageEmailProtectOid) },
    { extExtKeyUsageTimestampOid,    sizeof(extExtKeyUsageTimestampOid) },
    { extExtKeyUsageOcspSignOid,     sizeof(extExtKeyUsageOcspSignOid) },
};

#define EKU_OID_LO      1
#define EKU_OID_HI      6
#endif /* WOLFSSL_ASN_TEMPLATE */

/* encode Extended Key Usage (RFC 5280 4.2.1.12), return total bytes written */
static int SetExtKeyUsage(Cert* cert, byte* output, word32 outSz, byte input)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int idx = 0, oidListSz = 0, totalSz, ret = 0;
    const byte extkeyusage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };

    if (output == NULL)
        return BAD_FUNC_ARG;

    /* Skip to OID List */
    totalSz = 2 + sizeof(extkeyusage_oid) + 4;
    idx = totalSz;

    /* Build OID List */
    /* If any set, then just use it */
    if (input & EXTKEYUSE_ANY) {
        ret |= SetOjectIdValue(output, outSz, &idx,
            extExtKeyUsageAnyOid, sizeof(extExtKeyUsageAnyOid));
    }
    else {
        if (input & EXTKEYUSE_SERVER_AUTH)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageServerAuthOid, sizeof(extExtKeyUsageServerAuthOid));
        if (input & EXTKEYUSE_CLIENT_AUTH)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageClientAuthOid, sizeof(extExtKeyUsageClientAuthOid));
        if (input & EXTKEYUSE_CODESIGN)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageCodeSigningOid, sizeof(extExtKeyUsageCodeSigningOid));
        if (input & EXTKEYUSE_EMAILPROT)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageEmailProtectOid, sizeof(extExtKeyUsageEmailProtectOid));
        if (input & EXTKEYUSE_TIMESTAMP)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageTimestampOid, sizeof(extExtKeyUsageTimestampOid));
        if (input & EXTKEYUSE_OCSP_SIGN)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageOcspSignOid, sizeof(extExtKeyUsageOcspSignOid));
    #ifdef WOLFSSL_EKU_OID
        /* iterate through OID values */
        if (input & EXTKEYUSE_USER) {
            int i, sz;
            for (i = 0; i < CTC_MAX_EKU_NB; i++) {
                sz = cert->extKeyUsageOIDSz[i];
                if (sz > 0) {
                    ret |= SetOjectIdValue(output, outSz, &idx,
                        cert->extKeyUsageOID[i], sz);
                }
            }
        }
    #endif /* WOLFSSL_EKU_OID */
    }
    if (ret != 0)
        return ASN_PARSE_E;

    /* Calculate Sizes */
    oidListSz = idx - totalSz;
    totalSz = idx - 2; /* exclude first seq/len (2) */

    /* 1. Seq + Total Len (2) */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID (2) */
    XMEMCPY(&output[idx], extkeyusage_oid, sizeof(extkeyusage_oid));
    idx += sizeof(extkeyusage_oid);

    /* 3. Octet String (2) */
    idx += SetOctetString(totalSz - idx, &output[idx]);

    /* 4. Seq + OidListLen (2) */
    idx += SetSequence(oidListSz, &output[idx]);

    /* 5. Oid List (already set in-place above) */
    idx += oidListSz;

    (void)cert;
    return idx;
#else
    /* TODO: consider calculating size of OBJECT_IDs, setting length into
     * SEQUENCE, encode SEQUENCE, encode OBJECT_IDs into buffer.  */
    ASNSetData* dataASN;
    ASNItem* extKuASN = NULL;
    int asnIdx = 1;
    int cnt = 1 + EKU_OID_HI;
    int i;
    int ret = 0;
    int sz = 0;

#ifdef WOLFSSL_EKU_OID
    cnt += CTC_MAX_EKU_NB;
#endif

    /* Allocate memory for dynamic data items. */
    dataASN = (ASNSetData*)XMALLOC(cnt * sizeof(ASNSetData), cert->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (dataASN == NULL) {
        ret = MEMORY_E;
    }
    if (ret == 0) {
        /* Allocate memory for dynamic ASN.1 template. */
        extKuASN = (ASNItem*)XMALLOC(cnt * sizeof(ASNItem), cert->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (extKuASN == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Copy Sequence into dynamic ASN.1 template. */
        XMEMCPY(&extKuASN[EKUASN_IDX_SEQ], ekuASN, sizeof(ASNItem));
        /* Clear dynamic data. */
        XMEMSET(dataASN, 0, cnt * sizeof(ASNSetData));

        /* Build up the template and data. */
        /* If 'any' set, then just use it. */
        if ((input & EXTKEYUSE_ANY) == EXTKEYUSE_ANY) {
            /* Set template item. */
            XMEMCPY(&extKuASN[EKUASN_IDX_OID], &ekuASN[EKUASN_IDX_OID],
                    sizeof(ASNItem));
            /* Set data item. */
            SetASN_Buffer(&dataASN[asnIdx], extExtKeyUsageAnyOid,
                sizeof(extExtKeyUsageAnyOid));
            asnIdx++;
        }
        else {
            /* Step through the flagged purposes. */
            for (i = EKU_OID_LO; i <= EKU_OID_HI; i++) {
                if ((input & (1 << i)) != 0) {
                    /* Set template item. */
                    XMEMCPY(&extKuASN[asnIdx], &ekuASN[EKUASN_IDX_OID],
                            sizeof(ASNItem));
                    /* Set data item. */
                    SetASN_Buffer(&dataASN[asnIdx], ekuOid[i - 1].oid,
                        ekuOid[i - 1].oidSz);
                    asnIdx++;
                }
            }
        #ifdef WOLFSSL_EKU_OID
            if (input & EXTKEYUSE_USER) {
                /* Iterate through OID values */
                for (i = 0; i < CTC_MAX_EKU_NB; i++) {
                    sz = cert->extKeyUsageOIDSz[i];
                    if (sz > 0) {
                        /* Set template item. */
                        XMEMCPY(&extKuASN[asnIdx], &ekuASN[EKUASN_IDX_OID],
                                sizeof(ASNItem));
                        /* Set data item. */
                        SetASN_Buffer(&dataASN[asnIdx], cert->extKeyUsageOID[i],
                            sz);
                        asnIdx++;
                    }
                }
            }
        #endif /* WOLFSSL_EKU_OID */
            (void)cert;
        }

        /* Calculate size of encoding. */
        sz = 0;
        ret = SizeASN_Items(extKuASN, dataASN, asnIdx, &sz);
    }
    /* When buffer to write to, ensure it's big enough. */
    if ((ret == 0) && (output != NULL) && (sz > (int)outSz)) {
        ret = BUFFER_E;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Encode extended key usage. */
        SetASN_Items(extKuASN, dataASN, asnIdx, output);
    }
    if (ret == 0) {
        /* Return the encoding size. */
        ret = sz;
    }

    /* Dispose of allocated data. */
    if (extKuASN != NULL) {
        XFREE(extKuASN, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (dataASN != NULL) {
        XFREE(dataASN, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
#endif
}

#ifndef IGNORE_NETSCAPE_CERT_TYPE
#ifndef WOLFSSL_ASN_TEMPLATE
static int SetNsCertType(Cert* cert, byte* output, word32 outSz, byte input)
{
    word32 idx;
    byte unusedBits = 0;
    byte nsCertType = input;
    word32 totalSz;
    word32 bitStrSz;
    const byte nscerttype_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                    0x86, 0xF8, 0x42, 0x01, 0x01 };

    if (cert == NULL || output == NULL ||
            input == 0)
        return BAD_FUNC_ARG;

    totalSz = sizeof(nscerttype_oid);

    /* Get amount of lsb zero's */
    for (;(input & 1) == 0; input >>= 1)
        unusedBits++;

    /* 1 byte of NS Cert Type extension */
    bitStrSz = SetBitString(1, unusedBits, NULL) + 1;
    totalSz += SetOctetString(bitStrSz, NULL) + bitStrSz;

    if (SetSequence(totalSz, NULL) + totalSz > outSz)
        return BAD_FUNC_ARG;

    /* 1. Seq + Total Len */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID */
    XMEMCPY(&output[idx], nscerttype_oid, sizeof(nscerttype_oid));
    idx += sizeof(nscerttype_oid);

    /* 3. Octet String */
    idx += SetOctetString(bitStrSz, &output[idx]);

    /* 4. Bit String */
    idx += SetBitString(1, unusedBits, &output[idx]);
    output[idx++] = nsCertType;

    return idx;
}
#endif
#endif

#ifndef WOLFSSL_ASN_TEMPLATE
static int SetCRLInfo(Cert* cert, byte* output, word32 outSz, byte* input,
                      int inSz)
{
    word32 idx;
    word32 totalSz;
    const byte crlinfo_oid[] = { 0x06, 0x03, 0x55, 0x1D, 0x1F };

    if (cert == NULL || output == NULL ||
            input == 0 || inSz <= 0)
        return BAD_FUNC_ARG;

    totalSz = sizeof(crlinfo_oid) + SetOctetString(inSz, NULL) + inSz;

    if (SetSequence(totalSz, NULL) + totalSz > outSz)
        return BAD_FUNC_ARG;

    /* 1. Seq + Total Len */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID */
    XMEMCPY(&output[idx], crlinfo_oid, sizeof(crlinfo_oid));
    idx += sizeof(crlinfo_oid);

    /* 3. Octet String */
    idx += SetOctetString(inSz, &output[idx]);

    /* 4. CRL Info */
    XMEMCPY(&output[idx], input, inSz);
    idx += inSz;

    return idx;
}
#endif

/* encode Certificate Policies, return total bytes written
 * each input value must be ITU-T X.690 formatted : a.b.c...
 * input must be an array of values with a NULL terminated for the latest
 * RFC5280 : non-critical */
static int SetCertificatePolicies(byte *output,
                                  word32 outputSz,
                                  char input[MAX_CERTPOL_NB][MAX_CERTPOL_SZ],
                                  word16 nb_certpol,
                                  void* heap)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    byte    oid[MAX_OID_SZ];
    byte    der_oid[MAX_CERTPOL_NB][MAX_OID_SZ];
    byte    out[MAX_CERTPOL_SZ];
    word32  oidSz;
    word32  outSz;
    word32  i = 0;
    word32  der_oidSz[MAX_CERTPOL_NB];
    int     ret;

    const byte certpol_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04 };
    const byte oid_oid[] = { 0x06 };

    if (output == NULL || input == NULL || nb_certpol > MAX_CERTPOL_NB)
        return BAD_FUNC_ARG;

    for (i = 0; i < nb_certpol; i++) {
        oidSz = sizeof(oid);
        XMEMSET(oid, 0, oidSz);

        ret = EncodePolicyOID(oid, &oidSz, input[i], heap);
        if (ret != 0)
            return ret;

        /* compute sequence value for the oid */
        ret = SetOidValue(der_oid[i], MAX_OID_SZ, oid_oid,
                          sizeof(oid_oid), oid, oidSz);
        if (ret <= 0)
            return ret;
        else
            der_oidSz[i] = (word32)ret;
    }

    /* concatenate oid, keep two byte for sequence/size of the created value */
    for (i = 0, outSz = 2; i < nb_certpol; i++) {
        XMEMCPY(out+outSz, der_oid[i], der_oidSz[i]);
        outSz += der_oidSz[i];
    }

    /* add sequence */
    ret = SetSequence(outSz-2, out);
    if (ret <= 0)
        return ret;

    /* add Policy OID to compute final value */
    return SetOidValue(output, outputSz, certpol_oid, sizeof(certpol_oid),
                      out, outSz);
#else
    int    i;
    int    ret = 0;
    byte   oid[MAX_OID_SZ];
    word32 oidSz;
    word32 sz = 0;
    int    piSz;

    if ((input == NULL) || (nb_certpol > MAX_CERTPOL_NB)) {
        ret = BAD_FUNC_ARG;
    }
    /* Put in policyIdentifier but not policyQualifiers. */
    for (i = 0; (ret == 0) && (i < nb_certpol); i++) {
        ASNSetData dataASN[policyInfoASN_Length];

        oidSz = sizeof(oid);
        XMEMSET(oid, 0, oidSz);
        dataASN[POLICYINFOASN_IDX_QUALI].noOut = 1;

        ret = EncodePolicyOID(oid, &oidSz, input[i], heap);
        if (ret == 0) {
            XMEMSET(dataASN, 0, sizeof(dataASN));
            SetASN_Buffer(&dataASN[POLICYINFOASN_IDX_ID], oid, oidSz);
            ret = SizeASN_Items(policyInfoASN, dataASN, policyInfoASN_Length,
                                &piSz);
        }
        if ((ret == 0) && (output != NULL) && (sz + piSz > outputSz)) {
            ret = BUFFER_E;
        }
        if (ret == 0) {
            if (output != NULL) {
                SetASN_Items(policyInfoASN, dataASN, policyInfoASN_Length,
                    output);
                output += piSz;
            }
            sz += piSz;
        }
    }

    if (ret == 0) {
        ret = sz;
    }
    return ret;
#endif
}
#endif /* WOLFSSL_CERT_EXT */


#ifdef WOLFSSL_ALT_NAMES

#ifndef WOLFSSL_ASN_TEMPLATE
/* encode Alternative Names, return total bytes written */
static int SetAltNames(byte *output, word32 outSz,
        const byte *input, word32 length)
{
    byte san_len[1 + MAX_LENGTH_SZ];
    int idx = 0, san_lenSz;
    const byte san_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    if (outSz < length)
        return BUFFER_E;

    /* Octet String header */
    san_lenSz = SetOctetString(length, san_len);

    if (outSz < MAX_SEQ_SZ)
        return BUFFER_E;

    idx = SetSequence(length + sizeof(san_oid) + san_lenSz, output);

    if ((length + sizeof(san_oid) + san_lenSz) > outSz)
        return BUFFER_E;

    /* put oid */
    XMEMCPY(output+idx, san_oid, sizeof(san_oid));
    idx += sizeof(san_oid);

    /* put octet header */
    XMEMCPY(output+idx, san_len, san_lenSz);
    idx += san_lenSz;

    /* put value */
    XMEMCPY(output+idx, input, length);
    idx += length;

    return idx;
}
#endif /* WOLFSSL_ASN_TEMPLATE */


int FlattenAltNames(byte* output, word32 outputSz, const DNS_entry* names)
{
    word32 idx;
    const DNS_entry* curName;
    word32 namesSz = 0;
#ifdef WOLFSSL_ALT_NAMES_NO_REV
    word32 i;
#endif

    if (output == NULL)
        return BAD_FUNC_ARG;

    if (names == NULL)
        return 0;

    curName = names;
    do {
        namesSz += curName->len + 2 +
            ((curName->len < ASN_LONG_LENGTH) ? 0
             : BytePrecision(curName->len));
        curName = curName->next;
    } while (curName != NULL);

    if (outputSz < MAX_SEQ_SZ + namesSz)
        return BUFFER_E;

    idx = SetSequence(namesSz, output);
#ifdef WOLFSSL_ALT_NAMES_NO_REV
    namesSz += idx;
    i = namesSz;
#endif

    curName = names;
    do {
#ifdef WOLFSSL_ALT_NAMES_NO_REV
        word32 len = SetLength(curName->len, NULL);
        idx = i - curName->len - len - 1;
        i = idx;
#endif
        output[idx] = (byte) (ASN_CONTEXT_SPECIFIC | curName->type);
        if (curName->type == ASN_DIR_TYPE) {
            output[idx] |= ASN_CONSTRUCTED;
        }
        idx++;
        idx += SetLength(curName->len, output + idx);
        XMEMCPY(output + idx, curName->name, curName->len);
#ifndef WOLFSSL_ALT_NAMES_NO_REV
        idx += curName->len;
#endif
        curName = curName->next;
    } while (curName != NULL);

#ifdef WOLFSSL_ALT_NAMES_NO_REV
    idx = namesSz;
#endif
    return idx;
}

#endif /* WOLFSSL_ALT_NAMES */
#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_GEN)
/* Simple domain name OID size. */
#define DN_OID_SZ     3

/* Encodes one attribute of the name (issuer/subject)
 *
 * name     structure to hold result of encoding
 * nameStr  value to be encoded
 * nameTag  tag of encoding i.e CTC_UTF8
 * type     id of attribute i.e ASN_COMMON_NAME
 * emailTag tag of email i.e CTC_UTF8
 * returns length on success
 */
static int EncodeName(EncodedName* name, const char* nameStr,
                    byte nameTag, byte type, byte emailTag, CertName* cname)
{
#if !defined(WOLFSSL_ASN_TEMPLATE)
    word32 idx = 0;
    /* bottom up */
    byte firstLen[1 + MAX_LENGTH_SZ];
    byte secondLen[MAX_LENGTH_SZ];
    byte sequence[MAX_SEQ_SZ];
    byte set[MAX_SET_SZ];

    int strLen;
    int thisLen;
    int firstSz, secondSz, seqSz, setSz;

    if (nameStr == NULL) {
        name->used = 0;
        return 0;
    }

    thisLen = strLen = (int)XSTRLEN(nameStr);
#ifdef WOLFSSL_CUSTOM_OID
    if (type == ASN_CUSTOM_NAME) {
        if (cname == NULL || cname->custom.oidSz == 0) {
            name->used = 0;
            return 0;
        }
        thisLen = strLen = cname->custom.valSz;
    }
#else
    (void)cname;
#endif

    if (strLen == 0) { /* no user data for this item */
        name->used = 0;
        return 0;
    }

    /* Restrict country code size */
    if (type == ASN_COUNTRY_NAME && strLen != CTC_COUNTRY_SIZE) {
        WOLFSSL_MSG("Country code size error");
        return ASN_COUNTRY_SIZE_E;
    }

    secondSz = SetLength(strLen, secondLen);
    thisLen += secondSz;
    switch (type) {
        case ASN_EMAIL_NAME: /* email */
            thisLen += (int)sizeof(attrEmailOid);
            firstSz  = (int)sizeof(attrEmailOid);
            break;
        case ASN_DOMAIN_COMPONENT:
            thisLen += (int)sizeof(dcOid);
            firstSz  = (int)sizeof(dcOid);
            break;
        case ASN_USER_ID:
            thisLen += (int)sizeof(uidOid);
            firstSz  = (int)sizeof(uidOid);
            break;
    #ifdef WOLFSSL_CUSTOM_OID
        case ASN_CUSTOM_NAME:
            thisLen += cname->custom.oidSz;
            firstSz = cname->custom.oidSz;
            break;
    #endif
        default:
            thisLen += DN_OID_SZ;
            firstSz  = DN_OID_SZ;
    }
    thisLen++; /* id  type */
    firstSz  = SetObjectId(firstSz, firstLen);
    thisLen += firstSz;

    seqSz = SetSequence(thisLen, sequence);
    thisLen += seqSz;
    setSz = SetSet(thisLen, set);
    thisLen += setSz;

    if (thisLen > (int)sizeof(name->encoded)) {
        return BUFFER_E;
    }

    /* store it */
    idx = 0;
    /* set */
    XMEMCPY(name->encoded, set, setSz);
    idx += setSz;
    /* seq */
    XMEMCPY(name->encoded + idx, sequence, seqSz);
    idx += seqSz;
    /* asn object id */
    XMEMCPY(name->encoded + idx, firstLen, firstSz);
    idx += firstSz;
    switch (type) {
        case ASN_EMAIL_NAME:
            /* email joint id */
            XMEMCPY(name->encoded + idx, attrEmailOid, sizeof(attrEmailOid));
            idx += (int)sizeof(attrEmailOid);
            name->encoded[idx++] = emailTag;
            break;
        case ASN_DOMAIN_COMPONENT:
            XMEMCPY(name->encoded + idx, dcOid, sizeof(dcOid)-1);
            idx += (int)sizeof(dcOid)-1;
            /* id type */
            name->encoded[idx++] = type;
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
        case ASN_USER_ID:
            XMEMCPY(name->encoded + idx, uidOid, sizeof(uidOid));
            idx += (int)sizeof(uidOid);
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
    #ifdef WOLFSSL_CUSTOM_OID
        case ASN_CUSTOM_NAME:
            XMEMCPY(name->encoded + idx, cname->custom.oid,
                    cname->custom.oidSz);
            idx += cname->custom.oidSz;
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
    #endif
        default:
            name->encoded[idx++] = 0x55;
            name->encoded[idx++] = 0x04;
            /* id type */
            name->encoded[idx++] = type;
            /* str type */
            name->encoded[idx++] = nameTag;
    }
    /* second length */
    XMEMCPY(name->encoded + idx, secondLen, secondSz);
    idx += secondSz;
    /* str value */
    XMEMCPY(name->encoded + idx, nameStr, strLen);
    idx += strLen;

    name->type = type;
    name->totalLen = idx;
    name->used = 1;

    return idx;
#else
    DECL_ASNSETDATA(dataASN, rdnASN_Length);
    ASNItem namesASN[rdnASN_Length];
    byte dnOid[DN_OID_SZ] = { 0x55, 0x04, 0x00 };
    int ret = 0;
    int sz = 0;
    const byte* oid;
    int oidSz;
    word32 nameSz;

    /* Validate input parameters. */
    if ((name == NULL) || (nameStr == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, rdnASN_Length, ret, NULL);
    if (ret == 0) {
        nameSz = (word32)XSTRLEN(nameStr);
        /* Copy the RDN encoding template. ASN.1 tag for the name string is set
         * based on type. */
        XMEMCPY(namesASN, rdnASN, sizeof(namesASN));

        /* Set OID and ASN.1 tag for name depending on type. */
        switch (type) {
            case ASN_EMAIL_NAME:
                /* email OID different to standard types. */
                oid = attrEmailOid;
                oidSz = sizeof(attrEmailOid);
                /* Use email specific type/tag. */
                nameTag = emailTag;
                break;
            case ASN_DOMAIN_COMPONENT:
                /* Domain component OID different to standard types. */
                oid = dcOid;
                oidSz = sizeof(dcOid);
                break;
            case ASN_USER_ID:
                /* Domain component OID different to standard types. */
                oid = uidOid;
                oidSz = sizeof(uidOid);
                break;
        #ifdef WOLFSSL_CUSTOM_OID
            case ASN_CUSTOM_NAME:
                nameSz = cname->custom.valSz;
                oid = cname->custom.oid;
                oidSz = cname->custom.oidSz;
                break;
        #endif
            default:
                /* Construct OID using type. */
                dnOid[2] = type;
                oid = dnOid;
                oidSz = DN_OID_SZ;
                break;
        }

        /* Set OID corresponding to the name type. */
        SetASN_Buffer(&dataASN[RDNASN_IDX_ATTR_TYPE], oid, oidSz);
        /* Set name string. */
        SetASN_Buffer(&dataASN[RDNASN_IDX_ATTR_VAL], (const byte *)nameStr, nameSz);
        /* Set the ASN.1 tag for the name string. */
        namesASN[RDNASN_IDX_ATTR_VAL].tag = nameTag;

        /* Calculate size of encoded name and indexes of components. */
        ret = SizeASN_Items(namesASN, dataASN, rdnASN_Length, &sz);
    }
    /* Check if name's buffer is big enough. */
    if ((ret == 0) && (sz > (int)sizeof(name->encoded))) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode name into the buffer. */
        SetASN_Items(namesASN, dataASN, rdnASN_Length, name->encoded);
        /* Cache the type and size, and set that it is used. */
        name->type = type;
        name->totalLen = sz;
        name->used = 1;

        /* Return size of encoding. */
        ret = sz;
    }
    (void)cname;

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

/* canonical encoding one attribute of the name (issuer/subject)
 * call EncodeName with CTC_UTF8 for email type
 *
 * name     structure to hold result of encoding
 * nameStr  value to be encoded
 * nameType type of encoding i.e CTC_UTF8
 * type     id of attribute i.e ASN_COMMON_NAME
 *
 * returns length on success
 */
int wc_EncodeNameCanonical(EncodedName* name, const char* nameStr,
                           char nameType, byte type)
{
    return EncodeName(name, nameStr, (byte)nameType, type,
        ASN_UTF8STRING, NULL);
}
#endif /* WOLFSSL_CERT_GEN || OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef WOLFSSL_CERT_GEN
/* Encodes one attribute of the name (issuer/subject)
 * call we_EncodeName_ex with 0x16, IA5String for email type
 * name     structure to hold result of encoding
 * nameStr  value to be encoded
 * nameType type of encoding i.e CTC_UTF8
 * type     id of attribute i.e ASN_COMMON_NAME
 *
 * returns length on success
 */
int wc_EncodeName(EncodedName* name, const char* nameStr, char nameType,
                  byte type)
{
    return EncodeName(name, nameStr, (byte)nameType, type,
        ASN_IA5_STRING, NULL);
}

#ifdef WOLFSSL_ASN_TEMPLATE
static void SetRdnItems(ASNItem* namesASN, ASNSetData* dataASN, const byte* oid,
    int oidSz, byte tag, const byte* data, int sz)
{
    XMEMCPY(namesASN, rdnASN, sizeof(rdnASN));
    SetASN_Buffer(&dataASN[RDNASN_IDX_ATTR_TYPE], oid, oidSz);
    namesASN[RDNASN_IDX_ATTR_VAL].tag = tag;
    SetASN_Buffer(&dataASN[RDNASN_IDX_ATTR_VAL], data, sz);
}

#ifdef WOLFSSL_MULTI_ATTRIB
static int FindMultiAttrib(CertName* name, int id, int* idx)
{
    int i;
    for (i = *idx + 1; i < CTC_MAX_ATTRIB; i++) {
        if (name->name[i].sz > 0 && name->name[i].id == id) {
            break;
        }
    }
    if (i == CTC_MAX_ATTRIB) {
        i = -1;
    }
    *idx = i;
    return i >= 0;
}
#endif

/* ASN.1 template for the SEQUENCE around the RDNs.
 * X.509: RFC 5280, 4.1.2.4 - RDNSequence
 */
static const ASNItem nameASN[] = {
    { 0, ASN_SEQUENCE, 1, 1, 0 },
};
enum {
    NAMEASN_IDX_SEQ = 0,
};

/* Number of items in ASN.1 template for the SEQUENCE around the RDNs. */
#define nameASN_Length (sizeof(nameASN) / sizeof(ASNItem))

static int SetNameRdnItems(ASNSetData* dataASN, ASNItem* namesASN,
        int maxIdx, CertName* name)
{
    int         i;
    int         idx;
    int         ret = 0;
    int         nameLen[NAME_ENTRIES];
#ifdef WOLFSSL_MULTI_ATTRIB
    int         j;
#endif

    for (i = 0; i < NAME_ENTRIES; i++) {
        /* Keep name length to identify component is to be encoded. */
        const char* nameStr = GetOneCertName(name, i);
        nameLen[i] = nameStr ? (int)XSTRLEN(nameStr) : 0;
    }

    idx = nameASN_Length;
    for (i = 0; i < NAME_ENTRIES; i++) {
        int type = GetCertNameId(i);

    #ifdef WOLFSSL_MULTI_ATTRIB
        j = -1;
        /* Put DomainComponents before OrgUnitName. */
        while (FindMultiAttrib(name, type, &j)) {
            if (dataASN != NULL && namesASN != NULL) {
                if (idx > maxIdx - (int)rdnASN_Length) {
                    WOLFSSL_MSG("Wanted to write more ASN than allocated");
                    ret = BUFFER_E;
                    break;
                }
                /* Copy data into dynamic vars. */
                SetRdnItems(namesASN + idx, dataASN + idx, dcOid,
                    sizeof(dcOid), name->name[j].type,
                    (byte*)name->name[j].value, name->name[j].sz);
            }
            idx += rdnASN_Length;
        }
        if (ret != 0)
            break;
    #endif

        if (nameLen[i] > 0) {
            if (dataASN != NULL) {
                if (idx > maxIdx - (int)rdnASN_Length) {
                    WOLFSSL_MSG("Wanted to write more ASN than allocated");
                    ret = BUFFER_E;
                    break;
                }
                /* Write out first instance of attribute type. */
                if (type == ASN_EMAIL_NAME) {
                    /* Copy email data into dynamic vars. */
                    SetRdnItems(namesASN + idx, dataASN + idx, attrEmailOid,
                        sizeof(attrEmailOid), ASN_IA5_STRING,
                        (const byte*)GetOneCertName(name, i), nameLen[i]);
                }
                else if (type == ASN_USER_ID) {
                    /* Copy userID data into dynamic vars. */
                    SetRdnItems(namesASN + idx, dataASN + idx, uidOid,
                        sizeof(uidOid), GetNameType(name, i),
                        (const byte*)GetOneCertName(name, i), nameLen[i]);
                }
                else if (type == ASN_CUSTOM_NAME) {
                #ifdef WOLFSSL_CUSTOM_OID
                    SetRdnItems(namesASN + idx, dataASN + idx, name->custom.oid,
                        name->custom.oidSz, name->custom.enc,
                        name->custom.val, name->custom.valSz);
                #endif
                }
                else {
                    /* Copy name data into dynamic vars. */
                    SetRdnItems(namesASN + idx, dataASN + idx, nameOid[i],
                        NAME_OID_SZ, GetNameType(name, i),
                        (const byte*)GetOneCertName(name, i), nameLen[i]);
                }
            }
            idx += rdnASN_Length;
        }

    #ifdef WOLFSSL_MULTI_ATTRIB
        j = -1;
        /* Write all other attributes of this type. */
        while (FindMultiAttrib(name, type, &j)) {
            if (dataASN != NULL && namesASN != NULL) {
                if (idx > maxIdx - (int)rdnASN_Length) {
                    WOLFSSL_MSG("Wanted to write more ASN than allocated");
                    ret = BUFFER_E;
                    break;
                }
                /* Copy data into dynamic vars. */
                SetRdnItems(namesASN + idx, dataASN + idx, nameOid[i],
                    NAME_OID_SZ, name->name[j].type,
                    (byte*)name->name[j].value, name->name[j].sz);
            }
            idx += rdnASN_Length;
        }
        if (ret != 0)
            break;
    #endif
    }
    if (ret == 0)
        ret = idx;
    return ret;
}
#endif

/* encode CertName into output, return total bytes written */
int SetNameEx(byte* output, word32 outputSz, CertName* name, void* heap)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    int totalBytes = 0, i, idx;
    EncodedName  names[NAME_ENTRIES];
#ifdef WOLFSSL_MULTI_ATTRIB
    EncodedName addNames[CTC_MAX_ATTRIB];
    int j, type;
#endif

    if (output == NULL || name == NULL)
        return BAD_FUNC_ARG;

    if (outputSz < 3)
        return BUFFER_E;


    for (i = 0; i < NAME_ENTRIES; i++) {
        const char* nameStr = GetOneCertName(name, i);

        ret = EncodeName(&names[i], nameStr, GetNameType(name, i),
                          GetCertNameId(i), ASN_IA5_STRING, name);
        if (ret < 0) {
            WOLFSSL_MSG("EncodeName failed");
            return BUFFER_E;
        }
        totalBytes += ret;
    }
#ifdef WOLFSSL_MULTI_ATTRIB
    for (i = 0; i < CTC_MAX_ATTRIB; i++) {
        if (name->name[i].sz > 0) {
            ret = EncodeName(&addNames[i], name->name[i].value,
                        (byte)name->name[i].type, name->name[i].id,
                        ASN_IA5_STRING, NULL);
            if (ret < 0) {
                WOLFSSL_MSG("EncodeName on multiple attributes failed");
                return BUFFER_E;
            }
            totalBytes += ret;
        }
        else {
            addNames[i].used = 0;
        }
    }
#endif /* WOLFSSL_MULTI_ATTRIB */

    /* header */
    idx = SetSequence(totalBytes, output);
    totalBytes += idx;
    if (totalBytes > WC_ASN_NAME_MAX) {
        WOLFSSL_MSG("Total Bytes is greater than WC_ASN_NAME_MAX");
        return BUFFER_E;
    }

    for (i = 0; i < NAME_ENTRIES; i++) {
    #ifdef WOLFSSL_MULTI_ATTRIB
        type = GetCertNameId(i);
        for (j = 0; j < CTC_MAX_ATTRIB; j++) {
            if (name->name[j].sz > 0 && type == name->name[j].id) {
                if (outputSz < (word32)(idx+addNames[j].totalLen)) {
                    WOLFSSL_MSG("Not enough space left for DC value");
                    return BUFFER_E;
                }

                XMEMCPY(output + idx, addNames[j].encoded,
                        addNames[j].totalLen);
                idx += addNames[j].totalLen;
            }
        }
    #endif /* WOLFSSL_MULTI_ATTRIB */

        if (names[i].used) {
            if (outputSz < (word32)(idx+names[i].totalLen)) {
                return BUFFER_E;
            }

            XMEMCPY(output + idx, names[i].encoded, names[i].totalLen);
            idx += names[i].totalLen;
        }
    }

    (void)heap;

    return totalBytes;
#else
    /* TODO: consider calculating size of entries, putting length into
     * SEQUENCE, encode SEQUENCE, encode entries into buffer.  */
    ASNSetData* dataASN = NULL; /* Can't use DECL_ASNSETDATA. Always dynamic. */
    ASNItem*    namesASN = NULL;
    int         items = 0;
    int         ret = 0;
    int         sz = 0;

    /* Calculate length of name entries and size for allocating. */
    ret = SetNameRdnItems(NULL, NULL, 0, name);
    if (ret > 0) {
        items = ret;
        ret = 0;
    }

    /* Allocate dynamic data items. */
    dataASN = (ASNSetData*)XMALLOC(items * sizeof(ASNSetData), heap,
                                   DYNAMIC_TYPE_TMP_BUFFER);
    if (dataASN == NULL) {
        ret = MEMORY_E;
    }
    else {
        /* Allocate dynamic ASN.1 template items. */
        namesASN = (ASNItem*)XMALLOC(items * sizeof(ASNItem), heap,
                                     DYNAMIC_TYPE_TMP_BUFFER);
        if (namesASN == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        /* Clear the dynamic data. */
        XMEMSET(dataASN, 0, items * sizeof(ASNSetData));
        /* Copy in the outer sequence. */
        XMEMCPY(namesASN, nameASN, sizeof(nameASN));

        ret = SetNameRdnItems(dataASN, namesASN, items, name);
        if (ret == items)
            ret = 0;
        else if (ret > 0) {
            WOLFSSL_MSG("SetNameRdnItems returned different length");
            ret = BUFFER_E;
        }
    }
    if (ret == 0) {
        /* Calculate size of encoding. */
        ret = SizeASN_Items(namesASN, dataASN, items, &sz);
    }
    /* Check buffer size if passed in. */
    if (ret == 0 && output != NULL && sz > (int)outputSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        if (output != NULL) {
            /* Encode Name. */
            ret = SetASN_Items(namesASN, dataASN, items, output);
        }
        else {
            /* Return the encoding size. */
            ret = sz;
        }
    }

    if (namesASN != NULL)
        XFREE(namesASN, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (dataASN != NULL)
        XFREE(dataASN, heap, DYNAMIC_TYPE_TMP_BUFFER);
    (void)heap;
    return ret;
#endif
}
int SetName(byte* output, word32 outputSz, CertName* name)
{
    return SetNameEx(output, outputSz, name, NULL);
}

#ifdef WOLFSSL_ASN_TEMPLATE
static int EncodePublicKey(int keyType, byte* output, int outLen,
                           RsaKey* rsaKey, ecc_key* eccKey,
                           ed25519_key* ed25519Key, ed448_key* ed448Key,
                           DsaKey* dsaKey)
{
    int ret = 0;

    (void)outLen;
    (void)rsaKey;
    (void)eccKey;
    (void)ed25519Key;
    (void)ed448Key;
    (void)dsaKey;

    switch (keyType) {
        case RSA_KEY:
            ret = SetRsaPublicKey(output, rsaKey, outLen, 1);
            if (ret <= 0) {
                ret = PUBLIC_KEY_E;
            }
            break;
        case ECC_KEY:
            ret = SetEccPublicKey(output, eccKey, outLen, 1);
            if (ret <= 0) {
                ret = PUBLIC_KEY_E;
            }
            break;
        default:
            ret = PUBLIC_KEY_E;
            break;
    }

    return ret;
}

/* ASN.1 template for certificate extensions.
 * X.509: RFC 5280, 4.1 - Basic Certificate Fields.
 * All extensions supported for encoding are described.
 */
static const ASNItem static_certExtsASN[] = {
            /* Basic Constraints Extension - 4.2.1.9 */
/* BC_SEQ        */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* BC_OID        */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* BC_STR        */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* BC_STR_SEQ    */            { 2, ASN_SEQUENCE, 1, 1, 0 },
                                                   /* cA */
/* BC_CA         */                { 3, ASN_BOOLEAN, 0, 0, 0 },
                                                   /* pathLenConstraint */
/* BC_PATHLEN    */                { 3, ASN_INTEGER, 0, 0, 1 },
                                       /* Subject Alternative Name - 4.2.1.6  */
/* SAN_SEQ       */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* SAN_OID       */       { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* SAN_STR       */       { 1, ASN_OCTET_STRING, 0, 0, 0 },
            /* Subject Key Identifier - 4.2.1.2 */
/* SKID_SEQ      */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* SKID_OID      */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* SKID_STR      */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* SKID_KEYID    */            { 2, ASN_OCTET_STRING, 0, 0, 0 },
                                       /* Authority Key Identifier - 4.2.1.1 */
/* AKID_SEQ      */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* AKID_OID      */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* AKID_STR      */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* AKID_STR_SEQ, */            { 2, ASN_SEQUENCE, 1, 1, 0 },
/* AKID_KEYID    */                { 3, ASN_CONTEXT_SPECIFIC | 0, 0, 0, 0 },
                                       /* Key Usage - 4.2.1.3 */
/* KU_SEQ        */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* KU_OID        */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* KU_CRIT       */        { 1, ASN_BOOLEAN, 0, 0, 0 },
/* KU_STR        */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* KU_USAGE      */            { 2, ASN_BIT_STRING, 0, 0, 0 },
                                       /* Extended Key Usage - 4,2,1,12 */
/* EKU_SEQ       */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* EKU_OID       */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* EKU_STR       */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
                                       /* Certificate Policies - 4.2.1.4 */
/* POLICIES_SEQ, */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* POLICIES_OID, */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* POLICIES_STR, */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* POLICIES_INFO */            { 2, ASN_SEQUENCE, 1, 0, 0 },
                                       /* Netscape Certificate Type */
/* NSTYPE_SEQ    */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* NSTYPE_OID    */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* NSTYPE_STR    */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
/* NSTYPE_USAGE, */            { 2, ASN_BIT_STRING, 0, 0, 0 },
/* CRLINFO_SEQ   */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* CRLINFO_OID   */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* CRLINFO_STR   */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
/* CUSTOM_SEQ    */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* CUSTOM_OID    */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* CUSTOM_STR    */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
};
enum {
    CERTEXTSASN_IDX_BC_SEQ = 0,
    CERTEXTSASN_IDX_BC_OID,
    CERTEXTSASN_IDX_BC_STR,
    CERTEXTSASN_IDX_BC_STR_SEQ,
    CERTEXTSASN_IDX_BC_CA,
    CERTEXTSASN_IDX_BC_PATHLEN,
    CERTEXTSASN_IDX_SAN_SEQ,
    CERTEXTSASN_IDX_SAN_OID,
    CERTEXTSASN_IDX_SAN_STR,
    CERTEXTSASN_IDX_SKID_SEQ,
    CERTEXTSASN_IDX_SKID_OID,
    CERTEXTSASN_IDX_SKID_STR,
    CERTEXTSASN_IDX_SKID_KEYID,
    CERTEXTSASN_IDX_AKID_SEQ,
    CERTEXTSASN_IDX_AKID_OID,
    CERTEXTSASN_IDX_AKID_STR,
    CERTEXTSASN_IDX_AKID_STR_SEQ,
    CERTEXTSASN_IDX_AKID_KEYID,
    CERTEXTSASN_IDX_KU_SEQ,
    CERTEXTSASN_IDX_KU_OID,
    CERTEXTSASN_IDX_KU_CRIT,
    CERTEXTSASN_IDX_KU_STR,
    CERTEXTSASN_IDX_KU_USAGE,
    CERTEXTSASN_IDX_EKU_SEQ,
    CERTEXTSASN_IDX_EKU_OID,
    CERTEXTSASN_IDX_EKU_STR,
    CERTEXTSASN_IDX_POLICIES_SEQ,
    CERTEXTSASN_IDX_POLICIES_OID,
    CERTEXTSASN_IDX_POLICIES_STR,
    CERTEXTSASN_IDX_POLICIES_INFO,
    CERTEXTSASN_IDX_NSTYPE_SEQ,
    CERTEXTSASN_IDX_NSTYPE_OID,
    CERTEXTSASN_IDX_NSTYPE_STR,
    CERTEXTSASN_IDX_NSTYPE_USAGE,
    CERTEXTSASN_IDX_CRLINFO_SEQ,
    CERTEXTSASN_IDX_CRLINFO_OID,
    CERTEXTSASN_IDX_CRLINFO_STR,
    CERTEXTSASN_IDX_CUSTOM_SEQ,
    CERTEXTSASN_IDX_CUSTOM_OID,
    CERTEXTSASN_IDX_CUSTOM_STR,
    CERTEXTSASN_IDX_START_CUSTOM,

};

/* Number of items in ASN.1 template for certificate extensions. We multiply
 * by 4 because there are 4 things (seq, OID, crit flag, octet string). */
#define certExtsASN_Length ((sizeof(static_certExtsASN) / sizeof(ASNItem)) \
                            + (NUM_CUSTOM_EXT * 4))

static const ASNItem customExtASN[] = {
/* CUSTOM_SEQ    */    { 0, ASN_SEQUENCE, 1, 1, 0 },
/* CUSTOM_OID    */        { 1, ASN_OBJECT_ID, 0, 0, 0 },
/* CUSTOM_CRIT   */        { 1, ASN_BOOLEAN, 0, 0, 0 },
/* CUSTOM_STR    */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
};

static int EncodeExtensions(Cert* cert, byte* output, word32 maxSz,
                            int forRequest)
{
    DECL_ASNSETDATA(dataASN, certExtsASN_Length);
    int sz;
    int ret = 0;
    int i = 0;
    static const byte bcOID[]   = { 0x55, 0x1d, 0x13 };
#ifdef WOLFSSL_ALT_NAMES
    static const byte sanOID[]  = { 0x55, 0x1d, 0x11 };
#endif
#ifdef WOLFSSL_CERT_EXT
    static const byte skidOID[] = { 0x55, 0x1d, 0x0e };
    static const byte akidOID[] = { 0x55, 0x1d, 0x23 };
    static const byte kuOID[]   = { 0x55, 0x1d, 0x0f };
    static const byte ekuOID[]  = { 0x55, 0x1d, 0x25 };
    static const byte cpOID[]   = { 0x55, 0x1d, 0x20 };
    static const byte nsCertOID[] = { 0x60, 0x86, 0x48, 0x01,
                                      0x86, 0xF8, 0x42, 0x01, 0x01 };
    static const byte crlInfoOID[] = { 0x55, 0x1D, 0x1F };
#endif

    ASNItem certExtsASN[certExtsASN_Length];
#if defined(WOLFSSL_CUSTOM_OID) && defined(WOLFSSL_CERT_EXT)
    byte encodedOids[NUM_CUSTOM_EXT * MAX_OID_SZ];
#endif

    /* Clone static_certExtsASN into a certExtsASN and then fill the rest of it
     * with (NUM_CUSTOM_EXT*4) more ASNItems specifying extensions. See comment
     * above definition of certExtsASN_Length. */
    XMEMCPY(certExtsASN, static_certExtsASN, sizeof(static_certExtsASN));
    for (i = sizeof(static_certExtsASN) / sizeof(ASNItem);
         i < (int)certExtsASN_Length; i += 4) {
        XMEMCPY(&certExtsASN[i], customExtASN, sizeof(customExtASN));
    }

    (void)forRequest;

    CALLOC_ASNSETDATA(dataASN, certExtsASN_Length, ret, cert->heap);

    if (ret == 0) {
        if (cert->isCA) {
            /* Set Basic Constraints to be a Certificate Authority. */
            SetASN_Boolean(&dataASN[CERTEXTSASN_IDX_BC_CA], 1);
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_BC_OID], bcOID, sizeof(bcOID));
            /* TODO: consider adding path length field in Cert. */
            dataASN[CERTEXTSASN_IDX_BC_PATHLEN].noOut = 1;
        }
        else {
            /* Don't write out Basic Constraints extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_BC_SEQ,
                    CERTEXTSASN_IDX_BC_PATHLEN);
        }
    #ifdef WOLFSSL_ALT_NAMES
        if (!forRequest && cert->altNamesSz > 0) {
            /* Set Subject Alternative Name OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_SAN_OID],
                    sanOID, sizeof(sanOID));
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_SAN_STR],
                    cert->altNames, cert->altNamesSz);
        }
        else
    #endif
        {
            /* Don't write out Subject Alternative Name extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_SAN_SEQ,
                    CERTEXTSASN_IDX_SAN_STR);
        }
    #ifdef WOLFSSL_CERT_EXT
        if (cert->skidSz > 0) {
            /* Set Subject Key Identifier OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_SKID_OID],
                    skidOID, sizeof(skidOID));
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_SKID_KEYID],
                    cert->skid, cert->skidSz);
        }
        else {
            /* Don't write out Subject Key Identifier extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_SKID_SEQ,
                    CERTEXTSASN_IDX_SKID_KEYID);
        }
        if (cert->akidSz > 0) {
            /* Set Authority Key Identifier OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_AKID_OID],
                    akidOID, sizeof(akidOID));
        #ifdef WOLFSSL_AKID_NAME
            if (cert->rawAkid) {
                SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_AKID_STR],
                        cert->akid, cert->akidSz);
                /* cert->akid contains the internal ext structure */
                SetASNItem_NoOutBelow(dataASN, certExtsASN,
                        CERTEXTSASN_IDX_AKID_STR, certExtsASN_Length);
            }
            else
        #endif
            {
                SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_AKID_KEYID],
                        cert->akid, cert->akidSz);
            }
        }
        else {
            /* Don't write out Authority Key Identifier extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_AKID_SEQ,
                    CERTEXTSASN_IDX_AKID_KEYID);
        }
        if (cert->keyUsage != 0) {
            /* Set Key Usage OID, critical and value. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_KU_OID],
                    kuOID, sizeof(kuOID));
            SetASN_Boolean(&dataASN[CERTEXTSASN_IDX_KU_CRIT], 1);
            SetASN_Int16Bit(&dataASN[CERTEXTSASN_IDX_KU_USAGE],
                    cert->keyUsage);
        }
        else {
            /* Don't write out Key Usage extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_KU_SEQ,
                    CERTEXTSASN_IDX_KU_USAGE);
        }
        if (cert->extKeyUsage != 0) {
            /* Calculate size of Extended Key Usage data. */
            sz = SetExtKeyUsage(cert, NULL, 0, cert->extKeyUsage);
            if (sz <= 0) {
                ret = KEYUSAGE_E;
            }
            /* Set Extended Key Usage OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_EKU_OID],
                    ekuOID, sizeof(ekuOID));
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_EKU_STR],
                    NULL, sz);
        }
        else {
            /* Don't write out Extended Key Usage extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_EKU_SEQ,
                    CERTEXTSASN_IDX_EKU_STR);
        }

        if ((!forRequest) && (cert->certPoliciesNb > 0)) {
            /* Calculate size of certificate policies. */
            sz = SetCertificatePolicies(NULL, 0, cert->certPolicies,
                    cert->certPoliciesNb, cert->heap);
            if (sz > 0) {
                /* Set Certificate Policies OID. */
                SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_POLICIES_OID],
                        cpOID, sizeof(cpOID));
                /* Make space for data. */
                SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_POLICIES_INFO],
                        NULL, sz);
            }
            else {
                ret = CERTPOLICIES_E;
            }
        }
        else {
            /* Don't write out Certificate Policies extension items. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_POLICIES_SEQ,
                    CERTEXTSASN_IDX_POLICIES_INFO);
        }
    #ifndef IGNORE_NETSCAPE_CERT_TYPE
        /* Netscape Certificate Type */
        if (cert->nsCertType != 0) {
            /* Set Netscape Certificate Type OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_NSTYPE_OID],
                    nsCertOID, sizeof(nsCertOID));
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_NSTYPE_USAGE],
                    &cert->nsCertType, 1);
        }
        else
    #endif
        {
            /* Don't write out Netscape Certificate Type. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_NSTYPE_SEQ,
                    CERTEXTSASN_IDX_NSTYPE_USAGE);
        }
        if (cert->crlInfoSz > 0) {
            /* Set CRL Distribution Points OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_CRLINFO_OID],
                    crlInfoOID, sizeof(crlInfoOID));
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_CRLINFO_STR],
                    cert->crlInfo, cert->crlInfoSz);
        }
        else {
            /* Don't write out CRL Distribution Points. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_CRLINFO_SEQ,
                    CERTEXTSASN_IDX_CRLINFO_STR);
        }

    #ifdef WOLFSSL_CUSTOM_OID
        /* encode a custom oid and value */
        if (cert->extCustom.oidSz > 0) {
            /* Set CRL Distribution Points OID and data. */
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_CUSTOM_OID],
                    cert->extCustom.oid, cert->extCustom.oidSz);
            SetASN_Buffer(&dataASN[CERTEXTSASN_IDX_CUSTOM_STR],
                    cert->extCustom.val, cert->extCustom.valSz);
        }
        else
    #endif
        {
            /* Don't write out custom OID. */
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_CUSTOM_SEQ,
                    CERTEXTSASN_IDX_CUSTOM_STR);
        }

        i = 0;
    #ifdef WOLFSSL_CUSTOM_OID
        for (; i < cert->customCertExtCount; i++) {
             int idx = CERTEXTSASN_IDX_START_CUSTOM + (i * 4);
             word32 encodedOidSz = MAX_OID_SZ;
             idx++; /* Skip one for for SEQ. */
             /* EncodePolicyOID() will never return error since we parsed this
              * OID when it was set. */
             EncodePolicyOID(&encodedOids[i * MAX_OID_SZ], &encodedOidSz,
                             cert->customCertExt[i].oid, NULL);
             SetASN_Buffer(&dataASN[idx], &encodedOids[i * MAX_OID_SZ],
                           encodedOidSz);
             idx++;
             if (cert->customCertExt[i].crit) {
                 SetASN_Boolean(&dataASN[idx], 1);
             } else {
                 dataASN[idx].noOut = 1;
             }
             idx++;
             SetASN_Buffer(&dataASN[idx], cert->customCertExt[i].val,
                           cert->customCertExt[i].valSz);
        }
    #endif

        while (i < NUM_CUSTOM_EXT) {
            SetASNItem_NoOut(dataASN, CERTEXTSASN_IDX_START_CUSTOM + (i * 4),
                             CERTEXTSASN_IDX_START_CUSTOM + (i * 4) + 3);
            i++;
        }
    #endif /* WOLFSSL_CERT_EXT */
    }

    if (ret == 0) {
        /* Calculate size of encoded extensions. */
        ret = SizeASN_Items(certExtsASN, dataASN, certExtsASN_Length, &sz);
    }
    if (ret == 0) {
        /* Only SEQUENCE - don't encode extensions. */
        if (sz == 2) {
            sz = 0;
        }
        /* Check buffer is big enough. */
        else if ((output != NULL) && (sz > (int)maxSz)) {
            ret = BUFFER_E;
        }
    }

    if ((ret == 0) && (output != NULL) && (sz > 0)) {
        /* Encode certificate extensions into buffer. */
        SetASN_Items(certExtsASN, dataASN, certExtsASN_Length, output);

    #ifdef WOLFSSL_CERT_EXT
        if (cert->extKeyUsage != 0){
            /* Encode Extended Key Usage into space provided. */
            if (SetExtKeyUsage(cert,
                    (byte*)dataASN[CERTEXTSASN_IDX_EKU_STR].data.buffer.data,
                    dataASN[CERTEXTSASN_IDX_EKU_STR].data.buffer.length,
                    cert->extKeyUsage) <= 0) {
                ret = KEYUSAGE_E;
            }
        }
        if ((!forRequest) && (cert->certPoliciesNb > 0)) {
            /* Encode Certificate Policies into space provided. */
            if (SetCertificatePolicies(
                    (byte*)dataASN[CERTEXTSASN_IDX_POLICIES_INFO].data.buffer.data,
                    dataASN[CERTEXTSASN_IDX_POLICIES_INFO].data.buffer.length,
                    cert->certPolicies, cert->certPoliciesNb, cert->heap) <= 0) {
                ret = CERTPOLICIES_E;
            }
        }
    #endif
    }
    if (ret == 0) {
        /* Return the encoding size. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, cert->heap);

    return ret;
}
#endif /* WOLFSSL_ASN_TEMPLATE */

#ifndef WOLFSSL_ASN_TEMPLATE
/* Set Date validity from now until now + daysValid
 * return size in bytes written to output, 0 on error */
/* TODO https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
 * "MUST always encode certificate validity dates through the year 2049 as
 *  UTCTime; certificate validity dates in 2050 or later MUST be encoded as
 *  GeneralizedTime." */
static int SetValidity(byte* output, int daysValid)
{
#ifndef NO_ASN_TIME
    byte before[MAX_DATE_SIZE];
    byte  after[MAX_DATE_SIZE];

    int beforeSz;
    int afterSz;
    int seqSz;

    time_t now;
    time_t then;
    struct tm* tmpTime;
    struct tm* expandedTime;
    struct tm localTime;

#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    tmpTime = NULL;
#endif
    (void)tmpTime;

    now = wc_Time(0);

    /* before now */
    before[0] = ASN_GENERALIZED_TIME;
    beforeSz = SetLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

    /* subtract 1 day of seconds for more compliance */
    then = now - 86400;
    expandedTime = XGMTIME(&then, tmpTime);
    if (expandedTime == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;   /* error */
    }
    localTime = *expandedTime;

    /* adjust */
    localTime.tm_year += 1900;
    localTime.tm_mon +=    1;

    SetTime(&localTime, before + beforeSz);
    beforeSz += ASN_GEN_TIME_SZ;

    after[0] = ASN_GENERALIZED_TIME;
    afterSz  = SetLength(ASN_GEN_TIME_SZ, after + 1) + 1;  /* gen tag */

    /* add daysValid of seconds */
    then = now + (daysValid * (time_t)86400);
    expandedTime = XGMTIME(&then, tmpTime);
    if (expandedTime == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;   /* error */
    }
    localTime = *expandedTime;

    /* adjust */
    localTime.tm_year += 1900;
    localTime.tm_mon  +=    1;

    SetTime(&localTime, after + afterSz);
    afterSz += ASN_GEN_TIME_SZ;

    /* headers and output */
    seqSz = SetSequence(beforeSz + afterSz, output);
    XMEMCPY(output + seqSz, before, beforeSz);
    XMEMCPY(output + seqSz + beforeSz, after, afterSz);

    return seqSz + beforeSz + afterSz;
#else
    (void)output;
    (void)daysValid;
    return NOT_COMPILED_IN;
#endif
}
#else
static int SetValidity(byte* before, byte* after, int daysValid)
{
    int ret = 0;
    time_t now;
    time_t then;
    struct tm* tmpTime;
    struct tm* expandedTime;
    struct tm localTime;
#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    tmpTime = NULL;
#endif
    (void)tmpTime;

    now = wc_Time(0);

    /* subtract 1 day of seconds for more compliance */
    then = now - 86400;
    expandedTime = XGMTIME(&then, tmpTime);
    if (expandedTime == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        ret = DATE_E;
    }
    if (ret == 0) {
        localTime = *expandedTime;

        /* adjust */
        localTime.tm_year += 1900;
        localTime.tm_mon +=    1;

        SetTime(&localTime, before);

        /* add daysValid of seconds */
        then = now + (daysValid * (time_t)86400);
        expandedTime = XGMTIME(&then, tmpTime);
        if (expandedTime == NULL) {
            WOLFSSL_MSG("XGMTIME failed");
            ret = DATE_E;
        }
    }
    if (ret == 0) {
        localTime = *expandedTime;

        /* adjust */
        localTime.tm_year += 1900;
        localTime.tm_mon  +=    1;

        SetTime(&localTime, after);
    }

    return ret;
}
#endif /* WOLFSSL_ASN_TEMPLATE */


#ifndef WOLFSSL_ASN_TEMPLATE
/* encode info from cert into DER encoded format */
static int EncodeCert(Cert* cert, DerCert* der, RsaKey* rsaKey, ecc_key* eccKey,
                      WC_RNG* rng, DsaKey* dsaKey, ed25519_key* ed25519Key,
                      ed448_key* ed448Key, falcon_key* falconKey)
{
    int ret;

    if (cert == NULL || der == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    /* make sure at least one key type is provided */
    if (rsaKey == NULL && eccKey == NULL && ed25519Key == NULL &&
        dsaKey == NULL && ed448Key == NULL && falconKey == NULL) {
        return PUBLIC_KEY_E;
    }

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion(cert->version, der->version, TRUE);

    /* serial number (must be positive) */
    if (cert->serialSz == 0) {
        /* generate random serial */
        cert->serialSz = CTC_GEN_SERIAL_SZ;
        ret = wc_RNG_GenerateBlock(rng, cert->serial, cert->serialSz);
        if (ret != 0)
            return ret;
        /* Clear the top bit to avoid a negative value */
        cert->serial[0] &= 0x7f;
    }
    der->serialSz = SetSerialNumber(cert->serial, cert->serialSz, der->serial,
        sizeof(der->serial), CTC_SERIAL_SIZE);
    if (der->serialSz < 0)
        return der->serialSz;

    /* signature algo */
    der->sigAlgoSz = SetAlgoID(cert->sigType, der->sigAlgo, oidSigType, 0);
    if (der->sigAlgoSz <= 0)
        return ALGO_ID_E;

    /* public key */
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
    }

    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey,
                                           sizeof(der->publicKey), 1);
    }





    if (der->publicKeySz <= 0)
        return PUBLIC_KEY_E;

    der->validitySz = 0;
#ifdef WOLFSSL_ALT_NAMES
    /* date validity copy ? */
    if (cert->beforeDateSz && cert->afterDateSz) {
        der->validitySz = CopyValidity(der->validity, cert);
        if (der->validitySz <= 0)
            return DATE_E;
    }
#endif

    /* date validity */
    if (der->validitySz == 0) {
        der->validitySz = SetValidity(der->validity, cert->daysValid);
        if (der->validitySz <= 0)
            return DATE_E;
    }

    /* subject name */
#if defined(WOLFSSL_CERT_EXT)
    if (XSTRLEN((const char*)cert->sbjRaw) > 0) {
        /* Use the raw subject */
        int idx;

        der->subjectSz = min(sizeof(der->subject),
                (word32)XSTRLEN((const char*)cert->sbjRaw));
        /* header */
        idx = SetSequence(der->subjectSz, der->subject);
        if (der->subjectSz + idx > (int)sizeof(der->subject)) {
            return SUBJECT_E;
        }

        XMEMCPY((char*)der->subject + idx, (const char*)cert->sbjRaw,
                der->subjectSz);
        der->subjectSz += idx;
    }
    else
#endif
    {
        /* Use the name structure */
        der->subjectSz = SetNameEx(der->subject, sizeof(der->subject),
                &cert->subject, cert->heap);
    }
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* issuer name */
#if defined(WOLFSSL_CERT_EXT)
    if (XSTRLEN((const char*)cert->issRaw) > 0) {
        /* Use the raw issuer */
        int idx;

        der->issuerSz = min(sizeof(der->issuer),
                (word32)XSTRLEN((const char*)cert->issRaw));

        /* header */
        idx = SetSequence(der->issuerSz, der->issuer);
        if (der->issuerSz + idx > (int)sizeof(der->issuer)) {
            return ISSUER_E;
        }

        XMEMCPY((char*)der->issuer + idx, (const char*)cert->issRaw,
                der->issuerSz);
        der->issuerSz += idx;
    }
    else
#endif
    {
        /* Use the name structure */
        der->issuerSz = SetNameEx(der->issuer, sizeof(der->issuer),
                cert->selfSigned ? &cert->subject : &cert->issuer, cert->heap);
    }
    if (der->issuerSz <= 0)
        return ISSUER_E;

    /* set the extensions */
    der->extensionsSz = 0;

    /* CA */
    if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_ALT_NAMES
    /* Alternative Name */
    if (cert->altNamesSz) {
        der->altNamesSz = SetAltNames(der->altNames, sizeof(der->altNames),
                                      cert->altNames, cert->altNamesSz);
        if (der->altNamesSz <= 0)
            return ALT_NAME_E;

        der->extensionsSz += der->altNamesSz;
    }
    else
        der->altNamesSz = 0;
#endif

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)min(CTC_MAX_SKID_SIZE, sizeof(der->skid)))
            return SKID_E;

        /* Note: different skid buffers sizes for der (MAX_KID_SZ) and
            cert (CTC_MAX_SKID_SIZE). */
        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* AKID */
    if (cert->akidSz) {
        /* check the provided AKID size */
        if ((
#ifdef WOLFSSL_AKID_NAME
             !cert->rawAkid &&
#endif
              cert->akidSz > (int)min(CTC_MAX_AKID_SIZE, sizeof(der->akid)))
#ifdef WOLFSSL_AKID_NAME
          || (cert->rawAkid && cert->akidSz > (int)sizeof(der->akid))
#endif
             )
            return AKID_E;

        der->akidSz = SetAKID(der->akid, sizeof(der->akid), cert->akid,
                                cert->akidSz,
#ifdef WOLFSSL_AKID_NAME
                                cert->rawAkid
#else
                                0
#endif
                                );
        if (der->akidSz <= 0)
            return AKID_E;

        der->extensionsSz += der->akidSz;
    }
    else
        der->akidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0){
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;

    /* Extended Key Usage */
    if (cert->extKeyUsage != 0){
        der->extKeyUsageSz = SetExtKeyUsage(cert, der->extKeyUsage,
                                sizeof(der->extKeyUsage), cert->extKeyUsage);
        if (der->extKeyUsageSz <= 0)
            return EXTKEYUSAGE_E;

        der->extensionsSz += der->extKeyUsageSz;
    }
    else
        der->extKeyUsageSz = 0;

#ifndef IGNORE_NETSCAPE_CERT_TYPE
    /* Netscape Certificate Type */
    if (cert->nsCertType != 0) {
        der->nsCertTypeSz = SetNsCertType(cert, der->nsCertType,
                                sizeof(der->nsCertType), cert->nsCertType);
        if (der->nsCertTypeSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->nsCertTypeSz;
    }
    else
        der->nsCertTypeSz = 0;
#endif

    if (cert->crlInfoSz > 0) {
        der->crlInfoSz = SetCRLInfo(cert, der->crlInfo, sizeof(der->crlInfo),
                                cert->crlInfo, cert->crlInfoSz);
        if (der->crlInfoSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->crlInfoSz;
    }
    else
        der->crlInfoSz = 0;

    /* Certificate Policies */
    if (cert->certPoliciesNb != 0) {
        der->certPoliciesSz = SetCertificatePolicies(der->certPolicies,
                                                     sizeof(der->certPolicies),
                                                     cert->certPolicies,
                                                     cert->certPoliciesNb,
                                                     cert->heap);
        if (der->certPoliciesSz <= 0)
            return CERTPOLICIES_E;

        der->extensionsSz += der->certPoliciesSz;
    }
    else
        der->certPoliciesSz = 0;
#endif /* WOLFSSL_CERT_EXT */

    /* put extensions */
    if (der->extensionsSz > 0) {

        /* put the start of extensions sequence (ID, Size) */
        der->extensionsSz = SetExtensionsHeader(der->extensions,
                                                sizeof(der->extensions),
                                                der->extensionsSz);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret == 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_ALT_NAMES
        /* put Alternative Names */
        if (der->altNamesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->altNames, der->altNamesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put CRL Distribution Points */
        if (der->crlInfoSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->crlInfo, der->crlInfoSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put ExtendedKeyUsage */
        if (der->extKeyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extKeyUsage, der->extKeyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put Netscape Cert Type */
#ifndef IGNORE_NETSCAPE_CERT_TYPE
        if (der->nsCertTypeSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->nsCertType, der->nsCertTypeSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

        /* put Certificate Policies */
        if (der->certPoliciesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->certPolicies, der->certPoliciesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif /* WOLFSSL_CERT_EXT */
    }

    der->total = der->versionSz + der->serialSz + der->sigAlgoSz +
        der->publicKeySz + der->validitySz + der->subjectSz + der->issuerSz +
        der->extensionsSz;

    return 0;
}


/* write DER encoded cert to buffer, size already checked */
static int WriteCertBody(DerCert* der, byte* buf)
{
    int idx;

    /* signed part header */
    idx = SetSequence(der->total, buf);
    /* version */
    XMEMCPY(buf + idx, der->version, der->versionSz);
    idx += der->versionSz;
    /* serial */
    XMEMCPY(buf + idx, der->serial, der->serialSz);
    idx += der->serialSz;
    /* sig algo */
    XMEMCPY(buf + idx, der->sigAlgo, der->sigAlgoSz);
    idx += der->sigAlgoSz;
    /* issuer */
    XMEMCPY(buf + idx, der->issuer, der->issuerSz);
    idx += der->issuerSz;
    /* validity */
    XMEMCPY(buf + idx, der->validity, der->validitySz);
    idx += der->validitySz;
    /* subject */
    XMEMCPY(buf + idx, der->subject, der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    XMEMCPY(buf + idx, der->publicKey, der->publicKeySz);
    idx += der->publicKeySz;
    if (der->extensionsSz) {
        /* extensions */
        XMEMCPY(buf + idx, der->extensions, min(der->extensionsSz,
                                                   (int)sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */


/* Make RSA signature from buffer (sz), write to sig (sigSz) */
static int MakeSignature(CertSignCtx* certSignCtx, const byte* buf, int sz,
    byte* sig, int sigSz, RsaKey* rsaKey, ecc_key* eccKey,
    ed25519_key* ed25519Key, ed448_key* ed448Key, falcon_key* falconKey,
    WC_RNG* rng, int sigAlgoType, void* heap)
{
    int digestSz = 0, typeH = 0, ret = 0;

    (void)digestSz;
    (void)typeH;
    (void)buf;
    (void)sz;
    (void)sig;
    (void)sigSz;
    (void)rsaKey;
    (void)eccKey;
    (void)ed25519Key;
    (void)ed448Key;
    (void)falconKey;
    (void)rng;
    (void)heap;

    switch (certSignCtx->state) {
    case CERTSIGN_STATE_BEGIN:
    case CERTSIGN_STATE_DIGEST:

        certSignCtx->state = CERTSIGN_STATE_DIGEST;
        certSignCtx->digest = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (certSignCtx->digest == NULL) {
            ret = MEMORY_E; goto exit_ms;
        }

        ret = HashForSignature(buf, sz, sigAlgoType, certSignCtx->digest,
                               &typeH, &digestSz, 0);
        /* set next state, since WC_PENDING_E rentry for these are not "call again" */
        certSignCtx->state = CERTSIGN_STATE_ENCODE;
        if (ret != 0) {
            goto exit_ms;
        }
        FALL_THROUGH;

    case CERTSIGN_STATE_ENCODE:
        if (rsaKey) {
            certSignCtx->encSig = (byte*)XMALLOC(MAX_DER_DIGEST_SZ, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (certSignCtx->encSig == NULL) {
                ret = MEMORY_E; goto exit_ms;
            }

            /* signature */
            certSignCtx->encSigSz = wc_EncodeSignature(certSignCtx->encSig,
                                          certSignCtx->digest, digestSz, typeH);
        }
        FALL_THROUGH;

    case CERTSIGN_STATE_DO:
        certSignCtx->state = CERTSIGN_STATE_DO;
        ret = ALGO_ID_E; /* default to error */

        if (rsaKey) {
            /* signature */
            ret = wc_RsaSSL_Sign(certSignCtx->encSig, certSignCtx->encSigSz,
                                 sig, sigSz, rsaKey, rng);
        }

        if (!rsaKey && eccKey) {
            word32 outSz = sigSz;

            ret = wc_ecc_sign_hash(certSignCtx->digest, digestSz,
                                   sig, &outSz, rng, eccKey);
            if (ret == 0)
                ret = outSz;
        }




        break;
    }

exit_ms:


    if (rsaKey) {
        XFREE(certSignCtx->encSig, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    XFREE(certSignCtx->digest, heap, DYNAMIC_TYPE_TMP_BUFFER);
    certSignCtx->digest = NULL;

    /* reset state */
    certSignCtx->state = CERTSIGN_STATE_BEGIN;

    return ret;
}


#ifdef WOLFSSL_ASN_TEMPLATE
/* Generate a random integer value of at most len bytes.
 *
 * Most-significant bit will not be set when maximum size.
 * Random value may be smaller than maximum size in bytes.
 *
 * @param [in]  rng  Random number generator.
 * @param [out] out  Buffer to hold integer value.
 * @param [in]  len  Maximum number of bytes of integer.
 * @return  0 on success.
 * @return  -ve when random number generation failed.
 */
static int GenerateInteger(WC_RNG* rng, byte* out, int len)
{
    int ret;

    /* Generate random number. */
    ret = wc_RNG_GenerateBlock(rng, out, len);
    if (ret == 0) {
        int i;

        /* Clear the top bit to make positive. */
        out[0] &= 0x7f;

        /* Find first non-zero byte. One zero byte is valid though. */
        for (i = 0; i < len - 1; i++) {
            if (out[i] != 0) {
                break;
            }
        }
        if (i != 0) {
            /* Remove leading zeros. */
            XMEMMOVE(out, out + i, len - i);
        }
    }

    return ret;
}

/* ASN.1 template for a Certificate.
 * X.509: RFC 5280, 4.1 - Basic Certificate Fields.
 */
static const ASNItem sigASN[] = {
/* SEQ          */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                                     /* tbsCertificate */
/* TBS_SEQ      */        { 1, ASN_SEQUENCE, 1, 0, 0 },
                                     /* signatureAlgorithm */
/* SIGALGO_SEQ  */        { 1, ASN_SEQUENCE, 1, 1, 0 },
/* SIGALGO_OID  */            { 2, ASN_OBJECT_ID, 0, 0, 0 },
/* SIGALGO_NULL */            { 2, ASN_TAG_NULL, 0, 0, 0 },
                                     /* signatureValue */
/* SIGNATURE    */        { 1, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    SIGASN_IDX_SEQ = 0,
    SIGASN_IDX_TBS_SEQ,
    SIGASN_IDX_SIGALGO_SEQ,
    SIGASN_IDX_SIGALGO_OID,
    SIGASN_IDX_SIGALGO_NULL,
    SIGASN_IDX_SIGNATURE,
};

/* Number of items in ASN.1 template for a Certificate. */
#define sigASN_Length (sizeof(sigASN) / sizeof(ASNItem))
#endif

/* add signature to end of buffer, size of buffer assumed checked, return
   new length */
int AddSignature(byte* buf, int bodySz, const byte* sig, int sigSz,
                        int sigAlgoType)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    byte seq[MAX_SEQ_SZ];
    int  idx = bodySz, seqSz;

    /* algo */
    idx += SetAlgoID(sigAlgoType, buf ? buf + idx : NULL, oidSigType, 0);
    /* bit string */
    idx += SetBitString(sigSz, 0, buf ? buf + idx : NULL);
    /* signature */
    if (buf)
        XMEMCPY(buf + idx, sig, sigSz);
    idx += sigSz;

    /* make room for overall header */
    seqSz = SetSequence(idx, seq);
    if (buf) {
        XMEMMOVE(buf + seqSz, buf, idx);
        XMEMCPY(buf, seq, seqSz);
    }

    return idx + seqSz;
#else
    DECL_ASNSETDATA(dataASN, sigASN_Length);
    word32 seqSz;
    int sz;
    int ret = 0;

    CALLOC_ASNSETDATA(dataASN, sigASN_Length, ret, NULL);

    /* In place, put body between SEQUENCE and signature. */
    if (ret == 0) {
        /* Set sigature OID and signature data. */
        SetASN_OID(&dataASN[SIGASN_IDX_SIGALGO_OID], sigAlgoType, oidSigType);
        if (IsSigAlgoECC(sigAlgoType)) {
            /* ECDSA and EdDSA doesn't have NULL tagged item. */
            dataASN[SIGASN_IDX_SIGALGO_NULL].noOut = 1;
        }
        SetASN_Buffer(&dataASN[SIGASN_IDX_SIGNATURE], sig, sigSz);
        /* Calcuate size of signature data. */
        ret = SizeASN_Items(&sigASN[SIGASN_IDX_SIGALGO_SEQ],
                &dataASN[SIGASN_IDX_SIGALGO_SEQ], sigASN_Length - 2, &sz);
    }
    if (ret == 0) {
        /* Calculate size of outer sequence by calculating size of the encoded
         * length and adding 1 for tag. */
        seqSz = SizeASNHeader(bodySz + sz);
        if (buf != NULL) {
            /* Move body to after sequence. */
            XMEMMOVE(buf + seqSz, buf, bodySz);
        }
        /* Leave space for body in encoding. */
        SetASN_ReplaceBuffer(&dataASN[SIGASN_IDX_TBS_SEQ], NULL, bodySz);

        /* Calculate overall size and put in offsets and lengths. */
        ret = SizeASN_Items(sigASN, dataASN, sigASN_Length, &sz);
    }
    if ((ret == 0) && (buf != NULL)) {
        /* Write SEQUENCE and signature around body. */
        SetASN_Items(sigASN, dataASN, sigASN_Length, buf);
    }

    if (ret == 0) {
        /* Return the encoding size. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}


/* Make an x509 Certificate v3 any key type from cert input, write to buffer */
static int MakeAnyCert(Cert* cert, byte* derBuffer, word32 derSz,
                       RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng,
                       DsaKey* dsaKey, ed25519_key* ed25519Key,
                       ed448_key* ed448Key, falcon_key* falconKey)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    DerCert der[1];

    if (derBuffer == NULL)
        return BAD_FUNC_ARG;

    if (eccKey)
        cert->keyType = ECC_KEY;
    else if (rsaKey)
        cert->keyType = RSA_KEY;
    else if (dsaKey)
        cert->keyType = DSA_KEY;
    else if (ed25519Key)
        cert->keyType = ED25519_KEY;
    else if (ed448Key)
        cert->keyType = ED448_KEY;
    else
        return BAD_FUNC_ARG;


    ret = EncodeCert(cert, der, rsaKey, eccKey, rng, dsaKey, ed25519Key,
                     ed448Key, falconKey);
    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertBody(der, derBuffer);
    }


    return ret;
#else
    /* TODO: issRaw and sbjRaw should be NUL terminated. */
    DECL_ASNSETDATA(dataASN, x509CertASN_Length);
    word32 publicKeySz = 0;
    word32 issuerSz = 0;
    word32 subjectSz = 0;
    word32 extSz = 0;
    int sz = 0;
    int ret = 0;
    word32 issRawLen = 0;
    word32 sbjRawLen = 0;

    (void)falconKey; /* Unused without OQS */
    CALLOC_ASNSETDATA(dataASN, x509CertASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Set key type into certificate object based on key passed in. */
        if (rsaKey) {
            cert->keyType = RSA_KEY;
        }
        else if (eccKey) {
            cert->keyType = ECC_KEY;
        }
        else if (dsaKey) {
            cert->keyType = DSA_KEY;
        }
        else if (ed25519Key) {
            cert->keyType = ED25519_KEY;
        }
        else if (ed448Key) {
            cert->keyType = ED448_KEY;
        }
        else if (falconKey != NULL) {
        }
        else {
            ret = BAD_FUNC_ARG;
        }
    }
    if ((ret == 0) && (cert->serialSz == 0)) {
        /* Generate random serial number. */
        cert->serialSz = CTC_GEN_SERIAL_SZ;
        ret = GenerateInteger(rng, cert->serial, CTC_GEN_SERIAL_SZ);
    }
    if (ret == 0) {
        /* Determine issuer name size. */
    #if defined(WOLFSSL_CERT_EXT) ||  defined(WOLFSSL_CERT_REQ)
        issRawLen = (word32)XSTRLEN((const char*)cert->issRaw);
        if (issRawLen > 0) {
            issuerSz = min(sizeof(cert->issRaw), issRawLen);
        }
        else
    #endif
        {
            /* Calcuate issuer name encoding size. */
            issuerSz = SetNameEx(NULL, WC_ASN_NAME_MAX, &cert->issuer, cert->heap);
            ret = issuerSz;
        }
    }
    if (ret >= 0) {
        /* Determine subject name size. */
    #if defined(WOLFSSL_CERT_EXT) ||  defined(WOLFSSL_CERT_REQ)
        sbjRawLen = (word32)XSTRLEN((const char*)cert->sbjRaw);
        if (sbjRawLen > 0) {
            subjectSz = min(sizeof(cert->sbjRaw), sbjRawLen);
        }
        else
    #endif
        {
            /* Calcuate subject name encoding size. */
            subjectSz = SetNameEx(NULL, WC_ASN_NAME_MAX, &cert->subject, cert->heap);
            ret = subjectSz;
        }
    }
    if (ret >= 0) {
        /* Calcuate public key encoding size. */
        ret = publicKeySz = EncodePublicKey(cert->keyType, NULL, 0, rsaKey,
            eccKey, ed25519Key, ed448Key, dsaKey);
    }
    if (ret >= 0) {
        /* Calcuate extensions encoding size - may be 0. */
        ret = extSz = EncodeExtensions(cert, NULL, 0, 0);
    }
    if (ret >= 0) {
        /* Don't write out outer sequence - only doing body. */
        dataASN[X509CERTASN_IDX_SEQ].noOut = 1;
        /* Set version, serial number and signature OID */
        SetASN_Int8Bit(&dataASN[X509CERTASN_IDX_TBS_VER_INT], cert->version);
        SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_SERIAL], cert->serial,
                cert->serialSz);
        SetASN_OID(&dataASN[X509CERTASN_IDX_TBS_ALGOID_OID], cert->sigType,
                oidSigType);
        if (IsSigAlgoECC(cert->sigType)) {
            /* No NULL tagged item with ECDSA and EdDSA signature OIDs. */
            dataASN[X509CERTASN_IDX_TBS_ALGOID_PARAMS].noOut = 1;
        }
        if (issRawLen > 0) {
    #if defined(WOLFSSL_CERT_EXT) ||  defined(WOLFSSL_CERT_REQ)
            /* Put in encoded issuer name. */
            SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ],
                    cert->issRaw, issuerSz);
    #endif
        }
        else {
            /* Leave space for issuer name. */
            SetASN_ReplaceBuffer(&dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ],
                    NULL, issuerSz);
        }

#ifdef WOLFSSL_ALT_NAMES
        if (cert->beforeDateSz && cert->afterDateSz) {
            if (cert->beforeDate[0] == ASN_UTC_TIME) {
                /* Make space for before date data. */
                SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC],
                        cert->beforeDate + 2, ASN_UTC_TIME_SIZE - 1);
                /* Don't put out Generalized Time before data. */
                dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT].noOut = 1;
            }
            else {
                /* Don't put out UTC before data. */
                dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC].noOut = 1;
                /* Make space for before date data. */
                SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT],
                        cert->beforeDate + 2, ASN_GEN_TIME_SZ);
            }
            if (cert->afterDate[0] == ASN_UTC_TIME) {
                /* Make space for after date data. */
                SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC],
                        cert->afterDate + 2, ASN_UTC_TIME_SIZE - 1);
                /* Don't put out UTC Generalized Time after data. */
                dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT].noOut = 1;
            }
            else {
                /* Don't put out UTC after data. */
                dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC].noOut = 1;
                /* Make space for after date data. */
                SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT],
                        cert->afterDate + 2, ASN_GEN_TIME_SZ);
            }
        }
        else
#endif
        {
            /* Don't put out UTC before data. */
            dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_UTC].noOut = 1;
            /* Make space for before date data. */
            SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT],
                    NULL, ASN_GEN_TIME_SZ);
            /* Don't put out UTC after data. */
            dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_UTC].noOut = 1;
            /* Make space for after date data. */
            SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT],
                    NULL, ASN_GEN_TIME_SZ);
        }
        if (sbjRawLen > 0) {
            /* Put in encoded subject name. */
    #if defined(WOLFSSL_CERT_EXT) ||  defined(WOLFSSL_CERT_REQ)
            SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_SUBJECT_SEQ],
                    cert->sbjRaw, subjectSz);
    #endif
        }
        else {
            /* Leave space for subject name. */
            SetASN_ReplaceBuffer(&dataASN[X509CERTASN_IDX_TBS_SUBJECT_SEQ],
                    NULL, subjectSz);
        }
        /* Leave space for public key. */
        SetASN_ReplaceBuffer(&dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ],
                NULL, publicKeySz);
        /* Replacement buffer instead of algorithm identifier items. */
        SetASNItem_NoOut(dataASN,
                X509CERTASN_IDX_TBS_SPUBKEYINFO_ALGO_SEQ,
                X509CERTASN_IDX_TBS_SPUBKEYINFO_PUBKEY);
        /* issuerUniqueID and subjectUniqueID not supported. */
        dataASN[X509CERTASN_IDX_TBS_ISSUERUID].noOut = 1;
        dataASN[X509CERTASN_IDX_TBS_SUBJECTUID].noOut = 1;
        /* Leave space for extensions if any set into certificate object. */
        if (extSz > 0) {
            SetASN_Buffer(&dataASN[X509CERTASN_IDX_TBS_EXT_SEQ], NULL, extSz);
        }
        else {
            SetASNItem_NoOutNode(dataASN, x509CertASN,
                    X509CERTASN_IDX_TBS_EXT, x509CertASN_Length);
        }
        /* No signature - added later. */
        SetASNItem_NoOut(dataASN, X509CERTASN_IDX_SIGALGO_SEQ,
                X509CERTASN_IDX_SIGNATURE);

        /* Calculate encoded certificate body size. */
        ret = SizeASN_Items(x509CertASN, dataASN, x509CertASN_Length, &sz);
    }
    /* Check buffer is big enough for encoded data. */
    if ((ret == 0) && (sz > (int)derSz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode certificate body into buffer. */
        SetASN_Items(x509CertASN, dataASN, x509CertASN_Length, derBuffer);

        if (issRawLen == 0) {
            /* Encode issuer name into buffer. */
            ret = SetNameEx(
                (byte*)dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ].data.buffer.data,
                dataASN[X509CERTASN_IDX_TBS_ISSUER_SEQ].data.buffer.length,
                &cert->issuer, cert->heap);
        }
    }
    if ((ret >= 0) && (sbjRawLen == 0)) {
        /* Encode subject name into buffer. */
        ret = SetNameEx(
            (byte*)dataASN[X509CERTASN_IDX_TBS_SUBJECT_SEQ].data.buffer.data,
            dataASN[X509CERTASN_IDX_TBS_SUBJECT_SEQ].data.buffer.length,
            &cert->subject, cert->heap);
    }
    if (ret >= 0) {
#ifdef WOLFSSL_ALT_NAMES
        if (cert->beforeDateSz == 0 || cert->afterDateSz == 0)
#endif
        {
            /* Encode validity into buffer. */
            ret = SetValidity(
                (byte*)dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTB_GT]
                               .data.buffer.data,
                (byte*)dataASN[X509CERTASN_IDX_TBS_VALIDITY_NOTA_GT]
                               .data.buffer.data, cert->daysValid);
        }
    }
    if (ret >= 0) {
        /* Encode public key into buffer. */
        ret = EncodePublicKey(cert->keyType,
            (byte*)dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ]
                           .data.buffer.data,
            dataASN[X509CERTASN_IDX_TBS_SPUBKEYINFO_SEQ]
                           .data.buffer.length,
            rsaKey, eccKey, ed25519Key, ed448Key, dsaKey);
    }
    if ((ret >= 0) && (!dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].noOut)) {
        /* Encode extensions into buffer. */
        ret = EncodeExtensions(cert,
                (byte*)dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.buffer.data,
                dataASN[X509CERTASN_IDX_TBS_EXT_SEQ].data.buffer.length, 0);
    }
    if (ret >= 0) {
        /* Store encoded certifcate body size. */
        cert->bodySz = sz;
        /* Return the encoding size. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, cert->heap);
    return ret;
#endif
}


/* Make an x509 Certificate v3 RSA or ECC from cert input, write to buffer */
int wc_MakeCert_ex(Cert* cert, byte* derBuffer, word32 derSz, int keyType,
                   void* key, WC_RNG* rng)
{
    RsaKey*            rsaKey = NULL;
    DsaKey*            dsaKey = NULL;
    ecc_key*           eccKey = NULL;
    ed25519_key*       ed25519Key = NULL;
    ed448_key*         ed448Key = NULL;
    falcon_key*        falconKey = NULL;

    if (keyType == RSA_TYPE)
        rsaKey = (RsaKey*)key;
    else if (keyType == DSA_TYPE)
        dsaKey = (DsaKey*)key;
    else if (keyType == ECC_TYPE)
        eccKey = (ecc_key*)key;
    else if (keyType == ED25519_TYPE)
        ed25519Key = (ed25519_key*)key;
    else if (keyType == ED448_TYPE)
        ed448Key = (ed448_key*)key;
    else if (keyType == FALCON_LEVEL1_TYPE)
        falconKey = (falcon_key*)key;
    else if (keyType == FALCON_LEVEL5_TYPE)
        falconKey = (falcon_key*)key;

    return MakeAnyCert(cert, derBuffer, derSz, rsaKey, eccKey, rng, dsaKey,
                       ed25519Key, ed448Key, falconKey);
}

/* Make an x509 Certificate v3 RSA or ECC from cert input, write to buffer */
int wc_MakeCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* rsaKey,
             ecc_key* eccKey, WC_RNG* rng)
{
    return MakeAnyCert(cert, derBuffer, derSz, rsaKey, eccKey, rng, NULL, NULL,
                       NULL, NULL);
}

#ifdef WOLFSSL_CERT_REQ

#ifndef WOLFSSL_ASN_TEMPLATE
static int SetReqAttrib(byte* output, char* pw, int pwPrintableString,
                        int extSz)
{
    int sz      = 0; /* overall size */
    int cpSz    = 0; /* Challenge Password section size */
    int cpSeqSz = 0;
    int cpSetSz = 0;
    int cpStrSz = 0;
    int pwSz    = 0;
    int erSz    = 0; /* Extension Request section size */
    int erSeqSz = 0;
    int erSetSz = 0;
    byte cpSeq[MAX_SEQ_SZ];
    byte cpSet[MAX_SET_SZ];
    byte cpStr[MAX_PRSTR_SZ];
    byte erSeq[MAX_SEQ_SZ];
    byte erSet[MAX_SET_SZ];

    output[0] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
    sz++;

    if (pw && pw[0]) {
        int cpOidSz = SetObjectId(sizeof(attrChallengePasswordOid), NULL);
        cpOidSz += sizeof(attrChallengePasswordOid);
        pwSz = (int)XSTRLEN(pw);
        if (pwPrintableString) {
            cpStrSz = SetPrintableString(pwSz, cpStr);
        } else {
            cpStrSz = SetUTF8String(pwSz, cpStr);
        }
        cpSetSz = SetSet(cpStrSz + pwSz, cpSet);
        /* +2 for tag and length parts of the TLV triplet */
        cpSeqSz = SetSequence(cpOidSz + cpSetSz +
                cpStrSz + pwSz, cpSeq);
        cpSz = cpSeqSz + cpOidSz + cpSetSz +
                cpStrSz + pwSz;
    }

    if (extSz) {
        int erOidSz = SetObjectId(sizeof(attrExtensionRequestOid), NULL);
        erOidSz += sizeof(attrExtensionRequestOid);
        erSetSz = SetSet(extSz, erSet);
        erSeqSz = SetSequence(erSetSz + erOidSz + extSz, erSeq);
        erSz = extSz + erSetSz + erSeqSz + erOidSz;
    }

    /* Put the pieces together. */
    sz += SetLength(cpSz + erSz, &output[sz]);

    if (cpSz) {
        XMEMCPY(&output[sz], cpSeq, cpSeqSz);
        sz += cpSeqSz;
        sz += SetObjectId(sizeof(attrChallengePasswordOid), output + sz);
        XMEMCPY(&output[sz], attrChallengePasswordOid,
                sizeof(attrChallengePasswordOid));
        sz += sizeof(attrChallengePasswordOid);
        XMEMCPY(&output[sz], cpSet, cpSetSz);
        sz += cpSetSz;
        XMEMCPY(&output[sz], cpStr, cpStrSz);
        sz += cpStrSz;
        XMEMCPY(&output[sz], pw, pwSz);
        sz += pwSz;
    }

    if (erSz) {
        XMEMCPY(&output[sz], erSeq, erSeqSz);
        sz += erSeqSz;
        sz += SetObjectId(sizeof(attrExtensionRequestOid), output + sz);
        XMEMCPY(&output[sz], attrExtensionRequestOid,
                sizeof(attrExtensionRequestOid));
        sz += sizeof(attrExtensionRequestOid);
        XMEMCPY(&output[sz], erSet, erSetSz);
        sz += erSetSz;
        /* The actual extension data will be tacked onto the output later. */
    }

    return sz;
}

#ifdef WOLFSSL_CUSTOM_OID
/* encode a custom oid and value */
static int SetCustomObjectId(Cert* cert, byte* output, word32 outSz,
    CertOidField* custom)
{
    int idx = 0, cust_lenSz, cust_oidSz;

    if (cert == NULL || output == NULL || custom == NULL) {
        return BAD_FUNC_ARG;
    }
    if (custom->oid == NULL || custom->oidSz <= 0) {
        return 0; /* none set */
    }

    /* Octet String header */
    cust_lenSz = SetOctetString(custom->valSz, NULL);
    cust_oidSz = SetObjectId(custom->oidSz, NULL);

    /* check for output buffer room */
    if ((word32)(custom->valSz + custom->oidSz + cust_lenSz + cust_oidSz) >
                                                                        outSz) {
        return BUFFER_E;
    }

    /* put sequence with total */
    idx = SetSequence(custom->valSz + custom->oidSz + cust_lenSz + cust_oidSz,
                      output);

    /* put oid header */
    idx += SetObjectId(custom->oidSz, output+idx);
    XMEMCPY(output+idx, custom->oid, custom->oidSz);
    idx += custom->oidSz;

    /* put value */
    idx += SetOctetString(custom->valSz, output+idx);
    XMEMCPY(output+idx, custom->val, custom->valSz);
    idx += custom->valSz;

    return idx;
}
#endif /* WOLFSSL_CUSTOM_OID */


/* encode info from cert into DER encoded format */
static int EncodeCertReq(Cert* cert, DerCert* der, RsaKey* rsaKey,
                         DsaKey* dsaKey, ecc_key* eccKey,
                         ed25519_key* ed25519Key, ed448_key* ed448Key,
                         falcon_key* falconKey)
{
    int ret;

    (void)eccKey;
    (void)ed25519Key;
    (void)ed448Key;
    (void)falconKey;

    if (cert == NULL || der == NULL)
        return BAD_FUNC_ARG;

    if (rsaKey == NULL && eccKey == NULL && ed25519Key == NULL &&
        dsaKey == NULL && ed448Key == NULL && falconKey == NULL) {
        return PUBLIC_KEY_E;
    }

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion(cert->version, der->version, FALSE);

    /* subject name */
#if defined(WOLFSSL_CERT_EXT)
    if (XSTRLEN((const char*)cert->sbjRaw) > 0) {
        /* Use the raw subject */
        int idx;

        der->subjectSz = min(sizeof(der->subject),
                (word32)XSTRLEN((const char*)cert->sbjRaw));
        /* header */
        idx = SetSequence(der->subjectSz, der->subject);
        if (der->subjectSz + idx > (int)sizeof(der->subject)) {
            return SUBJECT_E;
        }

        XMEMCPY((char*)der->subject + idx, (const char*)cert->sbjRaw,
                der->subjectSz);
        der->subjectSz += idx;
    }
    else
#endif
    {
        der->subjectSz = SetNameEx(der->subject, sizeof(der->subject),
                &cert->subject, cert->heap);
    }
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* public key */
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
    }


    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey,
                                           sizeof(der->publicKey), 1);
    }



    if (der->publicKeySz <= 0)
        return PUBLIC_KEY_E;

    /* set the extensions */
    der->extensionsSz = 0;

    /* CA */
    if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_ALT_NAMES
    /* Alternative Name */
    if (cert->altNamesSz) {
        der->altNamesSz = SetAltNames(der->altNames, sizeof(der->altNames),
                                      cert->altNames, cert->altNamesSz);
        if (der->altNamesSz <= 0)
            return ALT_NAME_E;

        der->extensionsSz += der->altNamesSz;
    }
    else
        der->altNamesSz = 0;
#endif

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)min(CTC_MAX_SKID_SIZE, sizeof(der->skid)))
            return SKID_E;

        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0) {
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;

    /* Extended Key Usage */
    if (cert->extKeyUsage != 0) {
        der->extKeyUsageSz = SetExtKeyUsage(cert, der->extKeyUsage,
                                sizeof(der->extKeyUsage), cert->extKeyUsage);
        if (der->extKeyUsageSz <= 0)
            return EXTKEYUSAGE_E;

        der->extensionsSz += der->extKeyUsageSz;
    }
    else
        der->extKeyUsageSz = 0;

#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_CUSTOM_OID
    /* encode a custom oid and value */
    /* zero returns, means none set */
    ret = SetCustomObjectId(cert, der->extCustom,
        sizeof(der->extCustom), &cert->extCustom);
    if (ret < 0)
        return ret;
    der->extCustomSz = ret;
    der->extensionsSz += der->extCustomSz;
#endif

    /* put extensions */
    if (der->extensionsSz > 0) {
        /* put the start of sequence (ID, Size) */
        der->extensionsSz = SetSequence(der->extensionsSz, der->extensions);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_ALT_NAMES
        /* put Alternative Names */
        if (der->altNamesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->altNames, der->altNamesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put ExtendedKeyUsage */
        if (der->extKeyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extKeyUsage, der->extKeyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

    #ifdef WOLFSSL_CUSTOM_OID
        if (der->extCustomSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extCustom, der->extCustomSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
    #endif
#endif /* WOLFSSL_CERT_EXT */
    }

    der->attribSz = SetReqAttrib(der->attrib, cert->challengePw,
                                 cert->challengePwPrintableString,
                                 der->extensionsSz);
    if (der->attribSz <= 0)
        return REQ_ATTRIBUTE_E;

    der->total = der->versionSz + der->subjectSz + der->publicKeySz +
        der->extensionsSz + der->attribSz;

    return 0;
}


/* write DER encoded cert req to buffer, size already checked */
static int WriteCertReqBody(DerCert* der, byte* buf)
{
    int idx;

    /* signed part header */
    idx = SetSequence(der->total, buf);
    /* version */
    if (buf)
        XMEMCPY(buf + idx, der->version, der->versionSz);
    idx += der->versionSz;
    /* subject */
    if (buf)
        XMEMCPY(buf + idx, der->subject, der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    if (buf)
        XMEMCPY(buf + idx, der->publicKey, der->publicKeySz);
    idx += der->publicKeySz;
    /* attributes */
    if (buf)
        XMEMCPY(buf + idx, der->attrib, der->attribSz);
    idx += der->attribSz;
    /* extensions */
    if (der->extensionsSz) {
        if (buf)
            XMEMCPY(buf + idx, der->extensions, min(der->extensionsSz,
                                               (int)sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}
#endif

#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for Certificate Request body.
 * PKCS #10: RFC 2986, 4.1 - CertificationRequestInfo
 */
static const ASNItem certReqBodyASN[] = {
/* SEQ             */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                             /* version */
/* VER             */     { 1, ASN_INTEGER, 0, 0, 0 },
                                             /* subject */
/* SUBJ_SEQ        */     { 1, ASN_SEQUENCE, 1, 0, 0 },
                                             /* subjectPKInfo */
/* SPUBKEYINFO_SEQ */     { 1, ASN_SEQUENCE, 1, 0, 0 },
                                             /*  attributes*/
/* ATTRS           */     { 1, ASN_CONTEXT_SPECIFIC | 0, 1, 1, 1 },
                                                 /* Challenge Password Attribute */
/* ATTRS_CPW_SEQ   */         { 2, ASN_SEQUENCE, 1, 1, 1 },
/* ATTRS_CPW_OID   */             { 3, ASN_OBJECT_ID, 0, 0, 0 },
/* ATTRS_CPW_SET   */             { 3, ASN_SET, 1, 1, 0 },
/* ATTRS_CPW_PS    */                 { 4, ASN_PRINTABLE_STRING, 0, 0, 0 },
/* ATTRS_CPW_UTF   */                 { 4, ASN_UTF8STRING, 0, 0, 0 },
                                                 /* Extensions Attribute */
/* EXT_SEQ         */         { 2, ASN_SEQUENCE, 1, 1, 1 },
/* EXT_OID         */             { 3, ASN_OBJECT_ID, 0, 0, 0 },
/* EXT_SET         */             { 3, ASN_SET, 1, 1, 0 },
/* EXT_BODY        */                 { 4, ASN_SEQUENCE, 1, 0, 0 },
};
enum {
    CERTREQBODYASN_IDX_SEQ = 0,
    CERTREQBODYASN_IDX_VER,
    CERTREQBODYASN_IDX_SUBJ_SEQ,
    CERTREQBODYASN_IDX_SPUBKEYINFO_SEQ,
    CERTREQBODYASN_IDX_ATTRS,
    CERTREQBODYASN_IDX_ATTRS_CPW_SEQ,
    CERTREQBODYASN_IDX_ATTRS_CPW_OID,
    CERTREQBODYASN_IDX_ATTRS_CPW_SET,
    CERTREQBODYASN_IDX_ATTRS_CPW_PS,
    CERTREQBODYASN_IDX_ATTRS_CPW_UTF,
    CERTREQBODYASN_IDX_EXT_SEQ,
    CERTREQBODYASN_IDX_EXT_OID,
    CERTREQBODYASN_IDX_EXT_SET,
    CERTREQBODYASN_IDX_EXT_BODY,
};

/* Number of items in ASN.1 template for Certificate Request body. */
#define certReqBodyASN_Length (sizeof(certReqBodyASN) / sizeof(ASNItem))
#endif

static int MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
                   RsaKey* rsaKey, DsaKey* dsaKey, ecc_key* eccKey,
                   ed25519_key* ed25519Key, ed448_key* ed448Key,
                   falcon_key* falconKey)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    DerCert der[1];

    if (eccKey)
        cert->keyType = ECC_KEY;
    else if (rsaKey)
        cert->keyType = RSA_KEY;
    else if (dsaKey)
        cert->keyType = DSA_KEY;
    else if (ed25519Key)
        cert->keyType = ED25519_KEY;
    else if (ed448Key)
        cert->keyType = ED448_KEY;
    else
        return BAD_FUNC_ARG;


    ret = EncodeCertReq(cert, der, rsaKey, dsaKey, eccKey, ed25519Key, ed448Key,
                        falconKey);

    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertReqBody(der, derBuffer);
    }


    return ret;
#else
    DECL_ASNSETDATA(dataASN, certReqBodyASN_Length);
    word32 publicKeySz;
    word32 subjectSz = 0;
    word32 extSz;
    int sz = 0;
    int ret = 0;
#if defined(WOLFSSL_CERT_EXT)
    word32 sbjRawSz;
#endif

    (void)falconKey; /* Unused without OQS */
    CALLOC_ASNSETDATA(dataASN, certReqBodyASN_Length, ret, cert->heap);

    if (ret == 0) {
        /* Set key type into certificate object based on key passed in. */
        if (rsaKey != NULL) {
            cert->keyType = RSA_KEY;
        }
        else if (eccKey != NULL) {
            cert->keyType = ECC_KEY;
        }
        else if (dsaKey != NULL) {
            cert->keyType = DSA_KEY;
        }
        else if (ed25519Key != NULL) {
            cert->keyType = ED25519_KEY;
        }
        else if (ed448Key != NULL) {
            cert->keyType = ED448_KEY;
        }
        else if (falconKey != NULL) {
        }
        else {
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        /* Determine subject name size. */
    #if defined(WOLFSSL_CERT_EXT)
        sbjRawSz = (word32)XSTRLEN((const char*)cert->sbjRaw);
        if (sbjRawSz > 0) {
            subjectSz = min(sizeof(cert->sbjRaw), sbjRawSz);
        }
        else
    #endif
        {
            subjectSz = SetNameEx(NULL, WC_ASN_NAME_MAX, &cert->subject, cert->heap);
            ret = subjectSz;
        }
    }
    if (ret >= 0) {
        /* Determine encode public key size. */
         ret = publicKeySz = EncodePublicKey(cert->keyType, NULL, 0, rsaKey,
             eccKey, ed25519Key, ed448Key, dsaKey);
    }
    if (ret >= 0) {
        /* Determine encode extensions size. */
        ret = extSz = EncodeExtensions(cert, NULL, 0, 1);
    }
    if (ret >= 0) {
        /* Set version. */
        SetASN_Int8Bit(&dataASN[CERTREQBODYASN_IDX_VER], cert->version);
    #if defined(WOLFSSL_CERT_EXT)
        if (sbjRawSz > 0) {
            /* Put in encoded subject name. */
            SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_SUBJ_SEQ], cert->sbjRaw,
                    subjectSz);
        }
        else
    #endif
        {
            /* Leave space for subject name. */
            SetASN_ReplaceBuffer(&dataASN[CERTREQBODYASN_IDX_SUBJ_SEQ], NULL,
                    subjectSz);
        }
        /* Leave space for public key. */
        SetASN_ReplaceBuffer(&dataASN[CERTREQBODYASN_IDX_SPUBKEYINFO_SEQ],
                NULL, publicKeySz);
        if (cert->challengePw[0] != '\0') {
            /* Add challenge password attribute. */
            /* Set challenge password OID. */
            SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_ATTRS_CPW_OID], attrChallengePasswordOid,
                sizeof(attrChallengePasswordOid));
            /* Enable the ASN template item with the appropriate tag. */
            if (cert->challengePwPrintableString) {
                /* PRINTABLE_STRING - set buffer */
                SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_ATTRS_CPW_PS],
                        (byte*)cert->challengePw,
                        (word32)XSTRLEN(cert->challengePw));
                /* UTF8STRING - don't encode */
                dataASN[CERTREQBODYASN_IDX_ATTRS_CPW_UTF].noOut = 1;
            }
            else {
                /* PRINTABLE_STRING - don't encode */
                dataASN[CERTREQBODYASN_IDX_ATTRS_CPW_PS].noOut = 1;
                /* UTF8STRING - set buffer */
                SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_ATTRS_CPW_UTF],
                        (byte*)cert->challengePw,
                        (word32)XSTRLEN(cert->challengePw));
            }
        }
        else {
            /* Leave out challenge password attribute items. */
            SetASNItem_NoOutNode(dataASN, certReqBodyASN,
                    CERTREQBODYASN_IDX_ATTRS_CPW_SEQ, certReqBodyASN_Length);
        }
        if (extSz > 0) {
            /* Set extension attribute OID. */
            SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_EXT_OID], attrExtensionRequestOid,
                sizeof(attrExtensionRequestOid));
            /* Leave space for data. */
            SetASN_Buffer(&dataASN[CERTREQBODYASN_IDX_EXT_BODY], NULL, extSz);
        }
        else {
            /* Leave out extension attribute items. */
            SetASNItem_NoOutNode(dataASN, certReqBodyASN,
                    CERTREQBODYASN_IDX_EXT_SEQ, certReqBodyASN_Length);
        }

        /* Calculate size of encoded certificate request body. */
        ret = SizeASN_Items(certReqBodyASN, dataASN, certReqBodyASN_Length,
                            &sz);
    }
    /* Check buffer is big enough for encoded data. */
    if ((ret == 0) && (sz > (int)derSz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode certificate request body into buffer. */
        SetASN_Items(certReqBodyASN, dataASN, certReqBodyASN_Length, derBuffer);

        /* Put in generated data */
    #if defined(WOLFSSL_CERT_EXT)
        if (sbjRawSz == 0)
    #endif
        {
            /* Encode subject name into space in buffer. */
            ret = SetNameEx(
                (byte*)dataASN[CERTREQBODYASN_IDX_SUBJ_SEQ].data.buffer.data,
                dataASN[CERTREQBODYASN_IDX_SUBJ_SEQ].data.buffer.length,
                &cert->subject, cert->heap);
        }
    }
    if (ret >= 0) {
        /* Encode public key into space in buffer. */
        ret = EncodePublicKey(cert->keyType,
            (byte*)dataASN[CERTREQBODYASN_IDX_SPUBKEYINFO_SEQ].data.buffer.data,
            dataASN[CERTREQBODYASN_IDX_SPUBKEYINFO_SEQ].data.buffer.length,
            rsaKey, eccKey, ed25519Key, ed448Key, dsaKey);
    }
    if ((ret >= 0) && (!dataASN[CERTREQBODYASN_IDX_EXT_BODY].noOut)) {
        /* Encode extensions into space in buffer. */
        ret = EncodeExtensions(cert,
                (byte*)dataASN[CERTREQBODYASN_IDX_EXT_BODY].data.buffer.data,
                dataASN[CERTREQBODYASN_IDX_EXT_BODY].data.buffer.length, 1);
    }
    if (ret >= 0) {
        /* Store encoded certifcate request body size. */
        cert->bodySz = sz;
        /* Return the encoding size. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, cert->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

int wc_MakeCertReq_ex(Cert* cert, byte* derBuffer, word32 derSz, int keyType,
                      void* key)
{
    RsaKey*      rsaKey = NULL;
    DsaKey*      dsaKey = NULL;
    ecc_key*     eccKey = NULL;
    ed25519_key* ed25519Key = NULL;
    ed448_key*   ed448Key = NULL;
    falcon_key* falconKey = NULL;

    if (keyType == RSA_TYPE)
        rsaKey = (RsaKey*)key;
    else if (keyType == DSA_TYPE)
        dsaKey = (DsaKey*)key;
    else if (keyType == ECC_TYPE)
        eccKey = (ecc_key*)key;
    else if (keyType == ED25519_TYPE)
        ed25519Key = (ed25519_key*)key;
    else if (keyType == ED448_TYPE)
        ed448Key = (ed448_key*)key;
    else if (keyType == FALCON_LEVEL1_TYPE)
        falconKey = (falcon_key*)key;
    else if (keyType == FALCON_LEVEL5_TYPE)
        falconKey = (falcon_key*)key;

    return MakeCertReq(cert, derBuffer, derSz, rsaKey, dsaKey, eccKey,
                       ed25519Key, ed448Key, falconKey);
}

int wc_MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
                   RsaKey* rsaKey, ecc_key* eccKey)
{
    return MakeCertReq(cert, derBuffer, derSz, rsaKey, NULL, eccKey, NULL,
                       NULL, NULL);
}
#endif /* WOLFSSL_CERT_REQ */


static int SignCert(int requestSz, int sType, byte* buf, word32 buffSz,
                    RsaKey* rsaKey, ecc_key* eccKey, ed25519_key* ed25519Key,
                    ed448_key* ed448Key, falcon_key* falconKey, WC_RNG* rng)
{
    int sigSz = 0;
    void* heap = NULL;
    CertSignCtx* certSignCtx;
    CertSignCtx  certSignCtx_lcl;

    certSignCtx = &certSignCtx_lcl;
    XMEMSET(certSignCtx, 0, sizeof(CertSignCtx));

    if (requestSz < 0)
        return requestSz;

    /* locate ctx */
    if (rsaKey) {
        heap = rsaKey->heap;
    }
    else if (eccKey) {
        heap = eccKey->heap;
    }


    if (certSignCtx->sig == NULL) {
        certSignCtx->sig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (certSignCtx->sig == NULL)
            return MEMORY_E;
    }

    sigSz = MakeSignature(certSignCtx, buf, requestSz, certSignCtx->sig,
        MAX_ENCODED_SIG_SZ, rsaKey, eccKey, ed25519Key, ed448Key,
        falconKey, rng, sType, heap);

    if (sigSz >= 0) {
        if (requestSz + MAX_SEQ_SZ * 2 + sigSz > (int)buffSz)
            sigSz = BUFFER_E;
        else
            sigSz = AddSignature(buf, requestSz, certSignCtx->sig, sigSz,
                                 sType);
    }

    XFREE(certSignCtx->sig, heap, DYNAMIC_TYPE_TMP_BUFFER);
    certSignCtx->sig = NULL;

    return sigSz;
}

int wc_SignCert_ex(int requestSz, int sType, byte* buf, word32 buffSz,
                   int keyType, void* key, WC_RNG* rng)
{
    RsaKey*            rsaKey = NULL;
    ecc_key*           eccKey = NULL;
    ed25519_key*       ed25519Key = NULL;
    ed448_key*         ed448Key = NULL;
    falcon_key*        falconKey = NULL;

    if (keyType == RSA_TYPE)
        rsaKey = (RsaKey*)key;
    else if (keyType == ECC_TYPE)
        eccKey = (ecc_key*)key;
    else if (keyType == ED25519_TYPE)
        ed25519Key = (ed25519_key*)key;
    else if (keyType == ED448_TYPE)
        ed448Key = (ed448_key*)key;
    else if (keyType == FALCON_LEVEL1_TYPE)
        falconKey = (falcon_key*)key;
    else if (keyType == FALCON_LEVEL5_TYPE)
        falconKey = (falcon_key*)key;


    return SignCert(requestSz, sType, buf, buffSz, rsaKey, eccKey, ed25519Key,
                    ed448Key, falconKey, rng);
}

int wc_SignCert(int requestSz, int sType, byte* buf, word32 buffSz,
                RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng)
{
    return SignCert(requestSz, sType, buf, buffSz, rsaKey, eccKey, NULL, NULL,
                    NULL, rng);
}

int wc_MakeSelfCert(Cert* cert, byte* buf, word32 buffSz,
                    RsaKey* key, WC_RNG* rng)
{
    int ret;

    ret = wc_MakeCert(cert, buf, buffSz, key, NULL, rng);
    if (ret < 0)
        return ret;

    return wc_SignCert(cert->bodySz, cert->sigType,
                       buf, buffSz, key, NULL, rng);
}


#ifdef WOLFSSL_CERT_EXT

/* Get raw subject from cert, which may contain OIDs not parsed by Decode.
   The raw subject pointer will only be valid while "cert" is valid. */
int wc_GetSubjectRaw(byte **subjectRaw, Cert *cert)
{
    int rc = BAD_FUNC_ARG;
    if ((subjectRaw != NULL) && (cert != NULL)) {
        *subjectRaw = cert->sbjRaw;
        rc = 0;
    }
    return rc;
}

/* Set KID from public key */
static int SetKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey,
                                 ed25519_key* ed25519Key, ed448_key* ed448Key,
                                 falcon_key* falconKey, int kid_type)
{
    byte *buf;
    int   bufferSz, ret;

    if (cert == NULL ||
        (rsakey == NULL && eckey == NULL && ed25519Key == NULL &&
         ed448Key == NULL && falconKey == NULL) ||
        (kid_type != SKID_TYPE && kid_type != AKID_TYPE))
        return BAD_FUNC_ARG;

    buf = (byte *)XMALLOC(MAX_PUBLIC_KEY_SZ, cert->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return MEMORY_E;

    /* Public Key */
    bufferSz = -1;
    /* RSA public key */
    if (rsakey != NULL)
        bufferSz = SetRsaPublicKey(buf, rsakey, MAX_PUBLIC_KEY_SZ, 0);
    /* ECC public key */
    if (eckey != NULL)
        bufferSz = SetEccPublicKey(buf, eckey, MAX_PUBLIC_KEY_SZ, 0);

    if (bufferSz <= 0) {
        XFREE(buf, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return PUBLIC_KEY_E;
    }

    /* Compute SKID by hashing public key */
    if (kid_type == SKID_TYPE) {
        ret = CalcHashId(buf, bufferSz, cert->skid);
        cert->skidSz = KEYID_SIZE;
    }
    else if (kid_type == AKID_TYPE) {
        ret = CalcHashId(buf, bufferSz, cert->akid);
        cert->akidSz = KEYID_SIZE;
    }
    else
        ret = BAD_FUNC_ARG;

    XFREE(buf, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wc_SetSubjectKeyIdFromPublicKey_ex(Cert *cert, int keyType, void* key)
{
    RsaKey*            rsaKey = NULL;
    ecc_key*           eccKey = NULL;
    ed25519_key*       ed25519Key = NULL;
    ed448_key*         ed448Key = NULL;
    falcon_key*        falconKey = NULL;

    if (keyType == RSA_TYPE)
        rsaKey = (RsaKey*)key;
    else if (keyType == ECC_TYPE)
        eccKey = (ecc_key*)key;
    else if (keyType == ED25519_TYPE)
        ed25519Key = (ed25519_key*)key;
    else if (keyType == ED448_TYPE)
        ed448Key = (ed448_key*)key;
    else if (keyType == FALCON_LEVEL1_TYPE)
        falconKey = (falcon_key*)key;
    else if (keyType == FALCON_LEVEL5_TYPE)
        falconKey = (falcon_key*)key;

    return SetKeyIdFromPublicKey(cert, rsaKey, eccKey, ed25519Key, ed448Key,
                                 falconKey, SKID_TYPE);
}

/* Set SKID from RSA or ECC public key */
int wc_SetSubjectKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey)
{
    return SetKeyIdFromPublicKey(cert, rsakey, eckey, NULL, NULL, NULL,
                                 SKID_TYPE);
}

int wc_SetAuthKeyIdFromPublicKey_ex(Cert *cert, int keyType, void* key)
{
    RsaKey*            rsaKey = NULL;
    ecc_key*           eccKey = NULL;
    ed25519_key*       ed25519Key = NULL;
    ed448_key*         ed448Key = NULL;
    falcon_key*        falconKey = NULL;

    if (keyType == RSA_TYPE)
        rsaKey = (RsaKey*)key;
    else if (keyType == ECC_TYPE)
        eccKey = (ecc_key*)key;
    else if (keyType == ED25519_TYPE)
        ed25519Key = (ed25519_key*)key;
    else if (keyType == ED448_TYPE)
        ed448Key = (ed448_key*)key;
    else if (keyType == FALCON_LEVEL1_TYPE)
        falconKey = (falcon_key*)key;

    return SetKeyIdFromPublicKey(cert, rsaKey, eccKey, ed25519Key, ed448Key,
                                 falconKey, AKID_TYPE);
}

/* Set SKID from RSA or ECC public key */
int wc_SetAuthKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey)
{
    return SetKeyIdFromPublicKey(cert, rsakey, eckey, NULL, NULL, NULL,
                                 AKID_TYPE);
}


#if !defined(NO_FILESYSTEM) && !defined(NO_ASN_CRYPT)

/* Set SKID from public key file in PEM */
int wc_SetSubjectKeyId(Cert *cert, const char* file)
{
    int     ret, derSz;
    byte*   der;
    word32  idx;
    RsaKey  *rsakey = NULL;
    ecc_key *eckey = NULL;

    if (cert == NULL || file == NULL)
        return BAD_FUNC_ARG;

    der = (byte*)XMALLOC(MAX_PUBLIC_KEY_SZ, cert->heap, DYNAMIC_TYPE_CERT);
    if (der == NULL) {
        WOLFSSL_MSG("wc_SetSubjectKeyId memory Problem");
        return MEMORY_E;
    }
    derSz = MAX_PUBLIC_KEY_SZ;

    XMEMSET(der, 0, derSz);
    derSz = wc_PemPubKeyToDer(file, der, derSz);
    if (derSz <= 0) {
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return derSz;
    }

    /* Load PubKey in internal structure */
    rsakey = (RsaKey*) XMALLOC(sizeof(RsaKey), cert->heap, DYNAMIC_TYPE_RSA);
    if (rsakey == NULL) {
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return MEMORY_E;
    }

    if (wc_InitRsaKey(rsakey, cert->heap) != 0) {
        WOLFSSL_MSG("wc_InitRsaKey failure");
        XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return MEMORY_E;
    }

    idx = 0;
    ret = wc_RsaPublicKeyDecode(der, &idx, rsakey, derSz);
    if (ret != 0)
    {
        WOLFSSL_MSG("wc_RsaPublicKeyDecode failed");
        wc_FreeRsaKey(rsakey);
        XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
        rsakey = NULL;
        /* Check to load ecc public key */
        eckey = (ecc_key*) XMALLOC(sizeof(ecc_key), cert->heap,
                                                              DYNAMIC_TYPE_ECC);
        if (eckey == NULL) {
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            return MEMORY_E;
        }

        if (wc_ecc_init(eckey) != 0) {
            WOLFSSL_MSG("wc_ecc_init failure");
            wc_ecc_free(eckey);
            XFREE(eckey, cert->heap, DYNAMIC_TYPE_ECC);
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            return MEMORY_E;
        }

        idx = 0;
        ret = wc_EccPublicKeyDecode(der, &idx, eckey, derSz);
        if (ret != 0) {
            WOLFSSL_MSG("wc_EccPublicKeyDecode failed");
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            wc_ecc_free(eckey);
            XFREE(eckey, cert->heap, DYNAMIC_TYPE_ECC);
            return PUBLIC_KEY_E;
        }
    }

    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    ret = wc_SetSubjectKeyIdFromPublicKey(cert, rsakey, eckey);

    wc_FreeRsaKey(rsakey);
    XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
    wc_ecc_free(eckey);
    XFREE(eckey, cert->heap, DYNAMIC_TYPE_ECC);
    return ret;
}

#endif /* !NO_FILESYSTEM && !NO_ASN_CRYPT */

static int SetAuthKeyIdFromDcert(Cert* cert, DecodedCert* decoded)
{
    int ret = 0;

    /* Subject Key Id not found !! */
    if (decoded->extSubjKeyIdSet == 0) {
        ret = ASN_NO_SKID;
    }

    /* SKID invalid size */
    else if (sizeof(cert->akid) < sizeof(decoded->extSubjKeyId)) {
        ret = MEMORY_E;
    }

    else {
        /* Put the SKID of CA to AKID of certificate */
        XMEMCPY(cert->akid, decoded->extSubjKeyId, KEYID_SIZE);
        cert->akidSz = KEYID_SIZE;
    }

    return ret;
}

/* Set AKID from certificate contains in buffer (DER encoded) */
int wc_SetAuthKeyIdFromCert(Cert *cert, const byte *der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            ret = SetAuthKeyIdFromDcert(cert, (DecodedCert*)cert->decodedCert);
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }

    return ret;
}


#ifndef NO_FILESYSTEM

/* Set AKID from certificate file in PEM */
int wc_SetAuthKeyId(Cert *cert, const char* file)
{
    int         ret;
    DerBuffer*  der = NULL;

    if (cert == NULL || file == NULL)
        return BAD_FUNC_ARG;

    ret = wc_PemCertToDer_ex(file, &der);
    if (ret == 0)
    {
        ret = wc_SetAuthKeyIdFromCert(cert, der->buffer, der->length);
        FreeDer(&der);
    }

    return ret;
}

#endif /* !NO_FILESYSTEM */

/* Set KeyUsage from human readable string */
int wc_SetKeyUsage(Cert *cert, const char *value)
{
    int ret = 0;
    char *token, *str, *ptr;
    word32 len;

    if (cert == NULL || value == NULL)
        return BAD_FUNC_ARG;

    cert->keyUsage = 0;

    /* duplicate string (including terminator) */
    len = (word32)XSTRLEN(value);
    str = (char*)XMALLOC(len+1, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL)
        return MEMORY_E;
    XMEMCPY(str, value, len+1);

    /* parse value, and set corresponding Key Usage value */
    if ((token = XSTRTOK(str, ",", &ptr)) == NULL) {
        XFREE(str, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return KEYUSAGE_E;
    }
    while (token != NULL)
    {
        if (!XSTRCASECMP(token, "digitalSignature"))
            cert->keyUsage |= KEYUSE_DIGITAL_SIG;
        else if (!XSTRCASECMP(token, "nonRepudiation") ||
                 !XSTRCASECMP(token, "contentCommitment"))
            cert->keyUsage |= KEYUSE_CONTENT_COMMIT;
        else if (!XSTRCASECMP(token, "keyEncipherment"))
            cert->keyUsage |= KEYUSE_KEY_ENCIPHER;
        else if (!XSTRCASECMP(token, "dataEncipherment"))
            cert->keyUsage |= KEYUSE_DATA_ENCIPHER;
        else if (!XSTRCASECMP(token, "keyAgreement"))
            cert->keyUsage |= KEYUSE_KEY_AGREE;
        else if (!XSTRCASECMP(token, "keyCertSign"))
            cert->keyUsage |= KEYUSE_KEY_CERT_SIGN;
        else if (!XSTRCASECMP(token, "cRLSign"))
            cert->keyUsage |= KEYUSE_CRL_SIGN;
        else if (!XSTRCASECMP(token, "encipherOnly"))
            cert->keyUsage |= KEYUSE_ENCIPHER_ONLY;
        else if (!XSTRCASECMP(token, "decipherOnly"))
            cert->keyUsage |= KEYUSE_DECIPHER_ONLY;
        else {
            ret = KEYUSAGE_E;
            break;
        }

        token = XSTRTOK(NULL, ",", &ptr);
    }

    XFREE(str, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Set ExtendedKeyUsage from human readable string */
int wc_SetExtKeyUsage(Cert *cert, const char *value)
{
    int ret = 0;
    char *token, *str, *ptr;
    word32 len;

    if (cert == NULL || value == NULL)
        return BAD_FUNC_ARG;

    cert->extKeyUsage = 0;

    /* duplicate string (including terminator) */
    len = (word32)XSTRLEN(value);
    str = (char*)XMALLOC(len+1, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL)
        return MEMORY_E;
    XMEMCPY(str, value, len+1);

    /* parse value, and set corresponding Key Usage value */
    if ((token = XSTRTOK(str, ",", &ptr)) == NULL) {
        XFREE(str, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return EXTKEYUSAGE_E;
    }

    while (token != NULL)
    {
        if (!XSTRCASECMP(token, "any"))
            cert->extKeyUsage |= EXTKEYUSE_ANY;
        else if (!XSTRCASECMP(token, "serverAuth"))
            cert->extKeyUsage |= EXTKEYUSE_SERVER_AUTH;
        else if (!XSTRCASECMP(token, "clientAuth"))
            cert->extKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
        else if (!XSTRCASECMP(token, "codeSigning"))
            cert->extKeyUsage |= EXTKEYUSE_CODESIGN;
        else if (!XSTRCASECMP(token, "emailProtection"))
            cert->extKeyUsage |= EXTKEYUSE_EMAILPROT;
        else if (!XSTRCASECMP(token, "timeStamping"))
            cert->extKeyUsage |= EXTKEYUSE_TIMESTAMP;
        else if (!XSTRCASECMP(token, "OCSPSigning"))
            cert->extKeyUsage |= EXTKEYUSE_OCSP_SIGN;
        else {
            ret = EXTKEYUSAGE_E;
            break;
        }

        token = XSTRTOK(NULL, ",", &ptr);
    }

    XFREE(str, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#ifdef WOLFSSL_EKU_OID
/*
 * cert structure to set EKU oid in
 * oid  the oid in byte representation
 * sz   size of oid buffer
 * idx  index of array to place oid
 *
 * returns 0 on success
 */
int wc_SetExtKeyUsageOID(Cert *cert, const char *in, word32 sz, byte idx,
        void* heap)
{
    byte oid[MAX_OID_SZ];
    word32 oidSz = MAX_OID_SZ;

    if (idx >= CTC_MAX_EKU_NB || sz >= CTC_MAX_EKU_OID_SZ) {
        WOLFSSL_MSG("Either idx or sz was too large");
        return BAD_FUNC_ARG;
    }

    if (EncodePolicyOID(oid, &oidSz, in, heap) != 0) {
        return BUFFER_E;
    }

    XMEMCPY(cert->extKeyUsageOID[idx], oid, oidSz);
    cert->extKeyUsageOIDSz[idx] = oidSz;
    cert->extKeyUsage |= EXTKEYUSE_USER;

    return 0;
}
#endif /* WOLFSSL_EKU_OID */

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CUSTOM_OID) && defined(HAVE_OID_ENCODING) && \
    defined(WOLFSSL_CERT_EXT)
int wc_SetCustomExtension(Cert *cert, int critical, const char *oid,
                          const byte *der, word32 derSz) {
    CertExtension *ext;
    byte encodedOid[MAX_OID_SZ];
    word32 encodedOidSz = MAX_OID_SZ;
    int ret;

    if (cert == NULL || oid == NULL || der == NULL || derSz == 0) {
        return BAD_FUNC_ARG;
    }

    if (cert->customCertExtCount >= NUM_CUSTOM_EXT) {
        return MEMORY_E;
    }

    /* Make sure we can properly parse the OID. */
    ret = EncodePolicyOID(encodedOid, &encodedOidSz, oid, NULL);
    if (ret != 0) {
        return ret;
    }

    ext = &cert->customCertExt[cert->customCertExtCount];

    ext->oid = oid;
    ext->crit = (critical == 0) ? 0 : 1;
    ext->val = der;
    ext->valSz = derSz;

    cert->customCertExtCount++;
    return 0;
}
#endif

#endif /* WOLFSSL_CERT_EXT */


#ifdef WOLFSSL_ALT_NAMES

static int SetAltNamesFromDcert(Cert* cert, DecodedCert* decoded)
{
    int ret = 0;

    cert->altNamesSz = 0;
    if (decoded->altNames) {
        ret = FlattenAltNames(cert->altNames,
            sizeof(cert->altNames), decoded->altNames);
        if (ret >= 0) {
            cert->altNamesSz = ret;
            ret = 0;
        }
    }

    return ret;
}

#ifndef NO_FILESYSTEM

/* Set Alt Names from der cert, return 0 on success */
static int SetAltNamesFromCert(Cert* cert, const byte* der, int derSz)
{
    int ret;
    DecodedCert decoded[1];

    if (derSz < 0)
        return derSz;


    InitDecodedCert(decoded, der, derSz, NULL);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else {
        ret = SetAltNamesFromDcert(cert, decoded);
    }

    FreeDecodedCert(decoded);

    return ret < 0 ? ret : 0;
}

#endif

static int SetDatesFromDcert(Cert* cert, DecodedCert* decoded)
{
    int ret = 0;

    if (decoded->beforeDate == NULL || decoded->afterDate == NULL) {
        WOLFSSL_MSG("Couldn't extract dates");
        ret = -1;
    }
    else if (decoded->beforeDateLen > MAX_DATE_SIZE ||
                                        decoded->afterDateLen > MAX_DATE_SIZE) {
        WOLFSSL_MSG("Bad date size");
        ret = -1;
    }
    else {
        XMEMCPY(cert->beforeDate, decoded->beforeDate, decoded->beforeDateLen);
        XMEMCPY(cert->afterDate,  decoded->afterDate,  decoded->afterDateLen);

        cert->beforeDateSz = decoded->beforeDateLen;
        cert->afterDateSz  = decoded->afterDateLen;
    }

    return ret;
}

#endif /* WOLFSSL_ALT_NAMES */

static void SetNameFromDcert(CertName* cn, DecodedCert* decoded)
{
    int sz;

    if (decoded->subjectCN) {
        sz = (decoded->subjectCNLen < CTC_NAME_SIZE) ? decoded->subjectCNLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->commonName, decoded->subjectCN, sz);
        cn->commonName[sz] = '\0';
        cn->commonNameEnc = decoded->subjectCNEnc;
    }
    if (decoded->subjectC) {
        sz = (decoded->subjectCLen < CTC_NAME_SIZE) ? decoded->subjectCLen
                                                    : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->country, decoded->subjectC, sz);
        cn->country[sz] = '\0';
        cn->countryEnc = decoded->subjectCEnc;
    }
    if (decoded->subjectST) {
        sz = (decoded->subjectSTLen < CTC_NAME_SIZE) ? decoded->subjectSTLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->state, decoded->subjectST, sz);
        cn->state[sz] = '\0';
        cn->stateEnc = decoded->subjectSTEnc;
    }
    if (decoded->subjectL) {
        sz = (decoded->subjectLLen < CTC_NAME_SIZE) ? decoded->subjectLLen
                                                    : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->locality, decoded->subjectL, sz);
        cn->locality[sz] = '\0';
        cn->localityEnc = decoded->subjectLEnc;
    }
    if (decoded->subjectO) {
        sz = (decoded->subjectOLen < CTC_NAME_SIZE) ? decoded->subjectOLen
                                                    : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->org, decoded->subjectO, sz);
        cn->org[sz] = '\0';
        cn->orgEnc = decoded->subjectOEnc;
    }
    if (decoded->subjectOU) {
        sz = (decoded->subjectOULen < CTC_NAME_SIZE) ? decoded->subjectOULen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->unit, decoded->subjectOU, sz);
        cn->unit[sz] = '\0';
        cn->unitEnc = decoded->subjectOUEnc;
    }
    if (decoded->subjectSN) {
        sz = (decoded->subjectSNLen < CTC_NAME_SIZE) ? decoded->subjectSNLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->sur, decoded->subjectSN, sz);
        cn->sur[sz] = '\0';
        cn->surEnc = decoded->subjectSNEnc;
    }
    if (decoded->subjectSND) {
        sz = (decoded->subjectSNDLen < CTC_NAME_SIZE) ? decoded->subjectSNDLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->serialDev, decoded->subjectSND, sz);
        cn->serialDev[sz] = '\0';
        cn->serialDevEnc = decoded->subjectSNDEnc;
    }
    if (decoded->subjectUID) {
        sz = (decoded->subjectUIDLen < CTC_NAME_SIZE) ? decoded->subjectUIDLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->userId, decoded->subjectUID, sz);
        cn->userId[sz] = '\0';
        cn->userIdEnc = decoded->subjectUIDEnc;
    }
#ifdef WOLFSSL_CERT_EXT
    if (decoded->subjectBC) {
        sz = (decoded->subjectBCLen < CTC_NAME_SIZE) ? decoded->subjectBCLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->busCat, decoded->subjectBC, sz);
        cn->busCat[sz] = '\0';
        cn->busCatEnc = decoded->subjectBCEnc;
    }
    if (decoded->subjectJC) {
        sz = (decoded->subjectJCLen < CTC_NAME_SIZE) ? decoded->subjectJCLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->joiC, decoded->subjectJC, sz);
        cn->joiC[sz] = '\0';
        cn->joiCEnc = decoded->subjectJCEnc;
    }
    if (decoded->subjectJS) {
        sz = (decoded->subjectJSLen < CTC_NAME_SIZE) ? decoded->subjectJSLen
                                                     : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->joiSt, decoded->subjectJS, sz);
        cn->joiSt[sz] = '\0';
        cn->joiStEnc = decoded->subjectJSEnc;
    }
#endif
    if (decoded->subjectEmail) {
        sz = (decoded->subjectEmailLen < CTC_NAME_SIZE)
           ?  decoded->subjectEmailLen : CTC_NAME_SIZE - 1;
        XSTRNCPY(cn->email, decoded->subjectEmail, sz);
        cn->email[sz] = '\0';
    }
}

#ifndef NO_FILESYSTEM

/* Set cn name from der buffer, return 0 on success */
static int SetNameFromCert(CertName* cn, const byte* der, int derSz)
{
    int ret;
    DecodedCert decoded[1];

    if (derSz < 0)
        return derSz;


    InitDecodedCert(decoded, der, derSz, NULL);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else {
        SetNameFromDcert(cn, decoded);
    }

    FreeDecodedCert(decoded);


    return ret < 0 ? ret : 0;
}

/* Set cert issuer from issuerFile in PEM */
int wc_SetIssuer(Cert* cert, const char* issuerFile)
{
    int         ret;
    DerBuffer*  der = NULL;

    if (cert == NULL || issuerFile == NULL)
        return BAD_FUNC_ARG;

    ret = wc_PemCertToDer_ex(issuerFile, &der);
    if (ret == 0) {
        cert->selfSigned = 0;
        ret = SetNameFromCert(&cert->issuer, der->buffer, der->length);

        FreeDer(&der);
    }

    return ret;
}


/* Set cert subject from subjectFile in PEM */
int wc_SetSubject(Cert* cert, const char* subjectFile)
{
    int         ret;
    DerBuffer*  der = NULL;

    if (cert == NULL || subjectFile == NULL)
        return BAD_FUNC_ARG;

    ret = wc_PemCertToDer_ex(subjectFile, &der);
    if (ret == 0) {
        ret = SetNameFromCert(&cert->subject, der->buffer, der->length);

        FreeDer(&der);
    }

    return ret;
}

#ifdef WOLFSSL_ALT_NAMES

/* Set alt names from file in PEM */
int wc_SetAltNames(Cert* cert, const char* file)
{
    int         ret;
    DerBuffer*  der = NULL;

    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_PemCertToDer_ex(file, &der);
    if (ret == 0) {
        ret = SetAltNamesFromCert(cert, der->buffer, der->length);

        FreeDer(&der);
    }

    return ret;
}

#endif /* WOLFSSL_ALT_NAMES */

#endif /* !NO_FILESYSTEM */

/* Set cert issuer from DER buffer */
int wc_SetIssuerBuffer(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        cert->selfSigned = 0;

        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            SetNameFromDcert(&cert->issuer, (DecodedCert*)cert->decodedCert);
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }

    return ret;
}

/* Set cert subject from DER buffer */
int wc_SetSubjectBuffer(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            SetNameFromDcert(&cert->subject, (DecodedCert*)cert->decodedCert);
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }

    return ret;
}
#ifdef WOLFSSL_CERT_EXT
/* Set cert raw subject from DER buffer */
int wc_SetSubjectRaw(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            if ((((DecodedCert*)cert->decodedCert)->subjectRaw) &&
                (((DecodedCert*)cert->decodedCert)->subjectRawLen <=
                        (int)sizeof(CertName))) {
                XMEMCPY(cert->sbjRaw,
                        ((DecodedCert*)cert->decodedCert)->subjectRaw,
                        ((DecodedCert*)cert->decodedCert)->subjectRawLen);
            }
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }

    return ret;
}

/* Set cert raw issuer from DER buffer */
int wc_SetIssuerRaw(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            if ((((DecodedCert*)cert->decodedCert)->subjectRaw) &&
                (((DecodedCert*)cert->decodedCert)->subjectRawLen <=
                        (int)sizeof(CertName))) {
                /* Copy the subject to the issuer field */
                XMEMCPY(cert->issRaw,
                        ((DecodedCert*)cert->decodedCert)->subjectRaw,
                        ((DecodedCert*)cert->decodedCert)->subjectRawLen);
            }
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }
    return ret;
}
#endif

#ifdef WOLFSSL_ALT_NAMES

/* Set cert alt names from DER buffer */
int wc_SetAltNamesBuffer(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
       ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            ret = SetAltNamesFromDcert(cert, (DecodedCert*)cert->decodedCert);
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
       }
    }

    return(ret);
}

/* Set cert dates from DER buffer */
int wc_SetDatesBuffer(Cert* cert, const byte* der, int derSz)
{
    int ret = 0;

    if (cert == NULL) {
     ret = BAD_FUNC_ARG;
    }
    else {
        /* Check if decodedCert is cached */
        if (cert->der != der) {
            /* Allocate cache for the decoded cert */
            ret = wc_SetCert_LoadDer(cert, der, derSz);
        }

        if (ret >= 0) {
            ret = SetDatesFromDcert(cert, (DecodedCert*)cert->decodedCert);
#ifndef WOLFSSL_CERT_GEN_CACHE
            wc_SetCert_Free(cert);
#endif
        }
    }

    return(ret);
}

#endif /* WOLFSSL_ALT_NAMES */

#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
/* Encode OID string representation to ITU-T X.690 format */
int EncodePolicyOID(byte *out, word32 *outSz, const char *in, void* heap)
{
    word32 val, idx = 0, nb_val;
    char *token, *str, *ptr;
    word32 len;

    (void)heap;

    if (out == NULL || outSz == NULL || *outSz < 2 || in == NULL)
        return BAD_FUNC_ARG;

    /* duplicate string (including terminator) */
    len = (word32)XSTRLEN(in);
    str = (char *)XMALLOC(len+1, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL)
        return MEMORY_E;
    XMEMCPY(str, in, len+1);

    nb_val = 0;

    /* parse value, and set corresponding Policy OID value */
    token = XSTRTOK(str, ".", &ptr);
    while (token != NULL)
    {
        val = (word32)XATOI(token);

        if (nb_val == 0) {
            if (val > 2) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return ASN_OBJECT_ID_E;
            }

            out[idx] = (byte)(40 * val);
        }
        else if (nb_val == 1) {
            if (val > 127) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return ASN_OBJECT_ID_E;
            }

            if (idx > *outSz) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return BUFFER_E;
            }

            out[idx++] += (byte)val;
        }
        else {
            word32  tb = 0, x;
            int     i = 0;
            byte    oid[MAX_OID_SZ];

            while (val >= 128) {
                x = val % 128;
                val /= 128;
                oid[i++] = (byte) (((tb++) ? 0x80 : 0) | x);
            }

            if ((idx+(word32)i) >= *outSz) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return BUFFER_E;
            }

            oid[i] = (byte) (((tb++) ? 0x80 : 0) | val);

            /* push value in the right order */
            while (i >= 0)
                out[idx++] = oid[i--];
        }

        token = XSTRTOK(NULL, ".", &ptr);
        nb_val++;
    }

    *outSz = idx;

    XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
#endif /* WOLFSSL_CERT_EXT || OPENSSL_EXTRA */




#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for DSA signature.
 * RFC 5912, 6 - DSA-Sig-Value
 */
static const ASNItem dsaSigASN[] = {
/* SEQ */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                            /* r */
/* R   */     { 1, ASN_INTEGER, 0, 0, 0 },
                            /* s */
/* S   */     { 1, ASN_INTEGER, 0, 0, 0 },
};
enum {
    DSASIGASN_IDX_SEQ = 0,
    DSASIGASN_IDX_R,
    DSASIGASN_IDX_S,
};

#define dsaSigASN_Length (sizeof(dsaSigASN) / sizeof(ASNItem))
#endif

/* Der Encode r & s ints into out, outLen is (in/out) size */
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int    rSz;                           /* encoding size */
    int    sSz;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    int rLeadingZero = mp_leading_bit(r);
    int sLeadingZero = mp_leading_bit(s);
    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);

    if (*outLen < (rLen + rLeadingZero + sLen + sLeadingZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence(rLen + rLeadingZero + sLen+sLeadingZero + headerSz, out);

    /* store r */
    rSz = SetASNIntMP(r, *outLen - idx, &out[idx]);
    if (rSz < 0)
        return rSz;
    idx += rSz;

    /* store s */
    sSz = SetASNIntMP(s, *outLen - idx, &out[idx]);
    if (sSz < 0)
        return sSz;
    idx += sSz;

    *outLen = idx;

    return 0;
#else
    ASNSetData dataASN[dsaSigASN_Length];
    int ret;
    int sz;

    /* Clear dynamic data and set mp_ints r and s */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    SetASN_MP(&dataASN[DSASIGASN_IDX_R], r);
    SetASN_MP(&dataASN[DSASIGASN_IDX_S], s);

    /* Calculate size of encoding. */
    ret = SizeASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, &sz);
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && ((int)*outLen < sz)) {
       ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode DSA signature into buffer. */
        SetASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, out);
        /* Set the actual encoding size. */
        *outLen = sz;
    }

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#ifndef WOLFSSL_ASN_TEMPLATE
/* determine if leading bit is set */
static int is_leading_bit_set(const byte* input, word32 sz)
{
    byte c = 0;
    if (sz > 0)
        c = input[0];
    return (c & 0x80) != 0;
}
static int trim_leading_zeros(const byte** input, word32 sz)
{
    int i, leadingZeroCount = 0;
    const byte* tmp = *input;
    for (i=0; i<(int)sz; i++) {
        if (tmp[i] != 0)
            break;
        leadingZeroCount++;
    }
    /* catch all zero case */
    if (sz > 0 && leadingZeroCount == (int)sz) {
        leadingZeroCount--;
    }
    *input += leadingZeroCount;
    sz -= leadingZeroCount;
    return sz;
}
#endif

/* Der Encode r & s ints into out, outLen is (in/out) size */
/* All input/outputs are assumed to be big-endian */
int StoreECC_DSA_Sig_Bin(byte* out, word32* outLen, const byte* r, word32 rLen,
    const byte* s, word32 sLen)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int ret;
    word32 idx;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */
    int rAddLeadZero, sAddLeadZero;

    if ((out == NULL) || (outLen == NULL) || (r == NULL) || (s == NULL))
        return BAD_FUNC_ARG;

    /* Trim leading zeros */
    rLen = trim_leading_zeros(&r, rLen);
    sLen = trim_leading_zeros(&s, sLen);
    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    /* Add leading zero if MSB is set */
    rAddLeadZero = is_leading_bit_set(r, rLen);
    sAddLeadZero = is_leading_bit_set(s, sLen);

    if (*outLen < (rLen + rAddLeadZero + sLen + sAddLeadZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence(rLen+rAddLeadZero + sLen+sAddLeadZero + headerSz, out);

    /* store r */
    ret = SetASNInt(rLen, rAddLeadZero ? 0x80 : 0x00, &out[idx]);
    if (ret < 0)
        return ret;
    idx += ret;
    XMEMCPY(&out[idx], r, rLen);
    idx += rLen;

    /* store s */
    ret = SetASNInt(sLen, sAddLeadZero ? 0x80 : 0x00, &out[idx]);
    if (ret < 0)
        return ret;
    idx += ret;
    XMEMCPY(&out[idx], s, sLen);
    idx += sLen;

    *outLen = idx;

    return 0;
#else
    ASNSetData dataASN[dsaSigASN_Length];
    int ret;
    int sz;

    /* Clear dynamic data and set buffers for r and s */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    SetASN_Buffer(&dataASN[DSASIGASN_IDX_R], r, rLen);
    SetASN_Buffer(&dataASN[DSASIGASN_IDX_S], s, sLen);

    /* Calculate size of encoding. */
    ret = SizeASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, &sz);
    /* Check buffer is big enough for encoding. */
    if ((ret == 0) && ((int)*outLen < sz)) {
       ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Encode DSA signature into buffer. */
        SetASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, out);
        /* Set the actual encoding size. */
        *outLen = sz;
    }

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

/* Der Decode ECC-DSA Signature with R/S as unsigned bin */
/* All input/outputs are assumed to be big-endian */
int DecodeECC_DSA_Sig_Bin(const byte* sig, word32 sigLen, byte* r, word32* rLen,
    byte* s, word32* sLen)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    ret;
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* enable strict length checking for signature */
    if (sigLen != idx + (word32)len) {
        return ASN_ECC_KEY_E;
    }
#else
    /* allow extra signature bytes at end */
    if ((word32)len > (sigLen - idx)) {
        return ASN_ECC_KEY_E;
    }
#endif

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (rLen)
        *rLen = len;
    if (r)
        XMEMCPY(r, (byte*)sig + idx, len);
    idx += len;

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (sLen)
        *sLen = len;
    if (s)
        XMEMCPY(s, (byte*)sig + idx, len);

#ifndef NO_STRICT_ECDSA_LEN
    /* sanity check that the index has been advanced all the way to the end of
     * the buffer */
    if (idx + len != sigLen) {
        ret = ASN_ECC_KEY_E;
    }
#endif

    return ret;
#else
    ASNGetData dataASN[dsaSigASN_Length];
    word32 idx = 0;

    /* Clear dynamic data and set buffers to put r and s into. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_Buffer(&dataASN[DSASIGASN_IDX_R], r, rLen);
    GetASN_Buffer(&dataASN[DSASIGASN_IDX_S], s, sLen);

    /* Decode the DSA signature. */
    return GetASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, 1, sig, &idx,
                        sigLen);
#endif /* WOLFSSL_ASN_TEMPLATE */
}

int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* enable strict length checking for signature */
    if (sigLen != idx + (word32)len) {
        return ASN_ECC_KEY_E;
    }
#else
    /* allow extra signature bytes at end */
    if ((word32)len > (sigLen - idx)) {
        return ASN_ECC_KEY_E;
    }
#endif

    if (GetIntPositive(r, sig, &idx, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

    if (GetIntPositive(s, sig, &idx, sigLen) < 0) {
        mp_clear(r);
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* sanity check that the index has been advanced all the way to the end of
     * the buffer */
    if (idx != sigLen) {
        mp_clear(r);
        mp_clear(s);
        return ASN_ECC_KEY_E;
    }
#endif

    return 0;
#else
    ASNGetData dataASN[dsaSigASN_Length];
    word32 idx = 0;
    int ret;

    /* Clear dynamic data and set mp_ints to put r and s into. */
    XMEMSET(dataASN, 0, sizeof(dataASN));
    GetASN_MP(&dataASN[DSASIGASN_IDX_R], r);
    GetASN_MP(&dataASN[DSASIGASN_IDX_S], s);

    /* Decode the DSA signature. */
    ret = GetASN_Items(dsaSigASN, dataASN, dsaSigASN_Length, 1, sig, &idx,
                       sigLen);
#ifndef NO_STRICT_ECDSA_LEN
    /* sanity check that the index has been advanced all the way to the end of
     * the buffer */
    if ((ret == 0) && (idx != sigLen)) {
        mp_clear(r);
        mp_clear(s);
        ret = ASN_ECC_KEY_E;
    }

    return ret;
#endif
#endif /* WOLFSSL_ASN_TEMPLATE */
}


#ifdef WOLFSSL_ASN_TEMPLATE
#ifdef WOLFSSL_CUSTOM_CURVES
/* Convert data to hex string.
 *
 * Big-endian byte array is converted to big-endian hexadecimal string.
 *
 * @param [in]  input  Buffer containing data.
 * @param [in]  inSz   Size of data in buffer.
 * @param [out] out    Buffer to hold hex string.
 */
static void DataToHexString(const byte* input, word32 inSz, char* out)
{
    static const char hexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    word32 i;

    /* Converting a byte of data at a time to two hex characters. */
    for (i = 0; i < inSz; i++) {
        out[i*2 + 0] = hexChar[input[i] >> 4];
        out[i*2 + 1] = hexChar[input[i] & 0xf];
    }
    /* NUL terminate string. */
    out[i * 2] = '\0';
}

/* Convert data to hex string and place in allocated buffer.
 *
 * Big-endian byte array is converted to big-endian hexadecimal string.
 *
 * @param [in]  input     Buffer containing data.
 * @param [in]  inSz      Size of data in buffer.
 * @param [out] out       Allocated buffer holding hex string.
 * @param [in]  heap      Dynamic memory allocation hint.
 * @param [in]  heapType  Type of heap to use.
 * @return  0 on succcess.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int DataToHexStringAlloc(const byte* input, word32 inSz, char** out,
                                void* heap, int heapType)
{
    int ret = 0;
    char* str;

    /* Allocate for 2 string characters ber byte plus NUL. */
    str = (char*)XMALLOC(inSz * 2 + 1, heap, heapType);
    if (str == NULL) {
        ret = MEMORY_E;
    }
    else {
        /* Convert to hex string. */
        DataToHexString(input, inSz, str);
        *out = str;
    }

    (void)heap;
    (void)heapType;

    return ret;
}

/* ASN.1 template for SpecifiedECDomain.
 * SEC 1 Ver. 2.0, C.2 - Syntax for Elliptic Curve Domain Parameters
 * NOTE: characteristic-two-field not supported. */
static const ASNItem eccSpecifiedASN[] = {
            /* version */
/* VER        */ { 0, ASN_INTEGER, 0, 0, 0 },
                                     /* fieldID */
/* PRIME_SEQ  */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                         /* prime-field or characteristic-two-field */
/* PRIME_OID  */     { 1, ASN_OBJECT_ID, 0, 0, 0 },
                                         /* Prime-p */
/* PRIME_P    */     { 1, ASN_INTEGER, 0, 0, 0 },
                                     /* fieldID */
/* PARAM_SEQ, */ { 0, ASN_SEQUENCE, 1, 1, 0 },
                                         /* a */
/* PARAM_A    */     { 1, ASN_OCTET_STRING, 0, 0, 0 },
                                         /* b */
/* PARAM_B    */     { 1, ASN_OCTET_STRING, 0, 0, 0 },
                                         /* seed */
/* PARAM_SEED */     { 1, ASN_BIT_STRING, 0, 0, 1 },
                                     /* base */
/* BASE       */ { 0, ASN_OCTET_STRING, 0, 0, 0 },
                                     /* order */
/* ORDER      */ { 0, ASN_INTEGER, 0, 0, 0 },
                                     /* cofactor */
/* COFACTOR   */ { 0, ASN_INTEGER, 0, 0, 1 },
                                     /* hash */
/* HASH_SEQ   */ { 0, ASN_SEQUENCE, 0, 0, 1 },
};
enum {
    ECCSPECIFIEDASN_IDX_VER = 0,
    ECCSPECIFIEDASN_IDX_PRIME_SEQ,
    ECCSPECIFIEDASN_IDX_PRIME_OID,
    ECCSPECIFIEDASN_IDX_PRIME_P,
    ECCSPECIFIEDASN_IDX_PARAM_SEQ,
    ECCSPECIFIEDASN_IDX_PARAM_A,
    ECCSPECIFIEDASN_IDX_PARAM_B,
    ECCSPECIFIEDASN_IDX_PARAM_SEED,
    ECCSPECIFIEDASN_IDX_BASE,
    ECCSPECIFIEDASN_IDX_ORDER,
    ECCSPECIFIEDASN_IDX_COFACTOR,
    ECCSPECIFIEDASN_IDX_HASH_SEQ,
};

/* Number of items in ASN.1 template for SpecifiedECDomain. */
#define eccSpecifiedASN_Length (sizeof(eccSpecifiedASN) / sizeof(ASNItem))

/* OID indicating the prime field is explicity defined. */
static const byte primeFieldOID[] = {
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01
};
static const char ecSetCustomName[] = "Custom";

/* Explicit EC parameter values. */
static int EccSpecifiedECDomainDecode(const byte* input, word32 inSz,
                                      ecc_key* key)
{
    DECL_ASNGETDATA(dataASN, eccSpecifiedASN_Length);
    int ret = 0;
    ecc_set_type* curve;
    word32 idx = 0;
    byte version;
    byte cofactor;
    const byte *base;
    word32 baseLen;

    /* Allocate a new parameter set. */
    curve = (ecc_set_type*)XMALLOC(sizeof(*curve), key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
    if (curve == NULL)
        ret = MEMORY_E;

    CALLOC_ASNGETDATA(dataASN, eccSpecifiedASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Clear out parameters and set fields to indicate it is custom. */
        XMEMSET(curve, 0, sizeof(*curve));
        /* Set name to be: "Custom" */
    #ifndef WOLFSSL_ECC_CURVE_STATIC
        curve->name = ecSetCustomName;
    #else
        XMEMCPY((void*)curve->name, ecSetCustomName, sizeof(ecSetCustomName));
    #endif
        curve->id = ECC_CURVE_CUSTOM;

        /* Get version, must have prime field OID and get co-factor. */
        GetASN_Int8Bit(&dataASN[ECCSPECIFIEDASN_IDX_VER], &version);
        GetASN_ExpBuffer(&dataASN[ECCSPECIFIEDASN_IDX_PRIME_OID],
                primeFieldOID, sizeof(primeFieldOID));
        GetASN_Int8Bit(&dataASN[ECCSPECIFIEDASN_IDX_COFACTOR], &cofactor);
        /* Decode the explicit parameters. */
        ret = GetASN_Items(eccSpecifiedASN, dataASN, eccSpecifiedASN_Length, 1,
                           input, &idx, inSz);
    }
    /* Version must be 1 or 2 for supporting explicit parameters. */
    if ((ret == 0) && (version < 1 || version > 3)) {
        ret = ASN_PARSE_E;
    }
    /* Only version 2 and above can have a seed. */
    if ((ret == 0) && (dataASN[ECCSPECIFIEDASN_IDX_PARAM_SEED].tag != 0) &&
            (version < 2)) {
        ret = ASN_PARSE_E;
    }
    /* Only version 2 and above can have a hash algorithm. */
    if ((ret == 0) && (dataASN[ECCSPECIFIEDASN_IDX_HASH_SEQ].tag != 0) &&
            (version < 2)) {
        ret = ASN_PARSE_E;
    }
    if ((ret == 0) && (dataASN[ECCSPECIFIEDASN_IDX_COFACTOR].tag != 0)) {
        /* Store optional co-factor. */
        curve->cofactor = cofactor;
    }
    if (ret == 0) {
        /* Length of the prime in bytes is the curve size. */
        curve->size =
                (int)dataASN[ECCSPECIFIEDASN_IDX_PRIME_P].data.ref.length;
        /* Base point: 0x04 <x> <y> (must be uncompressed). */
        GetASN_GetConstRef(&dataASN[ECCSPECIFIEDASN_IDX_BASE], &base,
                &baseLen);
        if ((baseLen < (word32)curve->size * 2 + 1) || (base[0] != 0x4)) {
            ret = ASN_PARSE_E;
        }
    }
    /* Put the curve parameters into the set.
     * Convert the big-endian number byte array to a big-endian string.
     */
    #ifndef WOLFSSL_ECC_CURVE_STATIC
    /* Allocate buffer to put hex strings into. */
    if (ret == 0) {
        /* Base X-ordinate */
        ret = DataToHexStringAlloc(base + 1, curve->size,
                                   (char**)&curve->Gx, key->heap,
                                   DYNAMIC_TYPE_ECC_BUFFER);
    }
    if (ret == 0) {
        /* Base Y-ordinate */
        ret = DataToHexStringAlloc(base + 1 + curve->size, curve->size,
                                   (char**)&curve->Gy, key->heap,
                                   DYNAMIC_TYPE_ECC_BUFFER);
    }
    if (ret == 0) {
        /* Prime */
        ret = DataToHexStringAlloc(
                dataASN[ECCSPECIFIEDASN_IDX_PRIME_P].data.ref.data,
                dataASN[ECCSPECIFIEDASN_IDX_PRIME_P].data.ref.length,
                (char**)&curve->prime, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
    }
    if (ret == 0) {
        /* Parameter A */
        ret = DataToHexStringAlloc(
                dataASN[ECCSPECIFIEDASN_IDX_PARAM_A].data.ref.data,
                dataASN[ECCSPECIFIEDASN_IDX_PARAM_A].data.ref.length,
                (char**)&curve->Af, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
    }
    if (ret == 0) {
        /* Parameter B */
        ret = DataToHexStringAlloc(
                dataASN[ECCSPECIFIEDASN_IDX_PARAM_B].data.ref.data,
                dataASN[ECCSPECIFIEDASN_IDX_PARAM_B].data.ref.length,
                (char**)&curve->Bf, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
    }
    if (ret == 0) {
        /* Order of curve */
        ret = DataToHexStringAlloc(
                dataASN[ECCSPECIFIEDASN_IDX_ORDER].data.ref.data,
                dataASN[ECCSPECIFIEDASN_IDX_ORDER].data.ref.length,
                (char**)&curve->order, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
    }
    #else
    if (ret == 0) {
        /* Base X-ordinate */
        DataToHexString(base + 1, curve->size, curve->Gx);
        /* Base Y-ordinate */
        DataToHexString(base + 1 + curve->size, curve->size, curve->Gy);
        /* Prime */
        DataToHexString(dataASN[ECCSPECIFIEDASN_IDX_PRIME_P].data.ref.data,
                        dataASN[ECCSPECIFIEDASN_IDX_PRIME_P].data.ref.length,
                        curve->prime);
        /* Parameter A */
        DataToHexString(dataASN[ECCSPECIFIEDASN_IDX_PARAM_A].data.ref.data,
                        dataASN[ECCSPECIFIEDASN_IDX_PARAM_A].data.ref.length,
                        curve->Af);
        /* Parameter B */
        DataToHexString(dataASN[ECCSPECIFIEDASN_IDX_PARAM_B].data.ref.data,
                        dataASN[ECCSPECIFIEDASN_IDX_PARAM_B].data.ref.length,
                        curve->Bf);
        /* Order of curve */
        DataToHexString(dataASN[ECCSPECIFIEDASN_IDX_ORDER].data.ref.data,
                        dataASN[ECCSPECIFIEDASN_IDX_ORDER].data.ref.length,
                        curve->order);
    }
    #endif /* WOLFSSL_ECC_CURVE_STATIC */

    /* Store parameter set in key. */
    if ((ret == 0) && (wc_ecc_set_custom_curve(key, curve) < 0)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        /* The parameter set was allocated.. */
        key->deallocSet = 1;
    }

    if ((ret != 0) && (curve != NULL)) {
        /* Failed to set parameters so free paramter set. */
        wc_ecc_free_curve(curve, key->heap);
    }

    FREE_ASNGETDATA(dataASN, key->heap);
    return ret;
}
#endif /* WOLFSSL_CUSTOM_CURVES */
#endif /* WOLFSSL_ASN_TEMPLATE */


#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for ECC private key.
 * SEC.1 Ver 2.0, C.4 - Syntax for Elliptic Curve Private Keys
 */
static const ASNItem eccKeyASN[] = {
/* SEQ         */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                                       /* version */
/* VER         */        { 1, ASN_INTEGER, 0, 0, 0 },
                                       /* privateKey */
/* PKEY        */        { 1, ASN_OCTET_STRING, 0, 0, 0 },
                                       /* parameters */
/* PARAMS      */        { 1, ASN_CONTEXT_SPECIFIC | ASN_ECC_PARAMS, 1, 1, 1 },
                                           /* named */
/* CURVEID     */            { 2, ASN_OBJECT_ID, 0, 0, 2 },
                                           /* specified */
/* CURVEPARAMS */            { 2, ASN_SEQUENCE, 1, 0, 2 },
                                       /* publicKey */
/* PUBKEY      */        { 1, ASN_CONTEXT_SPECIFIC | ASN_ECC_PUBKEY, 1, 1, 1 },
                                           /* Uncompressed point - X9.62. */
/* PUBKEY_VAL, */            { 2, ASN_BIT_STRING, 0, 0, 0 },
};
enum {
    ECCKEYASN_IDX_SEQ = 0,
    ECCKEYASN_IDX_VER,
    ECCKEYASN_IDX_PKEY,
    ECCKEYASN_IDX_PARAMS,
    ECCKEYASN_IDX_CURVEID,
    ECCKEYASN_IDX_CURVEPARAMS,
    ECCKEYASN_IDX_PUBKEY,
    ECCKEYASN_IDX_PUBKEY_VAL,
};

/* Number of items in ASN.1 template for ECC private key. */
#define eccKeyASN_Length (sizeof(eccKeyASN) / sizeof(ASNItem))
#endif

int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 oidSum;
    int    version, length;
    int    privSz, pubSz = 0;
    byte   b;
    int    ret = 0;
    int    curve_id = ECC_CURVE_DEF;
    byte priv[ECC_MAXSIZE+1];
    byte pub[2*(ECC_MAXSIZE+1)]; /* public key has two parts plus header */
    word32 algId = 0;
    byte* pubData = NULL;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    if (*inOutIdx >= inSz)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7)
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;
    privSz = length;

    if (privSz > ECC_MAXSIZE)
        return BUFFER_E;


    /* priv key */
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    if ((*inOutIdx + 1) < inSz) {
        /* prefix 0, may have */
        b = input[*inOutIdx];
        if (b == ECC_PREFIX_0) {
            *inOutIdx += 1;

            if (GetLength(input, inOutIdx, &length, inSz) <= 0)
                ret = ASN_PARSE_E;
            else {
                ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType,
                                  inSz);
                if (ret == 0) {
                    if ((ret = CheckCurve(oidSum)) < 0)
                        ret = ECC_CURVE_OID_E;
                    else {
                        curve_id = ret;
                        ret = 0;
                    }
                }
            }
        }
    }

    if (ret == 0 && (*inOutIdx + 1) < inSz) {
        /* prefix 1 */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ECC_PREFIX_1) {
            ret = ASN_ECC_KEY_E;
        }
        else if (GetLength(input, inOutIdx, &length, inSz) <= 0) {
            ret = ASN_PARSE_E;
        }
        else {
            /* key header */
            ret = CheckBitString(input, inOutIdx, &length, inSz, 0, NULL);
            if (ret == 0) {
                /* pub key */
                pubSz = length;
                if (pubSz > 2*(ECC_MAXSIZE+1))
                    ret = BUFFER_E;
                else {
                    {
                        XMEMCPY(pub, &input[*inOutIdx], pubSz);
                        *inOutIdx += length;
                        pubData = pub;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(priv, privSz, pubData, pubSz, key,
                                                                      curve_id);
    }


    return ret;
#else
    DECL_ASNGETDATA(dataASN, eccKeyASN_Length);
    byte version;
    int ret = 0;
    int curve_id = ECC_CURVE_DEF;
#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    word32 algId = 0;
#endif

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }
#endif

    CALLOC_ASNGETDATA(dataASN, eccKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Get the version and set the expected OID type. */
        GetASN_Int8Bit(&dataASN[ECCKEYASN_IDX_VER], &version);
        GetASN_OID(&dataASN[ECCKEYASN_IDX_CURVEID], oidCurveType);
        /* Decode the private ECC key. */
        ret = GetASN_Items(eccKeyASN, dataASN, eccKeyASN_Length, 1, input,
                           inOutIdx, inSz);
    }
    /* Only version 1 supported. */
    if ((ret == 0) && (version != 1)) {
        ret = ASN_PARSE_E;
    }
    /* Curve Parameters are optional. */
    if ((ret == 0) && (dataASN[ECCKEYASN_IDX_PARAMS].tag != 0)) {
        if (dataASN[ECCKEYASN_IDX_CURVEID].tag != 0) {
            /* Named curve - check and get id. */
            curve_id = CheckCurve(dataASN[ECCKEYASN_IDX_CURVEID].data.oid.sum);
            if (curve_id < 0) {
                ret = ECC_CURVE_OID_E;
            }
        }
        else {
    #ifdef WOLFSSL_CUSTOM_CURVES
            /* Parse explicit parameters. */
            ret = EccSpecifiedECDomainDecode(
                    dataASN[ECCKEYASN_IDX_CURVEPARAMS].data.ref.data,
                    dataASN[ECCKEYASN_IDX_CURVEPARAMS].data.ref.length, key);
    #else
            /* Explicit parameters not supported in build configuration. */
            ret = ASN_PARSE_E;
    #endif
        }
    }
    if (ret == 0) {
        /* Import private key value and public point (may be NULL). */
        ret = wc_ecc_import_private_key_ex(
                dataASN[ECCKEYASN_IDX_PKEY].data.ref.data,
                dataASN[ECCKEYASN_IDX_PKEY].data.ref.length,
                dataASN[ECCKEYASN_IDX_PUBKEY_VAL].data.ref.data,
                dataASN[ECCKEYASN_IDX_PUBKEY_VAL].data.ref.length,
                key, curve_id);
    }

    FREE_ASNGETDATA(dataASN, key->heap);
    return ret;
#endif
}


#ifdef WOLFSSL_CUSTOM_CURVES
#ifndef WOLFSSL_ASN_TEMPLATE
/* returns 0 on success */
static int ASNToHexString(const byte* input, word32* inOutIdx, char** out,
                          word32 inSz, void* heap, int heapType)
{
    int len;
    int i;
    char* str;
    word32 localIdx;
    byte   tag;

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 && tag == ASN_INTEGER) {
        if (GetASNInt(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }
    else {
        if (GetOctetString(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }

    str = (char*)XMALLOC(len * 2 + 1, heap, heapType);
    if (str == NULL) {
        return MEMORY_E;
    }

    for (i=0; i<len; i++)
        ByteToHexStr(input[*inOutIdx + i], str + i*2);
    str[len*2] = '\0';

    *inOutIdx += len;
    *out = str;

    (void)heap;
    (void)heapType;

    return 0;
}

static int EccKeyParamCopy(char** dst, char* src)
{
    int ret = 0;
#ifdef WOLFSSL_ECC_CURVE_STATIC
    word32 length;
#endif

    if (dst == NULL || src == NULL)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_ECC_CURVE_STATIC
    *dst = src;
#else
    length = (int)XSTRLEN(src) + 1;
    if (length > MAX_ECC_STRING) {
        WOLFSSL_MSG("ECC Param too large for buffer");
        ret = BUFFER_E;
    }
    else {
        XSTRNCPY(*dst, src, MAX_ECC_STRING);
    }
    XFREE(src, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return ret;
}
#endif /* !WOLFSSL_ASN_TEMPLATE */
#endif /* WOLFSSL_CUSTOM_CURVES */

int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    ret;
    int    version, length;
    int    curve_id = ECC_CURVE_DEF;
    word32 oidSum, localIdx;
    byte   tag, isPrivFormat = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    /* Check if ECC private key is being used and skip private portion */
    if (GetMyVersion(input, inOutIdx, &version, inSz) >= 0) {
        isPrivFormat = 1;

        /* Type private key */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != 4 && tag != 6 && tag != 7)
            return ASN_PARSE_E;

        /* Skip Private Key */
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        if (length > ECC_MAXSIZE)
            return BUFFER_E;
        *inOutIdx += length;

        /* Private Curve Header */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_0)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }
    /* Standard ECC public key */
    else {
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        ret = SkipObjectId(input, inOutIdx, inSz);
        if (ret != 0)
            return ret;
    }

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 &&
            tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
#ifdef WOLFSSL_CUSTOM_CURVES
        ecc_set_type* curve;
        int len;
        char* point = NULL;

        ret = 0;

        curve = (ecc_set_type*)XMALLOC(sizeof(*curve), key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
        if (curve == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            static const char customName[] = "Custom";
            XMEMSET(curve, 0, sizeof(*curve));
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->name = customName;
        #else
            XMEMCPY((void*)curve->name, customName, sizeof(customName));
        #endif
            curve->id = ECC_CURVE_CUSTOM;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }

        if (ret == 0) {
            GetInteger7Bit(input, inOutIdx, inSz);
            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            char* p = NULL;
            SkipObjectId(input, inOutIdx, inSz);
            ret = ASNToHexString(input, inOutIdx, &p, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->prime, p);
        }
        if (ret == 0) {
            curve->size = (int)XSTRLEN(curve->prime) / 2;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            char* af = NULL;
            ret = ASNToHexString(input, inOutIdx, &af, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->Af, af);
        }
        if (ret == 0) {
            char* bf = NULL;
            ret = ASNToHexString(input, inOutIdx, &bf, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->Bf, bf);
        }
        if (ret == 0) {
            localIdx = *inOutIdx;
            if (*inOutIdx < inSz && GetASNTag(input, &localIdx, &tag, inSz)
                    == 0 && tag == ASN_BIT_STRING) {
                len = 0;
                ret = GetASNHeader(input, ASN_BIT_STRING, inOutIdx, &len, inSz);
                if (ret > 0)
                    ret = 0; /* reset on success */
                *inOutIdx += len;
            }
        }
        if (ret == 0) {
            ret = ASNToHexString(input, inOutIdx, (char**)&point, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);

            /* sanity check that point buffer is not smaller than the expected
             * size to hold ( 0 4 || Gx || Gy )
             * where Gx and Gy are each the size of curve->size * 2 */
            if (ret == 0 && (int)XSTRLEN(point) < (curve->size * 4) + 2) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = BUFFER_E;
            }
        }
        if (ret == 0) {
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->Gx = (const char*)XMALLOC(curve->size * 2 + 2, key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
            curve->Gy = (const char*)XMALLOC(curve->size * 2 + 2, key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
            if (curve->Gx == NULL || curve->Gy == NULL) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = MEMORY_E;
            }
        #else
            if (curve->size * 2 + 2 > MAX_ECC_STRING) {
                WOLFSSL_MSG("curve size is too large to fit in buffer");
                ret = BUFFER_E;
            }
        #endif
        }
        if (ret == 0) {
            char* o = NULL;

            XMEMCPY((char*)curve->Gx, point + 2, curve->size * 2);
            XMEMCPY((char*)curve->Gy, point + curve->size * 2 + 2,
                                                               curve->size * 2);
            ((char*)curve->Gx)[curve->size * 2] = '\0';
            ((char*)curve->Gy)[curve->size * 2] = '\0';
            XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            ret = ASNToHexString(input, inOutIdx, &o, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->order, o);
        }
        if (ret == 0) {
            curve->cofactor = GetInteger7Bit(input, inOutIdx, inSz);

        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->oid = NULL;
        #else
            XMEMSET((void*)curve->oid, 0, sizeof(curve->oid));
        #endif
            curve->oidSz = 0;
            curve->oidSum = 0;

            if (wc_ecc_set_custom_curve(key, curve) < 0) {
                ret = ASN_PARSE_E;
            }

            key->deallocSet = 1;

            curve = NULL;
        }
        if (curve != NULL)
            wc_ecc_free_curve(curve, key->heap);

        if (ret < 0)
            return ret;
#else
        return ASN_PARSE_E;
#endif /* WOLFSSL_CUSTOM_CURVES */
    }
    else {
        /* ecc params information */
        ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType, inSz);
        if (ret != 0)
            return ret;

        /* get curve id */
        if ((ret = CheckCurve(oidSum)) < 0)
            return ECC_CURVE_OID_E;
        else {
            curve_id = ret;
        }
    }

    if (isPrivFormat) {
        /* Public Curve Header - skip */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_1)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }

    /* key header */
    ret = CheckBitString(input, inOutIdx, &length, inSz, 1, NULL);
    if (ret != 0)
        return ret;

    /* This is the raw point data compressed or uncompressed. */
    if (wc_ecc_import_x963_ex(input + *inOutIdx, length, key,
                                                            curve_id) != 0) {
        return ASN_ECC_KEY_E;
    }

    *inOutIdx += length;

    return 0;
#else
    /* eccKeyASN is longer than eccPublicKeyASN. */
    DECL_ASNGETDATA(dataASN, eccKeyASN_Length);
    int ret = 0;
    int curve_id = ECC_CURVE_DEF;
    int oidIdx = ECCPUBLICKEYASN_IDX_ALGOID_CURVEID;
#ifdef WOLFSSL_CUSTOM_CURVES
    int specIdx = ECCPUBLICKEYASN_IDX_ALGOID_PARAMS;
#endif
    int pubIdx = ECCPUBLICKEYASN_IDX_PUBKEY;

    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    ALLOC_ASNGETDATA(dataASN, eccKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Clear dynamic data for ECC public key. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * eccPublicKeyASN_Length);
        /* Set required ECDSA OID and ignore the curve OID type. */
        GetASN_ExpBuffer(&dataASN[ECCPUBLICKEYASN_IDX_ALGOID_OID], keyEcdsaOid,
                sizeof(keyEcdsaOid));
        GetASN_OID(&dataASN[oidIdx], oidIgnoreType);
        /* Decode the public ECC key. */
        ret = GetASN_Items(eccPublicKeyASN, dataASN, eccPublicKeyASN_Length, 1,
                           input, inOutIdx, inSz);
        if (ret != 0) {
            oidIdx = ECCKEYASN_IDX_CURVEID;
        #ifdef WOLFSSL_CUSTOM_CURVES
            specIdx = ECCKEYASN_IDX_CURVEPARAMS;
        #endif
            pubIdx = ECCKEYASN_IDX_PUBKEY_VAL;

            /* Clear dynamic data for ECC private key. */
            XMEMSET(dataASN, 0, sizeof(*dataASN) * eccKeyASN_Length);
            /* Check named curve OID type. */
            GetASN_OID(&dataASN[oidIdx], oidIgnoreType);
            /* Try private key format .*/
            ret = GetASN_Items(eccKeyASN, dataASN, eccKeyASN_Length, 1, input,
                               inOutIdx, inSz);
            if (ret != 0) {
                ret = ASN_PARSE_E;
            }
        }
    }

    if (ret == 0) {
        if (dataASN[oidIdx].tag != 0) {
            /* Named curve - check and get id. */
            curve_id = CheckCurve(dataASN[oidIdx].data.oid.sum);
            if (curve_id < 0) {
                ret = ASN_OBJECT_ID_E;
            }
        }
        else {
        #ifdef WOLFSSL_CUSTOM_CURVES
            /* Parse explicit parameters. */
            ret = EccSpecifiedECDomainDecode(dataASN[specIdx].data.ref.data,
                                         dataASN[specIdx].data.ref.length, key);
        #else
            /* Explicit parameters not supported in build configuration. */
            ret = ASN_PARSE_E;
        #endif
        }
    }
    if (ret == 0) {
        /* Import public point. */
        ret = wc_ecc_import_x963_ex(dataASN[pubIdx].data.ref.data,
                dataASN[pubIdx].data.ref.length, key, curve_id);
        if (ret != 0) {
            ret = ASN_ECC_KEY_E;
        }
    }

    FREE_ASNGETDATA(dataASN, key->heap);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#if !defined(NO_ASN_CRYPT)
/* build DER formatted ECC key, include optional public key if requested,
 * return length on success, negative on error */
static int wc_BuildEccKeyDer(ecc_key* key, byte* output, word32 *inLen,
                             int pubIn, int curveIn)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    byte   curve[MAX_ALGO_SZ+2];
    byte   ver[MAX_VERSION_SZ];
    byte   seq[MAX_SEQ_SZ];
    int    ret, totalSz, curveSz, verSz;
    int    privHdrSz  = ASN_ECC_HEADER_SZ;
    int    pubHdrSz   = ASN_ECC_CONTEXT_SZ + ASN_ECC_HEADER_SZ;
    byte   *prv = NULL, *pub = NULL;

    word32 idx = 0, prvidx = 0, pubidx = 0, curveidx = 0;
    word32 seqSz, privSz, pubSz = ECC_BUFSIZE;

    if (key == NULL || (output == NULL && inLen == NULL))
        return BAD_FUNC_ARG;

    if (curveIn) {
        /* curve */
        curve[curveidx++] = ECC_PREFIX_0;
        curveidx++ /* to put the size after computation */;
        curveSz = SetCurve(key, curve+curveidx);
        if (curveSz < 0)
            return curveSz;
        /* set computed size */
        curve[1] = (byte)curveSz;
        curveidx += curveSz;
    }

    /* private */
    privSz = key->dp->size;


    prv = (byte*)XMALLOC(privSz + privHdrSz + MAX_SEQ_SZ,
                         key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (prv == NULL) {
        return MEMORY_E;
    }
    if (privSz < ASN_LONG_LENGTH) {
        prvidx += SetOctetString8Bit(privSz, &prv[prvidx]);
    }
    else {
        prvidx += SetOctetString(privSz, &prv[prvidx]);
    }
    ret = wc_ecc_export_private_only(key, prv + prvidx, &privSz);
    if (ret < 0) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    prvidx += privSz;

    /* pubIn */
    if (pubIn) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, NULL, &pubSz);
        PRIVATE_KEY_LOCK();
        if (ret != LENGTH_ONLY_E) {
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }

        pub = (byte*)XMALLOC(pubSz + pubHdrSz + MAX_SEQ_SZ,
                             key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pub == NULL) {
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }

        pub[pubidx++] = ECC_PREFIX_1;
        if (pubSz > 128) /* leading zero + extra size byte */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 2, pub+pubidx);
        else /* leading zero */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 1, pub+pubidx);

        /* SetBitString adds leading zero */
        pubidx += SetBitString(pubSz, 0, pub + pubidx);
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, pub + pubidx, &pubSz);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        pubidx += pubSz;
    }

    /* make headers */
    verSz = SetMyVersion(1, ver, FALSE);
    seqSz = SetSequence(verSz + prvidx + pubidx + curveidx, seq);

    totalSz = prvidx + pubidx + curveidx + verSz + seqSz;
    if (output == NULL) {
        *inLen = totalSz;
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubIn) {
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        return LENGTH_ONLY_E;
    }
    if (inLen != NULL && totalSz > (int)*inLen) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubIn) {
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        return BAD_FUNC_ARG;
    }

    /* write out */
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx = seqSz;

    /* ver */
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;

    /* private */
    XMEMCPY(output + idx, prv, prvidx);
    idx += prvidx;
    XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    /* curve */
    XMEMCPY(output + idx, curve, curveidx);
    idx += curveidx;

    /* pubIn */
    if (pubIn) {
        XMEMCPY(output + idx, pub, pubidx);
        /* idx += pubidx;  not used after write, if more data remove comment */
        XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return totalSz;
#else
    DECL_ASNSETDATA(dataASN, eccKeyASN_Length);
    word32 privSz, pubSz;
    int sz = 0;
    int ret = 0;

    /* Check validity of parameters. */
    if ((key == NULL) || ((output == NULL) && (inLen == NULL))) {
        ret = BAD_FUNC_ARG;
    }

    /* Check key has parameters when encoding curve. */
    if ((ret == 0) && curveIn && (key->dp == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    CALLOC_ASNSETDATA(dataASN, eccKeyASN_Length, ret, key->heap);

    if (ret == 0) {
        /* Private key size is the curve size. */
        privSz = key->dp->size;
        if (pubIn) {
            /* Get the length of the public key. */
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_export_x963(key, NULL, &pubSz);
            PRIVATE_KEY_LOCK();
            if (ret == LENGTH_ONLY_E)
                ret = 0;
        }
    }
    if (ret == 0) {
        /* Version: 1 */
        SetASN_Int8Bit(&dataASN[ECCKEYASN_IDX_VER], 1);
        /* Leave space for private key. */
        SetASN_Buffer(&dataASN[ECCKEYASN_IDX_PKEY], NULL, privSz);
        if (curveIn) {
            /* Curve OID */
            SetASN_Buffer(&dataASN[ECCKEYASN_IDX_CURVEID],
                          (const byte *)key->dp->oid, key->dp->oidSz);
            /* TODO: add support for SpecifiedECDomain curve. */
            dataASN[ECCKEYASN_IDX_CURVEPARAMS].noOut = 1;
        }
        else {
            SetASNItem_NoOutNode(dataASN, eccKeyASN, ECCKEYASN_IDX_PARAMS,
                    eccKeyASN_Length);
        }
        if (pubIn) {
            /* Leave space for public key. */
            SetASN_Buffer(&dataASN[ECCKEYASN_IDX_PUBKEY_VAL], NULL, pubSz);
        }
        else {
            /* Don't write out public key. */
            SetASNItem_NoOutNode(dataASN, eccKeyASN, ECCKEYASN_IDX_PUBKEY,
                    eccKeyASN_Length);
        }
        /* Calculate size of the private key encoding. */
        ret = SizeASN_Items(eccKeyASN, dataASN, eccKeyASN_Length, &sz);
    }
    /* Return the size if no buffer. */
    if ((ret == 0) && (output == NULL)) {
        *inLen = sz;
        ret = LENGTH_ONLY_E;
    }
    /* Check the buffer is big enough. */
    if ((ret == 0) && (inLen != NULL) && (sz > (int)*inLen)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Encode the private key. */
        SetASN_Items(eccKeyASN, dataASN, eccKeyASN_Length, output);

        /* Export the private value into the buffer. */
        ret = wc_ecc_export_private_only(key,
                (byte*)dataASN[ECCKEYASN_IDX_PKEY].data.buffer.data, &privSz);
        if ((ret == 0) && pubIn) {
            /* Export the public point into the buffer. */
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_export_x963(key,
                    (byte*)dataASN[ECCKEYASN_IDX_PUBKEY_VAL].data.buffer.data,
                    &pubSz);
            PRIVATE_KEY_LOCK();
        }
    }
    if (ret == 0) {
        /* Return the encoding size. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, key->heap);
    return ret;
#endif
}

/* Write a Private ecc key, including public to DER format,
 * length on success else < 0 */
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    return wc_BuildEccKeyDer(key, output, &inLen, 1, 1);
}

/* Write only private ecc key to DER format,
 * length on success else < 0 */
int wc_EccKeyDerSize(ecc_key* key, int pub)
{
    word32 sz = 0;
    int ret;

    ret = wc_BuildEccKeyDer(key, NULL, &sz, pub, 1);

    if (ret != LENGTH_ONLY_E) {
        return ret;
    }
    return sz;
 }

/* Write only private ecc key to DER format,
 * length on success else < 0 */
int wc_EccPrivateKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    return wc_BuildEccKeyDer(key, output, &inLen, 0, 1);
}



#ifdef HAVE_PKCS8

/* Write only private ecc key or both private and public parts to unencrypted
 * PKCS#8 format.
 *
 * If output is NULL, places required PKCS#8 buffer size in outLen and
 * returns LENGTH_ONLY_E.
 *
 * return length on success else < 0 */
static int eccToPKCS8(ecc_key* key, byte* output, word32* outLen,
        int includePublic)
{
    int ret, tmpDerSz;
    int algoID = 0;
    word32 oidSz = 0;
    word32 pkcs8Sz = 0;
    const byte* curveOID = NULL;
    byte* tmpDer = NULL;
    word32 sz = ECC_BUFSIZE;

    if (key == NULL || key->dp == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    /* set algoID, get curve OID */
    algoID = ECDSAk;
    ret = wc_ecc_get_oid(key->dp->oidSum, &curveOID, &oidSz);
    if (ret < 0)
        return ret;

    /* temp buffer for plain DER key */
    tmpDer = (byte*)XMALLOC(ECC_BUFSIZE, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpDer == NULL)
        return MEMORY_E;
    XMEMSET(tmpDer, 0, ECC_BUFSIZE);

    ret = wc_BuildEccKeyDer(key, tmpDer, &sz, includePublic, 0);
    if (ret < 0) {
        XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    tmpDerSz = ret;

    /* get pkcs8 expected output size */
    ret = wc_CreatePKCS8Key(NULL, &pkcs8Sz, tmpDer, tmpDerSz, algoID,
                            curveOID, oidSz);
    if (ret != LENGTH_ONLY_E) {
        XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    if (output == NULL) {
        XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        *outLen = pkcs8Sz;
        return LENGTH_ONLY_E;

    }
    else if (*outLen < pkcs8Sz) {
        XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WOLFSSL_MSG("Input buffer too small for ECC PKCS#8 key");
        return BUFFER_E;
    }

    ret = wc_CreatePKCS8Key(output, &pkcs8Sz, tmpDer, tmpDerSz,
                            algoID, curveOID, oidSz);
    if (ret < 0) {
        XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    XFREE(tmpDer, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    *outLen = ret;
    return ret;
}

/* Write only private ecc key to unencrypted PKCS#8 format.
 *
 * return length on success else < 0 */
int wc_EccPrivateKeyToPKCS8(ecc_key* key, byte* output, word32* outLen)
{
    return eccToPKCS8(key, output, outLen, 0);
}

/* Write both private and public ecc keys to unencrypted PKCS#8 format.
 *
 * return length on success else < 0 */
int wc_EccKeyToPKCS8(ecc_key* key, byte* output,
                     word32* outLen)
{
    return eccToPKCS8(key, output, outLen, 1);
}
#endif /* HAVE_PKCS8 */
#endif /* HAVE_ECC_KEY_EXPORT && !NO_ASN_CRYPT */

#ifdef WC_ENABLE_ASYM_KEY_IMPORT
#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for Ed25519 and Ed448 private key.
 * RFC 8410, 7 - Private Key Format (but public value is EXPLICIT OCTET_STRING)
 */
static const ASNItem edKeyASN[] = {
/* SEQ            */    { 0, ASN_SEQUENCE, 1, 1, 0 },
                                         /* Version */
/* VER            */        { 1, ASN_INTEGER, 0, 0, 0 },
                                         /* privateKeyAlgorithm */
/* PKEYALGO_SEQ   */        { 1, ASN_SEQUENCE, 1, 1, 0 },
/* PKEYALGO_OID   */            { 2, ASN_OBJECT_ID, 0, 0, 1 },
                                         /* privateKey */
/* PKEY           */        { 1, ASN_OCTET_STRING, 0, 1, 0 },
                                             /* CurvePrivateKey */
/* PKEY_CURVEPKEY */            { 2, ASN_OCTET_STRING, 0, 0, 0 },
                                         /* attributes */
/* ATTRS          */        { 1, ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_ATTRS, 1, 1, 1 },
                                         /* publicKey */
/* PUBKEY         */        { 1, ASN_CONTEXT_SPECIFIC | ASN_ASYMKEY_PUBKEY, 1, 1, 1 },
                                             /* Public value */
/* PUBKEY_VAL     */            { 2, ASN_OCTET_STRING, 0, 0, 0 }
};
enum {
    EDKEYASN_IDX_SEQ = 0,
    EDKEYASN_IDX_VER,
    EDKEYASN_IDX_PKEYALGO_SEQ,
    EDKEYASN_IDX_PKEYALGO_OID,
    EDKEYASN_IDX_PKEY,
    EDKEYASN_IDX_PKEY_CURVEPKEY,
    EDKEYASN_IDX_ATTRS,
    EDKEYASN_IDX_PUBKEY,
    EDKEYASN_IDX_PUBKEY_VAL,
};

/* Number of items in ASN.1 template for Ed25519 and Ed448 private key. */
#define edKeyASN_Length (sizeof(edKeyASN) / sizeof(ASNItem))
#endif

#endif /* WC_ENABLE_ASYM_KEY_IMPORT */




#ifdef WC_ENABLE_ASYM_KEY_EXPORT

/* Build ASN.1 formatted key based on RFC 5958 (Asymmetric Key Packages)
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  privKey      private key buffer
 * @param [in]  privKeyLen   private ket buffer length
 * @param [in]  pubKey       public key buffer (optional)
 * @param [in]  pubKeyLen    public ket buffer length
 * @param [out] output       Buffer to put encoded data in (optional)
 * @param [in]  outLen       Size of buffer in bytes
 * @param [in]  keyType      is "enum Key_Sum" like ED25519k
 * @return  Size of encoded data in bytes on success
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 * @return  LENGTH_ONLY_E return length only.
 */
static int SetAsymKeyDer(const byte* privKey, word32 privKeyLen,
    const byte* pubKey, word32 pubKeyLen,
    byte* output, word32 outLen, int keyType)
{
    int ret = 0;
#ifndef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0, seqSz, verSz, algoSz, privSz, pubSz = 0, sz;
#else
    DECL_ASNSETDATA(dataASN, edKeyASN_Length);
    int sz;
#endif

    /* Validate parameters. */
    if (privKey == NULL || outLen == 0) {
        return BAD_FUNC_ARG;
    }

#ifndef WOLFSSL_ASN_TEMPLATE
    /* calculate size */
    if (pubKey) {
        pubSz = 2 + 2 + pubKeyLen;
    }
    privSz = 2 + 2 + privKeyLen;
    algoSz = SetAlgoID(keyType, NULL, oidKeyType, 0);
    verSz  = 3; /* version is 3 bytes (enum + id + version(byte)) */
    seqSz  = SetSequence(verSz + algoSz + privSz + pubSz, NULL);
    sz = seqSz + verSz + algoSz + privSz + pubSz;

    /* checkout output size */
    if (output != NULL && sz > outLen) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && output != NULL) {
        /* write out */
        /* seq */
        seqSz  = SetSequence(verSz + algoSz + privSz + pubSz, output);
        idx = seqSz;
        /* ver */
        SetMyVersion(0, output + idx, FALSE);
        idx += verSz;
        /* algo */
        algoSz = SetAlgoID(keyType, output + idx, oidKeyType, 0);
        idx += algoSz;
        /* privKey */
        idx += SetOctetString(2 + privKeyLen, output + idx);
        idx += SetOctetString(privKeyLen, output + idx);
        XMEMCPY(output + idx, privKey, privKeyLen);
        idx += privKeyLen;
        /* pubKey */
        if (pubKey) {
            idx += SetExplicit(1, 2 + pubKeyLen, output + idx);
            idx += SetOctetString(pubKeyLen, output + idx);
            XMEMCPY(output + idx, pubKey, pubKeyLen);
            idx += pubKeyLen;
        }

        ret = idx;
    }
#else

    CALLOC_ASNSETDATA(dataASN, edKeyASN_Length, ret, NULL);

    if (ret == 0) {
        /* Set version = 0 */
        SetASN_Int8Bit(&dataASN[EDKEYASN_IDX_VER], 0);
        /* Set OID. */
        SetASN_OID(&dataASN[EDKEYASN_IDX_PKEYALGO_OID], keyType, oidKeyType);
        /* Leave space for private key. */
        SetASN_Buffer(&dataASN[EDKEYASN_IDX_PKEY_CURVEPKEY], NULL, privKeyLen);
        /* Don't write out attributes. */
        dataASN[EDKEYASN_IDX_ATTRS].noOut = 1;
        if (pubKey) {
            /* Leave space for public key. */
            SetASN_Buffer(&dataASN[EDKEYASN_IDX_PUBKEY_VAL], NULL, pubKeyLen);
        }
        else {
            /* Don't put out public part. */
            SetASNItem_NoOutNode(dataASN, edKeyASN, EDKEYASN_IDX_PUBKEY,
                    edKeyASN_Length);
        }

        /* Calculate the size of encoding. */
        ret = SizeASN_Items(edKeyASN, dataASN, edKeyASN_Length, &sz);
    }

    /* Check buffer is big enough. */
    if ((ret == 0) && (output != NULL) && (sz > (int)outLen)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (output != NULL)) {
        /* Encode private key. */
        SetASN_Items(edKeyASN, dataASN, edKeyASN_Length, output);

        /* Put private value into space provided. */
        XMEMCPY((byte*)dataASN[EDKEYASN_IDX_PKEY_CURVEPKEY].data.buffer.data,
                privKey, privKeyLen);

        if (pubKey != NULL) {
            /* Put public value into space provided. */
            XMEMCPY((byte*)dataASN[EDKEYASN_IDX_PUBKEY_VAL].data.buffer.data,
                    pubKey, pubKeyLen);
        }

        /* Return size of encoding. */
        ret = sz;
    }

    FREE_ASNSETDATA(dataASN, NULL);
#endif
    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */










#ifndef WOLFSSL_ASN_TEMPLATE
#endif /* WOLFSSL_ASN_TEMPLATE */




#ifdef WOLFSSL_ASN_TEMPLATE
/* ASN.1 template for certificate name hash. */
static const ASNItem nameHashASN[] = {
/* OID  */ { 0, ASN_OBJECT_ID, 0, 0, 1 },
/* NAME */ { 0, ASN_SEQUENCE, 1, 0, 0 },
};
enum {
    NAMEHASHASN_IDX_OID = 0,
    NAMEHASHASN_IDX_NAME,
};

/* Number of items in ASN.1 template for certificate name hash. */
#define nameHashASN_Length (sizeof(nameHashASN) / sizeof(ASNItem))
#endif /* WOLFSSL_ASN_TEMPLATE */

/* store WC_SHA hash of NAME */
int GetNameHash(const byte* source, word32* idx, byte* hash, int maxIdx)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int    length;  /* length of all distinguished names */
    int    ret;
    word32 dummy;
    byte   tag;

    WOLFSSL_ENTER("GetNameHash");

    dummy = *idx;
    if (GetASNTag(source, &dummy, &tag, maxIdx) == 0 && tag == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (GetLength(source, idx, &length, maxIdx) < 0)
            return ASN_PARSE_E;

        *idx += length;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    dummy = *idx;
    if (GetSequence(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    ret = CalcHashId(source + dummy, length + *idx - dummy, hash);

    *idx += length;

    return ret;
#else
    ASNGetData dataASN[nameHashASN_Length];
    int ret;

    XMEMSET(dataASN, 0, sizeof(dataASN));
    /* Ignore the OID even when present. */
    GetASN_OID(&dataASN[NAMEHASHASN_IDX_OID], oidIgnoreType);
    /* Decode certificate name. */
    ret = GetASN_Items(nameHashASN, dataASN, nameHashASN_Length, 0, source, idx,
           maxIdx);
    if (ret == 0) {
        /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
         * calculated over the entire DER encoding of the Name field, including
         * the tag and length. */
        /* Calculate hash of complete name including SEQUENCE. */
        ret = CalcHashId(
                GetASNItem_Addr(dataASN[NAMEHASHASN_IDX_NAME], source),
                GetASNItem_Length(dataASN[NAMEHASHASN_IDX_NAME], source),
                hash);
    }

    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}





#ifdef WOLFSSL_CERT_PIV

#ifdef WOLFSSL_ASN_TEMPLATE
/* Template for PIV. */
static const ASNItem pivASN[] = {
/* CERT        */ { 0, ASN_PIV_CERT, 0, 0, 0 },
/* NONCE       */ { 0, ASN_PIV_NONCE, 0, 0, 1 },
/* SIGNEDNONCE */ { 0, ASN_PIV_SIGNED_NONCE, 0, 0, 1 },
};
enum {
    PIVASN_IDX_CERT = 0,
    PIVASN_IDX_NONCE,
    PIVASN_IDX_SIGNEDNONCE,
};

#define pivASN_Length (sizeof(pivASN) / sizeof(ASNItem))

static const ASNItem pivCertASN[] = {
                          /* 0x53 = 0x40 | 0x13 */
/* CERT */ { 1, ASN_APPLICATION | 0x13, 0, 1, 0 },
                               /* 0x70 = 0x40 | 0x10 + 0x20 (CONSTRUCTED) */
/* X509 */      { 2, ASN_APPLICATION | 0x10, 1, 0, 0 },
                               /* 0x71 = 0x40 | 0x11 + 0x20 (CONSTRUCTED) */
/* INFO */      { 2, ASN_APPLICATION | 0x11, 1, 0, 1 },
                               /* 0xFE = 0xC0 | 0x1E + 0x20 (CONSTRUCTED) */
/* ERR */      { 2, ASN_PRIVATE | 0x1e, 1, 0, 1 },
};
enum {
    PIVCERTASN_IDX_CERT,
    PIVCERTASN_IDX_X509,
    PIVCERTASN_IDX_INFO,
    PIVCERTASN_IDX_ERR,
};

#define pivCertASN_Length (sizeof(pivCertASN) / sizeof(ASNItem))
#endif

int wc_ParseCertPIV(wc_CertPIV* piv, const byte* buf, word32 totalSz)
{
#ifndef WOLFSSL_ASN_TEMPLATE
    int length = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("wc_ParseCertPIV");

    if (piv == NULL || buf == NULL || totalSz == 0)
        return BAD_FUNC_ARG;

    XMEMSET(piv, 0, sizeof(wc_CertPIV));

    /* Detect Identiv PIV (with 0x0A, 0x0B and 0x0C sections) */
    /* Certificate (0A 82 05FA) */
    if (GetASNHeader(buf, ASN_PIV_CERT, &idx, &length, totalSz) >= 0) {
        /* Identiv Type PIV card */
        piv->isIdentiv = 1;

        piv->cert =   &buf[idx];
        piv->certSz = length;
        idx += length;

        /* Nonce (0B 14) */
        if (GetASNHeader(buf, ASN_PIV_NONCE, &idx, &length, totalSz) >= 0) {
            piv->nonce =   &buf[idx];
            piv->nonceSz = length;
            idx += length;
        }

        /* Signed Nonce (0C 82 0100) */
        if (GetASNHeader(buf, ASN_PIV_SIGNED_NONCE, &idx, &length, totalSz) >= 0) {
            piv->signedNonce =   &buf[idx];
            piv->signedNonceSz = length;
        }

        idx = 0;
        buf = piv->cert;
        totalSz = piv->certSz;
    }

    /* Certificate Buffer Total Size (53 82 05F6) */
    if (GetASNHeader(buf, ASN_APPLICATION | ASN_PRINTABLE_STRING, &idx,
                                                   &length, totalSz) < 0) {
        return ASN_PARSE_E;
    }
    /* PIV Certificate (70 82 05ED) */
    if (GetASNHeader(buf, ASN_PIV_TAG_CERT, &idx, &length,
                                                         totalSz) < 0) {
        return ASN_PARSE_E;
    }

    /* Capture certificate buffer pointer and length */
    piv->cert =   &buf[idx];
    piv->certSz = length;
    idx += length;

    /* PIV Certificate Info (71 01 00) */
    if (GetASNHeader(buf, ASN_PIV_TAG_CERT_INFO, &idx, &length,
                                                        totalSz) >= 0) {
        if (length >= 1) {
            piv->compression = (buf[idx] & ASN_PIV_CERT_INFO_COMPRESSED);
            piv->isX509 =      ((buf[idx] & ASN_PIV_CERT_INFO_ISX509) != 0);
        }
        idx += length;
    }

    /* PIV Error Detection (FE 00) */
    if (GetASNHeader(buf, ASN_PIV_TAG_ERR_DET, &idx, &length,
                                                        totalSz) >= 0) {
        piv->certErrDet =   &buf[idx];
        piv->certErrDetSz = length;
        idx += length;
    }

    return 0;
#else
    /* pivCertASN_Length is longer than pivASN_Length */
    DECL_ASNGETDATA(dataASN, pivCertASN_Length);
    int ret = 0;
    word32 idx;
    byte info;

    WOLFSSL_ENTER("wc_ParseCertPIV");

    ALLOC_ASNGETDATA(dataASN, pivCertASN_Length, ret, NULL);

    if (ret == 0) {
        /* Clear dynamic data. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * pivASN_Length);
        /* Start parsing from start of buffer. */
        idx = 0;
        /* Parse Identiv wrapper. */
        ret = GetASN_Items(pivASN, dataASN, pivASN_Length, 1, buf, &idx,
                totalSz);
        if (ret == 0) {
            /* Identiv wrapper found. */
            piv->isIdentiv = 1;
            /* Get nonce reference. */
            if (dataASN[PIVASN_IDX_NONCE].tag != 0) {
                GetASN_GetConstRef(&dataASN[PIVASN_IDX_NONCE], &piv->nonce,
                        &piv->nonceSz);
            }
            /* Get signedNonce reference. */
            if (dataASN[PIVASN_IDX_SIGNEDNONCE].tag != 0) {
                GetASN_GetConstRef(&dataASN[PIVASN_IDX_SIGNEDNONCE],
                        &piv->signedNonce, &piv->signedNonceSz);
            }
            /* Get the certificate data for parsing. */
            GetASN_GetConstRef(&dataASN[PIVASN_IDX_CERT], &buf, &totalSz);
        }
        ret = 0;
    }
    if (ret == 0) {
        /* Clear dynamic data and set variable to put cert info into. */
        XMEMSET(dataASN, 0, sizeof(*dataASN) * pivCertASN_Length);
        GetASN_Int8Bit(&dataASN[PIVCERTASN_IDX_INFO], &info);
        /* Start parsing from start of buffer. */
        idx = 0;
        /* Parse PIV cetificate data. */
        ret = GetASN_Items(pivCertASN, dataASN, pivCertASN_Length, 1, buf, &idx,
                totalSz);
        if (ret == 0) {
            /* Get X.509 certificate reference. */
            GetASN_GetConstRef(&dataASN[PIVCERTASN_IDX_X509], &piv->cert,
                    &piv->certSz);
            /* Set the certificate info if available. */
            if (dataASN[PIVCERTASN_IDX_INFO].tag != 0) {
                /* Bits 1 and 2 are compression. */
                piv->compression = info & ASN_PIV_CERT_INFO_COMPRESSED;
                /* Bits 3 is X509 flag. */
                piv->isX509 = ((info & ASN_PIV_CERT_INFO_ISX509) != 0);
            }
            /* Get X.509 certificate error detection reference. */
            GetASN_GetConstRef(&dataASN[PIVCERTASN_IDX_ERR], &piv->certErrDet,
                     &piv->certErrDetSz);
        }
        ret = 0;
    }

    FREE_ASNGETDATA(dataASN, NULL);
    return ret;
#endif /* WOLFSSL_ASN_TEMPLATE */
}

#endif /* WOLFSSL_CERT_PIV */



#ifdef HAVE_SMIME

/*****************************************************************************
* wc_MIME_parse_headers - Reads the char array in and parses out MIME headers
* and parameters into headers.  Will continue until in has no more content.
*
* RETURNS:
* returns zero on success, non-zero on error.
*/
int wc_MIME_parse_headers(char* in, int inLen, MimeHdr** headers)
{
    MimeHdr* nextHdr = NULL;
    MimeHdr* curHdr = NULL;
    MimeParam* nextParam = NULL;
    size_t start = 0;
    size_t end = 0;
    char* nameAttr = NULL;
    char* bodyVal = NULL;
    MimeTypes mimeType = MIME_HDR;
    MimeStatus mimeStatus = MIME_NAMEATTR;
    int ret = -1;
    size_t pos = 0;
    size_t lineLen = 0;
    char* curLine = NULL;
    char* ptr = NULL;

    if (in == NULL || inLen <= 0 || in[inLen] != '\0' || headers == NULL) {
        ret = BAD_FUNC_ARG;
        goto error;
    }
    nextHdr = (MimeHdr*)XMALLOC(sizeof(MimeHdr), NULL, DYNAMIC_TYPE_PKCS7);
    nextParam = (MimeParam*)XMALLOC(sizeof(MimeParam), NULL,
                                    DYNAMIC_TYPE_PKCS7);
    if (nextHdr == NULL || nextParam == NULL) {
        ret = MEMORY_E;
        goto error;
    }
    XMEMSET(nextHdr, 0, (word32)sizeof(MimeHdr));
    XMEMSET(nextParam, 0, (word32)sizeof(MimeParam));

    curLine = XSTRTOK(in, "\r\n", &ptr);
    if (curLine == NULL) {
        ret = ASN_PARSE_E;
        goto error;
    }

    while (curLine != NULL) {
        /* Leftover from previous line, add params to previous header. */
        if (curLine[0] == ' ' && curHdr) {
            mimeType = MIME_PARAM;
        }
        else {
            mimeType = MIME_HDR;
        }
        start = 0;
        lineLen = XSTRLEN(curLine);
        if (lineLen == 0) {
            ret = BAD_FUNC_ARG;
            goto error;
        }

        for (pos = 0; pos < lineLen; pos++) {
            char cur = curLine[pos];

            if (mimeStatus == MIME_NAMEATTR && ((cur == ':' &&
                mimeType == MIME_HDR) || (cur == '=' &&
                mimeType == MIME_PARAM)) && pos >= 1) {
                mimeStatus = MIME_BODYVAL;
                end = pos-1;
                if (nameAttr != NULL)
                    XFREE(nameAttr, NULL, DYNAMIC_TYPE_PKCS7);
                ret = wc_MIME_header_strip(curLine, &nameAttr, start, end);
                if (ret) {
                    goto error;
                }
                start = pos+1;
            }
            else if (mimeStatus == MIME_BODYVAL && cur == ';' && pos >= 1) {
                end = pos-1;
                if (bodyVal != NULL)
                    XFREE(bodyVal, NULL, DYNAMIC_TYPE_PKCS7);
                ret = wc_MIME_header_strip(curLine, &bodyVal, start, end);
                if (ret) {
                    goto error;
                }
                if (mimeType == MIME_HDR) {
                    nextHdr->name = nameAttr;
                    nameAttr = NULL;
                    nextHdr->body = bodyVal;
                    bodyVal = NULL;
                    nextHdr->next = curHdr;
                    curHdr = nextHdr;
                    nextHdr = (MimeHdr*)XMALLOC(sizeof(MimeHdr), NULL,
                                                DYNAMIC_TYPE_PKCS7);
                    if (nextHdr == NULL) {
                        ret = MEMORY_E;
                        goto error;
                    }
                    XMEMSET(nextHdr, 0, (word32)sizeof(MimeHdr));
                }
                else {
                    nextParam->attribute = nameAttr;
                    nameAttr = NULL;
                    nextParam->value = bodyVal;
                    bodyVal = NULL;
                    nextParam->next = curHdr->params;
                    curHdr->params = nextParam;
                    nextParam = (MimeParam*)XMALLOC(sizeof(MimeParam), NULL,
                                                    DYNAMIC_TYPE_PKCS7);
                    if (nextParam == NULL) {
                        ret = MEMORY_E;
                        goto error;
                    }
                    XMEMSET(nextParam, 0, (word32)sizeof(MimeParam));
                }
                mimeType = MIME_PARAM;
                mimeStatus = MIME_NAMEATTR;
                start = pos+1;
            }
        }

        end = lineLen-1;
        /* Omit newline characters. */
        while ((curLine[end] == '\r' || curLine[end] == '\n') && end > 0) {
            end--;
        }
        if (end >= start && mimeStatus == MIME_BODYVAL) {
            ret = wc_MIME_header_strip(curLine, &bodyVal, start, end);
            if (ret) {
                goto error;
            }
            if (mimeType == MIME_HDR) {
                nextHdr->name = nameAttr;
                nameAttr = NULL;
                nextHdr->body = bodyVal;
                bodyVal = NULL;
                nextHdr->next = curHdr;
                curHdr = nextHdr;
                nextHdr = (MimeHdr*)XMALLOC(sizeof(MimeHdr), NULL,
                                            DYNAMIC_TYPE_PKCS7);
                if (nextHdr == NULL) {
                    ret = MEMORY_E;
                    goto error;
                }
                XMEMSET(nextHdr, 0, (word32)sizeof(MimeHdr));
            } else {
                nextParam->attribute = nameAttr;
                nameAttr = NULL;
                nextParam->value = bodyVal;
                bodyVal = NULL;
                nextParam->next = curHdr->params;
                curHdr->params = nextParam;
                nextParam = (MimeParam*)XMALLOC(sizeof(MimeParam), NULL,
                                                DYNAMIC_TYPE_PKCS7);
                if (nextParam == NULL) {
                    ret = MEMORY_E;
                    goto error;
                }
                XMEMSET(nextParam, 0, (word32)sizeof(MimeParam));
            }
        }

        curLine = XSTRTOK(NULL, "\r\n", &ptr);
        mimeStatus = MIME_NAMEATTR;
    }

    *headers = curHdr;
    ret = 0; /* success if at this point */

error:
    if (ret != 0)
        wc_MIME_free_hdrs(curHdr);
    wc_MIME_free_hdrs(nextHdr);
    if (nameAttr != NULL)
        XFREE(nameAttr, NULL, DYNAMIC_TYPE_PKCS7);
    if (bodyVal != NULL)
        XFREE(bodyVal, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(nextParam, NULL, DYNAMIC_TYPE_PKCS7);

    return ret;
}

/*****************************************************************************
* wc_MIME_header_strip - Reads the string in from indices start to end, strips
* out disallowed/separator characters and places the rest into *out.
*
* RETURNS:
* returns zero on success, non-zero on error.
*/
int wc_MIME_header_strip(char* in, char** out, size_t start, size_t end)
{
    size_t inPos = start;
    size_t outPos = 0;
    size_t inLen = 0;

    if (end < start || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    inLen = XSTRLEN(in);
    if (start > inLen || end > inLen) {
        return BAD_FUNC_ARG;
    }

    *out = (char*)XMALLOC(((end-start)+2)*sizeof(char), NULL,
                          DYNAMIC_TYPE_PKCS7);
    if (*out == NULL) {
        return MEMORY_E;
    }

    while (inPos <= end) {
        if (in[inPos] >= MIME_HEADER_ASCII_MIN && in[inPos] <=
            MIME_HEADER_ASCII_MAX && in[inPos] != ';' && in[inPos] != '\"') {
            (*out)[outPos] = in[inPos];
            outPos++;
        }
        inPos++;
    }
    (*out)[outPos] = '\0';

    return 0;
}

/*****************************************************************************
* wc_MIME_find_header_name - Searches through all given headers until a header with
* a name matching the provided name is found.
*
* RETURNS:
* returns a pointer to the found header, if no match was found, returns NULL.
*/
MimeHdr* wc_MIME_find_header_name(const char* name, MimeHdr* header)
{
    while (header) {
        if (!XSTRCMP(name, header->name)) {
            return header;
        }
        header = header->next;
    }

    return header;
}

/*****************************************************************************
* wc_MIME_find_param_attr - Searches through all parameters until a parameter
* with a attribute matching the provided attribute is found.
*
* RETURNS:
* returns a pointer to the found parameter, if no match was found,
* returns NULL.
*/
MimeParam* wc_MIME_find_param_attr(const char* attribute,
                                    MimeParam* param)
{
    while (param) {
        if (!XSTRCMP(attribute, param->attribute)) {
            return param;
        }
        param = param->next;
    }

    return param;
}

/*****************************************************************************
* wc_MIME_single_canonicalize - Canonicalize a line by converting the trailing
* line ending to CRLF.
*
* line - input line to canonicalize
* len  - length of line in chars on input, length of output array on return
*
* RETURNS:
* returns a pointer to a canonicalized line on success, NULL on error.
*/
char* wc_MIME_single_canonicalize(const char* line, word32* len)
{
    size_t end = 0;
    char* canonLine = NULL;

    if (line == NULL || len == NULL || *len == 0) {
        return NULL;
    }

    end = *len;
    while (end >= 1 && ((line[end-1] == '\r') || (line[end-1] == '\n'))) {
        end--;
    }

    /* Need 2 chars for \r\n and 1 for EOL */
    canonLine = (char*)XMALLOC((end+3)*sizeof(char), NULL, DYNAMIC_TYPE_PKCS7);
    if (canonLine == NULL) {
        return NULL;
    }

    XMEMCPY(canonLine, line, end);
    canonLine[end] = '\r';
    canonLine[end+1] = '\n';
    canonLine[end+2] = '\0';
    *len = (word32)(end + 3);

    return canonLine;
}

/*****************************************************************************
* wc_MIME_free_hdrs - Frees all MIME headers, parameters and strings starting from
* the provided header pointer.
*
* RETURNS:
* returns zero on success, non-zero on error.
*/
int wc_MIME_free_hdrs(MimeHdr* head)
{
    MimeHdr* curHdr = NULL;
    MimeParam* curParam = NULL;

    while (head) {
        while (head->params) {
            curParam = head->params;
            head->params = head->params->next;
            XFREE(curParam->attribute, NULL, DYNAMIC_TYPE_PKCS7);
            XFREE(curParam->value, NULL, DYNAMIC_TYPE_PKCS7);
            XFREE(curParam, NULL, DYNAMIC_TYPE_PKCS7);
        }
        curHdr = head;
        head = head->next;
        XFREE(curHdr->name, NULL, DYNAMIC_TYPE_PKCS7);
        XFREE(curHdr->body, NULL, DYNAMIC_TYPE_PKCS7);
        XFREE(curHdr, NULL, DYNAMIC_TYPE_PKCS7);
    }

    return 0;
}

#endif /* HAVE_SMIME */


#undef ERROR_OUT

#endif /* !NO_ASN */

#ifdef WOLFSSL_SEP


#endif /* WOLFSSL_SEP */
