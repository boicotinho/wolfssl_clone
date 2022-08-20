/* tls13.c
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
 * BUILD_GCM
 *    Enables AES-GCM ciphersuites.
 * HAVE_AESCCM
 *    Enables AES-CCM ciphersuites.
 * HAVE_SESSION_TICKET
 *    Enables session tickets - required for TLS 1.3 resumption.
 * NO_PSK
 *    Do not enable Pre-Shared Keys.
 * HAVE_KEYING_MATERIAL
 *    Enables exporting keying material based on section 7.5 of RFC 8446.
 * WOLFSSL_ASYNC_CRYPT
 *    Enables the use of asynchronous cryptographic operations.
 *    This is available for ciphers and certificates.
 * HAVE_CHACHA && HAVE_POLY1305
 *    Enables use of CHACHA20-POLY1305 ciphersuites.
 * WOLFSSL_DEBUG_TLS
 *    Writes out details of TLS 1.3 protocol including handshake message buffers
 *    and key generation input and output.
 * WOLFSSL_EARLY_DATA
 *    Allow 0-RTT Handshake using Early Data extensions and handshake message
 * WOLFSSL_EARLY_DATA_GROUP
 *    Group EarlyData message with ClientHello when sending
 * WOLFSSL_NO_SERVER_GROUPS_EXT
 *    Do not send the server's groups in an extension when the server's top
 *    preference is not in client's list.
 * WOLFSSL_POST_HANDSHAKE_AUTH
 *    Allow TLS v1.3 code to perform post-handshake authentication of the
 *    client.
 * WOLFSSL_SEND_HRR_COOKIE
 *    Send a cookie in hello_retry_request message to enable stateless tracking
 *    of ClientHello replies.
 * WOLFSSL_TLS13
 *    Enable TLS 1.3 protocol implementation.
 * WOLFSSL_TLS13_MIDDLEBOX_COMPAT
 *    Enable middlebox compatibility in the TLS 1.3 handshake.
 *    This includes sending ChangeCipherSpec before encrypted messages and
 *    including a session id.
 * WOLFSSL_TLS13_SHA512
 *    Allow generation of SHA-512 digests in handshake - no ciphersuite
 *    requires SHA-512 at this time.
 * WOLFSSL_TLS13_TICKET_BEFORE_FINISHED
 *    Allow a NewSessionTicket message to be sent by server before Client's
 *    Finished message.
 *    See TLS v1.3 specification, Section 4.6.1, Paragraph 4 (Note).
 * WOLFSSL_PSK_ONE_ID
 *    When only one PSK ID is used and only one call to the PSK callback can
 *    be made per connect.
 *    You cannot use wc_psk_client_cs_callback type callback on client.
 * WOLFSSL_CHECK_ALERT_ON_ERR
 *    Check for alerts during the handshake in the event of an error.
 * WOLFSSL_NO_CLIENT_CERT_ERROR
 *    Requires client to set a client certificate
 * WOLFSSL_PSK_MULTI_ID_PER_CS
 *    When multiple PSK identities are available for the same cipher suite.
 *    Sets the first byte of the client identity to the count of identites
 *    that have been seen so far for the cipher suite.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

