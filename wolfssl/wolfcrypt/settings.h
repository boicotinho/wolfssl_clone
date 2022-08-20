/* settings.h
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


/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */


#ifndef WOLF_CRYPT_SETTINGS_H
#define WOLF_CRYPT_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

/* This flag allows wolfSSL to include options.h instead of having client
 * projects do it themselves. This should *NEVER* be defined when building
 * wolfSSL as it can cause hard to debug problems. */
#ifdef EXTERNAL_OPTS_OPENVPN
#include <wolfssl/options.h>
#endif

/* Uncomment next line if using IPHONE */
/* #define IPHONE */

/* Uncomment next line if using ThreadX */
/* #define THREADX */

/* Uncomment next line if using Micrium uC/OS-III */
/* #define MICRIUM */

/* Uncomment next line if using Deos RTOS*/
/* #define WOLFSSL_DEOS*/

/* Uncomment next line if using Mbed */
/* #define MBED */

/* Uncomment next line if using Microchip PIC32 ethernet starter kit */
/* #define MICROCHIP_PIC32 */

/* Uncomment next line if using Microchip TCP/IP stack, version 5 */
/* #define MICROCHIP_TCPIP_V5 */

/* Uncomment next line if using Microchip TCP/IP stack, version 6 or later */
/* #define MICROCHIP_TCPIP */

/* Uncomment next line if using above Microchip TCP/IP defines with BSD API */
/* #define MICROCHIP_TCPIP_BSD_API */

/* Uncomment next line if using PIC32MZ Crypto Engine */
/* #define WOLFSSL_MICROCHIP_PIC32MZ */

/* Uncomment next line if using FreeRTOS */
/* #define FREERTOS */

/* Uncomment next line if using FreeRTOS+ TCP */
/* #define FREERTOS_TCP */

/* Uncomment next line if using FreeRTOS Windows Simulator */
/* #define FREERTOS_WINSIM */

/* Uncomment next line if using RTIP */
/* #define EBSNET */

/* Uncomment next line if using lwip */
/* #define WOLFSSL_LWIP */

/* Uncomment next line if building wolfSSL for a game console */
/* #define WOLFSSL_GAME_BUILD */

/* Uncomment next line if building wolfSSL for LSR */
/* #define WOLFSSL_LSR */

/* Uncomment next line if building for Freescale Classic MQX version 5.0 */
/* #define FREESCALE_MQX_5_0 */

/* Uncomment next line if building for Freescale Classic MQX version 4.0 */
/* #define FREESCALE_MQX_4_0 */

/* Uncomment next line if building for Freescale Classic MQX/RTCS/MFS */
/* #define FREESCALE_MQX */

/* Uncomment next line if building for Freescale KSDK MQX/RTCS/MFS */
/* #define FREESCALE_KSDK_MQX */

/* Uncomment next line if building for Freescale KSDK Bare Metal */
/* #define FREESCALE_KSDK_BM */

/* Uncomment next line if building for Freescale KSDK FreeRTOS, */
/* (old name FREESCALE_FREE_RTOS) */
/* #define FREESCALE_KSDK_FREERTOS */

/* Uncomment next line if using STM32F2 */
/* #define WOLFSSL_STM32F2 */

/* Uncomment next line if using STM32F4 */
/* #define WOLFSSL_STM32F4 */

/* Uncomment next line if using STM32FL */
/* #define WOLFSSL_STM32FL */

/* Uncomment next line if using STM32F7 */
/* #define WOLFSSL_STM32F7 */

/* Uncomment next line if using QL SEP settings */
/* #define WOLFSSL_QL */

/* Uncomment next line if building for EROAD */
/* #define WOLFSSL_EROAD */

/* Uncomment next line if building for IAR EWARM */
/* #define WOLFSSL_IAR_ARM */

/* Uncomment next line if building for Rowley CrossWorks ARM */
/* #define WOLFSSL_ROWLEY_ARM */

/* Uncomment next line if using TI-RTOS settings */
/* #define WOLFSSL_TIRTOS */

/* Uncomment next line if building with PicoTCP */
/* #define WOLFSSL_PICOTCP */

/* Uncomment next line if building for PicoTCP demo bundle */
/* #define WOLFSSL_PICOTCP_DEMO */

/* Uncomment next line if building for uITRON4  */
/* #define WOLFSSL_uITRON4 */

/* Uncomment next line if building for uT-Kernel */
/* #define WOLFSSL_uTKERNEL2 */

/* Uncomment next line if using Max Strength build */
/* #define WOLFSSL_MAX_STRENGTH */

/* Uncomment next line if building for VxWorks */
/* #define WOLFSSL_VXWORKS */

/* Uncomment next line if building for Nordic nRF5x platform */
/* #define WOLFSSL_NRF5x */

/* Uncomment next line to enable deprecated less secure static DH suites */
/* #define WOLFSSL_STATIC_DH */

/* Uncomment next line to enable deprecated less secure static RSA suites */
/* #define WOLFSSL_STATIC_RSA */

/* Uncomment next line if building for ARDUINO */
/* Uncomment both lines if building for ARDUINO on INTEL_GALILEO */
/* #define WOLFSSL_ARDUINO */
/* #define INTEL_GALILEO */

/* Uncomment next line to enable asynchronous crypto WC_PENDING_E */
/* #define WOLFSSL_ASYNC_CRYPT */

/* Uncomment next line if building for uTasker */
/* #define WOLFSSL_UTASKER */

/* Uncomment next line if building for embOS */
/* #define WOLFSSL_EMBOS */

/* Uncomment next line if building for RIOT-OS */
/* #define WOLFSSL_RIOT_OS */

/* Uncomment next line if building for using XILINX hardened crypto */
/* #define WOLFSSL_XILINX_CRYPT */

/* Uncomment next line if building for using XILINX */
/* #define WOLFSSL_XILINX */

/* Uncomment next line if building for WICED Studio. */
/* #define WOLFSSL_WICED  */

/* Uncomment next line if building for Nucleus 1.2 */
/* #define WOLFSSL_NUCLEUS_1_2 */

/* Uncomment next line if building for using Apache mynewt */
/* #define WOLFSSL_APACHE_MYNEWT */

/* Uncomment next line if building for using ESP-IDF */
/* #define WOLFSSL_ESPIDF */

/* Uncomment next line if using Espressif ESP32-WROOM-32 */
/* #define WOLFSSL_ESPWROOM32 */

/* Uncomment next line if using Espressif ESP32-WROOM-32SE */
/* #define WOLFSSL_ESPWROOM32SE */

/* Uncomment next line if using ARM CRYPTOCELL*/
/* #define WOLFSSL_CRYPTOCELL */

/* Uncomment next line if using RENESAS TSIP */
/* #define WOLFSSL_RENESAS_TSIP */

/* Uncomment next line if using RENESAS RX64N */
/* #define WOLFSSL_RENESAS_RX65N */

/* Uncomment next line if using RENESAS SCE Protected Mode */
/* #define WOLFSSL_RENESAS_SCEPROTECT */

/* Uncomment next line if using RENESAS RA6M4 */
/* #define WOLFSSL_RENESAS_RA6M4 */

/* Uncomment next line if using Solaris OS*/
/* #define WOLFSSL_SOLARIS */

/* Uncomment next line if building for Linux Kernel Module */
/* #define WOLFSSL_LINUXKM */

/* Uncomment next line if building for devkitPro */
/* #define DEVKITPRO */

/* Uncomment next line if building for Dolphin Emulator */
/* #define DOLPHIN_EMULATOR */

#include <wolfssl/wolfcrypt/visibility.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include "user_settings.h"
#elif defined(USE_HAL_DRIVER) && !defined(HAVE_CONFIG_H)
    /* STM Configuration File (generated by CubeMX) */
    #include "wolfSSL.I-CUBE-wolfSSL_conf.h"
#endif

#define WOLFSSL_MAKE_FIPS_VERSION(major, minor) (((major) * 256) + (minor))
    #define WOLFSSL_FIPS_VERSION_CODE WOLFSSL_MAKE_FIPS_VERSION(0,0)

#define FIPS_VERSION_LT(major,minor) (WOLFSSL_FIPS_VERSION_CODE < WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_LE(major,minor) (WOLFSSL_FIPS_VERSION_CODE <= WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_EQ(major,minor) (WOLFSSL_FIPS_VERSION_CODE == WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_GE(major,minor) (WOLFSSL_FIPS_VERSION_CODE >= WOLFSSL_MAKE_FIPS_VERSION(major,minor))
#define FIPS_VERSION_GT(major,minor) (WOLFSSL_FIPS_VERSION_CODE > WOLFSSL_MAKE_FIPS_VERSION(major,minor))

/* make sure old RNG name is used with CTaoCrypt FIPS */


#if defined(_WIN32) && !defined(_M_X64)

/* The _M_X64 macro is what's used in the headers for MSC to tell if it
 * has the 64-bit versions of the 128-bit integers available. If one is
 * building on 32-bit Windows with AES-NI, turn off the AES-GCMloop
 * unrolling. */

    #define AES_GCM_AESNI_NO_UNROLL
#endif

#ifdef IPHONE
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef THREADX
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef HAVE_NETX
    #ifdef NEED_THREADX_TYPES
        #include <types.h>
    #endif
    #include <nx_api.h>
#endif

#if defined(WOLFSSL_ESPIDF)
    #define FREERTOS
    #define WOLFSSL_LWIP
    #define NO_WRITEV
    #define SIZEOF_LONG_LONG 8
    #define NO_WOLFSSL_DIR
    #define WOLFSSL_NO_CURRDIR

    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(303)
    #define WC_RSA_BLINDING

#if defined(WOLFSSL_ESPWROOM32) || defined(WOLFSSL_ESPWROOM32SE)
   #ifndef NO_ESP32WROOM32_CRYPT
        #define WOLFSSL_ESP32WROOM32_CRYPT
        #if defined(ESP32_USE_RSA_PRIMITIVE) && \
            !defined(NO_WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI)
            #define WOLFSSL_ESP32WROOM32_CRYPT_RSA_PRI
// error : inserted by coan: "#define WOLFSSL_SMALL_STACK" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(318)
        #endif
   #endif
#endif
#endif /* WOLFSSL_ESPIDF */

#if defined(WOLFCRYPT_ONLY)
    #undef WOLFSSL_RENESAS_TSIP
#endif /* WOLFCRYPT_ONLY */
#if defined(WOLFSSL_RENESAS_TSIP)
    #define TSIP_TLS_HMAC_KEY_INDEX_WORDSIZE 64
    #define TSIP_TLS_MASTERSECRET_SIZE       80   /* 20 words */
    #define TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY 560 /* in byte  */
    #if !defined(NO_RENESAS_TSIP_CRYPT) && defined(WOLFSSL_RENESAS_RX65N)
        #define WOLFSSL_RENESAS_TSIP_CRYPT
        #define WOLFSSL_RENESAS_TSIP_TLS
        #define WOLFSSL_RENESAS_TSIP_TLS_AES_CRYPT
    #endif
#endif /* WOLFSSL_RENESAS_TSIP */

#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    #define SCE_TLS_MASTERSECRET_SIZE         80  /* 20 words */
    #define TSIP_TLS_HMAC_KEY_INDEX_WORDSIZE  64
    #define TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY 560 /* in bytes */
    #define SCE_TLS_CLIENTRANDOM_SZ           36  /* in bytes */
    #define SCE_TLS_SERVERRANDOM_SZ           36  /* in bytes */
    #define SCE_TLS_ENCRYPTED_ECCPUBKEY_SZ    96  /* in bytes */

    #define WOLFSSL_RENESAS_SCEPROTECT_ECC
    #if defined(WOLFSSL_RENESAS_SCEPROTECT_ECC)
// error : inserted by coan: "#define HAVE_PK_CALLBACKS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(348)
        /* #define DEBUG_PK_CB */
    #endif
#endif
#if defined(WOLFSSL_RENESAS_RA6M3G) || defined(WOLFSSL_RENESAS_RA6M3) ||\
              defined(WOLFSSL_RENESAS_RA6M4)
    /* settings in user_settings.h */
#endif

#if defined(WOLFSSL_LWIP_NATIVE) || \
    defined(HAVE_LWIP_NATIVE) /* using LwIP native TCP socket */
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(360)

    #if defined(HAVE_LWIP_NATIVE)
    #define WOLFSSL_LWIP
    #define NO_WRITEV
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(365)
    #define NO_FILESYSTEM
    #endif
#endif

#if defined(WOLFSSL_CONTIKI)
    #include <contiki.h>
// error : inserted by coan: "#define WOLFSSL_UIP" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(372)
    #define NO_WOLFSSL_MEMORY
    #define NO_WRITEV
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(375)
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(376)
    #define NO_FILESYSTEM
    #ifndef CUSTOM_RAND_GENERATE
        #define CUSTOM_RAND_TYPE uint16_t
        #define CUSTOM_RAND_GENERATE random_rand
    #endif
    static inline word32 LowResTimer(void)
    {
       return clock_seconds();
    }
#endif

#if defined(WOLFSSL_IAR_ARM) || defined(WOLFSSL_ROWLEY_ARM)
    #define NO_MAIN_DRIVER
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(390)
    #if !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
        #define USE_CERT_BUFFERS_1024
    #endif
    #define BENCH_EMBEDDED
    #define NO_FILESYSTEM
    #define NO_WRITEV
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(397)
    #define BENCH_EMBEDDED
#endif

#ifdef MICROCHIP_PIC32
    /* #define WOLFSSL_MICROCHIP_PIC32MZ */
    #define SIZEOF_LONG_LONG 8
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(404)
    #ifndef MICROCHIP_TCPIP_BSD_API
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(406)
    #endif
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define TFM_TIMING_RESISTANT
    #define NO_BIG_INT
#endif

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX

    #ifndef NO_PIC32MZ_CRYPT
        #define WOLFSSL_PIC32MZ_CRYPT
    #endif
    #ifndef NO_PIC32MZ_RNG
        #define WOLFSSL_PIC32MZ_RNG
    #endif
    #ifndef NO_PIC32MZ_HASH
        #define WOLFSSL_PIC32MZ_HASH
    #endif
#endif

#ifdef MICROCHIP_TCPIP_V5
    /* include timer functions */
    #include "TCPIP Stack/TCPIP.h"
#endif

#ifdef MICROCHIP_TCPIP
    /* include timer, NTP functions */
    #ifdef MICROCHIP_MPLAB_HARMONY
        #include "tcpip/tcpip.h"
    #else
        #include "system/system_services.h"
        #include "tcpip/sntp.h"
    #endif
#endif


#ifdef MBED
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(457)
    #define NO_FILESYSTEM
// error : inserted by coan: "#define NO_CERTS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(459)
    #if !defined(USE_CERT_BUFFERS_2048) && !defined(USE_CERT_BUFFERS_4096)
        #define USE_CERT_BUFFERS_1024
    #endif
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_SHA512
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(466)
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define WOLFSSL_CMSIS_RTOS
#endif


#ifdef WOLFSSL_EROAD
// error : inserted by coan: "#define FREESCALE_MQX" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(477)
    #define FREESCALE_MMCAU
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(479)
    #define NO_STDIO_FILESYSTEM
    #define WOLFSSL_LEANPSK
// error : inserted by coan: "#define HAVE_NULL_CIPHER" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(482)
// error : inserted by coan: "#define NO_OLD_TLS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(483)
// error : inserted by coan: "#define NO_ASN" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(449)
    #define NO_BIG_INT
// error : inserted by coan: "#define NO_RSA" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(486)
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(488)
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
// error : inserted by coan: "#define NO_CERTS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(491)
    #define NO_PWDBASED
    #define NO_MD5
    #define NO_MAIN_DRIVER
#endif

#ifdef WOLFSSL_PICOTCP
    #ifndef errno
        #define errno pico_err
    #endif
    #include "pico_defines.h"
    #include "pico_stack.h"
    #include "pico_constants.h"
    #include "pico_protocol.h"
    #ifndef CUSTOM_RAND_GENERATE
        #define CUSTOM_RAND_GENERATE pico_rand
    #endif
#endif

#ifdef WOLFSSL_PICOTCP_DEMO
    #define WOLFSSL_STM32
    #define TFM_TIMING_RESISTANT
    #define XMALLOC(s, h, type)  PICO_ZALLOC((s))
    #define XFREE(p, h, type)    PICO_FREE((p))
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(520)
    #define NO_WRITEV
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(522)
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
#endif

#ifdef FREERTOS_WINSIM
    #define FREERTOS
// error : inserted by coan: "#define USE_WINDOWS_API" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(529)
#endif


#ifdef WOLFSSL_VXWORKS
    /* VxWorks simulator incorrectly detects building for i386 */
    #ifdef VXWORKS_SIM
        #define TFM_NO_ASM
    #endif
    /* For VxWorks pthreads wrappers for mutexes uncomment the next line. */
    /* #define WOLFSSL_PTHREADS */
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
    #define TFM_TIMING_RESISTANT
    #define NO_MAIN_DRIVER
    #define NO_DEV_RANDOM
    #define NO_WRITEV
    #define HAVE_STRINGS_H
#endif


#ifdef WOLFSSL_ARDUINO
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(554)
    #define NO_DEV_RANDOM
    #ifndef INTEL_GALILEO /* Galileo has time.h compatibility */
        #define TIME_OVERRIDES
        #ifndef XTIME
            #error "Must define XTIME externally see porting guide"
            #error "https://www.wolfssl.com/docs/porting-guide/"
        #endif
        #ifndef XGMTIME
            #error "Must define XGMTIME externally see porting guide"
            #error "https://www.wolfssl.com/docs/porting-guide/"
        #endif
    #endif
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(567)
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(569)
#endif


#ifdef WOLFSSL_UTASKER
    /* uTasker configuration - used for fnRandom() */
    #include "config.h"

// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(578)
    #define NO_WOLFSSL_DIR
    #define WOLFSSL_HAVE_MIN
    #define NO_WRITEV

// error : inserted by coan: "#define ALT_ECC_SIZE" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(563)
    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(565)

    /* used in wolfCrypt test */
    #define NO_MAIN_DRIVER
    #define USE_CERT_BUFFERS_2048

    /* uTasker port uses RAW sockets, use I/O callbacks
     * See wolfSSL uTasker example for sample callbacks */
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(595)

    /* uTasker filesystem not ported  */
    #define NO_FILESYSTEM

    /* uTasker RNG is abstracted, calls HW RNG when available */
    #define CUSTOM_RAND_GENERATE    fnRandom
    #define CUSTOM_RAND_TYPE        unsigned short

    /* user needs to define XTIME to function that provides
     * seconds since Unix epoch */
    #ifndef XTIME
        #error XTIME must be defined in wolfSSL settings.h
        /* #define XTIME fnSecondsSinceEpoch */
    #endif

    /* use uTasker std library replacements where available */
    #define STRING_USER
    #define XMEMCPY(d,s,l)         uMemcpy((d),(s),(l))
    #define XMEMSET(b,c,l)         uMemset((b),(c),(l))
    #define XMEMCMP(s1,s2,n)       uMemcmp((s1),(s2),(n))
    #define XMEMMOVE(d,s,l)        memmove((d),(s),(l))

    #define XSTRLEN(s1)            uStrlen((s1))
    #define XSTRNCPY(s1,s2,n)      strncpy((s1),(s2),(n))
    #define XSTRSTR(s1,s2)         strstr((s1),(s2))
    #define XSTRNSTR(s1,s2,n)      mystrnstr((s1),(s2),(n))
    #define XSTRNCMP(s1,s2,n)      strncmp((s1),(s2),(n))
    #define XSTRNCAT(s1,s2,n)      strncat((s1),(s2),(n))
    #define XSTRNCASECMP(s1,s2,n)  _strnicmp((s1),(s2),(n))
    #if defined(WOLFSSL_CERT_EXT) || defined(HAVE_ALPN)
        #define XSTRTOK            strtok_r
    #endif
#endif

#ifdef WOLFSSL_EMBOS
    #define NO_FILESYSTEM           /* Not ported at this time */
    #define USE_CERT_BUFFERS_2048   /* use when NO_FILESYSTEM */
    #define NO_MAIN_DRIVER
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(636)
#endif

#ifdef WOLFSSL_RIOT_OS
    #define NO_WRITEV
    #define TFM_NO_ASM
    #define NO_FILESYSTEM
    #define USE_CERT_BUFFERS_2048
    #if defined(WOLFSSL_GNRC)
// error : inserted by coan: "#define WOLFSSL_DTLS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(645)
    #endif
#endif

#ifdef WOLFSSL_CHIBIOS
    /* ChibiOS definitions. This file is distributed with chibiOS. */
    #include "wolfssl_chibios.h"
#endif

#ifdef WOLFSSL_PB
    /* PB is using older 1.2 version of Nucleus */
    #undef WOLFSSL_NUCLEUS
    #define WOLFSSL_NUCLEUS_1_2
#endif

#ifdef WOLFSSL_NUCLEUS_1_2
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR

    #if !defined(NO_ASN_TIME) && !defined(USER_TIME)
        #error User must define XTIME, see manual
    #endif

    #if !defined(XMALLOC_OVERRIDE) && !defined(XMALLOC_USER)
        extern void* nucleus_malloc(unsigned long size, void* heap, int type);
        extern void* nucleus_realloc(void* ptr, unsigned long size, void* heap,
                                     int type);
        extern void  nucleus_free(void* ptr, void* heap, int type);

        #define XMALLOC(s, h, type)  nucleus_malloc((s), (h), (type))
        #define XREALLOC(p, n, h, t) nucleus_realloc((p), (n), (h), (t))
        #define XFREE(p, h, type)    nucleus_free((p), (h), (type))
    #endif
#endif

#ifdef WOLFSSL_NRF5x
        #define SIZEOF_LONG 4
        #define SIZEOF_LONG_LONG 8
        #define NO_DEV_RANDOM
        #define NO_FILESYSTEM
        #define NO_MAIN_DRIVER
        #define NO_WRITEV
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(687)
        #define TFM_TIMING_RESISTANT
        #define WOLFSSL_NRF51
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(691)
#endif

/* Micrium will use Visual Studio for compilation but not the Win32 API */
#if defined(_WIN32) && !defined(MICRIUM) && !defined(FREERTOS) &&  !defined(FREERTOS_TCP) && !defined(WOLFSSL_EROAD) &&  !defined(WOLFSSL_UTASKER) && !defined(INTIME_RTOS)
// error : inserted by coan: "#define USE_WINDOWS_API" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(699)
#endif

#if defined(WOLFSSL_uITRON4)

#define XMALLOC_USER
#include <stddef.h>
#define ITRON_POOL_SIZE 1024*20
extern int uITRON4_minit(size_t poolsz) ;
extern void *uITRON4_malloc(size_t sz) ;
extern void *uITRON4_realloc(void *p, size_t sz) ;
extern void uITRON4_free(void *p) ;

#define XMALLOC(sz, heap, type)     uITRON4_malloc(sz)
#define XREALLOC(p, sz, heap, type) uITRON4_realloc(p, sz)
#define XFREE(p, heap, type)        uITRON4_free(p)
#endif

#if defined(WOLFSSL_uTKERNEL2)
  #ifndef NO_TKERNEL_MEM_POOL
    #define XMALLOC_OVERRIDE
    int   uTKernel_init_mpool(unsigned int sz); /* initializing malloc pool */
    void* uTKernel_malloc(unsigned int sz);
    void* uTKernel_realloc(void *p, unsigned int sz);
    void  uTKernel_free(void *p);
    #define XMALLOC(s, h, type)  uTKernel_malloc((s))
    #define XREALLOC(p, n, h, t) uTKernel_realloc((p), (n))
    #define XFREE(p, h, type)    uTKernel_free((p))
  #endif

  #ifndef NO_STDIO_FGETS_REMAP
    #include <stdio.h>
    #include "tm/tmonitor.h"

    /* static char* gets(char *buff); */
    static char* fgets(char *buff, int sz, XFILE fp) {
        char * s = buff;
        *s = '\0';
        while (1) {
            *s = tm_getchar(-1);
            tm_putchar(*s);
            if (*s == '\r') {
                tm_putchar('\n');
                *s = '\0';
                break;
            }
            s++;
        }
        return buff;
    }
  #endif /* !NO_STDIO_FGETS_REMAP */
#endif


#if defined(WOLFSSL_LEANPSK) && !defined(XMALLOC_USER) && \
        !defined(NO_WOLFSSL_MEMORY)
    #include <stdlib.h>
    #define XMALLOC(s, h, type)  malloc((s))
    #define XFREE(p, h, type)    free((p))
    #define XREALLOC(p, n, h, t) realloc((p), (n))
#endif

#if defined(XMALLOC_USER) && defined(SSN_BUILDING_LIBYASSL)
    #undef  XMALLOC
    #define XMALLOC     yaXMALLOC
    #undef  XFREE
    #define XFREE       yaXFREE
    #undef  XREALLOC
    #define XREALLOC    yaXREALLOC
#endif


#ifdef FREERTOS
    #include "FreeRTOS.h"

    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY)
        #define XMALLOC(s, h, type)  pvPortMalloc((s))
        #define XFREE(p, h, type)    vPortFree((p))
        /* FreeRTOS pvPortRealloc() implementation can be found here:
            https://github.com/wolfSSL/wolfssl-freertos/pull/3/files */
    #endif

    #ifndef NO_WRITEV
        #define NO_WRITEV
    #endif
    #ifndef HAVE_SHA512
        #ifndef NO_SHA512
            #define NO_SHA512
        #endif
    #endif
    #ifndef HAVE_DH
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(802)
    #endif

        #include "semphr.h"
#endif

#ifdef FREERTOS_TCP
    #if !defined(NO_WOLFSSL_MEMORY) && !defined(XMALLOC_USER)
        #define XMALLOC(s, h, type)  pvPortMalloc((s))
        #define XFREE(p, h, type)    vPortFree((p))
    #endif

    #define WOLFSSL_GENSEED_FORTEST

    #define NO_WOLFSSL_DIR
    #define NO_WRITEV
    #define TFM_TIMING_RESISTANT
    #define NO_MAIN_DRIVER
#endif

#ifdef WOLFSSL_TI_CRYPT
    #define NO_GCM_ENCRYPT_EXTRA
    #define NO_PUBLIC_GCM_SET_IV
    #define NO_PUBLIC_CCM_SET_NONCE
#endif

#ifdef WOLFSSL_TIRTOS
    #define SIZEOF_LONG_LONG 8
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR

    /* Use SP_MATH by default, unless
     * specified in user_settings.
     */
    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(797)
    #define WC_RSA_BLINDING
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define NO_SIG_WRAPPER
    #define NO_MAIN_DRIVER
    #define USE_CERT_BUFFERS_2048
// error : inserted by coan: "#define NO_ERROR_STRINGS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(860)
    /* Uncomment this setting if your toolchain does not offer time.h header */
    /* #define USER_TIME */
    #define HAVE_ALPN
    #define USE_WOLF_STRTOK /* use with HAVE_ALPN */
    #ifdef __IAR_SYSTEMS_ICC__
        #pragma diag_suppress=Pa089
    #elif !defined(__GNUC__)
        /* Suppress the sslpro warning */
        #pragma diag_suppress=11
    #endif
    #include <ti/sysbios/hal/Seconds.h>
#endif


#ifdef WOLFSSL_GAME_BUILD
    #define SIZEOF_LONG_LONG 8
#endif

#ifdef WOLFSSL_LSR
// error : inserted by coan: "#define HAVE_WEBSERVER" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(936)
    #define SIZEOF_LONG_LONG 8
    #define WOLFSSL_LOW_MEMORY
    #define NO_WRITEV
    #define NO_SHA512
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(941)
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define NO_DEV_RANDOM
    #define NO_WOLFSSL_DIR
    #ifndef NO_FILESYSTEM
        #define LSR_FS
        #include "inc/hw_types.h"
        #include "fs.h"
    #endif
    #define WOLFSSL_LWIP
    #include <errno.h>  /* for tcp errno */
    #define WOLFSSL_SAFERTOS
    #if defined(__IAR_SYSTEMS_ICC__)
        /* enum uses enum */
        #pragma diag_suppress=Pa089
    #endif
#endif

#ifdef WOLFSSL_SAFERTOS
        #include "SafeRTOS/semphr.h"
        #include "SafeRTOS/heap.h"
    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY)
        #define XMALLOC(s, h, type)  pvPortMalloc((s))
        #define XFREE(p, h, type)    vPortFree((p))

        /* FreeRTOS pvPortRealloc() implementation can be found here:
            https://github.com/wolfSSL/wolfssl-freertos/pull/3/files */
    #endif
#endif

#ifdef WOLFSSL_LOW_MEMORY
    #undef  RSA_LOW_MEM
    #define RSA_LOW_MEM
// error : inserted by coan: "#define WOLFSSL_SMALL_STACK" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(986)
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT
#endif

/* To support storing some of the large constant tables in flash memory rather than SRAM.
   Useful for processors that have limited SRAM, such as the AVR family of microtrollers. */
#ifdef WOLFSSL_USE_FLASHMEM
    /* This is supported on the avr-gcc compiler, for more information see:
         https://gcc.gnu.org/onlinedocs/gcc/Named-Address-Spaces.html */
    #define FLASH_QUALIFIER __flash

    /* Copy data out of flash memory and into SRAM */
    #define XMEMCPY_P(pdest, psrc, size) memcpy_P((pdest), (psrc), (size))
#else
    #define FLASH_QUALIFIER
#endif

#ifdef FREESCALE_MQX_5_0
    /* use normal Freescale MQX port, but with minor changes for 5.0 */
// error : inserted by coan: "#define FREESCALE_MQX" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1006)
#endif

#ifdef FREESCALE_MQX_4_0
    /* use normal Freescale MQX port, but with minor changes for 4.0 */
// error : inserted by coan: "#define FREESCALE_MQX" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1011)
#endif



#if defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)
    #define NO_FILESYSTEM
    #define WOLFSSL_CRYPT_HW_MUTEX 1

    #if !defined(XMALLOC_USER) && !defined(NO_WOLFSSL_MEMORY)
        #define XMALLOC(s, h, type)  pvPortMalloc((s))
        #define XFREE(p, h, type)    vPortFree((p))
    #endif

    /* #define USER_TICKS */
    /* Allows use of DH with fixed points if uncommented and NO_DH is removed */
    /* WOLFSSL_DH_CONST */
    #define WOLFSSL_LWIP
    #define FREERTOS_TCP

    #define FREESCALE_FREE_RTOS
    #define FREERTOS_SOCKET_ERROR ( -1 )
    #define FREERTOS_EWOULDBLOCK ( -2 )
    #define FREERTOS_EINVAL ( -4 )
    #define FREERTOS_EADDRNOTAVAIL ( -5 )
    #define FREERTOS_EADDRINUSE ( -6 )
    #define FREERTOS_ENOBUFS ( -7 )
    #define FREERTOS_ENOPROTOOPT ( -8 )
#endif /* FREESCALE_FREE_RTOS || FREESCALE_KSDK_FREERTOS */

#ifdef FREESCALE_KSDK_BM
    #define FREESCALE_COMMON
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1100)
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1101)
    #define NO_FILESYSTEM
    #ifndef TIME_OVERRIDES
        #define USER_TICKS
    #endif
#endif /* FREESCALE_KSDK_BM */

#ifdef FREESCALE_COMMON
    #define SIZEOF_LONG_LONG 8

    /* disable features */
    #undef  NO_WRITEV
    #define NO_WRITEV
    #undef  NO_DEV_RANDOM
    #define NO_DEV_RANDOM
    #undef  NO_WOLFSSL_DIR
    #define NO_WOLFSSL_DIR

    /* enable features */

    #define USE_CERT_BUFFERS_2048
    #define BENCH_EMBEDDED

    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(947)

// error : inserted by coan: "#undef HAVE_ECC" contradicts -D symbol at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1131)
    #ifndef WOLFCRYPT_FIPS_RAND
    #endif
// error : inserted by coan: "#define HAVE_AESCCM" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1137)
        #undef  WOLFSSL_AES_COUNTER
        #define WOLFSSL_AES_COUNTER
        #undef  WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT

    #ifdef FREESCALE_KSDK_1_3
        #include "fsl_device_registers.h"
    #else
        /* Classic MQX does not have fsl_common.h */
        #include "fsl_common.h"
    #endif

    /* random seed */
    #define NO_OLD_RNGNAME
    #if   defined(FREESCALE_NO_RNG)
        /* nothing to define */
    #elif defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
        #define FREESCALE_KSDK_2_0_TRNG
    #elif defined(FSL_FEATURE_SOC_RNG_COUNT) && (FSL_FEATURE_SOC_RNG_COUNT > 0)
        #ifdef FREESCALE_KSDK_1_3
            #include "fsl_rnga_driver.h"
            #define FREESCALE_RNGA
            #define RNGA_INSTANCE (0)
        #else
            #define FREESCALE_KSDK_2_0_RNGA
        #endif
    #elif !defined(FREESCALE_KSDK_BM) && !defined(FREESCALE_FREE_RTOS) && !defined(FREESCALE_KSDK_FREERTOS)
        #define FREESCALE_RNGA
        #define RNGA_INSTANCE (0)
        /* defaulting to K70 RNGA, user should change if different */
        /* #define FREESCALE_K53_RNGB */
        #define FREESCALE_K70_RNGA
    #endif

    /* HW crypto */
    /* automatic enable based on Kinetis feature */
    /* if case manual selection is required, for example for benchmarking purposes,
     * just define FREESCALE_USE_MMCAU or FREESCALE_USE_LTC or none of these two macros (for software only)
     * both can be enabled simultaneously as LTC has priority over MMCAU in source code.
     */
    /* #define FSL_HW_CRYPTO_MANUAL_SELECTION */
    #ifndef FSL_HW_CRYPTO_MANUAL_SELECTION
        #if defined(FSL_FEATURE_SOC_MMCAU_COUNT) && FSL_FEATURE_SOC_MMCAU_COUNT
            #define FREESCALE_USE_MMCAU
        #endif

        #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
            #define FREESCALE_USE_LTC
        #endif
    #else
        /* #define FREESCALE_USE_MMCAU */
        /* #define FREESCALE_USE_LTC */
    #endif
#endif /* FREESCALE_COMMON */

/* Classic pre-KSDK mmCAU library */
#ifdef FREESCALE_USE_MMCAU_CLASSIC
    #define FREESCALE_USE_MMCAU
    #define FREESCALE_MMCAU_CLASSIC
    #define FREESCALE_MMCAU_CLASSIC_SHA
#endif

/* KSDK mmCAU library */
#ifdef FREESCALE_USE_MMCAU
    /* AES and DES */
    #define FREESCALE_MMCAU
    /* MD5, SHA-1 and SHA-256 */
    #define FREESCALE_MMCAU_SHA
#endif /* FREESCALE_USE_MMCAU */

#ifdef FREESCALE_USE_LTC
    #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
        #define FREESCALE_LTC
        #define LTC_BASE LTC0

        #if defined(FSL_FEATURE_LTC_HAS_DES) && FSL_FEATURE_LTC_HAS_DES
            #define FREESCALE_LTC_DES
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_GCM) && FSL_FEATURE_LTC_HAS_GCM
            #define FREESCALE_LTC_AES_GCM
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_SHA) && FSL_FEATURE_LTC_HAS_SHA
            #define FREESCALE_LTC_SHA
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_PKHA) && FSL_FEATURE_LTC_HAS_PKHA
            #ifndef WOLFCRYPT_FIPS_RAND
            #define FREESCALE_LTC_ECC
            #endif
            #define FREESCALE_LTC_TFM

            /* the LTC PKHA hardware limit is 2048 bits (256 bytes) for integer arithmetic.
               the LTC_MAX_INT_BYTES defines the size of local variables that hold big integers. */
            /* size is multiplication of 2 big ints */
                #define LTC_MAX_INT_BYTES   (256*2)

            /* This FREESCALE_LTC_TFM_RSA_4096_ENABLE macro can be defined.
             * In such a case both software and hardware algorithm
             * for TFM is linked in. The decision for which algorithm is used is determined at runtime
             * from size of inputs. If inputs and result can fit into LTC (see LTC_MAX_INT_BYTES)
             * then we call hardware algorithm, otherwise we call software algorithm.
             *
             * Chinese reminder theorem is used to break RSA 4096 exponentiations (both public and private key)
             * into several computations with 2048-bit modulus and exponents.
             */
            /* #define FREESCALE_LTC_TFM_RSA_4096_ENABLE */

            /* ECC-384, ECC-256, ECC-224 and ECC-192 have been enabled with LTC PKHA acceleration */
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1064)

                /* the LTC PKHA hardware limit is 512 bits (64 bytes) for ECC.
                   the LTC_MAX_ECC_BITS defines the size of local variables that hold ECC parameters
                   and point coordinates */
                #ifndef LTC_MAX_ECC_BITS
                    #define LTC_MAX_ECC_BITS (384)
                #endif

                /* Enable curves up to 384 bits */
                #if !defined(ECC_USER_CURVES)
                    #define ECC_USER_CURVES
// error : inserted by coan: "#define HAVE_ECC192" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1269)
                #endif
        #endif
    #endif
#endif /* FREESCALE_USE_LTC */

#ifdef FREESCALE_LTC_TFM_RSA_4096_ENABLE
    #undef  USE_CERT_BUFFERS_4096
    #define USE_CERT_BUFFERS_4096
    #undef  FP_MAX_BITS
    #define FP_MAX_BITS (8192)
    #undef  SP_INT_BITS
    #define SP_INT_BITS (4096)

// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1288)
#endif /* FREESCALE_LTC_TFM_RSA_4096_ENABLE */

/* if LTC has AES engine but doesn't have GCM, use software with LTC AES ECB mode */
#if defined(FREESCALE_USE_LTC) && !defined(FREESCALE_LTC_AES_GCM)
    #define GCM_TABLE
#endif

#if defined(WOLFSSL_STM32F2) || defined(WOLFSSL_STM32F4) || \
    defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32F1) || \
    defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
    defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32H7) || \
    defined(WOLFSSL_STM32G0) || defined(WOLFSSL_STM32U5)

    #define SIZEOF_LONG_LONG 8
    #ifndef CHAR_BIT
      #define CHAR_BIT 8
    #endif
    #define NO_DEV_RANDOM
    #define NO_WOLFSSL_DIR
    #ifndef NO_STM32_RNG
        #undef  STM32_RNG
        #define STM32_RNG
        #ifdef WOLFSSL_STM32F427_RNG
            #include "stm32f427xx.h"
        #endif
    #endif
    #ifndef NO_STM32_CRYPTO
        #undef  STM32_CRYPTO
        #define STM32_CRYPTO

        #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
            defined(WOLFSSL_STM32WB)
        #endif
    #endif
    #ifndef NO_STM32_HASH
        #undef  STM32_HASH
        #define STM32_HASH
    #endif
    #if !defined(__GNUC__) && !defined(__ICCARM__)
        #define KEIL_INTRINSICS
    #endif
    #define NO_OLD_RNGNAME
    #ifdef WOLFSSL_STM32_CUBEMX
        #if defined(WOLFSSL_STM32F1)
            #include "stm32f1xx_hal.h"
        #elif defined(WOLFSSL_STM32F2)
            #include "stm32f2xx_hal.h"
        #elif defined(WOLFSSL_STM32L5)
            #include "stm32l5xx_hal.h"
        #elif defined(WOLFSSL_STM32L4)
            #include "stm32l4xx_hal.h"
        #elif defined(WOLFSSL_STM32F4)
            #include "stm32f4xx_hal.h"
        #elif defined(WOLFSSL_STM32F7)
            #include "stm32f7xx_hal.h"
        #elif defined(WOLFSSL_STM32F1)
            #include "stm32f1xx_hal.h"
        #elif defined(WOLFSSL_STM32H7)
            #include "stm32h7xx_hal.h"
        #elif defined(WOLFSSL_STM32WB)
            #include "stm32wbxx_hal.h"
        #elif defined(WOLFSSL_STM32G0)
            #include "stm32g0xx_hal.h"
        #elif defined(WOLFSSL_STM32U5)
            #include "stm32u5xx_hal.h"
        #endif
        #if defined(WOLFSSL_CUBEMX_USE_LL) && defined(WOLFSSL_STM32L4)
            #include "stm32l4xx_ll_rng.h"
        #endif

        #ifndef STM32_HAL_TIMEOUT
            #define STM32_HAL_TIMEOUT   0xFF
        #endif
    #else
        #if defined(WOLFSSL_STM32F2)
            #include "stm32f2xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32f2xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32f2xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32F4)
            #include "stm32f4xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32f4xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32f4xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32L5)
            #include "stm32l5xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32l5xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32l5xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32L4)
            #include "stm32l4xx.h"
            #ifdef STM32_CRYPTO
                #include "stm32l4xx_cryp.h"
            #endif
            #ifdef STM32_HASH
                #include "stm32l4xx_hash.h"
            #endif
        #elif defined(WOLFSSL_STM32F7)
            #include "stm32f7xx.h"
        #elif defined(WOLFSSL_STM32H7)
            #include "stm32h7xx.h"
        #elif defined(WOLFSSL_STM32F1)
            #include "stm32f1xx.h"
        #endif
    #endif /* WOLFSSL_STM32_CUBEMX */
#endif /* WOLFSSL_STM32F2 || WOLFSSL_STM32F4 || WOLFSSL_STM32L4 ||
          WOLFSSL_STM32L5 || WOLFSSL_STM32F7 || WOLFSSL_STMWB ||
          WOLFSSL_STM32H7 || WOLFSSL_STM32G0 || WOLFSSL_STM32U5 */
#ifdef WOLFSSL_DEOS
    #include <deos.h>
    #include <timeout.h>
    #include <socketapi.h>
    #include <lwip-socket.h>
    #include <mem.h>
    #include <string.h>
    #include <stdlib.h> /* for rand_r: pseudo-random number generator */
    #include <stdio.h>  /* for snprintf */

    /* use external memory XMALLOC, XFREE and XREALLOC functions */
    #define XMALLOC_USER

    /* disable fall-back case, malloc, realloc and free are unavailable */
// error : inserted by coan: "#define WOLFSSL_NO_MALLOC" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1222)

    /* file system has not been ported since it is a separate product. */

    #define NO_FILESYSTEM

    #ifdef NO_FILESYSTEM
        #define NO_WOLFSSL_DIR
        #define NO_WRITEV
    #endif

    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1234)
    #define WC_RSA_BLINDING

    #define TFM_ECC192
    #define TFM_ECC224
    #define TFM_ECC384
    #define TFM_ECC521


    #if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
#endif /* WOLFSSL_DEOS*/

#ifdef MICRIUM
    #include <stdlib.h>
    #include <os.h>
    #if defined(RTOS_MODULE_NET_AVAIL) || (APP_CFG_TCPIP_EN == DEF_ENABLED)
        #include <net_cfg.h>
        #include <net_sock.h>
        #if (OS_VERSION < 50000)
            #include <net_err.h>
        #endif
    #endif
    #include <lib_mem.h>
    #include <lib_math.h>
    #include <lib_str.h>
    #include  <stdio.h>
    #include <string.h>

    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1268)
    #define WC_RSA_BLINDING

// error : inserted by coan: "#define ALT_ECC_SIZE" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1271)
    #define TFM_ECC192
    #define TFM_ECC224
    #define TFM_ECC384
    #define TFM_ECC521


    #define NO_WOLFSSL_DIR
    #define NO_WRITEV

    #if !defined(CUSTOM_RAND_GENERATE)
        #define CUSTOM_RAND_TYPE     RAND_NBR
        #define CUSTOM_RAND_GENERATE Math_Rand
    #endif
    #define STRING_USER
    #define XSTRLEN(pstr) ((CPU_SIZE_T)Str_Len((CPU_CHAR *)(pstr)))
    #define XSTRNCPY(pstr_dest, pstr_src, len_max) \
                    ((CPU_CHAR *)Str_Copy_N((CPU_CHAR *)(pstr_dest), \
                     (CPU_CHAR *)(pstr_src), (CPU_SIZE_T)(len_max)))
    #define XSTRNCMP(pstr_1, pstr_2, len_max) \
                    ((CPU_INT16S)Str_Cmp_N((CPU_CHAR *)(pstr_1), \
                     (CPU_CHAR *)(pstr_2), (CPU_SIZE_T)(len_max)))
    #define XSTRNCASECMP(pstr_1, pstr_2, len_max) \
                    ((CPU_INT16S)Str_CmpIgnoreCase_N((CPU_CHAR *)(pstr_1), \
                     (CPU_CHAR *)(pstr_2), (CPU_SIZE_T)(len_max)))
    #define XSTRSTR(pstr, pstr_srch) \
                    ((CPU_CHAR *)Str_Str((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch)))
    #define XSTRNSTR(pstr, pstr_srch, len_max) \
                    ((CPU_CHAR *)Str_Str_N((CPU_CHAR *)(pstr), \
                     (CPU_CHAR *)(pstr_srch),(CPU_SIZE_T)(len_max)))
    #define XSTRNCAT(pstr_dest, pstr_cat, len_max) \
                    ((CPU_CHAR *)Str_Cat_N((CPU_CHAR *)(pstr_dest), \
                     (const CPU_CHAR *)(pstr_cat),(CPU_SIZE_T)(len_max)))
    #define XMEMSET(pmem, data_val, size) \
                    ((void)Mem_Set((void *)(pmem), \
                    (CPU_INT08U) (data_val), \
                    (CPU_SIZE_T)(size)))
    #define XMEMCPY(pdest, psrc, size) ((void)Mem_Copy((void *)(pdest), \
                     (void *)(psrc), (CPU_SIZE_T)(size)))

    #if (OS_VERSION < 50000)
        #define XMEMCMP(pmem_1, pmem_2, size)                   \
                   (((CPU_BOOLEAN)Mem_Cmp((void *)(pmem_1),     \
                                          (void *)(pmem_2),     \
                     (CPU_SIZE_T)(size))) ? DEF_NO : DEF_YES)
    #else
      /* Work around for Micrium OS version 5.8 change in behavior
       * that returns DEF_NO for 0 size compare
       */
        #define XMEMCMP(pmem_1, pmem_2, size)                           \
            (( (size < 1 ) ||                                           \
               ((CPU_BOOLEAN)Mem_Cmp((void *)(pmem_1),                  \
                                     (void *)(pmem_2),                  \
                                     (CPU_SIZE_T)(size)) == DEF_YES))   \
             ? 0 : 1)
        #define XSNPRINTF snprintf
    #endif

    #define XMEMMOVE XMEMCPY

    #if (OS_CFG_MUTEX_EN == DEF_DISABLED)
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1548)
    #endif

    #if (CPU_CFG_ENDIAN_TYPE == CPU_ENDIAN_TYPE_BIG)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
#endif /* MICRIUM */

#if defined(sun)
# if defined(__SVR4) || defined(__svr4__)
    /* Solaris */
    #ifndef WOLFSSL_SOLARIS
        #define WOLFSSL_SOLARIS
    #endif
# else
    /* SunOS */
# endif
#endif

#ifdef WOLFSSL_SOLARIS
    /* Avoid naming clash with fp_zero from math.h > ieefp.h */
    #define WOLFSSL_DH_CONST
#endif

#ifdef WOLFSSL_MCF5441X
    #define BIG_ENDIAN_ORDER
    #ifndef SIZEOF_LONG
        #define SIZEOF_LONG 4
    #endif
    #ifndef SIZEOF_LONG_LONG
        #define SIZEOF_LONG_LONG 8
    #endif
#endif

#ifdef WOLFSSL_QL
    #ifndef WOLFSSL_SEP
        #define WOLFSSL_SEP
    #endif
// error : inserted by coan: "#define OPENSSL_EXTRA" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1590)
// error : inserted by coan: "#define SESSION_CERTS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1593)
// error : inserted by coan: "#define HAVE_AESCCM" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1596)
// error : inserted by coan: "#define ATOMIC_USER" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1599)
    #ifndef WOLFSSL_DER_LOAD
        #define WOLFSSL_DER_LOAD
    #endif
// error : inserted by coan: "#define KEEP_PEER_CERT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1605)
    #ifndef SESSION_INDEX
        #define SESSION_INDEX
    #endif
#endif /* WOLFSSL_QL */


#if defined(WOLFSSL_XILINX)
    #define NO_WOLFSSL_DIR
    #define NO_DEV_RANDOM
#endif

#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_AFALG_XILINX)
    #if defined(WOLFSSL_ARMASM)
        #error can not use both ARMv8 instructions and XILINX hardened crypto
    #endif
        /* only SHA3-384 is supported */
        #undef WOLFSSL_NOSHA3_224
        #undef WOLFSSL_NOSHA3_256
        #undef WOLFSSL_NOSHA3_512
        #define WOLFSSL_NOSHA3_224
        #define WOLFSSL_NOSHA3_256
        #define WOLFSSL_NOSHA3_512
    #ifdef WOLFSSL_AFALG_XILINX_AES
        #undef  WOLFSSL_AES_DIRECT
        #define WOLFSSL_AES_DIRECT
    #endif
#endif /*(WOLFSSL_XILINX_CRYPT)*/

#ifdef WOLFSSL_KCAPI_AES
    #define WOLFSSL_AES_GCM_FIXED_IV_AAD
#endif

#if defined(WOLFSSL_APACHE_MYNEWT)
    #include "os/os_malloc.h"
    #if !defined(WOLFSSL_LWIP)
        #include <mn_socket/mn_socket.h>
    #endif

    #if !defined(SIZEOF_LONG)
        #define SIZEOF_LONG 4
    #endif
    #if !defined(SIZEOF_LONG_LONG)
        #define SIZEOF_LONG_LONG 8
    #endif
    #if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN_ORDER
    #else
        #undef  BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
    #define NO_WRITEV
// error : inserted by coan: "#define WOLFSSL_USER_IO" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1673)
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1674)
    #define NO_DEV_RANDOM
// error : inserted by coan: "#define NO_DH" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1676)
    #define NO_WOLFSSL_DIR
// error : inserted by coan: "#define NO_ERROR_STRINGS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1678)
// error : inserted by coan: "#define NO_ERROR_STRINGS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1681)
    #define XMALLOC_USER
    #define XMALLOC(sz, heap, type)     os_malloc(sz)
    #define XREALLOC(p, sz, heap, type) os_realloc(p, sz)
    #define XFREE(p, heap, type)        os_free(p)

#endif /*(WOLFSSL_APACHE_MYNEWT)*/

#ifdef WOLFSSL_ZEPHYR
    #include <zephyr.h>
    #include <sys/printk.h>
    #include <sys/util.h>
    #include <stdlib.h>

    #define WOLFSSL_DH_CONST
    #define WOLFSSL_HAVE_MAX
    #define NO_WRITEV

    #define USE_FLAT_BENCHMARK_H
    #define USE_FLAT_TEST_H
    #define EXIT_FAILURE 1
    #define MAIN_NO_ARGS

    void *z_realloc(void *ptr, size_t size);
    #define realloc   z_realloc

    #ifndef CONFIG_NET_SOCKETS_POSIX_NAMES
    #define CONFIG_NET_SOCKETS_POSIX_NAMES
    #endif
#endif

#ifdef WOLFSSL_IMX6
    #ifndef SIZEOF_LONG_LONG
        #define SIZEOF_LONG_LONG 8
    #endif
#endif

/* if defined turn on all CAAM support */
#ifdef WOLFSSL_IMX6_CAAM
    #undef  WOLFSSL_IMX6_CAAM_RNG
    #define WOLFSSL_IMX6_CAAM_RNG

    #undef  WOLFSSL_IMX6_CAAM_BLOB
    #define WOLFSSL_IMX6_CAAM_BLOB

    /* large performance gain with HAVE_AES_ECB defined */
    #undef HAVE_AES_ECB
    #define HAVE_AES_ECB

    /* @TODO used for now until plugging in caam aes use with qnx */
    #undef WOLFSSL_AES_DIRECT
    #define WOLFSSL_AES_DIRECT
#endif

/* If DCP is used without SINGLE_THREADED, enforce WOLFSSL_CRYPT_HW_MUTEX */
#if defined(WOLFSSL_IMXRT_DCP)
    #undef WOLFSSL_CRYPT_HW_MUTEX
    #define WOLFSSL_CRYPT_HW_MUTEX 1
#endif

#if !defined(XMALLOC_USER) && !defined(MICRIUM_MALLOC) && \
    !defined(WOLFSSL_LEANPSK) && !defined(NO_WOLFSSL_MEMORY) && \
    !defined(XMALLOC_OVERRIDE)
    #define USE_WOLFSSL_MEMORY
#endif




/* stream ciphers except arc4 need 32bit alignment, intel ok without */
#ifndef XSTREAM_ALIGN
    #if defined(__x86_64__) || defined(__ia64__) || defined(__i386__)
        #define NO_XSTREAM_ALIGN
    #else
        #define XSTREAM_ALIGN
    #endif
#endif

/* write dup cannot be used with secure renegotiation because write dup
 * make write side write only and read side read only */

#ifdef WOLFSSL_SGX
        #define NO_WRITEV
        #define NO_MAIN_DRIVER
        #define USER_TICKS
        #define WOLFSSL_LOG_PRINTF
        #define WOLFSSL_DH_CONST
        #define WC_RSA_BLINDING

    #define NO_FILESYSTEM
// error : inserted by coan: "#define ECC_TIMING_RESISTANT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1535)
    #define TFM_TIMING_RESISTANT
// error : inserted by coan: "#define SINGLE_THREADED" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1802)
    #define NO_ASN_TIME /* can not use headers such as windows.h */
    #define USE_CERT_BUFFERS_2048
#endif /* WOLFSSL_SGX */

/* FreeScale MMCAU hardware crypto has 4 byte alignment.
   However, KSDK fsl_mmcau.h gives API with no alignment
   requirements (4 byte alignment is managed internally by fsl_mmcau.c) */
#ifdef FREESCALE_MMCAU
    #ifdef FREESCALE_MMCAU_CLASSIC
        #define WOLFSSL_MMCAU_ALIGNMENT 4
    #else
        #define WOLFSSL_MMCAU_ALIGNMENT 0
    #endif
#endif

/* if using hardware crypto and have alignment requirements, specify the
   requirement here.  The record header of SSL/TLS will prevent easy alignment.
   This hint tries to help as much as possible.  */

    #if defined(__GNUC__)
        #define XGEN_ALIGN __attribute__((aligned(WOLFSSL_GENERAL_ALIGNMENT)))
    #else
        #define XGEN_ALIGN
    #endif


#ifdef __INTEL_COMPILER
    #pragma warning(disable:2259) /* explicit casts to smaller sizes, disable */
#endif

/* user can specify what curves they want with ECC_USER_CURVES otherwise
 * all curves are on by default for now */
#ifndef ECC_USER_CURVES
// error : inserted by coan: "#define HAVE_ALL_CURVES" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(1856)
#endif

/* The minimum allowed ECC key size */
/* Note: 224-bits is equivelant to 2048-bit RSA */
#ifndef ECC_MIN_KEY_SZ
    #ifdef WOLFSSL_MIN_ECC_BITS
        #define ECC_MIN_KEY_SZ WOLFSSL_MIN_ECC_BITS
    #else
        #if FIPS_VERSION_GE(2,0)
            /* FIPSv2 and ready (for now) includes 192-bit support */
            #define ECC_MIN_KEY_SZ 192
        #else
            #define ECC_MIN_KEY_SZ 224
        #endif
    #endif
#endif

/* ECC Configs */
    /* By default enable Sign, Verify, DHE, Key Import and Key Export unless explicitly disabled */
    #if !defined(NO_ECC_SIGN) &&   !defined(WC_NO_RNG)
        #undef HAVE_ECC_SIGN
        #define HAVE_ECC_SIGN
    #endif
    #ifndef NO_ECC_VERIFY
    #endif
    #ifndef NO_ECC_CHECK_KEY
        #undef HAVE_ECC_CHECK_KEY
        #define HAVE_ECC_CHECK_KEY
    #endif
    #if !defined(NO_ECC_DHE) && !defined(WC_NO_RNG)
    #endif
    #ifndef NO_ECC_KEY_IMPORT
    #endif
    #ifndef NO_ECC_KEY_EXPORT
    #endif

/* Curve25519 Configs */

/* Ed25519 Configs */

/* Curve448 Configs */

/* Ed448 Configs */

/* AES Config */
    /* By default enable all AES key sizes, decryption and CBC */
    #ifndef AES_MAX_KEY_SIZE
        #undef  AES_MAX_KEY_SIZE
        #define AES_MAX_KEY_SIZE    256
    #endif

    #ifndef NO_AES_128
        #undef  WOLFSSL_AES_128
        #define WOLFSSL_AES_128
    #endif
    #if !defined(WOLFSSL_AES_128) && !defined(WOLFSSL_AES_256) && \
        defined(HAVE_ECC_ENCRYPT)
        #warning HAVE_ECC_ENCRYPT uses AES 128/256 bit keys
     #endif

    #ifndef NO_AES_DECRYPT
        #undef  HAVE_AES_DECRYPT
        #define HAVE_AES_DECRYPT
    #endif
    #ifndef NO_AES_CBC
        #undef  HAVE_AES_CBC
        #define HAVE_AES_CBC
    #endif
    #ifdef WOLFSSL_AES_XTS
        /* AES-XTS makes calls to AES direct functions */
    #endif
    #ifdef WOLFSSL_AES_CFB
        /* AES-CFB makes calls to AES direct functions */
    #endif

#if  !defined(HAVE_AES_CBC)
// error : inserted by coan: "#define WOLFSSL_AEAD_ONLY" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2040)
#endif

#if !defined(HAVE_PUBLIC_FFDHE) && !defined(WOLFSSL_NO_PUBLIC_FFDHE) && FIPS_VERSION_LE(2,0)
    /* This should only be enabled for FIPS v2 or older. It enables use of the
     * older wc_Dh_ffdhe####_Get() API's */
    #define HAVE_PUBLIC_FFDHE
#endif

#if defined(HAVE_FFDHE_8192)
    #define MIN_FFDHE_FP_MAX_BITS 16384
#elif defined(HAVE_FFDHE_6144)
    #define MIN_FFDHE_FP_MAX_BITS 12288
#elif defined(HAVE_FFDHE_4096)
    #define MIN_FFDHE_FP_MAX_BITS 8192
#elif defined(HAVE_FFDHE_3072)
    #define MIN_FFDHE_FP_MAX_BITS 6144
#else
    #define MIN_FFDHE_FP_MAX_BITS 4096
#endif
#if defined(FP_MAX_BITS)
    #if MIN_FFDHE_FP_MAX_BITS > FP_MAX_BITS
        #error "FFDHE parameters are too large for FP_MAX_BIT as set"
    #endif
#endif
#if defined(SP_INT_BITS)
    #if MIN_FFDHE_FP_MAX_BITS > SP_INT_BITS * 2
        #error "FFDHE parameters are too large for SP_INT_BIT as set"
    #endif
#endif

/* if desktop type system and fastmath increase default max bits */
    #if !defined(FP_MAX_BITS)
            #define FP_MAX_BITS 8192
    #endif
    #if defined(WOLFSSL_SP_MATH_ALL) && !defined(SP_INT_BITS)
            #define SP_INT_BITS 4096
    #endif

/* If using the max strength build, ensure OLD TLS is disabled. */


/* Default AES minimum auth tag sz, allow user to override */
#ifndef WOLFSSL_MIN_AUTH_TAG_SZ
    #define WOLFSSL_MIN_AUTH_TAG_SZ 12
#endif


/* sniffer requires:
 * static RSA cipher suites
 * session stats and peak stats
 */

/* Decode Public Key extras on by default, user can turn off with
 * WOLFSSL_NO_DECODE_EXTRA */
#ifndef WOLFSSL_NO_DECODE_EXTRA
    #ifndef RSA_DECODE_EXTRA
        #define RSA_DECODE_EXTRA
    #endif
    #ifndef ECC_DECODE_EXTRA
        #define ECC_DECODE_EXTRA
    #endif
#endif

/* C Sharp wrapper defines */
#ifdef HAVE_CSHARP
// error : inserted by coan: "#define WOLFSSL_DTLS" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2149)
// error : inserted by coan: "#undef NO_PSK" contradicts -D symbol at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2151)
#endif

/* Asynchronous Crypto */
#ifndef WC_ASYNC_DEV_SIZE
    #define WC_ASYNC_DEV_SIZE 0
#endif

/* leantls checks */
#ifdef WOLFSSL_LEANTLS
#endif /* WOLFSSL_LEANTLS*/

/* restriction with static memory */

#ifdef HAVE_AES_KEYWRAP
#endif

#ifdef HAVE_PKCS7
    #ifndef HAVE_AES_KEYWRAP
        #error PKCS7 requires AES key wrap please define HAVE_AES_KEYWRAP
    #endif
    #if !defined(HAVE_X963_KDF)
        #error PKCS7 requires X963 KDF please define HAVE_X963_KDF
    #endif
#endif

#ifndef NO_PKCS12
    #undef  HAVE_PKCS12
    #define HAVE_PKCS12
#endif

#if !defined(NO_PKCS8) || defined(HAVE_PKCS12)
    #undef  HAVE_PKCS8
    #define HAVE_PKCS8
#endif

#if !defined(NO_PBKDF1) || defined(WOLFSSL_ENCRYPTED_KEYS) || \
    defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
    #undef  HAVE_PBKDF1
    #define HAVE_PBKDF1
#endif

#if !defined(NO_PBKDF2) || defined(HAVE_PKCS7) || defined(HAVE_SCRYPT)
    #undef  HAVE_PBKDF2
    #define HAVE_PBKDF2
#endif


#if !defined(WOLFCRYPT_ONLY) &&  defined(NO_MD5)
    #error old TLS requires MD5 and SHA
#endif

/* for backwards compatibility */
#if defined(TEST_IPV6) && !defined(WOLFSSL_IPV6)
    #define WOLFSSL_IPV6
#endif




/* Place any other flags or defines here */


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_LIGHTY)
    #define OPENSSL_NO_ENGINE
// error : inserted by coan: "#define OPENSSL_EXTRA" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2320)
    /* Session Tickets will be enabled when --enable-opensslall is used.
     * Time is required for ticket expiration checking */
    #if !defined(NO_ASN_TIME)
// error : inserted by coan: "#define HAVE_SESSION_TICKET" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2325)
    #endif
    /* OCSP will be enabled in configure.ac when --enable-opensslall is used,
     * but do not force all users to have it enabled. */
        /*#define HAVE_OCSP*/
    #ifndef KEEP_OUR_CERT
        #define KEEP_OUR_CERT
    #endif
#endif

    #define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

/* both CURVE and ED small math should be enabled */
#ifdef CURVED25519_SMALL
    #define CURVE25519_SMALL
    #define ED25519_SMALL
#endif

/* both CURVE and ED small math should be enabled */
#ifdef CURVED448_SMALL
    #define CURVE448_SMALL
    #define ED448_SMALL
#endif


#ifndef WOLFSSL_ALERT_COUNT_MAX
    #define WOLFSSL_ALERT_COUNT_MAX 5
#endif

/* warning for not using harden build options (default with ./configure) */

#ifdef OPENSSL_COEXIST
    /* make sure old names are disabled */
    #ifndef NO_OLD_SSL_NAMES
        #define NO_OLD_SSL_NAMES
    #endif
    #ifndef NO_OLD_WC_NAMES
        #define NO_OLD_WC_NAMES
    #endif
#endif

#if defined(NO_OLD_WC_NAMES)
    /* added to have compatibility with SHA256() */
    #if !defined(NO_OLD_SHA_NAMES)
        #define NO_OLD_SHA_NAMES
    #endif
    #if !defined(NO_OLD_MD5_NAME)
        #define NO_OLD_MD5_NAME
    #endif
#endif

/* switch for compatibility layer functionality. Has subparts i.e. BIO/X509
 * When opensslextra is enabled all subparts should be turned on. */

/* support for converting DER to PEM */
#if (defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_NO_DER_TO_PEM)) ||  defined(WOLFSSL_CERT_GEN)
    #undef  WOLFSSL_DER_TO_PEM
    #define WOLFSSL_DER_TO_PEM
#endif

/* keep backwards compatibility enabling encrypted private key */
#ifndef WOLFSSL_ENCRYPTED_KEYS
#endif

/* support for disabling PEM to DER */
#if !defined(WOLFSSL_NO_PEM) && !defined(NO_CODING)
    #undef  WOLFSSL_PEM_TO_DER
    #define WOLFSSL_PEM_TO_DER
#endif

/* Parts of the openssl compatibility layer require peer certs */
#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)  || defined(HAVE_LIGHTY)
// error : inserted by coan: "#define KEEP_PEER_CERT" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2430)
#endif

/*
 * Keeps the "Finished" messages after a TLS handshake for use as the so-called
 * "tls-unique" channel binding. See comment in internal.h around clientFinished
 * and serverFinished for more information.
 */
#if defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS)
    #undef  WOLFSSL_HAVE_TLS_UNIQUE
    #define WOLFSSL_HAVE_TLS_UNIQUE
#endif

/* RAW hash function APIs are not implemented */
#if defined(WOLFSSL_ARMASM) || defined(WOLFSSL_AFALG_HASH)
    #undef  WOLFSSL_NO_HASH_RAW
    #define WOLFSSL_NO_HASH_RAW
#endif

/* XChacha not implemented with ARM assembly ChaCha */
#if defined(WOLFSSL_ARMASM)
    #undef HAVE_XCHACHA
#endif


#if !defined(WOLFCRYPT_ONLY)
#endif



#if defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    defined(WC_NO_RSA_OAEP)
    #undef  WOLFSSL_NO_CT_OPS
    #define WOLFSSL_NO_CT_OPS
#endif



/* Detect old cryptodev name */
#if defined(WOLF_CRYPTO_DEV)
// error : inserted by coan: "#define WOLF_CRYPTO_CB" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2501)
#endif


#ifndef NO_WOLFSSL_BASE64_DECODE
    #define WOLFSSL_BASE64_DECODE
#endif

#if defined(HAVE_EX_DATA) || defined(FORTRESS)
    #if defined(FORTRESS) && !defined(HAVE_EX_DATA)
        #define HAVE_EX_DATA
    #endif
    #ifndef MAX_EX_DATA
    #define MAX_EX_DATA 5  /* allow for five items of ex_data */
    #endif
#endif

#ifdef NO_WOLFSSL_SMALL_STACK
#endif

#ifdef WOLFSSL_SMALL_STACK_STATIC
    #undef WOLFSSL_SMALL_STACK_STATIC
    #define WOLFSSL_SMALL_STACK_STATIC static
#else
    #define WOLFSSL_SMALL_STACK_STATIC
#endif

/* The client session cache requires time for timeout */

/* Use static ECC structs for Position Independant Code (PIC) */
#if defined(__IAR_SYSTEMS_ICC__) && defined(__ROPI__)
    #define WOLFSSL_ECC_CURVE_STATIC
    #define WOLFSSL_NAMES_STATIC
    #define WOLFSSL_NO_CONSTCHARCONST
#endif

/* FIPS v1 does not support TLS v1.3 (requires RSA PSS and HKDF) */
#if FIPS_VERSION_EQ(1,0)
#endif

/* For FIPSv2 make sure the ECDSA encoding allows extra bytes
 * but make sure users consider enabling it */
#if !defined(NO_STRICT_ECDSA_LEN) && FIPS_VERSION_GE(2,0)
    /* ECDSA length checks off by default for CAVP testing
     * consider enabling strict checks in production */
    #define NO_STRICT_ECDSA_LEN
#endif

/* Do not allow using small stack with no malloc */

/* Enable DH Extra for QT, openssl all, openssh and static ephemeral */
/* Allows export/import of DH key and params as DER */
#if !defined(WOLFSSL_DH_EXTRA) &&  defined(WOLFSSL_OPENSSH)
    #define WOLFSSL_DH_EXTRA
#endif

/* DH Extra is not supported on FIPS v1 or v2 (is missing DhKey .pub/.priv) */

/* wc_Sha512.devId isn't available before FIPS 5.1 */

/* Enable HAVE_ONE_TIME_AUTH by default for use with TLS cipher suites
 * when poly1305 is enabled
 */

/* Check for insecure build combination:
 * secure renegotiation   [enabled]
 * extended master secret [disabled]
 * session resumption     [enabled]
 */

/* if secure renegotiation is enabled, make sure server info is enabled */

/* Crypto callbacks should enable hash flag support */

/* Enable Post-Quantum Cryptography if we have liboqs from the OpenQuantumSafe
 * group */
#ifdef HAVE_LIBOQS
// error : inserted by coan: "#define HAVE_PQC" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2631)
#define HAVE_FALCON
#define HAVE_KYBER
#endif

#ifdef HAVE_PQM4
// error : inserted by coan: "#define HAVE_PQC" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2637)
#define HAVE_KYBER
#endif



/* SRTP requires DTLS */
#if defined(WOLFSSL_SRTP)
    #error The SRTP extension requires DTLS
#endif

/* Are we using an external private key store like:
 *     PKCS11 / HSM / crypto callback / PK callback */
#if  defined(HAVE_PKCS11) || defined(WOLFSSL_KCAPI)
     /* Enables support for using wolfSSL_CTX_use_PrivateKey_Id and
      *   wolfSSL_CTX_use_PrivateKey_Label */
// error : inserted by coan: "#define WOLF_PRIVATE_KEY_ID" contradicts -U or --implicit at /home/fabio/dev/cpp-core-gh/extern/wolfssl_prebuilt/download/wolfssl/wolfcrypt/settings.h(2661)
#endif


/* With titan cache size there is too many sessions to fit with the default
 * multiplier of 8 */
#if defined(TITAN_SESSION_CACHE) && !defined(NO_SESSION_CACHE_REF)
    #define NO_SESSION_CACHE_REF
#endif


/* ---------------------------------------------------------------------------
 * Depricated Algorithm Handling
 *   Unless allowed via a build macro, disable support
 * ---------------------------------------------------------------------------*/

/* RC4: Per RFC7465 Feb 2015, the cipher suite has been deprecated due to a
 * number of exploits capable of decrypting portions of encrypted messages. */
#ifndef WOLFSSL_ALLOW_RC4
#endif


#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
