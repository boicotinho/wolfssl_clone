/* wolfevent.h
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

#ifndef _WOLF_EVENT_H_
#define _WOLF_EVENT_H_

#ifdef __cplusplus
    extern "C" {
#endif

    #include <wolfssl/wolfcrypt/wc_port.h>

typedef struct WOLF_EVENT WOLF_EVENT;
typedef unsigned short WOLF_EVENT_FLAG;

typedef enum WOLF_EVENT_TYPE {
    WOLF_EVENT_TYPE_NONE,
} WOLF_EVENT_TYPE;

typedef enum WOLF_EVENT_STATE {
    WOLF_EVENT_STATE_READY,
    WOLF_EVENT_STATE_PENDING,
    WOLF_EVENT_STATE_DONE,
} WOLF_EVENT_STATE;

struct WOLF_EVENT {
    /* double linked list */
    WOLF_EVENT*         next;
    WOLF_EVENT*         prev;

    void*               context;
    union {
        void* ptr;
    } dev;
#ifdef HAVE_CAVIUM
    word64              reqId;
    #ifdef WOLFSSL_NITROX_DEBUG
    word32              pendCount;
    #endif
#endif
    int                 ret;    /* Async return code */
    unsigned int        flags;
    WOLF_EVENT_TYPE     type;
    WOLF_EVENT_STATE    state;
};

enum WOLF_POLL_FLAGS {
    WOLF_POLL_FLAG_CHECK_HW = 0x01,
};

typedef struct {
    WOLF_EVENT*         head;     /* head of queue */
    WOLF_EVENT*         tail;     /* tail of queue */
    wolfSSL_Mutex       lock;     /* queue lock */
    int                 count;
} WOLF_EVENT_QUEUE;




#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif /* _WOLF_EVENT_H_ */
