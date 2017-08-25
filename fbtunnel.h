/*
 * fbtunnel.h
 *
 * Copyright (C) Rick Payne <rickp@rossfell.co.uk>, August 2003
 * 
 * fbtunnel is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * fbtunnel is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fbtunnel; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _FBTUNNEL_H_
#define _FBTUNNEL_H_

/* For Linux */
#define INTERFACESIZE 16

typedef enum {
  FB_DOWN,
  FB_UPDOWN,
  FB_UP,
} fb_state;

typedef struct _fb_packet {
  struct _fb_packet *next;
  u_int16_t id;
  time_t    now;   /* When the first packet arrived */
  int       len;
  char      space[8];  /* Some room */
  char      packet[1530];
} fb_packet;

typedef struct _fb_tunnel {
  fb_state state;

  u_int16_t packetid;

  time_t timeout; /* Time to send next keepalive */
  int localid;    /* Local tunnel id */
  int remoteid;   /* Remote tunnel id */

  /* Sockets */
  int udp;
  int interface;

  /* Addresses */
  struct sockaddr_in remote_addr;
  struct sockaddr_in local_addr;

  /* Local tunnel interface */
  char dev[INTERFACESIZE];

  /* Key */
  char *key;
  int keylen;

  /* Unre-assembled packets */
  fb_packet *packets;
} fb_tunnel;

typedef struct _fb_header {
  unsigned char flags;
  unsigned char tunnelid;
  unsigned char keepalive_flags;
} fb_header;

#define FB_PORT 1     /* Currently, UDP from port 1 to port 1, requires root */
#define FB_VERSION 2

#define FB_GET_VERSION(x) ((x) & 15)
#define FB_GET_PART(x) (((x) >> 4) & 3)
#define FB_GET_FIN(x) (((x) >> 6) & 1)
#define FB_GET_SIGNED(x) (((x) >> 7) & 1)
#define FB_GET_STATUS(x) (((x) >> 1) & 1)
#define FB_SET_VERSION(x) ((x) & 15)
#define FB_SET_PART(x) (((x) & 3) << 4)
#define FB_SET_FIN(x) (((x) & 1) << 6)
#define FB_SET_SIGNED(x) (((x) & 1) << 7)
#define FB_SET_STATUS(x) (((x) & 1) << 1)

/* Prototypes */
void die(char *);

#endif /* _FBTUNNEL_H_ */
