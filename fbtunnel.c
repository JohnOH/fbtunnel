/*
 * fbtunnel.c
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/md5.h>

#ifdef __APPLE__
#include <sys/time.h>
#endif

#include "fbtunnel.h"

/* #define Dprintf printf */
#define Dprintf(...)

/* The platform specific code is expect to provide... */
int tun_alloc(char *dev);
int tun_setip(const char *dev, struct sockaddr_in *);
int tun_updown(const char *dev, int up);
int tun_sendpacket(fb_tunnel *, char *area, char *packet, int len);
int tun_retrievepacket(fb_tunnel *, char **, int *);

void
die(char *details)
{
  /* Who needs error handling? ;) */
  perror(details);
  exit(-2);
}

/*
 * We build fragments into packets in this hack of
 * a structure. Currently it doesn't handle getting
 * the 'fin' packet before the rest - I should fix
 * that soon.
 */
static fb_packet *
lookup_or_create_packet(fb_tunnel *tunnel, int id)
{
  fb_packet *fbp = tunnel->packets, *prev;

  prev = NULL;
  while(fbp) {
    if (fbp->id == id)
      return fbp;
    prev = fbp;
    fbp = fbp->next;
  }

  /* Didn't find it */
  fbp = calloc(1, sizeof(fbp[0]));
  fbp->id = id;
  fbp->now = time(NULL);
  if(!prev)
    tunnel->packets = fbp;
  else
    prev->next = fbp;

  return(fbp);
}

/* Fragments have a lifetime of only 2 seconds
 * so when we send a keepalive, we remove 'old'
 * fragments. This allows the code to be lazy,
 * and not remove them when they're complete and
 * sent to the tun interface. So sue me.
 */
static void
cull_packets(fb_tunnel *tunnel)
{
  fb_packet *fbp, **prev;
  time_t now = time(NULL);

  /* Give a bit of leeway */
  now -= 1;
  fbp = tunnel->packets;
  prev = &tunnel->packets;
  while(fbp) {
    if (fbp->now+2 < now) {
      fb_packet *next = fbp->next;
	*prev = next;
      free(fbp);
      fbp = next;
    } else {
      prev = &fbp->next;
      fbp = fbp->next;
    }
  }
}

static int
setup_udp()
{
  int udp_fd;
  struct sockaddr_in my_addr;

  udp_fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (!udp_fd)
    die("failed to get UDP socket");

  /* Always UDP port 1 */
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  my_addr.sin_port = htons(FB_PORT);
  if (0 != bind(udp_fd, (struct sockaddr *)&my_addr, sizeof(my_addr)))
    die("failed to bind socket");

  return(udp_fd);
}

/*
 * Generate a 16byte md5 checksum from the
 * the data, and store it into key.
 */
static void
checksum(fb_tunnel *tunnel, char *packet, int packet_len,
	 char *key)
{
  MD5_CTX context;

  MD5_Init(&context);
  MD5_Update(&context, packet, packet_len);
  MD5_Update(&context, tunnel->key, tunnel->keylen);
  MD5_Final(key, &context);
}

static int
fb_sendkeepalive(fb_tunnel *tunnel)
{
  char packet[64];
  fb_header *header = (fb_header *)packet;

  memset(packet, 0, 3);
  header->flags |= FB_SET_VERSION(FB_VERSION);
  header->flags |= FB_SET_PART(3);
  header->flags |= FB_SET_FIN(0);
  header->flags |= FB_SET_SIGNED(1);
  header->tunnelid = tunnel->remoteid;

  header->keepalive_flags = 5; /* Keepalives */
  header->keepalive_flags |= FB_SET_STATUS((tunnel->state == FB_UP));
  
  checksum(tunnel, packet, 3, &packet[3]);

  if (sendto(tunnel->udp, packet, 19, 0, (struct sockaddr *)&tunnel->remote_addr,
	     sizeof(struct sockaddr)) == -1)
    die("Failed to send keepalive");

  /* Cull packets */
  cull_packets(tunnel);
  return(0);
}

#ifdef NOTYET
/*
 * We need to fix up the source address if its 0.0.0.0
 */
static int
fixup_packet(fb_tunnel *tunnel, char *packet, int len)
{
  int *packint = &packet[0];

  if (packint[3] == 0) {
    packint[3] = tunnel->local_addr.sin_addr.s_addr;
    /* Recalculate header here! */
  }
}
#endif

static int
udp_packet (fb_tunnel *tunnel)
{
  /* Area for packet, including 30 bytes to move header, and 4 bytes
   * for tun details */
  unsigned char area[1500+30+4];
  unsigned char *packet = &area[30+4];
  fb_header *header;
  struct sockaddr_in from;
  int socklen, len;
  int part, finished;

  socklen = sizeof(from);
  len = recvfrom(tunnel->udp, packet, sizeof(area) -30 -4, 0,
		 (struct sockaddr *)&from, &socklen);
  if (len < 0)
    return(-1);
  
  header = (fb_header *)packet;
  if(FB_GET_SIGNED(header->flags)) {
    /* Check signature */
    char csum[16];

    checksum(tunnel, packet, len-16, csum);
    if (0 != memcmp(csum, &packet[len-16], 16)) {
      Dprintf("Discarding invalid packet\n");
      return(-1);
    }
    /* remove the csum from the equation */
    len -= 16;
  }

  if (header->tunnelid != tunnel->localid) {
    Dprintf("Discarding packet for the wrong tunnel\n");
    return(-1);
  }

  /* Process packet */
  if(FB_GET_PART(header->flags) == 3
     && FB_GET_FIN(header->flags) == 0) {
    /* Keepalive packet! */
    fb_state old = tunnel->state;
    if(FB_GET_STATUS(header->keepalive_flags))
      /* other end hears us, tunnel is up! */
      tunnel->state = FB_UP;
    else 
      tunnel->state = FB_UPDOWN;

    /* If state has changed, didle the tunnel interface */
    if (old != tunnel->state)
      tun_updown(tunnel->dev, (tunnel->state == FB_UP));
    return (0);
  }

  /* Stash what we want from teh packet, and step over the header */
  part = FB_GET_PART(header->flags);
  finished = FB_GET_FIN(header->flags);
  len -= 2;
  packet += 2;
  if(tunnel->state == FB_UP) {
    if(finished && part == 0) {

      /* Deal with real packets, move the header to the front*/
      memmove(packet-30, &packet[len-30], 30);
      packet -= 30;
      /* fixup_packet(tunnel, packet, len); */
      tun_sendpacket(tunnel, area, packet, len);
    } else {
      /* Packet is split across several packets */
      fb_packet *fbp;
      int offset;

      /* Grab id from packet, and step over it,
       * then look for other fragments from this packet
       */
      u_int16_t pkt_id = packet[0] << 8 | packet[1];
      packet += 2;
      len -= 2;
      
      fbp = lookup_or_create_packet(tunnel, pkt_id);
      offset = part * 512;
      memcpy(&fbp->packet[offset], packet, len);
      fbp->len += len;
      if (finished) {
	/* fixup_packet(tunnel, fbp->packet, fbp->len); */
	tun_sendpacket(tunnel, fbp->space, fbp->packet, fbp->len);
      }
    }
  }
  return(0);
}

static int
send_data(fb_tunnel *tunnel, char *packet, int len, int part, int fin)
{
  fb_header *header = (void *)packet;

   header->flags = 0;
   header->flags |= FB_SET_VERSION(2);
   header->flags |= FB_SET_FIN(fin);
   header->flags |= FB_SET_PART(part);
   header->flags |= FB_SET_SIGNED(1);
   header->tunnelid = tunnel->remoteid;
   
   checksum(tunnel, packet, len,
	    &packet[len]);
   len += 16;
   
   sendto(tunnel->udp, packet, len, 0,
	  (struct sockaddr *)&tunnel->remote_addr,
	  sizeof(struct sockaddr));
   return(0);
}

static int
interface_packet(fb_tunnel *tunnel)
{
  char space[1510];
  char *packet = space;
  int len = sizeof(space);

  if (0 != tun_retrievepacket(tunnel, &packet, &len))
    return(-1);

  if (len <= 512) {
    /* This is a special - packet just fits in one packet */
    /* Move the first 30 bytes to the end */
    memmove(&packet[len], &packet[0], 30);
    /* no packet id, so just a 2 byte header */
    len += 2;
    send_data(tunnel, packet+28, len, 0, 1);
  } else {
    int offset = 0;
    int part = 0, fin = 0;
    tunnel->packetid++;

    /* Segment the packet into 512byte chunks,
     * Each chunk is checksummed, and has the 4 byte header
     */
    while(len) {
      char buffer[512+16+4];
      /* Each packet is 512 less 16 checksum, 4 header */
      int copy = len > 512 ? 512 : len;
      
      if (len - copy == 0)
	fin = 1;
      /* Stuff the packetid into the header */
      buffer[3] = tunnel->packetid & 255;
      buffer[2] = tunnel->packetid >> 8;
      /* Copy over into our buffer (otherwise the checksum
       * splats bits of the packet we've not written out yet)
       */
      memcpy(&buffer[4], &packet[offset], copy);
      send_data(tunnel, buffer, copy+4, part, fin);

      /* Fix up the lengths / offsets etc. */
      part++;
      len -= copy;
      offset += copy;
    }
  }
  return(0);
}

static void
firebrick(fb_tunnel *tunnel)
{
  struct timeval tm;
  int max_fd = tunnel->udp;
  fd_set rs;

  if (tunnel->interface > max_fd)
    max_fd = tunnel->interface;

  /* Poke the first keepalive */
  fb_sendkeepalive(tunnel);

  FD_ZERO(&rs);
  while(1) {
    time_t now;

    FD_SET(tunnel->udp, &rs);
    FD_SET(tunnel->interface, &rs);
    tm.tv_usec = 0;
    tm.tv_sec = 1;
    select(max_fd+1, &rs, NULL, NULL, &tm);

    if (FD_ISSET(tunnel->udp, &rs))
      udp_packet(tunnel);

    if (FD_ISSET(tunnel->interface, &rs))
      interface_packet(tunnel);

    now = time(NULL);
    if (now >= tunnel->timeout) {
      fb_sendkeepalive(tunnel);
      tunnel->timeout = now + 2;
    }
  }
}

static int
usage(char *program)
{
  printf("Usage: %s remote-id key local-ip firebrick-ip\n", program);
  printf("   eg: %s 2 ding 10.0.0.1 1.2.3.4\n", program);
  exit(-1);
}


int
main (int argc, char **argv)
{
  pid_t pid;
  fb_tunnel *tunnel;

  if (argc != 5)
    usage(argv[0]); /* and die! */

  tunnel = calloc(1, sizeof(tunnel[0]));
  if (!tunnel)
    die("Failed to allocate memory for tunnel!");

  tunnel->localid = 1;
  tunnel->remoteid = atoi(argv[1]);
  tunnel->key = strdup(argv[2]);
  tunnel->keylen = strlen(tunnel->key);
  /* Remove key from parameter list */
  memset(argv[2], 0, tunnel->keylen);

  if(0 == inet_aton(argv[3],
		    &tunnel->local_addr.sin_addr))
    die("invalid remote ip address");
  if(0 == inet_aton(argv[4],
		    &tunnel->remote_addr.sin_addr))
    die("invalid remote ip address");
  tunnel->local_addr.sin_family = AF_INET;
  tunnel->remote_addr.sin_family = AF_INET;
  tunnel->remote_addr.sin_port = htons(FB_PORT);

  if ((tunnel->interface = tun_alloc(tunnel->dev)) < 0)
    die("failed to allocate tunnel");
  if ((tunnel->udp = setup_udp()) < 0)
    die("failed to allocate udp socket");

  /* Dies if fails */
  tun_setip(tunnel->dev, &tunnel->local_addr);

  printf("Tunnel is using %s\n", tunnel->dev);
  pid = fork();
  switch(pid) {
  case -1:
    die("Failed to fork!");
    break;
  case 0:
    /* Do the firebrick thing */
    firebrick(tunnel);
    break;
  default:
    printf("Tunnel pid is %d\n", pid);
  }
  return(0);
}
