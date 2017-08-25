/*
 * fb_linux.c
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
#ifdef linux

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "fbtunnel.h"

/* Linnux specific */
#include <linux/if.h>
#include <linux/if_tun.h>

/*
 * Linux specific tunnel set
 */
int
tun_alloc(char *dev)
{
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return -1;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  if (*dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return(err);
  }
  strcpy(dev, ifr.ifr_name);
  return(fd);
}

int
tun_setip(const char *dev, struct sockaddr_in *saddr)
{
  struct sockaddr_in *in;
  struct ifreq ifr;
  int fd = socket(PF_INET, SOCK_DGRAM, 0);

  if (! fd)
    die("Failed to get socket to setup interface");

  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  in = (struct sockaddr_in *)&ifr.ifr_addr;
  in->sin_family = saddr->sin_family;
  in->sin_addr = saddr->sin_addr;

  /* use ioctl SIOCSIFADDR to set the address */
  if (ioctl(fd, SIOCSIFADDR, &ifr) < 0)
    die("Failed to set ip address");
  close(fd);

  return(0);
}

int
tun_updown(const char *dev, int up)
{
  struct ifreq ifr;
  int fd = socket(PF_INET, SOCK_DGRAM, 0);

  if (! fd)
    die("Failed to get socket to setup interface");

  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if (up)
    ifr.ifr_flags = IFF_UP;
  else
    ifr.ifr_flags = 0;

  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    die("Could not bring up interface");

  close(fd);
  return(0);
}

/*
 * Send a packet to the tunnel interface
 * must have at least 4 bytes before the start
 * of packet
 */
int
tun_sendpacket (fb_tunnel *tunnel, char *area, char *packet, int len)
{
  if (packet - area < 4)
    die("Must have 4 bytes before the packet, BUG!\n");

  /* No flags, 0x0800 for IP */
  packet -= 4;
  packet[0] = 0;
  packet[1] = 0;
  packet[2] = 8;
  packet[3] = 0;
  len += 4;
  
  if (len != write(tunnel->interface, packet, len))
    return -1;
  return 0;
}

int
tun_retrievepacket (fb_tunnel *tunnel, char **packet, int *len)
{
  int readlen;
  char *area = *packet;

  readlen = read(tunnel->interface, area, *len);
  if (readlen < 0)
    return -1;

  if (area[2] !=0x08 && area[3] != 00)
    return -1;

  *packet = &area[4];
  *len = readlen - 4;
  return 0;
}

#endif /* linux */
