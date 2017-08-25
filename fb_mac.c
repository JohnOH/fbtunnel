/*
 * fb_mac.c
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
#ifdef __APPLE__
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "fbtunnel.h"

/*
 * Linux specific tunnel set
 */
int
tun_alloc(char *dev)
{
  char device[20];
  int fd, i;

  for(i = 0; i < 4; i++) {
    sprintf(device, "/dev/tun%d", i);
    fd = open(device, O_RDWR);
    if (fd > 0) {
      strcpy(dev, &device[5]);
      return fd;
    }
  }
  return(-1);
}

int
tun_setip(const char *dev, struct sockaddr_in *saddr)
{
  /* Not sure yet */
  printf("Can't set ip on %s just yet, please do it manually\n", dev);
  return(0);
}

int
tun_updown(const char *dev, int up)
{
  /* Not sure yet */
  printf("Can't mark %s as up just yet, please do it manually\n", dev);
  return(0);
}

/*
 * Send a packet to the tunnel interface - this is
 * simple on the mac
 */
int
tun_sendpacket (fb_tunnel *tunnel, char *area, char *packet, int len)
{
  if (len != write(tunnel->interface, packet, len))
    return -1;
  return 0;
}

/*
 * No byte moving needed here, either
 */
int
tun_retrievepacket (fb_tunnel *tunnel, char **packet, int *len)
{
  char *area = *packet;

  /* no shifting to be done on the mac! */
  *len = read(tunnel->interface, area, *len);
  if (*len < 0)
    return -1;
  return 0;
}

#endif /* __APPLE__ */
