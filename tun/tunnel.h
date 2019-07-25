//
// tunnel.h
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

int tun_create(char **name_return, int *errno_return);
ssize_t tun_read(int fd, void *data, size_t size, int *errno_return);

#endif /* not TUNNEL_H */
