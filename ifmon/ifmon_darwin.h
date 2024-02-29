/*
 * ifmon_darwin.h
 *
 * Copyright (c) 2019-2024 Markku Rossi
 *
 * All rights reserved.
 */

#ifndef IFMON_DARWIN_H
#define IFMON_DARWIN_H

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/kern_event.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int ifmon_create(int *errno_return);
int ifmon_wait(int fd, u_int32_t *cls, u_int32_t *subcls, u_int32_t *code,
               int *errno_return);

#endif /* not IFMON_DARWIN_H */
