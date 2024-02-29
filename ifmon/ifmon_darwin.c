/*
 * ifmon_darwin.c
 *
 * Copyright (c) 2019-2024 Markku Rossi
 *
 * All rights reserved.
 */

#include "ifmon_darwin.h"

int
ifmon_create(int *errno_return)
{
  int s = -1;
  int ret;
  struct kev_request req;

  *errno_return = 0;

  s = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
  if (s == -1)
    goto error;

  /* Filter events. */

  memset(&req, 0, sizeof(req));
  req.vendor_code = KEV_VENDOR_APPLE;
  req.kev_class = KEV_NETWORK_CLASS;
  req.kev_subclass = KEV_ANY_SUBCLASS;

  ret = ioctl(s, SIOCSKEVFILT, &req);
  if (ret == -1)
    goto error;

  return s;


  /* Error handling. */

 error:

  if (s != -1)
    close(s);
  *errno_return = errno;

  return -1;
}

int
ifmon_wait(int fd, u_int32_t *cls, u_int32_t *subcls, u_int32_t *code,
           int *errno_return)
{
  int ret;
  struct kern_event_msg msg;

  *cls = 0;
  *subcls = 0;
  *code = 0;
  *errno_return = 0;

  memset(&msg, 0, sizeof(msg));

  ret = recv(fd, &msg, sizeof(msg), 0);
  if (ret == -1)
    {
      *errno_return = errno;
      return -1;
    }

  *cls = msg.kev_class;
  *subcls = msg.kev_subclass;
  *code = msg.event_code;

  return 0;
}
