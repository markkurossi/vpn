//
// tunnel_darwin.c
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

// Tunnel code by Frank Denis with the following original license:
//
// MIT License
//
// Copyright (c) 2019 Frank Denis
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "tunnel.h"

#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

static int tun_create_by_id(char if_name[IFNAMSIZ], unsigned int id)
{
    struct ctl_info     ci;
    struct sockaddr_ctl sc;
    int                 err;
    int                 fd;

    if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
        return -1;
    }
    memset(&ci, 0, sizeof ci);
    snprintf(ci.ctl_name, sizeof ci.ctl_name, "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    memset(&sc, 0, sizeof sc);
    sc = (struct sockaddr_ctl){
        .sc_id      = ci.ctl_id,
        .sc_len     = sizeof sc,
        .sc_family  = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit    = id + 1,
    };
    if (connect(fd, (struct sockaddr *) &sc, sizeof sc) != 0) {
        err = errno;
        (void) close(fd);
        errno = err;
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "utun%u", id);

    return fd;
}

int
tun_create(char **name_return, int *errno_return)
{
  unsigned int id;
  char *if_name;

  *name_return = NULL;
  *errno_return = 0;

  if_name = calloc(1, IFNAMSIZ);
  if (if_name == NULL)
    {
      *errno_return = ENOMEM;
      return -1;
    }

  for (id = 0; id < 32; id++)
    {
      int fd;

      fd = tun_create_by_id(if_name, id);
      if (fd != -1)
        {
          *name_return = if_name;
          return fd;
        }
    }

  free(if_name);
  *errno_return = errno;

  return -1;
}

ssize_t
tun_read(int fd, void *data, size_t size, int *errno_return)
{
  ssize_t  ret;
  uint32_t family;

  *errno_return = 0;

  struct iovec iov[2] =
    {
     {
      .iov_base = &family,
      .iov_len  = sizeof(family),
     },
     {
      .iov_base = data,
      .iov_len  = size,
     },
    };

    ret = readv(fd, iov, 2);
    if (ret <= (ssize_t) 0)
      {
        *errno_return = errno;
        return -1;
      }
    if (ret <= (ssize_t) sizeof(family))
      return 0;

    return ret - sizeof(family);
}
