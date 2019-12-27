//
// tunnel_darwin.c
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

// Tunnel code by Frank Denis (https://github.com/jedisct1/dsvpn) with
// the following original license:
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

#include <fcntl.h>
#include <poll.h>
#include <linux/if_tun.h>

#define TIMEOUT (60 * 1000)

int tun_create(char **name_return, int *errno_return)
{
    struct ifreq ifr = {0};
    int          fd;
    int          err;
    char         *if_name;

    *name_return = NULL;
    *errno_return = 0;

    if_name = calloc(1, IFNAMSIZ);
    if (if_name == NULL)
      {
	*errno_return = ENOMEM;
	return -1;
      }

    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1)
      {
        fprintf(stderr, "tun module not present\n");
	*errno_return = ENODEV;
	free(if_name);
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) != 0)
      {
	*errno_return = errno;
        (void) close(fd);
	free(if_name);
        return -1;
    }
    snprintf(if_name, IFNAMSIZ, "%s", ifr.ifr_name);

    *name_return = if_name;

    return fd;
}

ssize_t
tun_read(int fd, void *data, size_t size, int *errno_return)
{
    ssize_t readnb;

    while ((readnb = read(fd, data, size)) < (ssize_t) 0 && errno == EINTR)
      ;
    *errno_return = errno;
    return readnb;
}

ssize_t
tun_write(int fd, const void *data, size_t size, int *errno_return)
{
    struct pollfd pfd;
    ssize_t written;
    ssize_t result = 0;

    *errno_return = 0;

    while (size > (size_t) 0)
      {
        while ((written = write(fd, data, size)) < (ssize_t) 0)
	  {
            if (errno == EAGAIN)
	      {
		pfd.fd = fd;
		pfd.events = POLLOUT;
		if (poll(&pfd, (nfds_t) 1, TIMEOUT) <= 0)
		  {
		    *errno_return = ETIMEDOUT;
		    return (ssize_t) -1;
		  }
	      }
	    else if (errno != EINTR)
	      {
		*errno_return = errno;
                return (ssize_t) -1;
	      }
	  }
        data += written;
        size -= written;
	result += written;
    }
    return result;
}

