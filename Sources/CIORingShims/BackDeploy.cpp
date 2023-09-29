//
// Copyright 2020 Jens Axboe
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <CIORingShims.h>

#if _CIOURINGSHIMS_BACKDEPLOY_H_

struct io_uring_recvmsg_out *
io_uring_recvmsg_validate(void *buf, int buf_len, struct msghdr *msgh) {
  unsigned long header = msgh->msg_controllen + msgh->msg_namelen +
                         sizeof(struct io_uring_recvmsg_out);
  if (buf_len < 0 || (unsigned long)buf_len < header)
    return NULL;
  return (struct io_uring_recvmsg_out *)buf;
}

void *io_uring_recvmsg_name(struct io_uring_recvmsg_out *o) {
  return (void *)&o[1];
}

struct cmsghdr *io_uring_recvmsg_cmsg_firsthdr(struct io_uring_recvmsg_out *o,
                                               struct msghdr *msgh) {
  if (o->controllen < sizeof(struct cmsghdr))
    return NULL;

  return (struct cmsghdr *)((unsigned char *)io_uring_recvmsg_name(o) +
                            msgh->msg_namelen);
}

struct cmsghdr *io_uring_recvmsg_cmsg_nexthdr(struct io_uring_recvmsg_out *o,
                                              struct msghdr *msgh,
                                              struct cmsghdr *cmsg) {
  unsigned char *end;

  if (cmsg->cmsg_len < sizeof(struct cmsghdr))
    return NULL;
  end =
      (unsigned char *)io_uring_recvmsg_cmsg_firsthdr(o, msgh) + o->controllen;
  cmsg = (struct cmsghdr *)((unsigned char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len));

  if ((unsigned char *)(cmsg + 1) > end)
    return NULL;
  if (((unsigned char *)cmsg) + CMSG_ALIGN(cmsg->cmsg_len) > end)
    return NULL;

  return cmsg;
}

void *io_uring_recvmsg_payload(struct io_uring_recvmsg_out *o,
                               struct msghdr *msgh) {
  return (void *)((unsigned char *)io_uring_recvmsg_name(o) +
                  msgh->msg_namelen + msgh->msg_controllen);
}

unsigned int io_uring_recvmsg_payload_length(struct io_uring_recvmsg_out *o,
                                             int buf_len,
                                             struct msghdr *msgh) {
  unsigned long payload_start, payload_end;

  payload_start = (unsigned long)io_uring_recvmsg_payload(o, msgh);
  payload_end = (unsigned long)o + buf_len;
  return (unsigned int)(payload_end - payload_start);
}

#endif /* _CIOURINGSHIMS_BACKDEPLOY_H_ */
