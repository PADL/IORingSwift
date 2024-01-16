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

#ifndef _CIOURINGSHIMS_BACKDEPLOY_H_
#define _CIOURINGSHIMS_BACKDEPLOY_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

struct io_uring_recvmsg_out {
  uint32_t namelen;
  uint32_t controllen;
  uint32_t payloadlen;
  uint32_t flags;
};

struct io_uring_recvmsg_out *
io_uring_recvmsg_validate(void *buf, int buf_len, struct msghdr *msgh);

void *io_uring_recvmsg_name(struct io_uring_recvmsg_out *o);

struct cmsghdr *io_uring_recvmsg_cmsg_firsthdr(struct io_uring_recvmsg_out *o,
                                               struct msghdr *msgh);

struct cmsghdr *io_uring_recvmsg_cmsg_nexthdr(struct io_uring_recvmsg_out *o,
                                              struct msghdr *msgh,
                                              struct cmsghdr *cmsg);

void *io_uring_recvmsg_payload(struct io_uring_recvmsg_out *o,
                               struct msghdr *msgh);

unsigned int io_uring_recvmsg_payload_length(struct io_uring_recvmsg_out *o,
                                             int buf_len,
                                             struct msghdr *msgh);

#ifdef __cplusplus
}
#endif

#endif /* _CIOURINGSHIMS_BACKDEPLOY_H_ */
