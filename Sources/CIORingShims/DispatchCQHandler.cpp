//
// Copyright (c) 2023 PADL Software Pty Ltd
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "CQHandlerInternal.hpp"

static void cqe_handler(dispatch_source_t source) {
  auto ring = static_cast<struct io_uring *>(dispatch_get_context(source));
  struct io_uring_cqe *cqe;
  eventfd_t value;
  int err;

  err = eventfd_read(dispatch_source_get_handle(source), &value);
  if (err)
    return;

  err = io_uring_wait_cqe(ring, &cqe);
  if (err)
    return;

  io_uring_cq_invoke_blocks(ring, cqe);
}

int dispatch_io_uring_init_cq_handler(void **handle, struct io_uring *ring) {
  *handle = nullptr;

  // previously, we spun up a thread to wait on cqe notifications.
  // however we can use eventfd to integrate this with libdispatch
  auto fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (fd < 0)
    return -errno;

  if (io_uring_register_eventfd(ring, fd) != 0) {
    close(fd);
    return -errno;
  }

  auto source = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_READ, fd, 0,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
  if (source == nullptr) {
    io_uring_unregister_eventfd(ring);
    close(fd);
    return -errno;
  }

  dispatch_set_context(source, ring);

  dispatch_source_set_event_handler(source, ^{
    cqe_handler(source);
  });

  dispatch_source_set_cancel_handler(source, ^{
    io_uring_unregister_eventfd(ring);
    close(fd);
  });

  dispatch_resume(source);

  *handle = static_cast<void *>(source);

  return 0;
}

void dispatch_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring) {
  if (handle) {
    auto source = static_cast<dispatch_source_t>(handle);
    dispatch_cancel(source);
    dispatch_release(source);
  }
}
