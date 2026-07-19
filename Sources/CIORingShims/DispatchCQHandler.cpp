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

#include <sys/eventfd.h>

namespace {
// Context carried by the dispatch source. `cancelled` lets deinit block until the
// source's cancel handler has run, which is the only point at which we know no
// libdispatch thread is executing cqe_handler (touching `ring`) any longer.
struct DispatchCQHandlerContext {
  struct io_uring *ring;
  int fd;
  dispatch_semaphore_t cancelled;
};
} // namespace

static void cqe_handler(dispatch_source_t source) {
  auto ctx =
      static_cast<DispatchCQHandlerContext *>(dispatch_get_context(source));
  io_uring_cq_handler(ctx->ring);
}

int dispatch_io_uring_init_cq_handler(uintptr_t *handle,
                                      struct io_uring *ring) {
  *handle = 0;

  // previously, we spun up a thread to wait on cqe notifications.
  // however we can use eventfd to integrate this with libdispatch
  auto fd = eventfd(0, EFD_CLOEXEC);
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

  auto ctx = new DispatchCQHandlerContext{ring, fd,
                                          dispatch_semaphore_create(0)};
  dispatch_set_context(source, ctx);

  dispatch_source_set_event_handler(source, ^{
    cqe_handler(source);
  });

  // The cancel handler only signals: it must not touch `ring`, because deinit
  // submits a wake NOP concurrently. The eventfd/fd are torn down in deinit once
  // the handler is known to be stopped.
  dispatch_source_set_cancel_handler(source, ^{
    dispatch_semaphore_signal(ctx->cancelled);
  });

  dispatch_resume(source);

  *handle = reinterpret_cast<uintptr_t>(source);

  return 0;
}

void dispatch_io_uring_deinit_cq_handler(uintptr_t handle,
                                         struct io_uring *ring) {
  if (handle == 0)
    return;

  auto source = reinterpret_cast<dispatch_source_t>(handle);
  auto ctx =
      static_cast<DispatchCQHandlerContext *>(dispatch_get_context(source));

  // dispatch_cancel() is asynchronous: it stops future invocations but does not
  // interrupt an in-flight cqe_handler. At teardown that handler is typically
  // parked in io_uring_wait_cqe(), so the cancel handler (which signals
  // `cancelled`) would never run and we would deadlock below. Mirror the pthread
  // backend's teardown: wake the handler with a NOP so it returns, lets the
  // cancel handler run, and stops touching `ring` before we return. We use an
  // ordinary empty completion block so the well-tested io_uring_cq_handler() path
  // processes it exactly like any other completion (no hot-path change).
  dispatch_cancel(source);

  struct io_uring_sqe *sqe;
  while ((sqe = io_uring_get_sqe(ctx->ring)) == nullptr)
    io_uring_submit(ctx->ring);
  io_uring_prep_nop(sqe);
  io_uring_sqe_set_block(sqe, ^(struct io_uring_cqe *){
  });
  io_uring_submit(ctx->ring);

  // Blocks until the cancel handler has run (the dispatch analogue of
  // pthread_join): once it returns, no libdispatch thread touches `ring`, so the
  // caller's io_uring_queue_exit() cannot race the handler.
  dispatch_semaphore_wait(ctx->cancelled, DISPATCH_TIME_FOREVER);

  // Handler is stopped: safe to tear down the eventfd registration single-threaded.
  io_uring_unregister_eventfd(ctx->ring);
  close(ctx->fd);

  dispatch_release(ctx->cancelled);
  dispatch_release(source);
  delete ctx;
}
