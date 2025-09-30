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

void *io_uring_sqe_set_block(struct io_uring_sqe *sqe,
                             io_uring_cqe_block block) {
  void *cancellationToken;
  io_uring_sqe_set_data(sqe, (cancellationToken = _Block_copy(block)));
  return cancellationToken;
}

static void invoke_cqe_block(struct io_uring_cqe *cqe) {
  auto block = reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
  assert(block != nullptr);
  block(cqe);
  if ((cqe->flags & IORING_CQE_F_MORE) == 0)
    _Block_release(block);
}

int io_uring_cq_handler(struct io_uring *ring) {
  struct io_uring_cqe *cqe;
  unsigned head, i = 0;

  auto err = io_uring_wait_cqe(ring, &cqe);
  if (err)
    return err;

  io_uring_for_each_cqe(ring, head, cqe) {
    assert(cqe != nullptr);
#if PTHREAD_IO_URING
    if (cqe->user_data == ~0ULL) {
      err = -ECANCELED;
      break;
    }
#endif
    invoke_cqe_block(cqe);
    i++;
  }
  io_uring_cq_advance(ring, i);

  if (err == -EAGAIN)
    err = 0;

  return err;
}

int io_uring_init_cq_handler(uintptr_t *handle, struct io_uring *ring) {
#if DISPATCH_IO_URING
  return dispatch_io_uring_init_cq_handler(handle, ring);
#elif PTHREAD_IO_URING
  return pthread_io_uring_init_cq_handler(handle, ring);
#else
#error implement io_uring_init_cq_handler() for your platform
#endif
}

void io_uring_deinit_cq_handler(uintptr_t handle, struct io_uring *ring) {
#if DISPATCH_IO_URING
  dispatch_io_uring_deinit_cq_handler(handle, ring);
#elif PTHREAD_IO_URING
  pthread_io_uring_deinit_cq_handler(handle, ring);
#else
#error implement io_uring_deinit_cq_handler() for your platform
#endif
}
