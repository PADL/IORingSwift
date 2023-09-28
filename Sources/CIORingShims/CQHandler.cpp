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

void io_uring_sqe_set_block(struct io_uring_sqe *sqe,
                            io_uring_cqe_block block) {
  io_uring_sqe_set_data(sqe, _Block_copy(block));
}

void io_uring_cq_invoke_blocks(struct io_uring *ring,
                               struct io_uring_cqe *cqe) {
  unsigned int head, i = 0;

  io_uring_for_each_cqe(ring, head, cqe) {
    auto block =
        reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
    block(cqe);
    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
      _Block_release(block);
    i++;
  }
  io_uring_cq_advance(ring, i);
}

int io_uring_init_cq_handler(void **handle, struct io_uring *ring) {
#if DISPATCH_IO_URING
  return dispatch_io_uring_init_cq_handler(handle, ring);
#elif PTHREAD_IO_URING
  return pthread_io_uring_init_cq_handler(handle, ring);
#else
#error implement io_uring_init_cq_handler() for your platform
#endif
}

void io_uring_deinit_cq_handler(void *handle, struct io_uring *ring) {
#if DISPATCH_IO_URING
  dispatch_io_uring_deinit_cq_handler(handle, ring);
#elif PTHREAD_IO_URING
  pthread_io_uring_deinit_cq_handler(handle, ring);
#else
#error implement io_uring_deinit_cq_handler() for your platform
#endif
}