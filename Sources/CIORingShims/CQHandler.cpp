//
// Copyright (c) 2023-2026 PADL Software Pty Ltd
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

static void release_cqe_block(struct io_uring_cqe *cqe) {
  auto block = reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
  if (block != nullptr)
    _Block_release(block);
}

// For a ring nothing can await any longer, as every submission holds its ring:
// the blocks are owed a release, not a call. The cancel itself carries no block.
void io_uring_cancel_and_drain(struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  if (sqe == nullptr)
    return;
  io_uring_prep_cancel(sqe, nullptr, IORING_ASYNC_CANCEL_ANY);
  io_uring_sqe_set_data(sqe, nullptr);
  io_uring_submit(ring);

  struct io_uring_cqe *cqe;
  // the cancel's own completion, then whatever it cancelled
  if (io_uring_wait_cqe_nr(ring, &cqe, 1) == 0) {
    release_cqe_block(cqe);
    io_uring_cqe_seen(ring, cqe);
  }
  while (io_uring_wait_cqe_nr(ring, &cqe, 0) == 0) {
    release_cqe_block(cqe);
    io_uring_cqe_seen(ring, cqe);
  }
}

// For a ring whose enter has failed for good and is not tried again: the SQEs
// it holds were never taken by the kernel, so their blocks are owed a completion,
// given here with `error`, after which the queue is empty. Under SQPOLL they may
// have been taken all the same, by a kernel thread that needs no enter and reads
// the queue as we walk it, so there the queue is left alone.
void io_uring_sq_fail(struct io_uring *ring, int error) {
  if (ring->flags & IORING_SETUP_SQPOLL)
    return;
  struct io_uring_sq *sq = &ring->sq;
  unsigned head = *sq->khead;
  unsigned shift = (ring->flags & IORING_SETUP_SQE128) ? 1 : 0;
  for (unsigned i = head; i != sq->sqe_tail; i++) {
    struct io_uring_sqe *sqe = &sq->sqes[(i & sq->ring_mask) << shift];
    auto block = reinterpret_cast<io_uring_cqe_block>(uintptr_t(sqe->user_data));
    if (block == nullptr)
      continue;
    struct io_uring_cqe cqe = {};
    cqe.user_data = sqe->user_data;
    cqe.res = -error;
    block(&cqe);
    _Block_release(block);
  }
  sq->sqe_head = sq->sqe_tail = head;
  io_uring_smp_store_release(sq->ktail, head);
}

unsigned io_uring_cq_reap(struct io_uring *ring,
                          std::vector<io_uring_cqe_block> &finished) {
  struct io_uring_cqe *cqe;
  unsigned head, total = 0;

  do {
    unsigned count = 0;
    io_uring_for_each_cqe(ring, head, cqe) {
      auto block = reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
      // a linked timeout carries none: nothing awaits its completion
      if (block != nullptr) {
        block(cqe);
        if ((cqe->flags & IORING_CQE_F_MORE) == 0)
          finished.push_back(block);
      }
      count++;
    }
    io_uring_cq_advance(ring, count);
    total += count;
    // completions that overflowed the CQ are posted only when asked for, and
    // do not signal the eventfd
  } while (io_uring_cq_has_overflow(ring) && io_uring_get_events(ring) == 0);

  return total;
}
