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

#include <map>
#include <mutex>
#include <cassert>

static time_t cq_t0 = (time_t)-1;

struct IORingStatistics {
  time_t submitTime;
  pthread_t submitThread;
  time_t completionTime;
  pthread_t completionThread;
  time_t accessTime;
  struct io_uring_sqe sqe;
  struct io_uring_cqe cqe;
  void *block;
  bool submit;
  int complete;

  bool isMultishot() {
    return (sqe.ioprio & 1);
  }
  void log() {
    assert(reinterpret_cast<uintptr_t>(block) == sqe.user_data);
    bool releasing = ((cqe.flags & IORING_CQE_F_MORE) == 0) && (complete == 1);
    assert (cqe.user_data == 0 || cqe.user_data == sqe.user_data);

    fprintf(stderr, "%s %c bl %p flags %04x/%04x Ts %lds[thr %lx] Tc %lds[thr %lx] Ta %lds opcode %d result %d %s%s[%d]%s\n",
      isMultishot() ? "MS" : "SS",
      complete ? '<' : '>',
      block,
      sqe.flags, cqe.flags,
      submitTime - cq_t0, submitThread,
      (completionTime = 0 ? (completionTime - cq_t0) : 0), completionThread,
      accessTime - cq_t0, sqe.opcode, cqe.res,
      submit ? "SUBMITTED/" : "/",
      complete ? "COMPLETED/" : "/", complete,
      releasing ? "RELEASING/" : "/");
  }

  static void submitted(struct io_uring_sqe *sqe, io_uring_cqe_block block);
  static void completed(struct io_uring_cqe *cqe, bool &doubleComplete);
};

static std::map<uintptr_t, IORingStatistics> cq_stats;
static std::mutex cq_mutex;

void
IORingStatistics::submitted(struct io_uring_sqe *sqe, io_uring_cqe_block block) {
  IORingStatistics stat{};

  if (cq_t0 == -1)
    time(&cq_t0);

  time(&stat.accessTime);
  time(&stat.submitTime);
  stat.sqe = *sqe;
  stat.block = block;
  stat.submitThread = pthread_self();
  stat.submit = true;
  stat.log();
  auto guard = std::lock_guard(cq_mutex);
  cq_stats[reinterpret_cast<uintptr_t>(block)] = stat;
}

void
IORingStatistics::completed(struct io_uring_cqe *cqe, bool &doubleComplete) {
  if (!cq_stats.contains(cqe->user_data)) {
    fprintf(stderr, "IORingStatistics block %p cqe->user_data not registered!\n", (void *)cqe->user_data);
    return;
  }

  auto &stat = cq_stats[cqe->user_data];
  time(&stat.accessTime);
  doubleComplete = stat.complete > 0;
  if (!doubleComplete) {
    time(&stat.completionTime);
    stat.completionThread = pthread_self();
    stat.cqe = *cqe;
  } else {
    fprintf(stderr, "IORingStatistics double complete! user_data %p res %d flags %d thread %lx\n", reinterpret_cast<void *>(cqe->user_data), cqe->res, cqe->flags, pthread_self());
  }
  stat.complete++;
  stat.log();
}

void io_uring_sqe_set_block(struct io_uring_sqe *sqe,
                            io_uring_cqe_block block) {
  io_uring_sqe_set_data(sqe, _Block_copy(block));
  IORingStatistics::submitted(sqe, block);
}

static void invoke_cqe_block(struct io_uring_cqe *cqe) {
  auto block = reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
  assert(block);
  bool doubleComplete;
  IORingStatistics::completed(cqe, doubleComplete);
  block(cqe);
  if ((cqe->flags & IORING_CQE_F_MORE) == 0 && !doubleComplete) {
    _Block_release(block);
    cqe->user_data = ~0ULL; // should never happen, will cause ECANCELED
  }
}

int io_uring_cq_handler(struct io_uring *ring) {
  struct io_uring_cqe *cqe;
  unsigned head, seen = 0;

  auto err = io_uring_wait_cqe(ring, &cqe);
  if (err)
    return err;

  io_uring_for_each_cqe(ring, head, cqe) {
    assert(cqe != nullptr);
    seen++;
    if (cqe->user_data == ~0ULL) {
      // used by pthreads backend to signal thread ending
      err = -ECANCELED;
      break;
    }
    if (cqe->user_data)
        invoke_cqe_block(cqe);
    else
        fprintf(stderr, "Warning: io_uring_cq_handler: CQE %d:%p missing completion block!\n", seen, cqe);
  }
  io_uring_cq_advance(ring, seen);

  if (err == -EAGAIN)
    err = 0;

  return err;
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

int32_t io_uring_op_to_int(io_uring_op op) { return static_cast<int32_t>(op); }
