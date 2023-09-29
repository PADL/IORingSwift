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

#include <pthread.h>

static void *cqe_thread(void *arg) {
  auto ring = static_cast<struct io_uring *>(arg);

  while (true) {
    auto err = io_uring_cq_handler(ring);
    if (err == -EINTR)
      continue;
    else if (err)
      break;
  }

  return nullptr;
}

int pthread_io_uring_init_cq_handler(void **handle, struct io_uring *ring) {
  pthread_attr_t attr;
  pthread_t thread;
  int err;

  *handle = nullptr;

  err = pthread_attr_init(&attr);
  if (err)
    return -err;

  err = pthread_create(&thread, &attr, cqe_thread, ring);
  if (err) {
    pthread_attr_destroy(&attr);
    return -err;
  }

  pthread_attr_destroy(&attr);
  *handle = reinterpret_cast<void *>(thread);
  return 0;
}

void pthread_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring) {
  auto thread = reinterpret_cast<pthread_t>(handle);
  struct io_uring_sqe *sqe;
  void *retval;

  while ((sqe = io_uring_get_sqe(ring)) == nullptr)
    ;

  io_uring_prep_nop(sqe);
  io_uring_submit(ring);

  pthread_join(thread, &retval);
}
