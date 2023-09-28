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

#include "EventHandlerInternal.hpp"

static void *event_thread(void *arg) {
  auto ring = static_cast<struct io_uring *>(arg);

  for (;;) {
    struct io_uring_cqe *cqe;
    int oldstate;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
    pthread_testcancel();
    auto err = io_uring_wait_cqe(ring, &cqe);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
    if (err == -EINTR)
      continue;
    else if (err)
      break;

    io_uring_event_handle_completion(ring, cqe);
  }

  return nullptr;
}

int pthread_io_uring_init_event(void **eventHandle, struct io_uring *ring) {
  pthread_attr_t attr;
  pthread_t thread;
  int err;

  *eventHandle = nullptr;

  err = pthread_attr_init(&attr);
  if (err)
    return -err;

  err = pthread_create(&thread, &attr, event_thread, ring);
  if (err) {
    pthread_attr_destroy(&attr);
    return -err;
  }

  pthread_attr_destroy(&attr);
  *eventHandle = reinterpret_cast<void *>(thread);
  return 0;
}

void pthread_io_uring_deinit_event(void *eventHandle, struct io_uring *ring) {
  auto thread = reinterpret_cast<pthread_t>(eventHandle);
  int err;
  void *retval;

  err = pthread_cancel(thread);
  if (err == 0)
    err = pthread_join(thread, &retval);
}
