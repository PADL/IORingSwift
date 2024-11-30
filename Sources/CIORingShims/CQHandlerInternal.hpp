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

#pragma once

#include <liburing.h>
#include <cassert>

#if __has_include(<Block.h>)
#include <Block.h>
#elif __has_include(<Block/Block.h>)
#include <Block/Block.h>
#else
extern "C" void *_Block_copy(const void *);
extern "C" void _Block_release(const void *);
#endif

#if __has_include(<dispatch/dispatch.h>)
#include <dispatch/dispatch.h>
#else
// on Linux dispatch/dispatch.h is only available with unsafe Swift flags,
// which preclude the use of this package as a versioned dependency
struct dispatch_source_type_s {} __attribute__((aligned(sizeof(uintptr_t))));

typedef struct dispatch_source_s *dispatch_source_t;
typedef struct dispatch_queue_s *dispatch_queue_t;
typedef const struct dispatch_source_type_s *dispatch_source_type_t;

typedef void (^dispatch_block_t)(void);

extern "C" {
  extern const struct dispatch_source_type_s _dispatch_source_type_read;

  void dispatch_release(void *object);
  void dispatch_resume(void *object);

  void *dispatch_get_context(void *object);
  void dispatch_set_context(void *object, void *context);

  void dispatch_source_cancel(void *object);
  void dispatch_source_set_event_handler(dispatch_source_t source, dispatch_block_t handler);
  void dispatch_source_set_cancel_handler(dispatch_source_t source, dispatch_block_t handler);

  dispatch_queue_t dispatch_get_global_queue(intptr_t identifier, uintptr_t flags);
  dispatch_source_t dispatch_source_create(dispatch_source_type_t type, uintptr_t handle, uintptr_t mask, dispatch_queue_t queue);
}

#define dispatch_cancel dispatch_source_cancel
#define DISPATCH_QUEUE_PRIORITY_DEFAULT 0
#define DISPATCH_SOURCE_TYPE_READ (&_dispatch_source_type_read)

#endif

#include "CIORingShims.h"

int io_uring_cq_handler(struct io_uring *ring);

// enabled with DISPATCH_IO_URING
void dispatch_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring);
int dispatch_io_uring_init_cq_handler(void **handle, struct io_uring *ring);

// enabled with PTHREAD_IO_URING
void pthread_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring);
int pthread_io_uring_init_cq_handler(void **handle, struct io_uring *ring);
