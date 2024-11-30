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

#include <dispatch/dispatch.h>

#include "CIORingShims.h"

int io_uring_cq_handler(struct io_uring *ring);

// enabled with DISPATCH_IO_URING
void dispatch_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring);
int dispatch_io_uring_init_cq_handler(void **handle, struct io_uring *ring);

// enabled with PTHREAD_IO_URING
void pthread_io_uring_deinit_cq_handler(void *handle, struct io_uring *ring);
int pthread_io_uring_init_cq_handler(void **handle, struct io_uring *ring);
