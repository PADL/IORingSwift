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

#include <sys/eventfd.h>
#include <liburing.h>
#include <dispatch/dispatch.h>
#include <Block/Block.h>

#include "CIORingShims.h"

void io_uring_event_handle_completion(struct io_uring *ring, struct io_uring_cqe *cqe);

// enabled with DISPATCH_IO_URING
void dispatch_io_uring_deinit_event(void *eventHandle, struct io_uring *ring);
int dispatch_io_uring_init_event(void **eventHandle, struct io_uring *ring);

// enabled with PTHREAD_IO_URING
void pthread_io_uring_deinit_event(void *eventHandle, struct io_uring *ring);
int pthread_io_uring_init_event(void **eventHandle, struct io_uring *ring);
