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

#include <inttypes.h>
#include <liburing.h>

#ifndef IORING_SETUP_COOP_TASKRUN
#include "BackDeploy.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// Completion queue event block, released after last event received
typedef void (^io_uring_cqe_block)(struct io_uring_cqe *_Nonnull);

/// Retains and sets block in submission queue event
void * _Nonnull
io_uring_sqe_set_block(struct io_uring_sqe *_Nonnull sqe,
                       _Nonnull io_uring_cqe_block block);

/// Enrol a `io_uring` for `io_uring_cqe_block` processing
int io_uring_init_cq_handler(void *_Nullable *_Nonnull,
                             struct io_uring *_Nonnull);

/// De-enroll `io_uring` from block processing
void io_uring_deinit_cq_handler(void *_Nullable, struct io_uring *_Nonnull);

#ifdef __cplusplus
}
#endif
