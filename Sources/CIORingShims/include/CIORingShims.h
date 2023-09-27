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

#ifdef __cplusplus
extern "C" {
#endif

/// Completion queue event block, released after last event received
typedef void (^io_uring_cqe_block)(struct io_uring_cqe *_Nonnull);

/// Retains and sets block in submission queue event
void io_uring_sqe_set_block(struct io_uring_sqe *_Nonnull sqe,
                            _Nonnull io_uring_cqe_block block);

/// Enrol a `io_uring` for `io_uring_cqe_block` processing
int io_uring_init_event(void *_Nullable *_Nonnull, struct io_uring *_Nonnull);

/// De-enroll `io_uring` from block processing
void io_uring_deinit_event(void *_Nullable, struct io_uring *_Nonnull);

/// Private helper API, presently unused
void CMSG_APPLY(const struct msghdr *_Nonnull,
                void (^_Nonnull)(struct cmsghdr *_Nonnull,
                                 const uint8_t *_Nonnull,
                                 size_t));

#ifdef __cplusplus
}
#endif
