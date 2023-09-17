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

typedef void (^io_uring_cqe_block)(struct io_uring_cqe *_Nonnull);

void io_uring_prep_rw_block(int op,
                            struct io_uring_sqe *_Nonnull,
                            int fd,
                            const void *_Nullable,
                            unsigned,
                            __u64,
                            _Nonnull io_uring_cqe_block);

int io_uring_init_notify(pthread_t *_Nonnull, struct io_uring *_Nonnull);
int io_uring_deinit_notify(pthread_t, struct io_uring *_Nonnull);

#ifdef __cplusplus
}
#endif
