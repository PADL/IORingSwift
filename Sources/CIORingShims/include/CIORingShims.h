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
#include <linux/io_uring.h>

#ifndef IORING_MSG_RING_FLAGS_PASS
#define IORING_MSG_RING_FLAGS_PASS (1U << 1)
#endif
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
void *_Nonnull io_uring_sqe_set_block(struct io_uring_sqe *_Nonnull sqe,
                                      _Nonnull io_uring_cqe_block block);

/// Cancels every request on a ring being torn down and drains their completions,
/// releasing their blocks without invoking them
void io_uring_cancel_and_drain(struct io_uring *_Nonnull ring);

/// A pool of persistent threads that run jobs and reap completions
typedef struct ioring_pool *ioring_pool_t;

/// Runs one job on a pool thread
typedef void (*ioring_job_runner)(void *_Nullable context, void *_Nonnull job);

/// The CPUs this process may run on
unsigned ioring_pool_default_threads(void);

/// Starts `threads` threads; NULL with errno set on failure
ioring_pool_t _Nullable ioring_pool_create(unsigned threads,
                                           ioring_job_runner _Nonnull run,
                                           void *_Nullable context);

/// Sets the context passed to the job runner
void ioring_pool_set_context(ioring_pool_t _Nonnull pool, void *_Nullable context);

/// Whether the calling thread is one of the pool's
bool ioring_pool_is_worker(ioring_pool_t _Nonnull pool);

/// `io_uring_submit(ring)` made by a pool thread, which the requests then belong to
int ioring_pool_submit(ioring_pool_t _Nonnull pool, struct io_uring *_Nonnull ring);

/// Runs `job` on a pool thread
void ioring_pool_enqueue(ioring_pool_t _Nonnull pool, void *_Nonnull job);

/// Runs `job` once `nanoseconds` have passed on `clock` (CLOCK_MONOTONIC or CLOCK_BOOTTIME)
void ioring_pool_enqueue_after(ioring_pool_t _Nonnull pool, clockid_t clock,
                               uint64_t nanoseconds, void *_Nonnull job);

/// Reaps `ring`'s completions on pool threads, instead of `io_uring_init_cq_handler`
int ioring_pool_add_ring(ioring_pool_t _Nonnull pool,
                         struct io_uring *_Nonnull ring,
                         uintptr_t *_Nonnull handle);

/// Stops reaping the ring; returns once no pool thread touches it
void ioring_pool_remove_ring(ioring_pool_t _Nonnull pool, uintptr_t handle);

#ifdef __cplusplus
}
#endif
