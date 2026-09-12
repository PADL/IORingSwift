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
#include <cstdint>

#if __has_include(<Block.h>)
#include <Block.h>
#elif __has_include(<Block/Block.h>)
#include <Block/Block.h>
#else
extern "C" void *_Block_copy(const void *);
extern "C" void _Block_release(const void *);
#endif

#include "CIORingShims.h"

#include <vector>

// Invokes the blocks of the completions already posted, without waiting, and
// flushes any the kernel had to hold back. A block whose request is finished is
// appended to `finished` for the caller to release: releasing it may free the
// last owner of the ring, and must wait until the ring is no longer being read.
unsigned io_uring_cq_reap(struct io_uring *ring,
                          std::vector<io_uring_cqe_block> &finished);
