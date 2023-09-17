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

#include <pthread.h>
#include <liburing.h>

#include "CIORingShims.h"

extern "C" {
// avoids importing Block.h which is not in the default include path on Linux
extern void *_Block_copy(const void *aBlock);
extern void _Block_release(const void *aBlock);
}

void io_uring_prep_rw_block(int op,
                            struct io_uring_sqe *sqe,
                            int fd,
                            const void *addr,
                            unsigned len,
                            __u64 offset,
                            io_uring_cqe_block block) {
    io_uring_prep_rw(op, sqe, fd, addr, len, offset);
    io_uring_sqe_set_data(sqe, _Block_copy(block));
}

static void notify_block(struct io_uring_cqe *cqe) {
    auto block =
        reinterpret_cast<io_uring_cqe_block>(io_uring_cqe_get_data(cqe));
    block(cqe);
    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
        _Block_release(block);
}

static void *io_uring_notify_thread(void *arg) {
    struct io_uring *ring = static_cast<io_uring *>(arg);

    while (true) {
        struct io_uring_cqe *cqe;
        unsigned head, i = 0;
        int oldstate;

        // FIXME: ideally we would use IORING_OP_MSG_RING or NOP to terminate
        // the notify thread, but we need to cancel even if the queue is full

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
        pthread_testcancel();
        auto err = io_uring_wait_cqe(ring, &cqe);
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

        if (err == -EINTR)
            continue;
        else if (err)
            break;

        io_uring_for_each_cqe(ring, head, cqe) {
            notify_block(cqe);
            i++;
        }
        io_uring_cq_advance(ring, i);
    }

    return nullptr;
}

int io_uring_init_notify(pthread_t *thread, struct io_uring *ring) {
    pthread_attr_t attr;
    int err;

    *thread = 0;

    err = pthread_attr_init(&attr);
    if (err)
        return -err;

    err = pthread_create(thread, &attr, io_uring_notify_thread, ring);
    if (err)
        return -err;

    pthread_setname_np(*thread, "IORingSwift Notify Thread");
    pthread_attr_destroy(&attr);

    return 0;
}

int io_uring_deinit_notify(pthread_t thread, struct io_uring *ring) {
    // FIXME: use IORING_OP_MSG_RING but needs newer kernel support
    int err;
    void *retval;

#if 0
    auto sqe = io_uring_get_sqe(ring);
    // FIXME: what if the queue is full?
    io_uring_prep_nop(sqe);

    err = io_uring_submit(ring);
    if (err)
        return err;
#else
    err = pthread_cancel(thread);
    if (err)
        return -err;
#endif

    err = pthread_join(thread, &retval);
    if (err)
        return -err;

    return 0;
}
