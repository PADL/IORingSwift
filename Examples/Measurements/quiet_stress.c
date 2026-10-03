// Stress for the IORING_CQ_EVENTFD_DISABLED hand-over used by the inline reap:
// thread A quietens the eventfd, lets thread X post a completion (a NOP it
// submits) at a random moment, turns the eventfd back on, full barrier, and
// reaps. A completion A does not find must be signalled on the eventfd; one
// that is neither found nor signalled within a second is a lost wake-up.
//   cc -O2 -pthread quiet_stress.c -luring -o quiet_stress && ./quiet_stress [iterations]
#define _GNU_SOURCE
#include <liburing.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

static struct io_uring ring;
static atomic_ulong go, done;
static atomic_uint spinX;
static unsigned long iterations = 2000000;

static void *poster(void *arg) {
  (void)arg;
  for (unsigned long i = 1; i <= iterations; i++) {
    while (atomic_load_explicit(&go, memory_order_acquire) < i)
      ;
    for (volatile unsigned n = atomic_load(&spinX); n > 0; n--)
      ;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_nop(sqe);
    io_uring_submit(&ring);
    atomic_store_explicit(&done, i, memory_order_release);
  }
  return NULL;
}

static unsigned reap(void) {
  unsigned head, count = 0;
  struct io_uring_cqe *cqe;
  io_uring_for_each_cqe(&ring, head, cqe) count++;
  io_uring_cq_advance(&ring, count);
  return count;
}

static void quiet(int on) {
  unsigned *flags = ring.cq.kflags;
  unsigned value = __atomic_load_n(flags, __ATOMIC_RELAXED);
  value = on ? value | IORING_CQ_EVENTFD_DISABLED : value & ~IORING_CQ_EVENTFD_DISABLED;
  __atomic_store_n(flags, value, __ATOMIC_RELAXED);
  if (!on)
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

int main(int argc, char **argv) {
  if (argc > 1)
    iterations = strtoul(argv[1], NULL, 10);
  unsigned span = argc > 2 ? atoi(argv[2]) : 600;
  if (io_uring_queue_init(8, &ring, 0) != 0)
    return 1;
  int fd = eventfd(0, EFD_NONBLOCK);
  if (io_uring_register_eventfd(&ring, fd) != 0)
    return 1;
  pthread_t thread;
  pthread_create(&thread, NULL, poster, NULL);

  unsigned long inlineReaped = 0, signalled = 0, both = 0, lost = 0;
  unsigned seed = 1;
  for (unsigned long i = 1; i <= iterations; i++) {
    atomic_store(&spinX, rand_r(&seed) % span);
    unsigned spinA = rand_r(&seed) % span;
    quiet(1);
    atomic_store_explicit(&go, i, memory_order_release);
    for (volatile unsigned n = spinA; n > 0; n--)
      ;
    quiet(0);
    unsigned found = reap();
    if (found == 0) {
      struct pollfd pfd = {fd, POLLIN, 0};
      if (poll(&pfd, 1, 1000) == 0) {
        // not found, not signalled: was it posted while we slept?
        while (atomic_load(&done) < i)
          ;
        lost++;
        fprintf(stderr, "iteration %lu: completion neither reaped nor signalled\n", i);
      } else {
        signalled++;
      }
      while (atomic_load_explicit(&done, memory_order_acquire) < i)
        ;
      uint64_t count;
      (void)!read(fd, &count, sizeof(count));
      found = reap();
      if (found != 1) {
        fprintf(stderr, "iteration %lu: %u completions\n", i, found);
        return 2;
      }
    } else {
      inlineReaped++;
      while (atomic_load_explicit(&done, memory_order_acquire) < i)
        ;
      uint64_t count;
      if (read(fd, &count, sizeof(count)) == sizeof(count))
        both++; // posted after the eventfd was back on, and found all the same
    }
  }
  pthread_join(thread, NULL);
  printf("iterations %lu: reaped by A %lu (of which also signalled %lu), signalled only %lu, LOST %lu\n",
         iterations, inlineReaped, both, signalled, lost);
  return lost != 0;
}
