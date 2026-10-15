// How a thread waits for a completion that arrives while it is idle: a recv on
// a unix stream socket whose byte another thread writes once the waiter sleeps.
//   mode 0: eventfd + epoll (edge-triggered), eventfd read back, as the pool did
//   mode 1: eventfd + epoll, eventfd not read
//   mode 2: io_uring_submit, then io_uring_wait_cqe (io_uring_enter GETEVENTS)
//   mode 3: io_uring_submit_and_wait(1): the submit and the wait in one enter
// Prints the waiter thread's CPU time and system calls per completion.
//   cc -O2 -pthread wait_bench.c -luring -o wait_bench && ./wait_bench [ops] [setup flags]
#define _GNU_SOURCE
#include <errno.h>
#include <liburing.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fds[2];
static atomic_ulong consumed;
static unsigned long ops = 20000;

static double now(clockid_t clock) {
  struct timespec ts;
  clock_gettime(clock, &ts);
  return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void *writer(void *arg) {
  (void)arg;
  for (unsigned long i = 0; i < ops; i++) {
    while (atomic_load_explicit(&consumed, memory_order_acquire) < i)
      ;
    // long enough for the waiter to have submitted its recv and gone to sleep
    double until = now(CLOCK_MONOTONIC) + 60000;
    while (now(CLOCK_MONOTONIC) < until)
      ;
    char byte = 1;
    if (write(fds[0], &byte, 1) != 1)
      abort();
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc > 1)
    ops = strtoul(argv[1], NULL, 10);
  unsigned setup = argc > 2 ? strtoul(argv[2], NULL, 0) : 0;
  for (int mode = 0; mode < 4; mode++) {
    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, setup) != 0)
      return 1;
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    int efd = -1, epfd = -1;
    if (mode < 2) {
      efd = eventfd(0, EFD_NONBLOCK);
      io_uring_register_eventfd(&ring, efd);
      epfd = epoll_create1(0);
      struct epoll_event event = {EPOLLIN | EPOLLET, {.u64 = 1}};
      epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &event);
    }
    atomic_store(&consumed, 0);
    pthread_t thread;
    pthread_create(&thread, NULL, writer, NULL);

    unsigned long syscalls = 0;
    double cpu = now(CLOCK_THREAD_CPUTIME_ID);
    char buffer[16];
    for (unsigned long i = 0; i < ops; i++) {
      struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
      io_uring_prep_recv(sqe, fds[1], buffer, sizeof(buffer), 0);
      struct io_uring_cqe *cqe;
      if (mode == 3) {
        io_uring_submit_and_wait(&ring, 1);
        syscalls++;
      } else {
        io_uring_submit(&ring);
        syscalls++;
      }
      if (mode < 2) {
        // as the pool's driver does: until the epoll reports the eventfd, which
        // is the second call, the first being interrupted for the task work
        for (;;) {
          struct epoll_event event;
          int count = epoll_wait(epfd, &event, 1, -1);
          syscalls++;
          if (count > 0)
            break;
        }
        if (mode == 0) {
          uint64_t count;
          (void)!read(efd, &count, sizeof(count));
          syscalls++;
        }
      } else if (mode == 2) {
        if (io_uring_cq_ready(&ring) == 0) {
          io_uring_wait_cqe(&ring, &cqe);
          syscalls++;
        }
      }
      if (io_uring_peek_cqe(&ring, &cqe) != 0 || cqe->res != 1)
        abort();
      io_uring_cqe_seen(&ring, cqe);
      atomic_store_explicit(&consumed, i + 1, memory_order_release);
    }
    cpu = now(CLOCK_THREAD_CPUTIME_ID) - cpu;
    pthread_join(thread, NULL);
    printf("mode %d: %.0f ns CPU per completion, %.2f system calls per completion\n", mode,
           cpu / ops, (double)syscalls / ops);
    io_uring_queue_exit(&ring);
    close(fds[0]);
    close(fds[1]);
    if (efd >= 0) {
      close(efd);
      close(epfd);
    }
  }
  return 0;
}
