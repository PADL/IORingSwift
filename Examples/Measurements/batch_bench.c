// What one enter per burst can save: 40-byte writes to a unix stream socket,
// k requests per io_uring_enter, against k send(2) calls. A thread drains the
// other end. Prints the submitting thread's CPU time per write.
//   cc -O2 -pthread batch_bench.c -luring -o batch_bench && ./batch_bench [writes]
#define _GNU_SOURCE
#include <liburing.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fds[2];

static double cpu(void) {
  struct timespec ts;
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
  return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void *drain(void *arg) {
  (void)arg;
  char buffer[65536];
  while (read(fds[1], buffer, sizeof(buffer)) > 0)
    ;
  return NULL;
}

int main(int argc, char **argv) {
  unsigned long writes = argc > 1 ? strtoul(argv[1], NULL, 10) : 800000;
  char message[40] = {0};
  socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
  pthread_t thread;
  pthread_create(&thread, NULL, drain, NULL);
  struct io_uring ring;
  io_uring_queue_init(64, &ring, 0);

  double start = cpu();
  for (unsigned long i = 0; i < writes; i++)
    if (send(fds[0], message, sizeof(message), MSG_DONTWAIT) != sizeof(message))
      i--; // full: the reader is behind, try again
  printf("send(2):               %4.0f ns per write\n", (cpu() - start) / writes);

  for (unsigned k = 1; k <= 16; k *= 2) {
    start = cpu();
    for (unsigned long i = 0; i < writes; i += k) {
      for (unsigned j = 0; j < k; j++) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        io_uring_prep_write(sqe, fds[0], message, sizeof(message), 0);
      }
      io_uring_submit(&ring);
      // completions posted inline are reaped; a write that found the socket
      // full completes later, and is waited for
      unsigned seen = 0;
      while (seen < k) {
        struct io_uring_cqe *cqe;
        if (io_uring_peek_cqe(&ring, &cqe) != 0)
          io_uring_wait_cqe(&ring, &cqe);
        io_uring_cqe_seen(&ring, cqe);
        seen++;
      }
    }
    printf("io_uring, %2u per enter: %4.0f ns per write\n", k, (cpu() - start) / writes);
  }
  shutdown(fds[0], SHUT_WR);
  pthread_join(thread, NULL);
  return 0;
}
