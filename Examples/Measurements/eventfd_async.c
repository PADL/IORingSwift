// Does a completion posted from task work signal an eventfd registered with
// IORING_REGISTER_EVENTFD_ASYNC? A recv waits on an empty socket; another
// thread writes; the submitting thread sleeps in poll(2) on the eventfd.
//   cc -O2 -pthread eventfd_async.c -luring -o eventfd_async && ./eventfd_async
#define _GNU_SOURCE
#include <liburing.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

static int fds[2];

static void *writer(void *arg) {
  (void)arg;
  usleep(100000);
  char byte = 1;
  (void)!write(fds[0], &byte, 1);
  return NULL;
}

int main(void) {
  for (int async = 0; async < 2; async++) {
    struct io_uring ring;
    io_uring_queue_init(8, &ring, 0);
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    int efd = eventfd(0, EFD_NONBLOCK);
    if (async)
      io_uring_register_eventfd_async(&ring, efd);
    else
      io_uring_register_eventfd(&ring, efd);
    char buffer[8];
    io_uring_prep_recv(io_uring_get_sqe(&ring), fds[1], buffer, sizeof(buffer), 0);
    io_uring_submit(&ring);
    pthread_t thread;
    pthread_create(&thread, NULL, writer, NULL);
    struct pollfd pfd = {efd, POLLIN, 0};
    int signalled = 0;
    for (int i = 0; i < 20 && !signalled; i++) // poll restarts when task work interrupts it
      signalled = poll(&pfd, 1, 50) > 0;
    printf("%s: completion %s, eventfd %s\n", async ? "REGISTER_EVENTFD_ASYNC" : "REGISTER_EVENTFD",
           io_uring_cq_ready(&ring) ? "posted" : "not posted", signalled ? "signalled" : "NOT signalled after 1 s");
    pthread_join(thread, NULL);
    io_uring_queue_exit(&ring);
    close(fds[0]); close(fds[1]); close(efd);
  }
  return 0;
}
