//
// Copyright (c) 2026 PADL Software Pty Ltd
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

// A pool of threads that never exit, for running Swift concurrency jobs and
// reaping io_uring completions. The kernel completes a request with -ECANCELED
// when the thread that submitted it exits, and libdispatch's cooperative pool
// retires idle threads after five seconds; these threads live for the process.
//
// Jobs go through one FIFO. A worker with nothing queued blocks in the pool's
// epoll, which holds each ring's eventfd, a timerfd per clock for delayed jobs,
// and an eventfd for waking it; at most one worker blocks there (the driver),
// the others park on a futex each, most recently parked first. The driver reaps
// the ring whose eventfd fired and runs the first two jobs that reaping resumes
// itself: a completion and the task waiting on it stay on one thread, and so
// does the peer of a request that completed with it, whose reply is usually the
// next thing the first task waits on. Jobs beyond those, and jobs enqueued from
// a running job, wake a parked worker. Each ring's eventfd is edge-triggered,
// and a ring is reaped by one worker at a time.

#include "CQHandlerInternal.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

namespace {

struct Worker {
  ioring_pool *pool;
  std::atomic<uint32_t> unparked{0}; // futex word, set by whoever unparks us
  Worker *nextIdle = nullptr;        // under pool->mutex
  bool reaping = false;              // handling epoll events, on this thread only
};

// A registered ring. Entries are reused, never freed: an epoll_wait that
// returned before the ring was removed may still hand its event to a worker,
// which the generation tells to ignore it.
struct RingEntry {
  struct io_uring *ring = nullptr;
  int eventFd = -1;
  uint32_t generation = 0;
  bool active = false; // in the epoll; under pool->mutex
  bool busy = false;   // a worker is reaping it; under pool->mutex
};

struct Timer {
  uint64_t deadline; // nanoseconds on the queue's clock
  uint64_t sequence; // orders jobs with equal deadlines
  void *job;
};

struct TimerQueue {
  clockid_t clock;
  int fd = -1;
  std::vector<Timer> heap; // min-heap on (deadline, sequence)
  uint64_t armed = 0;      // deadline the timerfd is set to, 0 if disarmed
};

constexpr uint64_t kWakeSource = ~0ULL;
constexpr uint64_t kTimerSource = ~1ULL; // minus the queue index
constexpr int kMaxEvents = 64;
// An idle worker wakes this often to take over the epoll if no worker is blocked
// in it: the driver may be running a job that, against the rules, blocks its
// thread, and nobody else would reap completions.
constexpr struct timespec kIdleParkTimeout = {0, 250000000};

thread_local Worker *tlsWorker __attribute__((tls_model("initial-exec"))) = nullptr;

uint64_t nanoseconds(clockid_t clock) {
  struct timespec now;
  clock_gettime(clock, &now);
  return uint64_t(now.tv_sec) * 1000000000ULL + uint64_t(now.tv_nsec);
}

bool timerLater(const Timer &a, const Timer &b) {
  return a.deadline != b.deadline ? a.deadline > b.deadline : a.sequence > b.sequence;
}

uint64_t ringSource(uint32_t index, uint32_t generation) {
  return uint64_t(index) << 32 | generation;
}

template <typename Body> struct ScopeExit {
  Body body;
  ~ScopeExit() { body(); }
};

} // namespace

struct ioring_pool {
  std::mutex mutex;
  std::condition_variable ringIdle; // a RingEntry's `busy` was cleared
  std::deque<void *> jobs;
  Worker *idle = nullptr;    // stack of workers parked on their futex
  bool driverParked = false; // a worker is blocked in epoll_wait
  int epollFd = -1;
  int wakeFd = -1;
  TimerQueue timers[2] = {{CLOCK_MONOTONIC}, {CLOCK_BOOTTIME}};
  uint64_t timerSequence = 0;
  std::vector<RingEntry *> rings;
  std::vector<uint32_t> freeRings;
  ioring_job_runner run;
  void *context;
};

namespace {

// Resets an eventfd or timerfd; nothing to read means it already was.
void drain(int fd) {
  uint64_t count;
  ssize_t length = read(fd, &count, sizeof(count));
  assert(length == sizeof(count) || (length < 0 && errno == EAGAIN));
  (void)length;
}

void unpark(Worker *worker) {
  // `unparked` was set under the lock by whoever popped the worker
  syscall(SYS_futex, &worker->unparked, FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
}

void wakeDriver(ioring_pool *pool) {
  uint64_t one = 1;
  // the counter is never read; it would take 2^64 wakes to fill
  ssize_t length = write(pool->wakeFd, &one, sizeof(one));
  assert(length == sizeof(one));
  (void)length;
}

// Jobs a reaper keeps for itself rather than waking a worker for
constexpr size_t kReaperJobs = 2;

// Adds a job with the lock held, drops the lock, and does whatever waking the
// job needs.
void enqueueAndUnlock(ioring_pool *pool, std::unique_lock<std::mutex> &lock,
                      void *job) {
  pool->jobs.push_back(job);
  Worker *self = tlsWorker;
  if (self != nullptr && self->pool == pool && self->reaping &&
      pool->jobs.size() <= kReaperJobs) {
    lock.unlock();
    return;
  }
  if (Worker *worker = pool->idle) {
    pool->idle = worker->nextIdle;
    worker->nextIdle = nullptr;
    worker->unparked.store(1, std::memory_order_relaxed);
    lock.unlock();
    unpark(worker);
    return;
  }
  if (pool->driverParked) {
    lock.unlock();
    wakeDriver(pool);
    return;
  }
  // every worker is busy; one will find the job when it looks for the next
  lock.unlock();
}

void armTimer(TimerQueue &queue) {
  uint64_t deadline = queue.heap.empty() ? 0 : queue.heap.front().deadline;
  if (deadline == queue.armed)
    return;
  struct itimerspec spec = {};
  spec.it_value.tv_sec = deadline / 1000000000ULL;
  spec.it_value.tv_nsec = deadline % 1000000000ULL;
  timerfd_settime(queue.fd, TFD_TIMER_ABSTIME, &spec, nullptr);
  queue.armed = deadline;
}

// lock held
void expireTimers(ioring_pool *pool, std::unique_lock<std::mutex> &lock,
                  TimerQueue &queue) {
  drain(queue.fd);
  uint64_t now = nanoseconds(queue.clock);
  while (!queue.heap.empty() && queue.heap.front().deadline <= now) {
    std::pop_heap(queue.heap.begin(), queue.heap.end(), timerLater);
    void *job = queue.heap.back().job;
    queue.heap.pop_back();
    enqueueAndUnlock(pool, lock, job);
    lock.lock();
  }
  armTimer(queue);
}

// lock held
void reapRing(ioring_pool *pool, std::unique_lock<std::mutex> &lock,
              uint64_t source) {
  uint32_t index = uint32_t(source >> 32), generation = uint32_t(source);
  if (index >= pool->rings.size())
    return;
  RingEntry *entry = pool->rings[index];
  // another worker got an earlier edge and is still reaping
  while (entry->busy && entry->active && entry->generation == generation)
    pool->ringIdle.wait(lock);
  if (!entry->active || entry->generation != generation)
    return;
  entry->busy = true;
  lock.unlock();

  // a completion posted after the drain signals again, so nothing is missed
  drain(entry->eventFd);
  io_uring_cq_reap(entry->ring);

  lock.lock();
  entry->busy = false;
  pool->ringIdle.notify_all();
}

// lock held
void handleEvents(ioring_pool *pool, std::unique_lock<std::mutex> &lock,
                  const struct epoll_event *events, int count) {
  for (int i = 0; i < count; i++) {
    uint64_t source = events[i].data.u64;
    if (source == kWakeSource)
      continue; // a job was queued; the loop takes it
    else if (source == kTimerSource || source == kTimerSource - 1)
      expireTimers(pool, lock, pool->timers[kTimerSource - source]);
    else
      reapRing(pool, lock, source);
  }
}

void park(ioring_pool *pool, std::unique_lock<std::mutex> &lock, Worker *worker) {
  worker->nextIdle = pool->idle;
  pool->idle = worker;
  lock.unlock();
  if (worker->unparked.load(std::memory_order_acquire) == 0)
    syscall(SYS_futex, &worker->unparked, FUTEX_WAIT_PRIVATE, 0, &kIdleParkTimeout,
            nullptr, 0);
  lock.lock();
  if (worker->unparked.exchange(0, std::memory_order_acquire) != 0)
    return; // popped from the stack by whoever woke us
  // timed out: leave the stack ourselves
  for (Worker **link = &pool->idle; *link != nullptr; link = &(*link)->nextIdle) {
    if (*link == worker) {
      *link = worker->nextIdle;
      worker->nextIdle = nullptr;
      break;
    }
  }
}

void *workerMain(void *argument) {
  auto worker = static_cast<Worker *>(argument);
  auto pool = worker->pool;
  struct epoll_event events[kMaxEvents];

  pthread_setname_np(pthread_self(), "IORingExecutor");
  tlsWorker = worker;

  std::unique_lock<std::mutex> lock(pool->mutex);
  for (;;) {
    if (!pool->jobs.empty()) {
      void *job = pool->jobs.front();
      pool->jobs.pop_front();
      lock.unlock();
      pool->run(pool->context, job);
      lock.lock();
      continue;
    }
    if (!pool->driverParked) {
      pool->driverParked = true;
      lock.unlock();
      int count = epoll_wait(pool->epollFd, events, kMaxEvents, -1);
      lock.lock();
      pool->driverParked = false;
      worker->reaping = true;
      handleEvents(pool, lock, events, count);
      worker->reaping = false;
      continue;
    }
    park(pool, lock, worker);
  }
}

} // namespace

unsigned ioring_pool_default_threads(void) {
  cpu_set_t cpus;
  int count = 0;
  if (sched_getaffinity(0, sizeof(cpus), &cpus) == 0)
    count = CPU_COUNT(&cpus);
  if (count <= 0)
    count = int(sysconf(_SC_NPROCESSORS_ONLN));
  return count > 0 ? unsigned(count) : 1;
}

ioring_pool_t ioring_pool_create(unsigned threads, ioring_job_runner run,
                                 void *context) {
  auto pool = std::make_unique<ioring_pool>();
  pool->run = run;
  pool->context = context;

  // closes whatever was opened if anything below fails, keeping its errno
  bool created = false;
  auto cleanup = ScopeExit([&] {
    if (created)
      return;
    int error = errno;
    for (auto &queue : pool->timers)
      if (queue.fd >= 0)
        close(queue.fd);
    if (pool->wakeFd >= 0)
      close(pool->wakeFd);
    if (pool->epollFd >= 0)
      close(pool->epollFd);
    errno = error;
  });

  if ((pool->epollFd = epoll_create1(EPOLL_CLOEXEC)) < 0)
    return nullptr;
  if ((pool->wakeFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0)
    return nullptr;
  // edge-triggered: the counter is never read, each write wakes the driver
  struct epoll_event wake = {EPOLLIN | EPOLLET, {.u64 = kWakeSource}};
  if (epoll_ctl(pool->epollFd, EPOLL_CTL_ADD, pool->wakeFd, &wake) != 0)
    return nullptr;
  for (size_t i = 0; i < 2; i++) {
    TimerQueue &queue = pool->timers[i];
    if ((queue.fd = timerfd_create(queue.clock, TFD_CLOEXEC | TFD_NONBLOCK)) < 0)
      return nullptr;
    struct epoll_event event = {EPOLLIN | EPOLLET, {.u64 = kTimerSource - i}};
    if (epoll_ctl(pool->epollFd, EPOLL_CTL_ADD, queue.fd, &event) != 0)
      return nullptr;
  }

  for (unsigned i = 0; i < std::max(threads, 1u); i++) {
    auto worker = new Worker{pool.get()};
    pthread_t thread;
    if (int error = pthread_create(&thread, nullptr, workerMain, worker)) {
      delete worker;
      if (i > 0)
        break; // the threads there are will do
      errno = error;
      return nullptr;
    }
    pthread_detach(thread);
  }
  created = true;
  return pool.release();
}

void ioring_pool_set_context(ioring_pool_t pool, void *context) {
  std::unique_lock<std::mutex> lock(pool->mutex);
  pool->context = context;
}

void ioring_pool_enqueue(ioring_pool_t pool, void *job) {
  std::unique_lock<std::mutex> lock(pool->mutex);
  enqueueAndUnlock(pool, lock, job);
}

void ioring_pool_enqueue_after(ioring_pool_t pool, clockid_t clock,
                               uint64_t delay, void *job) {
  TimerQueue &queue = pool->timers[clock == CLOCK_BOOTTIME ? 1 : 0];
  uint64_t now = nanoseconds(queue.clock);
  uint64_t deadline = now + delay < now ? UINT64_MAX : now + delay;

  std::unique_lock<std::mutex> lock(pool->mutex);
  queue.heap.push_back({deadline, pool->timerSequence++, job});
  std::push_heap(queue.heap.begin(), queue.heap.end(), timerLater);
  armTimer(queue);
}

int ioring_pool_add_ring(ioring_pool_t pool, struct io_uring *ring,
                         uintptr_t *handle) {
  *handle = 0;
  int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (fd < 0)
    return -errno;
  if (io_uring_register_eventfd(ring, fd) != 0) {
    int error = -errno;
    close(fd);
    return error;
  }

  std::unique_lock<std::mutex> lock(pool->mutex);
  uint32_t index;
  if (!pool->freeRings.empty()) {
    index = pool->freeRings.back();
    pool->freeRings.pop_back();
  } else {
    index = uint32_t(pool->rings.size());
    pool->rings.push_back(new RingEntry);
  }
  RingEntry *entry = pool->rings[index];
  entry->ring = ring;
  entry->eventFd = fd;
  entry->active = true;
  uint64_t source = ringSource(index, entry->generation);
  struct epoll_event event = {EPOLLIN | EPOLLET, {.u64 = source}};
  if (epoll_ctl(pool->epollFd, EPOLL_CTL_ADD, fd, &event) != 0) {
    int error = -errno;
    entry->active = false;
    entry->ring = nullptr;
    entry->eventFd = -1;
    pool->freeRings.push_back(index);
    lock.unlock();
    io_uring_unregister_eventfd(ring);
    close(fd);
    return error;
  }
  *handle = uintptr_t(index) + 1;
  return 0;
}

void ioring_pool_remove_ring(ioring_pool_t pool, uintptr_t handle) {
  if (handle == 0)
    return;
  uint32_t index = uint32_t(handle - 1);

  std::unique_lock<std::mutex> lock(pool->mutex);
  RingEntry *entry = pool->rings[index];
  entry->active = false;
  epoll_ctl(pool->epollFd, EPOLL_CTL_DEL, entry->eventFd, nullptr);
  // a reaper that has the ring in hand finishes with it before clearing `busy`;
  // after that nothing touches the ring or the fd
  while (entry->busy)
    pool->ringIdle.wait(lock);
  struct io_uring *ring = entry->ring;
  int fd = entry->eventFd;
  entry->ring = nullptr;
  entry->eventFd = -1;
  entry->generation++;
  pool->freeRings.push_back(index);
  lock.unlock();

  io_uring_unregister_eventfd(ring);
  close(fd);
}
