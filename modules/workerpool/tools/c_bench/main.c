// SPDX-License-Identifier: MIT

// C side of `zig build bench-workerpool` (modules/workerpool/tools/bench.zig):
// times Pithikos/C-Thread-Pool (thpool/, pinned unmodified, see thpool/SOURCE)
// through its public API only. bench.zig builds this with
//   zig cc -O2 -DDISABLE_PRINT -pthread main.c thpool/thpool.c -o thpool_bench
// and runs it as `thpool_bench <workload>`; it prints one line, tab-separated:
// name, ns/op, count, sum. One op = the whole workload once.
//
//   burst_noop      submit 100 000 no-op jobs from the main thread, then wait
//   burst_work      the same, ~1 us of work per job (64 rounds of splitmix64)
//   pingpong        10 000 x (submit one job, wait)
//   multi_producer  4 producer threads x 25 000 no-op jobs, then wait
//   inline          the 100 000 no-op jobs run directly on the caller (no pool)
//
// A job adds 1 to a shared counter and its result to a shared sum (the
// checksum both sides print and bench.zig compares). The job argument is the
// job's index + 1, passed as the pointer value. ONE pool of 4 threads is made
// before timing and destroyed after (thpool keeps global state, so a process
// holds one pool at a time). Timing matches the Zig side: double the batch
// until one batch takes over 100 ms, then keep the best of five.

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "thpool/thpool.h"

#define N_WORKERS 4
#define BURST 100000
#define PINGPONG 10000
#define PRODUCERS 4
#define PER_PRODUCER 25000

static atomic_uint_fast64_t g_count;
static atomic_uint_fast64_t g_sum;

static uint64_t splitmix64(uint64_t *x) {
	uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static void job_noop(void *arg) {
	atomic_fetch_add_explicit(&g_count, 1, memory_order_relaxed);
	atomic_fetch_add_explicit(&g_sum, (uint64_t)(uintptr_t)arg, memory_order_relaxed);
}

static void job_work(void *arg) {
	uint64_t s = (uint64_t)(uintptr_t)arg;
	uint64_t h = 0;
	for (int r = 0; r < 64; r++) h ^= splitmix64(&s);
	atomic_fetch_add_explicit(&g_count, 1, memory_order_relaxed);
	atomic_fetch_add_explicit(&g_sum, h, memory_order_relaxed);
}

static threadpool pool;

static void reset(void) {
	atomic_store(&g_count, 0);
	atomic_store(&g_sum, 0);
}

static void op_burst(void (*fn)(void *)) {
	for (uintptr_t i = 0; i < BURST; i++) thpool_add_work(pool, fn, (void *)(i + 1));
	thpool_wait(pool);
}

static void op_burst_noop(void) { op_burst(job_noop); }
static void op_burst_work(void) { op_burst(job_work); }

static void op_pingpong(void) {
	for (uintptr_t i = 0; i < PINGPONG; i++) {
		thpool_add_work(pool, job_noop, (void *)(i + 1));
		thpool_wait(pool);
	}
}

static void *producer(void *p) {
	uintptr_t base = (uintptr_t)p * PER_PRODUCER;
	for (uintptr_t i = 0; i < PER_PRODUCER; i++) thpool_add_work(pool, job_noop, (void *)(base + i + 1));
	return NULL;
}

static void op_multi_producer(void) {
	pthread_t t[PRODUCERS];
	for (uintptr_t k = 0; k < PRODUCERS; k++) pthread_create(&t[k], NULL, producer, (void *)k);
	for (int k = 0; k < PRODUCERS; k++) pthread_join(t[k], NULL);
	thpool_wait(pool);
}

static void op_inline(void) {
	void (*volatile fn)(void *) = job_noop;
	for (uintptr_t i = 0; i < BURST; i++) fn((void *)(i + 1));
}

static double now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void run_op(void (*op)(void)) {
	reset();
	op();
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: thpool_bench <workload>\n");
		return 2;
	}
	const char *name = argv[1];
	void (*op)(void) = NULL;
	int needs_pool = 1;
	if (!strcmp(name, "burst_noop")) op = op_burst_noop;
	else if (!strcmp(name, "burst_work")) op = op_burst_work;
	else if (!strcmp(name, "pingpong")) op = op_pingpong;
	else if (!strcmp(name, "multi_producer")) op = op_multi_producer;
	else if (!strcmp(name, "inline")) { op = op_inline; needs_pool = 0; }
	else {
		fprintf(stderr, "unknown workload %s\n", name);
		return 2;
	}

	if (needs_pool) pool = thpool_init(N_WORKERS);

	size_t n = 1;
	for (;;) {
		double t = now_ns();
		for (size_t i = 0; i < n; i++) run_op(op);
		if (now_ns() - t > 100e6) break;
		n *= 2;
	}
	double best = 1e300;
	for (int k = 0; k < 5; k++) {
		double t = now_ns();
		for (size_t i = 0; i < n; i++) run_op(op);
		double d = now_ns() - t;
		if (d < best) best = d;
	}
	// The counters hold the last op's result (reset at the start of each op).
	uint64_t count = atomic_load(&g_count);
	uint64_t sum = atomic_load(&g_sum);

	if (needs_pool) thpool_destroy(pool);
	printf("%s\t%.1f\t%llu\t%llu\n", name, best / (double)n, (unsigned long long)count, (unsigned long long)sum);
	return 0;
}
