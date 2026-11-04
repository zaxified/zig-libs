// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-blobmsg` (modules/blobmsg/tools/bench.zig): OpenWrt
// libubox's blobmsg (ISC) and json-c (MIT), compiled from source by the driver with
// `zig cc -O3 -march=native`, timed on the same work as the Zig side:
//
//   bench_libubox <work dir> <workload>      workload = <op>.<doc>
//   json2blob.<doc>   JSON text -> blobmsg bytes: json-c parse + blobmsg_add_json_from_string
//                     into a reused blob_buf. count = bytes of the blobmsg body.
//   blob2json.<doc>   blobmsg bytes -> JSON text: blobmsg_format_json (malloc'd, freed).
//                     count = text length.
//   walk.<doc>        every attribute of the blob, nested, checked with
//                     blobmsg_check_attr and read (name length, string length, integers).
//                     count = fields + sum, as the Zig side adds them up.
//
// <work dir>/<doc>.json is the input; the blob of the two decode rows is built from it
// untimed. Output: name, ns/op, cycles/op (0 = no counter), count. Timing matches the Zig
// side: double the batch until it takes over 100 ms, best of five.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include "blobmsg.h"
#include "blobmsg_json.h"

static double now_ns(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int cycles_open(void) {
#ifdef __linux__
	struct perf_event_attr a;
	memset(&a, 0, sizeof a);
	a.type = PERF_TYPE_HARDWARE;
	a.size = sizeof a;
	a.config = PERF_COUNT_HW_CPU_CYCLES;
	a.exclude_kernel = 1;
	a.exclude_hv = 1;
	return (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
#else
	return -1;
#endif
}

static unsigned long long cycles_read(int fd) {
	unsigned long long v = 0;
#ifdef __linux__
	if (fd >= 0 && read(fd, &v, sizeof v) != sizeof v) v = 0;
#endif
	return v;
}

static char *slurp(const char *path, size_t *len) {
	FILE *f = fopen(path, "rb");
	if (!f) { perror(path); exit(1); }
	fseek(f, 0, SEEK_END);
	*len = (size_t)ftell(f);
	fseek(f, 0, SEEK_SET);
	char *b = malloc(*len + 1);
	if (fread(b, 1, *len, f) != *len) { fprintf(stderr, "short read %s\n", path); exit(1); }
	b[*len] = 0;
	fclose(f);
	return b;
}

static uint64_t walk_n, walk_sum;

static void walk_children(struct blob_attr *first, size_t len, int has_names);

static void walk_attr(struct blob_attr *cur) {
	walk_n++;
	walk_sum += strlen(blobmsg_name(cur));
	switch (blobmsg_type(cur)) {
	case BLOBMSG_TYPE_STRING: walk_sum += strlen(blobmsg_get_string(cur)); break;
	case BLOBMSG_TYPE_INT8: walk_sum += blobmsg_get_u8(cur); break;
	case BLOBMSG_TYPE_INT16: walk_sum += (uint16_t)blobmsg_get_u16(cur); break;
	case BLOBMSG_TYPE_INT32: walk_sum += (uint32_t)blobmsg_get_u32(cur); break;
	case BLOBMSG_TYPE_INT64: walk_sum += (uint64_t)blobmsg_get_u64(cur); break;
	case BLOBMSG_TYPE_TABLE:
	case BLOBMSG_TYPE_ARRAY:
		walk_children(blobmsg_data(cur), blobmsg_data_len(cur), 1);
		break;
	default: break;
	}
}

static void walk_children(struct blob_attr *first, size_t len, int has_names) {
	struct blob_attr *cur;
	size_t rem = len;
	for (cur = first; rem >= sizeof(struct blob_attr) && blob_pad_len(cur) <= rem && blob_pad_len(cur) >= sizeof(struct blob_attr);
	     rem -= blob_pad_len(cur), cur = blob_next(cur)) {
		if (!blobmsg_check_attr(cur, false)) { fprintf(stderr, "bad attr\n"); exit(1); }
		walk_attr(cur);
	}
	(void)has_names;
}

static uint64_t run_op(int op, const char *text, struct blob_buf *b, struct blob_buf *src) {
	switch (op) {
	case 0: // json2blob
		blob_buf_init(b, 0);
		if (!blobmsg_add_json_from_string(b, text)) { fprintf(stderr, "parse failed\n"); exit(1); }
		return blob_len(b->head);
	case 1: { // blob2json
		char *s = blobmsg_format_json(src->head, true);
		uint64_t n = strlen(s);
		free(s);
		return n;
	}
	default: // walk
		walk_n = 0;
		walk_sum = 0;
		walk_children((struct blob_attr *)blob_data(src->head), blob_len(src->head), 0);
		return walk_n + walk_sum;
	}
}

int main(int argc, char **argv) {
	if (argc != 3) { fprintf(stderr, "usage: bench_libubox <work dir> <op.doc>\n"); return 2; }
	fprintf(stderr, "libubox a396f38a + json-c d9b375ff, compiled from source with zig cc -O3 -march=native\n");
	char name[256];
	snprintf(name, sizeof name, "%s", argv[2]);
	char *dot = strchr(name, '.');
	if (!dot) { fprintf(stderr, "workload must be op.doc\n"); return 2; }
	*dot = 0;
	int op = !strcmp(name, "json2blob") ? 0 : !strcmp(name, "blob2json") ? 1 : !strcmp(name, "walk") ? 2 : -1;
	if (op < 0) { fprintf(stderr, "unknown op %s\n", name); return 2; }
	char path[4096];
	snprintf(path, sizeof path, "%s/%s.json", argv[1], dot + 1);
	size_t len;
	char *text = slurp(path, &len);

	static struct blob_buf b, src;
	blob_buf_init(&src, 0);
	if (!blobmsg_add_json_from_string(&src, text)) { fprintf(stderr, "parse failed\n"); return 1; }
	int cyc = cycles_open();
	uint64_t result = 0;
	size_t n = 1;
	for (;;) {
		double t = now_ns();
		for (size_t i = 0; i < n; i++) result = run_op(op, text, &b, &src);
		if (now_ns() - t > 1e8) break;
		n *= 2;
	}
	double best = 1e300;
	unsigned long long best_cyc = ~0ULL;
	for (int k = 0; k < 5; k++) {
		double t = now_ns();
		unsigned long long c0 = cycles_read(cyc);
		for (size_t i = 0; i < n; i++) result = run_op(op, text, &b, &src);
		unsigned long long c = cycles_read(cyc) - c0;
		double d = now_ns() - t;
		if (d < best) best = d;
		if (c < best_cyc) best_cyc = c;
	}
	printf("%s\t%.1f\t%.1f\t%llu\n", argv[2], best / (double)n, cyc >= 0 ? (double)best_cyc / (double)n : 0.0, (unsigned long long)result);
	return 0;
}
