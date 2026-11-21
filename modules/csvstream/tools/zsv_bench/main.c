// SPDX-License-Identifier: MIT
//
// The zsv side of `zig build bench-csvstream` (modules/csvstream/tools/bench.zig): liquidaty/zsv
// (C, MIT, SIMD) over the SAME generated files, as a black box through its public API
// (`zsv_new`, `zsv_parse_more`, `zsv_parse_bytes`, `zsv_get_cell`). Nothing of zsv is copied here.
//
//   zsv_bench <work dir> <workload>           time it: name, ns/op, count (stderr: banner)
//   zsv_bench <work dir> <workload> check     print "records fields checksum" once
//
// Workloads (the reader ones of go_bench): narrow, wide, quoted, multiline (FILE* -> zsv's own
// fread loop, default buffer) and mem_narrow (the file read into RAM first, one `zsv_parse_bytes` call). The checksum is the one of the Zig and Go sides: per field h = (h ^ len) * P, then
// (h ^ first byte) * P and (h ^ last byte) * P when not empty; per record h = (h ^ cells) * P.
//
// Built by bench.zig with: cc -O3 -I<zsv>/include main.c <zsv>/lib/libzsv.a (see ZSV_PREFIX there).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zsv.h>

#define PRIME 0x100000001b3ULL

struct result {
  uint64_t records, fields, h;
};

static uint64_t sink;

// What the row handler gets: the running result and the parser it reads cells from.
struct ctx {
  struct result res;
  zsv_parser parser;
};
static void row(void *ctx) {
  struct ctx *cx = ctx;
  struct result *r = &cx->res;
  zsv_parser p = cx->parser;
  size_t n = zsv_cell_count(p);
  uint64_t h = r->h;
  for (size_t i = 0; i < n; i++) {
    struct zsv_cell c = zsv_get_cell(p, i);
    h = (h ^ (uint64_t)c.len) * PRIME;
    if (c.len > 0) {
      h = (h ^ (uint64_t)c.str[0]) * PRIME;
      h = (h ^ (uint64_t)c.str[c.len - 1]) * PRIME;
    }
  }
  r->h = (h ^ (uint64_t)n) * PRIME;
  r->records++;
  r->fields += n;
}



static struct result scan_file(const char *path) {
  struct ctx c = {{0, 0, 0xcbf29ce484222325ULL}, NULL};
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    exit(1);
  }
  struct zsv_opts opts;
  memset(&opts, 0, sizeof opts);
  opts.row_handler = row;
  opts.ctx = &c;
  opts.stream = f;
  c.parser = zsv_new(&opts);
  enum zsv_status st;
  while ((st = zsv_parse_more(c.parser)) == zsv_status_ok) {
  }
  if (st == zsv_status_no_more_input) st = zsv_finish(c.parser);
  zsv_delete(c.parser);
  fclose(f);
  if (st != zsv_status_ok && st != zsv_status_no_more_input) {
    fprintf(stderr, "zsv status %d\n", (int)st);
    exit(1);
  }
  return c.res;
}

static struct result scan_mem(const unsigned char *data, size_t len) {
  struct ctx c = {{0, 0, 0xcbf29ce484222325ULL}, NULL};
  struct zsv_opts opts;
  memset(&opts, 0, sizeof opts);
  opts.row_handler = row;
  opts.ctx = &c;
  c.parser = zsv_new(&opts);
  enum zsv_status st = zsv_status_ok;
  st = zsv_parse_bytes(c.parser, data, len);
  // No `zsv_finish`: over `zsv_parse_bytes` it reports one more, empty, row after a final newline.
  zsv_delete(c.parser);
  if (st != zsv_status_ok) {
    fprintf(stderr, "zsv status %d\n", (int)st);
    exit(1);
  }
  return c.res;
}

static double now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static const unsigned char *g_data;
static size_t g_len;
static const char *g_path;
static int g_mem;

static uint64_t op(void) {
  struct result r = g_mem ? scan_mem(g_data, g_len) : scan_file(g_path);
  return r.h;
}

int main(int argc, char **argv) {
  if (argc != 3 && !(argc == 4 && strcmp(argv[3], "check") == 0)) {
    fprintf(stderr, "usage: zsv_bench <work dir> <workload> [check]\n");
    return 2;
  }
  const char *dir = argv[1], *name = argv[2];
  int check = argc == 4;
  const char *file = NULL;
  if (!strcmp(name, "narrow") || !strcmp(name, "mem_narrow")) file = "narrow-v1.csv";
  else if (!strcmp(name, "wide")) file = "wide-v1.csv";
  else if (!strcmp(name, "quoted")) file = "quoted-v1.csv";
  else if (!strcmp(name, "multiline")) file = "multiline-v1.csv";
  else {
    fprintf(stderr, "zsv_bench: no workload %s\n", name);
    return 2;
  }
  char path[4096];
  snprintf(path, sizeof path, "%s/%s", dir, file);
  g_path = path;
  if (!strcmp(name, "mem_narrow")) {
    g_mem = 1;
    FILE *f = fopen(path, "rb");
    if (!f) {
      perror(path);
      return 1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) return 1;
    fclose(f);
    g_data = buf;
    g_len = (size_t)n;
  }
  if (check) {
    struct result r = g_mem ? scan_mem(g_data, g_len) : scan_file(path);
    printf("%llu %llu %llu\n", (unsigned long long)r.records, (unsigned long long)r.fields, (unsigned long long)r.h);
    return 0;
  }
  long n = 1;
  for (;;) {
    double t = now_ns();
    for (long i = 0; i < n; i++) sink += op();
    if (now_ns() - t > 100e6) break;
    n *= 2;
  }
  double best = 1e300;
  uint64_t count = 0;
  for (int k = 0; k < 5; k++) {
    double t = now_ns();
    for (long i = 0; i < n; i++) count = op();
    double d = now_ns() - t;
    if (d < best) best = d;
  }
  fprintf(stderr, "zsv (liquidaty/zsv, SIMD scan engine, default buffers)\n");
  printf("%s\t%.1f\t%llu\n", name, best / (double)n, (unsigned long long)count);
  return 0;
}
