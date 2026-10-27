// SPDX-License-Identifier: MIT
//
// C side of `zig build bench-sandbox` (modules/sandbox/tools/bench.zig): times
// libseccomp (the system library, linked dynamically) over the syscall
// allow-list the Zig program writes (`allow.txt`, one number per line) into the
// directory given as the first argument, and runs both libseccomp's filters and
// the Zig side's program (`ours.bpf`, raw struct sock_filter array) under the
// SAME measuring loop, for the one workload named by the second argument:
//   build            libseccomp: seccomp_init + one seccomp_rule_add per
//                    allowed syscall + seccomp_export_bpf_mem (the compile
//                    step; the filter is not loaded). count = syscalls added.
//   sys_<probe>@ref   install libseccomp's filter (default optimisation) in
//   sys_<probe>@tree  this process (@tree: SCMP_FLTATR_CTL_OPTIMIZE = 2, the
//                    binary-tree layout), @ours: install ours.bpf, then time
//                    100 back-to-back raw syscalls of <probe> per op
//                    (read of /dev/null, epoll_wait with timeout 0, futex
//                    wake, gettid) -- user and kernel time, wall clock:
//                    seccomp runs in the kernel. @none: no filter (baseline).
//   info             prints the program length of each libseccomp variant and
//                    writes both programs (lib_default.bpf, lib_tree.bpf) for the
//                    Zig side to count the instructions a syscall costs in each.
// Prints one line: name, ns/op, user-mode cycles/op (0: not counted for the
// sys_ rows), count. A filter is irreversible, so each sys_ run is its own
// process; everything it needs afterwards (write, exit_group, clock_gettime,
// brk/mmap) is on the allow-list.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// ---- shared harness (same in every module's c_bench) ----
static const char *dir;
static int cyc_fd = -1;
static volatile size_t sink;
static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}
static void cycles_open(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    cyc_fd = (int)syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
}
static unsigned long long cycles_read(void) {
    unsigned long long v = 0;
    if (cyc_fd < 0 || read(cyc_fd, &v, sizeof v) != sizeof v) return 0;
    return v;
}
static unsigned char *slurp(const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short %s\n", path); exit(1); }
    fclose(f);
    if (len) *len = (size_t)n;
    return b;
}
static void spit(const char *name, const void *b, size_t n) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(b, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}
static void bench(const char *name, size_t (*f)(void)) {
    size_t n = 1;
    for (;;) {
        double t = now_ns();
        for (size_t i = 0; i < n; i++) sink += f();
        if (now_ns() - t > 1e8) break;
        n *= 2;
    }
    double best = 1e300, bestc = 1e300;
    size_t count = 0;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        unsigned long long c0 = cycles_read();
        for (size_t i = 0; i < n; i++) count = f();
        double c = (double)(cycles_read() - c0);
        double d = now_ns() - t;
        if (d < best) best = d;
        if (c < bestc) bestc = c;
    }
    printf("%s\t%.1f\t%.1f\t%zu\n", name, best / (double)n, cyc_fd < 0 ? 0.0 : bestc / (double)n, count);
}
// ---- end shared harness ----

static int nrs[512], nr_count;
static int devnull, epfd;
static unsigned int futex_word;
static char one;
static struct epoll_event evs[1];

static void load_allow(void) {
    size_t n;
    char *t = (char *)slurp("allow.txt", &n);
    t = realloc(t, n + 1);
    t[n] = 0;
    for (char *p = strtok(t, "\n"); p; p = strtok(NULL, "\n")) nrs[nr_count++] = atoi(p);
}

static scmp_filter_ctx make_ctx(int optimize) {
    scmp_filter_ctx c = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!c) { fprintf(stderr, "seccomp_init failed\n"); exit(1); }
    if (optimize && seccomp_attr_set(c, SCMP_FLTATR_CTL_OPTIMIZE, (uint32_t)optimize) != 0) { fprintf(stderr, "optimize attr\n"); exit(1); }
    for (int i = 0; i < nr_count; i++)
        if (seccomp_rule_add(c, SCMP_ACT_ALLOW, nrs[i], 0) != 0) { fprintf(stderr, "rule_add %d failed\n", nrs[i]); exit(1); }
    return c;
}

static size_t build_op(void) {
    scmp_filter_ctx c = make_ctx(0);
    static char buf[1 << 16];
    size_t len = sizeof buf;
    if (seccomp_export_bpf_mem(c, buf, &len) != 0) { fprintf(stderr, "export_bpf_mem failed\n"); exit(1); }
    sink += len;
    seccomp_release(c);
    return (size_t)nr_count;
}

static size_t export_prog(int optimize, const char *name) {
    scmp_filter_ctx c = make_ctx(optimize);
    static char buf[1 << 16];
    size_t len = sizeof buf;
    if (seccomp_export_bpf_mem(c, buf, &len) != 0) { fprintf(stderr, "export_bpf_mem failed\n"); exit(1); }
    seccomp_release(c);
    spit(name, buf, len);
    return len / sizeof(struct sock_filter);
}

static size_t probe_read(void) { for (int i = 0; i < 100; i++) sink += (size_t)syscall(SYS_read, devnull, &one, 1); return 100; }
static size_t probe_epoll(void) { for (int i = 0; i < 100; i++) sink += (size_t)syscall(SYS_epoll_wait, epfd, evs, 1, 0); return 100; }
static size_t probe_futex(void) { for (int i = 0; i < 100; i++) sink += (size_t)syscall(SYS_futex, &futex_word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0); return 100; }
static size_t probe_gettid(void) { for (int i = 0; i < 100; i++) sink += (size_t)syscall(SYS_gettid); return 100; }

static void install_ours(void) {
    size_t n;
    unsigned char *b = slurp("ours.bpf", &n);
    struct sock_fprog fp = {.len = (unsigned short)(n / sizeof(struct sock_filter)), .filter = (struct sock_filter *)b};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("no_new_privs"); exit(1); }
    if (prctl(PR_SET_SECCOMP, 2 /* SECCOMP_MODE_FILTER */, &fp) != 0) { perror("seccomp"); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: foreign_bench <work dir> <workload>\n"); return 2; }
    dir = argv[1];
    const char *w = argv[2];
    fprintf(stderr, "libseccomp %d.%d.%d\n", SCMP_VER_MAJOR, SCMP_VER_MINOR, SCMP_VER_MICRO);
    load_allow();
    if (strcmp(w, "info") == 0) {
        printf("libseccomp program length: default %zu, optimize=2 (binary tree) %zu, %d syscalls\n", export_prog(0, "lib_default.bpf"), export_prog(2, "lib_tree.bpf"), nr_count);
        return 0;
    }
    if (strcmp(w, "build") == 0) { cycles_open(); bench(w, build_op); return 0; }
    char probe[32], variant[16];
    if (sscanf(w, "sys_%31[a-z]@%15s", probe, variant) != 2) { fprintf(stderr, "unknown workload %s\n", w); return 2; }
    size_t (*f)(void);
    if (strcmp(probe, "read") == 0) f = probe_read;
    else if (strcmp(probe, "epoll") == 0) f = probe_epoll;
    else if (strcmp(probe, "futex") == 0) f = probe_futex;
    else if (strcmp(probe, "gettid") == 0) f = probe_gettid;
    else { fprintf(stderr, "unknown probe %s\n", probe); return 2; }
    devnull = open("/dev/null", O_RDONLY);
    epfd = epoll_create1(0);
    // Everything that needs a syscall off the allow-list is done before the filter.
    sink += (size_t)syscall(SYS_gettid);
    if (strcmp(variant, "ref") == 0) { scmp_filter_ctx c = make_ctx(0); if (seccomp_load(c) != 0) { fprintf(stderr, "seccomp_load failed\n"); return 1; } }
    else if (strcmp(variant, "tree") == 0) { scmp_filter_ctx c = make_ctx(2); if (seccomp_load(c) != 0) { fprintf(stderr, "seccomp_load failed\n"); return 1; } }
    else if (strcmp(variant, "ours") == 0) install_ours();
    else if (strcmp(variant, "none") != 0) { fprintf(stderr, "unknown variant %s\n", variant); return 2; }
    bench(w, f); // no cycle counter: the filter runs in the kernel
    return 0;
}
