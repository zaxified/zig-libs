// SPDX-License-Identifier: MIT
//
// soracle -- libseccomp behind a pipe, for `tools/interop.zig`.
//
// Written against libseccomp's public API only (seccomp.h and its man
// pages); libseccomp's source is LGPL-2.1 and was not read. Links the
// system libseccomp (`-lseccomp`).
//
// Requests on stdin, little-endian:
//   'V'                                     -> the library version "a.b.c"
//   'B' u32 default_action u32 badarch_action u8 optimize u32 n_rules
//       n_rules x { u32 action i32 nr u32 n_cmp
//                   n_cmp x { u32 arg u32 op u64 datum_a u64 datum_b } }
//                                           -> the exported classic-BPF program
// Reply: u8 status, u32 n, then n bytes (status 0) or nothing (status 1, n =
// the failing step: 0 init, 1 attributes, 2 + i rule i, 0xffffffff export;
// the -errno follows as an extra u32).

#include <seccomp.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what) {
    fprintf(stderr, "soracle: %s\n", what);
    exit(2);
}

static void rd(void *p, size_t n) {
    if (fread(p, 1, n, stdin) != n) {
        if (feof(stdin)) exit(0);
        die("short read");
    }
}

static uint8_t r8(void) { uint8_t v; rd(&v, 1); return v; }
static uint32_t r32(void) { uint8_t b[4]; rd(b, 4); return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }
static uint64_t r64(void) { uint64_t lo = r32(); return lo | (uint64_t)r32() << 32; }

static void w32(uint32_t v) {
    uint8_t b[4] = { v, v >> 8, v >> 16, v >> 24 };
    fwrite(b, 1, 4, stdout);
}

static void ok(const void *p, uint32_t n) {
    fputc(0, stdout);
    w32(n);
    fwrite(p, 1, n, stdout);
    fflush(stdout);
}

static void fail(uint32_t step, int rc) {
    alarm(0);
    fputc(1, stdout);
    w32(step);
    w32((uint32_t)rc);
    fflush(stdout);
}

#define MAX_RULES 1024
#define MAX_CMP 6

// The request being built, for the watchdog's report.
static uint32_t cur_def, cur_n, cur_action[MAX_RULES], cur_ncmp[MAX_RULES];
static int32_t cur_nr[MAX_RULES];
static struct scmp_arg_cmp cur_cmp[MAX_RULES][MAX_CMP];
static uint8_t cur_opt;

// A libseccomp call that runs this long is a finding: report the rule set
// and exit (the caller then fails the run instead of hanging).
static void watchdog(int sig) {
    (void)sig;
    fprintf(stderr, "soracle: HANG building a filter (optimize %u, default %#x, %u rules)\n", cur_opt, cur_def, cur_n);
    for (uint32_t i = 0; i < cur_n; i++) {
        fprintf(stderr, "  rule %u: nr %d action %#x", i, cur_nr[i], cur_action[i]);
        for (uint32_t j = 0; j < cur_ncmp[i]; j++)
            fprintf(stderr, " [arg%u op%d a=%#llx b=%#llx]", cur_cmp[i][j].arg, (int)cur_cmp[i][j].op,
                    (unsigned long long)cur_cmp[i][j].datum_a, (unsigned long long)cur_cmp[i][j].datum_b);
        fprintf(stderr, "\n");
    }
    _exit(3);
}

static void build(void) {
    uint32_t def = r32(), badarch = r32();
    uint8_t optimize = r8();
    uint32_t n = r32();
    if (n > MAX_RULES) die("too many rules");
    uint32_t *action = cur_action, *ncmp = cur_ncmp;
    int32_t *nr = cur_nr;
    struct scmp_arg_cmp (*cmp)[MAX_CMP] = cur_cmp;
    cur_def = def;
    cur_opt = optimize;
    cur_n = n;
    for (uint32_t i = 0; i < n; i++) {
        action[i] = r32();
        nr[i] = (int32_t)r32();
        ncmp[i] = r32();
        if (ncmp[i] > MAX_CMP) die("too many comparisons");
        for (uint32_t j = 0; j < ncmp[i]; j++) {
            cmp[i][j].arg = r32();
            cmp[i][j].op = (enum scmp_compare)r32();
            cmp[i][j].datum_a = r64();
            cmp[i][j].datum_b = r64();
        }
    }
    alarm(5);
    scmp_filter_ctx ctx = seccomp_init(def);
    if (ctx == NULL) { fail(0, 0); return; }
    int rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, badarch);
    if (rc == 0 && optimize != 0) rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, optimize);
    if (rc != 0) { seccomp_release(ctx); fail(1, rc); return; }
    for (uint32_t i = 0; i < n; i++) {
        rc = seccomp_rule_add_exact_array(ctx, action[i], nr[i], ncmp[i], cmp[i]);
        if (rc != 0) { seccomp_release(ctx); fail(2 + i, rc); return; }
    }
    static uint8_t buf[8 * 65536];
    size_t len = sizeof buf;
    rc = seccomp_export_bpf_mem(ctx, buf, &len);
    seccomp_release(ctx);
    alarm(0);
    if (rc != 0) { fail(0xffffffffu, rc); return; }
    ok(buf, (uint32_t)len);
}

int main(void) {
    signal(SIGALRM, watchdog);
    for (;;) {
        int c = getchar();
        if (c == EOF) return 0;
        switch (c) {
        case 'V': {
            const struct scmp_version *v = seccomp_version();
            char s[64];
            int k = snprintf(s, sizeof s, "%u.%u.%u", v->major, v->minor, v->micro);
            ok(s, (uint32_t)k);
            break;
        }
        case 'B':
            build();
            break;
        default:
            die("unknown request");
        }
    }
}
