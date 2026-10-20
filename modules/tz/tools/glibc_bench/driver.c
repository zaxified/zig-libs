// SPDX-License-Identifier: MIT

// glibc side of `zig build bench-tz` (modules/tz/tools/bench.zig): the C library's
// own localtime_r / mktime over the SAME pinned tzdata tree the module was
// generated from (never the host's /usr/share/zoneinfo). See README.md here.
//
//   driver <work dir> <workload>                  time it: "name\tns/op\tcount"
//   driver <work dir> <workload> dump <outfile>   write one i64 per input
//
// <work dir>/tzdir.txt holds the zoneinfo directory (TZDIR); <work dir>/<workload>.in
// holds u64 lens[4] followed by the inputs of the four zones in order (i64
// instants, or 6 x i32 {y,m,d,hh,mm,ss} records for local_to_utc).
//
//   utc_to_offset_table / utc_to_offset_footer   localtime_r -> tm_gmtoff
//   local_to_utc                                 mktime, tm_isdst = -1
//   abbrev                                       localtime_r -> tm_zone, hashed
//
// One zone is active at a time (TZ=:<zone>, tzset between zones, untimed); only
// the conversion loops are timed. One op = all four zones' inputs once. Timing
// matches the other sides: double the batch until it takes over 100 ms, then the
// best of five.
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gnu/libc-version.h>

static const char *zones[4] = { "Europe/Prague", "America/New_York", "Australia/Sydney", "Asia/Kolkata" };

enum kind { K_OFFSET, K_LOCAL, K_ABBREV };

static uint64_t lens[4];
static void *data[4];
static enum kind kind;
static double acc_ns;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void die(const char *m, const char *a) {
    fprintf(stderr, "driver: %s %s\n", m, a ? a : "");
    exit(1);
}

static uint64_t hash_abbr(const char *s) {
    uint64_t h = 0;
    for (; *s; s++) h = h * 131 + (unsigned char)*s;
    return h;
}

static inline __attribute__((always_inline)) uint64_t run_zone(int z, int64_t *out) {
    uint64_t sum = 0;
    uint64_t n = lens[z];
    struct tm tm;
    if (kind == K_LOCAL) {
        const int32_t *in = data[z];
        for (uint64_t i = 0; i < n; i++, in += 6) {
            memset(&tm, 0, sizeof tm);
            tm.tm_year = in[0] - 1900;
            tm.tm_mon = in[1] - 1;
            tm.tm_mday = in[2];
            tm.tm_hour = in[3];
            tm.tm_min = in[4];
            tm.tm_sec = in[5];
            tm.tm_isdst = -1;
            int64_t r = (int64_t)mktime(&tm);
            sum += (uint64_t)r;
            if (out) *out++ = r;
        }
    } else {
        const int64_t *in = data[z];
        for (uint64_t i = 0; i < n; i++) {
            time_t t = (time_t)in[i];
            localtime_r(&t, &tm);
            int64_t r = kind == K_OFFSET ? (int64_t)tm.tm_gmtoff : (int64_t)hash_abbr(tm.tm_zone);
            sum += (uint64_t)r;
            if (out) *out++ = r;
        }
    }
    return sum;
}

static void set_zone(int z) {
    char buf[64];
    snprintf(buf, sizeof buf, ":%s", zones[z]);
    setenv("TZ", buf, 1);
    tzset();
}

static uint64_t op(void) {
    uint64_t sum = 0;
    for (int z = 0; z < 4; z++) {
        set_zone(z);
        double t0 = now_ns();
        sum += run_zone(z, NULL);
        acc_ns += now_ns() - t0;
    }
    return sum;
}

int main(int argc, char **argv) {
    if (argc != 3 && !(argc == 5 && strcmp(argv[3], "dump") == 0)) die("usage: driver <work dir> <workload> [dump <outfile>]", NULL);
    const char *dir = argv[1], *name = argv[2];
    char path[1024], tzdir[1024];
    snprintf(path, sizeof path, "%s/tzdir.txt", dir);
    FILE *f = fopen(path, "r");
    if (!f) die("cannot open", path);
    if (!fgets(tzdir, sizeof tzdir, f)) die("empty", path);
    fclose(f);
    tzdir[strcspn(tzdir, "\r\n")] = 0;
    setenv("TZDIR", tzdir, 1);

    if (strcmp(name, "utc_to_offset_table") == 0 || strcmp(name, "utc_to_offset_footer") == 0) kind = K_OFFSET;
    else if (strcmp(name, "local_to_utc") == 0) kind = K_LOCAL;
    else if (strcmp(name, "abbrev") == 0) kind = K_ABBREV;
    else die("unknown workload", name);

    snprintf(path, sizeof path, "%s/%s.in", dir, name);
    f = fopen(path, "rb");
    if (!f) die("cannot open", path);
    if (fread(lens, 8, 4, f) != 4) die("short header", path);
    for (int z = 0; z < 4; z++) {
        size_t rec = kind == K_LOCAL ? 24 : 8;
        data[z] = malloc(lens[z] * rec + 8);
        if (fread(data[z], rec, lens[z], f) != lens[z]) die("short data", path);
    }
    fclose(f);

    // Zone files must really be the pinned tree's: a missing one makes glibc fall
    // back to UTC silently.
    for (int z = 0; z < 4; z++) {
        snprintf(path, sizeof path, "%s/%s", tzdir, zones[z]);
        FILE *zf = fopen(path, "rb");
        if (!zf) die("zone file missing", path);
        fclose(zf);
    }

    if (argc == 5) {
        uint64_t total = lens[0] + lens[1] + lens[2] + lens[3];
        int64_t *out = malloc(total * 8 + 8), *p = out;
        for (int z = 0; z < 4; z++) {
            set_zone(z);
            run_zone(z, p);
            p += lens[z];
        }
        FILE *o = fopen(argv[4], "wb");
        if (!o) die("cannot write", argv[4]);
        fwrite(out, 8, total, o);
        fclose(o);
        return 0;
    }

    uint64_t n = 1, count = 0;
    for (;;) {
        acc_ns = 0;
        for (uint64_t i = 0; i < n; i++) count = op();
        if (acc_ns > 100e6) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        acc_ns = 0;
        for (uint64_t i = 0; i < n; i++) count = op();
        double per = acc_ns / (double)n;
        if (per < best) best = per;
    }
    fprintf(stderr, "glibc %s (localtime_r/mktime), TZDIR=%s\n", gnu_get_libc_version(), tzdir);
    printf("%s\t%.1f\t%llu\n", name, best, (unsigned long long)count);
    return 0;
}
