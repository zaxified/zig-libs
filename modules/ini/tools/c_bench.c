// SPDX-License-Identifier: MIT

// C side of `zig build bench-ini` (modules/ini/tools/bench.zig): times inih over
// the text the Zig program writes into the directory given as the first
// argument. Prints one line: name, ns/op, result count (tab-separated).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ini.h"

static unsigned long long total;

static int handler(void *user, const char *section, const char *name, const char *value) {
    (void)user;
    if (name == NULL) {
        total += strlen(section);
    } else {
        total += strlen(name) + strlen(value);
    }
    return 1;
}

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[2], "scan_inih") != 0) return 2;
    char path[4096];
    snprintf(path, sizeof path, "%s/large.ini", argv[1]);
    FILE *f = fopen(path, "rb");
    if (!f) return 3;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *text = malloc((size_t)len + 1);
    if (!text || fread(text, 1, (size_t)len, f) != (size_t)len) return 4;
    text[len] = 0;
    fclose(f);

    unsigned long long n = 1;
    for (;;) {
        double t = now_ns();
        for (unsigned long long i = 0; i < n; i++) {
            if (ini_parse_string_length(text, (size_t)len, handler, NULL) != 0) return 5;
        }
        if (now_ns() - t > 100e6) break;
        n *= 2;
    }
    double best = 1e300;
    unsigned long long count = 0;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (unsigned long long i = 0; i < n; i++) {
            total = 0;
            if (ini_parse_string_length(text, (size_t)len, handler, NULL) != 0) return 5;
        }
        double d = now_ns() - t;
        if (d < best) best = d;
        count = total;
    }
    fprintf(stderr, "inih r62\n");
    printf("scan_inih\t%.1f\t%llu\n", best / (double)n, count);
    return 0;
}
