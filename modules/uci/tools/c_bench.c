// SPDX-License-Identifier: MIT

// C side of `zig build bench-uci` (modules/uci/tools/bench.zig): times libuci
// (a copy of the OpenWrt tree built from source by the bench; libuci is
// LGPL-2.1, none of it is kept in this repository) over the config files the
// Zig program writes into the directory given as the first argument.
// Workloads: parse_small, parse_large, parse_quoted (uci_load of a file + uci_unload),
// export_small, export_large (uci_export of a loaded package to a memory
// stream). Prints one line: name, ns/op, result count (tab-separated); the
// count is the number of sections, found by walking the loaded package once,
// outside the timed loop.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <uci.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static struct uci_context *ctx;
static const char *cfg;
static struct uci_package *loaded;

static int load_once(void) {
    struct uci_package *p = NULL;
    if (uci_load(ctx, cfg, &p) != UCI_OK || !p) return -1;
    uci_unload(ctx, p);
    return 0;
}

static int export_once(void) {
    char *buf = NULL;
    size_t len = 0;
    FILE *m = open_memstream(&buf, &len);
    if (!m) return -1;
    int rc = uci_export(ctx, m, loaded, true);
    fclose(m);
    free(buf);
    return rc == UCI_OK ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int is_export = strncmp(argv[2], "export_", 7) == 0;
    int is_parse = strncmp(argv[2], "parse_", 6) == 0;
    if (!is_export && !is_parse) return 2;
    cfg = strstr(argv[2], "_large") ? "large" : strstr(argv[2], "_quoted") ? "quoted" : strstr(argv[2], "_multiline") ? "multiline" : "small";
    ctx = uci_alloc_context();
    if (!ctx) return 3;
    uci_set_confdir(ctx, argv[1]);

    struct uci_package *p = NULL;
    if (uci_load(ctx, cfg, &p) != UCI_OK || !p) return 4;
    unsigned long long count = 0;
    struct uci_element *e;
    uci_foreach_element(&p->sections, e) count++;
    if (is_export) loaded = p; else uci_unload(ctx, p);

    int (*once)(void) = is_export ? export_once : load_once;
    unsigned long long n = 1;
    for (;;) {
        double t = now_ns();
        for (unsigned long long i = 0; i < n; i++)
            if (once() != 0) return 5;
        if (now_ns() - t > 100e6) break;
        n *= 2;
    }
    double best = 1e300;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (unsigned long long i = 0; i < n; i++)
            if (once() != 0) return 5;
        double d = now_ns() - t;
        if (d < best) best = d;
    }
    fprintf(stderr, "libuci (OpenWrt uci, built from a source copy)\n");
    printf("%s\t%.1f\t%llu\n", argv[2], best / (double)n, count);
    return 0;
}
