// SPDX-License-Identifier: MIT

// C side of `zig build bench-rawsock` (modules/rawsock/tools/bench.zig): times
// libpcap through its public API over the corpus the Zig program writes into
// the directory given as the first argument. Linked against the system's
// libpcap.so by path, so no headers are needed: the few declarations below are
// libpcap's documented API (pcap(3pcap)). Prints one line: name, ns/op, count
// (tab-separated); stderr is the banner (libpcap's version).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
struct bpf_insn {
    unsigned short code;
    unsigned char jt, jf;
    unsigned int k;
};
struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};
struct pcap_pkthdr {
    struct timeval ts;
    unsigned int caplen, len;
};

extern pcap_t *pcap_open_dead(int linktype, int snaplen);
extern int pcap_compile(pcap_t *, struct bpf_program *, const char *, int optimize, unsigned int netmask);
extern void pcap_freecode(struct bpf_program *);
extern unsigned int pcap_offline_filter(const struct bpf_program *, const struct pcap_pkthdr *, const unsigned char *);
extern pcap_t *pcap_fopen_offline(FILE *, char *errbuf);
extern int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
extern void pcap_close(pcap_t *);
extern pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *);
extern void pcap_dump(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
extern long pcap_dump_ftell(pcap_dumper_t *);
extern void pcap_dump_close(pcap_dumper_t *);
extern const char *pcap_lib_version(void);

#define N_EXPR 8
#define N_RUN_FRAMES 2000

static char dir[4096];
static pcap_t *dead;
static char *exprs[N_EXPR];
static struct bpf_program progs[N_EXPR];
static struct pcap_pkthdr *hdrs;
static unsigned char **datas;
static size_t n_frames;
static unsigned char *file_buf;
static size_t file_len;
static unsigned char *out_buf;
static size_t out_cap;
static int op;
static int optimize;
static const char *prog_prefix = "prog_";
static int dump_mode;

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static unsigned char *slurp(const char *name, size_t *len) {
    char path[8192];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) exit(3);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)n + 1);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) exit(4);
    fclose(f);
    *len = (size_t)n;
    return b;
}

static unsigned long long run_once(void) {
    unsigned long long count = 0;
    char err[256];
    switch (op) {
    case 0: { // compile: the eight expressions
        for (int i = 0; i < N_EXPR; i++) {
            struct bpf_program p;
            if (pcap_compile(dead, &p, exprs[i], optimize, 0xffffffffu) != 0) exit(5);
            count++;
            pcap_freecode(&p);
        }
        break;
    }
    case 1: { // filter_run: the programs the Zig side compiled, libpcap's interpreter
        for (int i = 0; i < N_EXPR; i++) {
            for (size_t j = 0; j < N_RUN_FRAMES && j < n_frames; j++) {
                if (pcap_offline_filter(&progs[i], &hdrs[j], datas[j]) != 0) count++;
            }
        }
        break;
    }
    case 2:
    case 4: { // pcap_read / pcapng_read through an in-memory FILE
        FILE *f = fmemopen(file_buf, file_len, "rb");
        if (!f) exit(6);
        pcap_t *p = pcap_fopen_offline(f, err);
        if (!p) exit(7);
        struct pcap_pkthdr *h;
        const unsigned char *d;
        while (pcap_next_ex(p, &h, &d) == 1) {
            count += (unsigned long long)h->caplen + h->len + (unsigned long long)h->ts.tv_sec * 1000000ull + (unsigned long long)h->ts.tv_usec;
            __asm__ volatile("" : : "r"(d) : "memory");
        }
        pcap_close(p);
        break;
    }
    case 3: { // pcap_write into memory
        FILE *f = fmemopen(out_buf, out_cap, "wb");
        if (!f) exit(8);
        pcap_dumper_t *dp = pcap_dump_fopen(dead, f);
        if (!dp) exit(9);
        for (size_t j = 0; j < n_frames; j++) pcap_dump((unsigned char *)dp, &hdrs[j], datas[j]);
        count = (unsigned long long)pcap_dump_ftell(dp);
        pcap_dump_close(dp);
        break;
    }
    }
    return count;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    snprintf(dir, sizeof dir, "%s", argv[1]);
    const char *name = argv[2];
    if (!strcmp(name, "compile")) op = 0;
    else if (!strcmp(name, "compile_opt")) { op = 0; optimize = 1; }
    else if (!strcmp(name, "filter_run")) op = 1;
    else if (!strcmp(name, "filter_run_lp")) { op = 1; prog_prefix = "prog_lp_"; }
    else if (!strcmp(name, "dump_progs")) { op = 0; optimize = 1; dump_mode = 1; }
    else if (!strcmp(name, "pcap_read")) op = 2;
    else if (!strcmp(name, "pcap_write")) op = 3;
    else if (!strcmp(name, "pcapng_read")) op = 4;
    else return 2;
    fprintf(stderr, "%s\n", pcap_lib_version());

    dead = pcap_open_dead(1, 262144);
    size_t n;
    char *text = (char *)slurp("exprs.txt", &n);
    text[n] = 0;
    char *line = strtok(text, "\n");
    for (int i = 0; i < N_EXPR && line; i++, line = strtok(NULL, "\n")) exprs[i] = line;

    if (dump_mode) {
        // libpcap's own (optimised) programs for the eight expressions, as
        // `tcpdump -dd` prints them, for the `filter_run_lp` row.
        for (int i = 0; i < N_EXPR; i++) {
            struct bpf_program p;
            if (pcap_compile(dead, &p, exprs[i], 1, 0xffffffffu) != 0) return 5;
            char fn[8192];
            snprintf(fn, sizeof fn, "%s/prog_lp_%d.bin", dir, i);
            FILE *o = fopen(fn, "wb");
            if (!o) return 6;
            fwrite(p.bf_insns, 8, p.bf_len, o);
            fclose(o);
            pcap_freecode(&p);
        }
        return 0;
    }
    if (op == 1 || op == 3) {
        // The frames, read once through libpcap itself from the classic file.
        size_t len;
        unsigned char *pc = slurp("frames.pcap", &len);
        FILE *f = fmemopen(pc, len, "rb");
        char err[256];
        pcap_t *p = pcap_fopen_offline(f, err);
        if (!p) return 10;
        size_t cap = 1 << 16;
        hdrs = malloc(cap * sizeof *hdrs);
        datas = malloc(cap * sizeof *datas);
        struct pcap_pkthdr *h;
        const unsigned char *d;
        while (pcap_next_ex(p, &h, &d) == 1) {
            if (n_frames == cap) return 11;
            hdrs[n_frames] = *h;
            datas[n_frames] = malloc(h->caplen);
            memcpy(datas[n_frames], d, h->caplen);
            n_frames++;
        }
        pcap_close(p);
        out_cap = len + 4096;
        out_buf = malloc(out_cap);
    }
    if (op == 1) {
        for (int i = 0; i < N_EXPR; i++) {
            char fn[64];
            snprintf(fn, sizeof fn, "%s%d.bin", prog_prefix, i);
            size_t len;
            unsigned char *b = slurp(fn, &len);
            progs[i].bf_len = (unsigned int)(len / 8);
            progs[i].bf_insns = (struct bpf_insn *)b;
        }
    }
    if (op == 2) file_buf = slurp("frames.pcap", &file_len);
    if (op == 4) file_buf = slurp("frames.pcapng", &file_len);

    unsigned long long reps = 1;
    for (;;) {
        double t = now_ns();
        for (unsigned long long i = 0; i < reps; i++) run_once();
        if (now_ns() - t > 100e6) break;
        reps *= 2;
    }
    double best = 1e300;
    unsigned long long count = 0;
    for (int k = 0; k < 5; k++) {
        double t = now_ns();
        for (unsigned long long i = 0; i < reps; i++) count = run_once();
        double dt = (now_ns() - t) / (double)reps;
        if (dt < best) best = dt;
    }
    printf("%s\t%.1f\t%llu\n", name, best, count);
    return 0;
}
