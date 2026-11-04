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
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

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
extern pcap_t *pcap_create(const char *, char *);
extern int pcap_set_snaplen(pcap_t *, int);
extern int pcap_set_timeout(pcap_t *, int);
extern int pcap_set_buffer_size(pcap_t *, int);
extern int pcap_activate(pcap_t *);
extern int pcap_setnonblock(pcap_t *, int, char *);
extern int pcap_dispatch(pcap_t *, int, void (*)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *), unsigned char *);
extern pcap_t *pcap_create(const char *, char *);
extern int pcap_set_snaplen(pcap_t *, int);
extern int pcap_set_timeout(pcap_t *, int);
extern int pcap_set_buffer_size(pcap_t *, int);
extern int pcap_activate(pcap_t *);
extern int pcap_dispatch(pcap_t *, int, void (*)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *), unsigned char *);

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

// ---- live capture: libpcap (TPACKET_V3 by default) over a burst on lo; every wait has a deadline ----
#define LIVE_FRAMES 50000
static volatile int burst_done;
static unsigned long long live_got;
static void *burst(void *arg) {
    (void)arg;
    int s = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = (int)if_nametoindex("lo");
        sll.sll_protocol = htons(0x88b5);
        sll.sll_halen = 6;
        sll.sll_addr[0] = 2;
        sll.sll_addr[5] = 9;
        unsigned char payload[46];
        memset(payload, 0x5a, sizeof payload);
        for (int i = 0; i < LIVE_FRAMES; i++) sendto(s, payload, sizeof payload, 0, (struct sockaddr *)&sll, sizeof sll);
        close(s);
    }
    burst_done = 1;
    return NULL;
}
static void on_pkt(unsigned char *u, const struct pcap_pkthdr *h, const unsigned char *d) {
    (void)u;
    (void)h;
    if (d[12] == 0x88 && d[13] == 0xb5) live_got++;
}
static int live_main(void) {
    char err[256];
    double best = 1e300;
    unsigned long long best_got = 0;
    for (int round = 0; round < 3; round++) {
        pcap_t *p = pcap_create("lo", err);
        if (!p) { fprintf(stderr, "pcap_create: %s\n", err); return 3; }
        pcap_set_snaplen(p, 2048);
        pcap_set_timeout(p, 10);
        pcap_set_buffer_size(p, 16 << 20);
        if (pcap_activate(p) < 0) { fprintf(stderr, "pcap_activate failed\n"); return 4; }
        // Non-blocking: a blocking pcap_dispatch did not return in 40 s under this namespace (attempt 1).
        pcap_setnonblock(p, 1, err);
        live_got = 0;
        burst_done = 0;
        pthread_t th;
        pthread_create(&th, NULL, burst, NULL);
        double t0 = now_ns(), first = 0, last = 0;
        int quiet = 0;
        // non-blocking reads 2 ms apart; stop 20 empty reads (40 ms) after the sender is done, or after 15 s.
        while (now_ns() - t0 < 15e9 && quiet < 20) {
            int n = pcap_dispatch(p, -1, on_pkt, NULL);
            if (n > 0) {
                last = now_ns();
                if (first == 0) first = last;
            } else {
                if (burst_done) quiet++;
                usleep(2000);
            }
        }
        fprintf(stderr, "libpcap round %d: %llu frames\n", round, live_got);
        pthread_join(th, NULL);
        pcap_close(p);
        double dt = last - first;
        if (first != 0 && dt < best) {
            best = dt;
            best_got = live_got;
        }
    }
    printf("received %llu of %d  %8.1f ms  %8.0f kframes/s\n", best_got, LIVE_FRAMES, best / 1e6, best_got * 1e6 / (best > 1 ? best : 1));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (!strcmp(argv[2], "cap_live")) { fprintf(stderr, "%s\n", pcap_lib_version()); return live_main(); }
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

    // FIXED_REPS=N: exactly N runs, no calibration and no timing (for perf stat).
    const char *fixed = getenv("FIXED_REPS");
    if (fixed) {
        unsigned long long acc = 0, nrep = strtoull(fixed, NULL, 10);
        for (unsigned long long i = 0; i < nrep; i++) acc += run_once();
        printf("fixed %s x %llu: count sum %llu\n", name, nrep, acc);
        return 0;
    }
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
