// SPDX-License-Identifier: MIT

// libpcap's classic-BPF interpreter as the oracle for `filter.run`
// (tools/gen_run_diff.py builds and drives this). Reads programs (one per
// line, hex, 8 bytes per instruction in host order: code u16, jt, jf, k u32)
// from argv[1] and frames (one per line, hex) from argv[2]; prints, per
// program, `bpf_validate` (1/0) and the value `pcap_offline_filter` returns
// for every frame. Linked by path against the system's libpcap.so; the few
// declarations are libpcap's documented API (pcap(3pcap)).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

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
extern unsigned int pcap_offline_filter(const struct bpf_program *, const struct pcap_pkthdr *, const unsigned char *);
extern int bpf_validate(const struct bpf_insn *, int);

static unsigned char *unhex(const char *s, size_t *n) {
    size_t len = strlen(s);
    while (len && (s[len - 1] == '\n' || s[len - 1] == '\r')) len--;
    unsigned char *b = malloc(len / 2 + 1);
    for (size_t i = 0; i < len / 2; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        b[i] = (unsigned char)v;
    }
    *n = len / 2;
    return b;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    char line[8192];
    unsigned char *frames[64];
    size_t flen[64];
    int nf = 0;
    FILE *f = fopen(argv[2], "r");
    if (!f) return 3;
    while (fgets(line, sizeof line, f) && nf < 64) frames[nf] = unhex(line, &flen[nf]), nf++;
    fclose(f);
    f = fopen(argv[1], "r");
    if (!f) return 3;
    while (fgets(line, sizeof line, f)) {
        size_t n;
        unsigned char *p = unhex(line, &n);
        struct bpf_program prog = {(unsigned int)(n / 8), (struct bpf_insn *)p};
        printf("%d", bpf_validate(prog.bf_insns, (int)prog.bf_len));
        for (int i = 0; i < nf; i++) {
            struct pcap_pkthdr h = {{0, 0}, (unsigned int)flen[i], (unsigned int)flen[i]};
            printf(" %u", pcap_offline_filter(&prog, &h, frames[i]));
        }
        printf("\n");
        free(p);
    }
    return 0;
}
