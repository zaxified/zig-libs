/* SPDX-License-Identifier: MIT
 *
 * Standalone HQC KEM benchmark with per-sample spread statistics.
 * Each "sample" is the mean over INNER back-to-back calls; we report
 * min/median/max/mean/sd over SAMPLES samples, in ns/op and TSC cycles/op.
 *
 * WHY THIS EXISTS, and why it reports a SPREAD. A single number from a
 * benchmark is not a measurement, it is one draw from a distribution: the same
 * binary on this machine moves by percent between runs. A comparison against
 * the reference implementation that quotes one figure per side cannot tell a
 * real difference from that movement, so this prints min/median/max and the
 * standard deviation, and the median is what should be compared.
 *
 * WHY IT IS COMPILED AGAINST THE REFERENCE rather than reading its published
 * numbers: those were measured on another machine. Built by `bench.sh` in three
 * lanes (ref, avx256, native), it puts both implementations on this CPU, this
 * compiler and — with `taskset` — this core.
 *
 * WHAT IT NEEDS. The reference's headers and static library; `bench.sh`
 * supplies them. This file is ours. The reference's own licence (public domain)
 * is recorded in the module's NOTICE.
 *
 * WHAT IT PRODUCES. Three lines on stdout — keypair, enc, dec — each carrying
 * us/op (min, median, max, mean+-sd), ops/s at the median, and cycles/op.
 * It also checks that dec agrees with enc before timing dec, so a broken build
 * cannot quietly benchmark nonsense.
 *
 * Build: see bench.sh */
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "api.h"
#include "symmetric.h"

#ifndef SAMPLES
#define SAMPLES 51
#endif
#ifndef INNER
#define INNER 20
#endif

static inline uint64_t rdtsc_start(void) {
    unsigned hi, lo;
    __asm__ __volatile__("CPUID\n\tRDTSC\n\tmov %%edx,%0\n\tmov %%eax,%1\n\t"
        : "=r"(hi), "=r"(lo) :: "%rax","%rbx","%rcx","%rdx");
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}
static inline uint64_t rdtsc_stop(void) {
    unsigned hi, lo;
    __asm__ __volatile__("RDTSCP\n\tmov %%edx,%0\n\tmov %%eax,%1\n\tCPUID\n\t"
        : "=r"(hi), "=r"(lo) :: "%rax","%rbx","%rcx","%rdx");
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}
static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int cmp_d(const void *a, const void *b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}
static void report(const char *label, double *ns, double *cyc, int n) {
    double *sn = malloc(n*sizeof(double)), *sc = malloc(n*sizeof(double));
    memcpy(sn, ns, n*sizeof(double)); memcpy(sc, cyc, n*sizeof(double));
    qsort(sn, n, sizeof(double), cmp_d); qsort(sc, n, sizeof(double), cmp_d);
    double mn = 0, mc = 0;
    for (int i = 0; i < n; i++) { mn += ns[i]; mc += cyc[i]; }
    mn /= n; mc /= n;
    double vn = 0, vc = 0;
    for (int i = 0; i < n; i++) { vn += (ns[i]-mn)*(ns[i]-mn); vc += (cyc[i]-mc)*(cyc[i]-mc); }
    vn = (n>1)? vn/(n-1) : 0; vc = (n>1)? vc/(n-1) : 0;
    double med_n = sn[n/2], med_c = sc[n/2];
    printf("%-8s %-7s us/op: min %9.2f  med %9.2f  max %9.2f  mean %9.2f +- %8.2f   ops/s(med) %10.1f   cycles/op: min %11.0f med %11.0f max %11.0f\n",
           CRYPTO_ALGNAME, label,
           sn[0]/1000.0, med_n/1000.0, sn[n-1]/1000.0, mn/1000.0, (vn>0?__builtin_sqrt(vn):0)/1000.0,
           1e9/med_n, sc[0], med_c, sc[n-1]);
    (void)vc;
    free(sn); free(sc);
}

int main(void) {
    static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    static unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    static unsigned char ss1[CRYPTO_BYTES], ss2[CRYPTO_BYTES];
    unsigned char seed[48] = {0};
    if (syscall(SYS_getrandom, seed, 48, 0) != 48) return 2;
    prng_init(seed, NULL, 48, 0);

    double ns[SAMPLES], cyc[SAMPLES];

    /* keypair */
    for (int i = 0; i < 5; i++) crypto_kem_keypair(pk, sk);
    for (int s = 0; s < SAMPLES; s++) {
        uint64_t c0, c1, n0, n1;
        n0 = now_ns(); c0 = rdtsc_start();
        for (int j = 0; j < INNER; j++) crypto_kem_keypair(pk, sk);
        c1 = rdtsc_stop(); n1 = now_ns();
        ns[s] = (double)(n1-n0)/INNER; cyc[s] = (double)(c1-c0)/INNER;
    }
    report("keypair", ns, cyc, SAMPLES);

    /* enc */
    for (int i = 0; i < 5; i++) crypto_kem_enc(ct, ss1, pk);
    for (int s = 0; s < SAMPLES; s++) {
        uint64_t c0, c1, n0, n1;
        n0 = now_ns(); c0 = rdtsc_start();
        for (int j = 0; j < INNER; j++) crypto_kem_enc(ct, ss1, pk);
        c1 = rdtsc_stop(); n1 = now_ns();
        ns[s] = (double)(n1-n0)/INNER; cyc[s] = (double)(c1-c0)/INNER;
    }
    report("enc", ns, cyc, SAMPLES);

    /* dec */
    for (int i = 0; i < 5; i++) crypto_kem_dec(ss2, ct, sk);
    if (memcmp(ss1, ss2, CRYPTO_BYTES) != 0) { fprintf(stderr, "FATAL: ss mismatch\n"); return 1; }
    for (int s = 0; s < SAMPLES; s++) {
        uint64_t c0, c1, n0, n1;
        n0 = now_ns(); c0 = rdtsc_start();
        for (int j = 0; j < INNER; j++) crypto_kem_dec(ss2, ct, sk);
        c1 = rdtsc_stop(); n1 = now_ns();
        ns[s] = (double)(n1-n0)/INNER; cyc[s] = (double)(c1-c0)/INNER;
    }
    report("dec", ns, cyc, SAMPLES);
    return 0;
}
