/* SPDX-License-Identifier: MIT */
/* fixture: sub-programs. `xdp_main` calls a static __noinline helper and a
 * global one (both land in .text and are reached through R_BPF_64_32), hands
 * a callback's address to bpf_loop (an LD_IMM64 against .text), and a second
 * entry point shares the global helper. The static helper reads a map and a
 * .rodata global, so the callee carries its own relocations. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_ARRAY 2
#define XDP_PASS 2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} counts SEC(".maps");

const volatile unsigned int bias = 7;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_loop)(unsigned int n, void *cb, void *ctx, unsigned long long flags) = (void *)181;

static __attribute__((noinline)) unsigned long long bump(unsigned int k)
{
    unsigned long long *v = bpf_map_lookup_elem(&counts, &k);
    return v ? *v + bias : 0;
}

__attribute__((noinline)) int global_helper(int x)
{
    return x * 3 + (int)bump(1);
}

static long cb(unsigned int i, void *ctx)
{
    *(unsigned long long *)ctx += i;
    return 0;
}

SEC("xdp")
int xdp_main(void *ctx)
{
    unsigned long long acc = 0;
    (void)ctx;
    bpf_loop(4, cb, &acc, 0);
    return global_helper((int)bump(0)) + (int)acc > 100 ? XDP_PASS : 1;
}

SEC("xdp/other")
int xdp_other(void *ctx)
{
    (void)ctx;
    return global_helper(5);
}

char _license[] SEC("license") = "GPL";
