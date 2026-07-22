/* fixture: TWO programs in ONE section, sharing one map — the case where a
 * program does not start at byte 0 of its section and relocations have to be
 * split between the two functions. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_ARRAY 2
#define XDP_DROP 1
#define XDP_PASS 2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} stats SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

SEC("xdp")
int first(void *ctx)
{
    unsigned int k = 0;
    unsigned long long *v = bpf_map_lookup_elem(&stats, &k);
    (void)ctx;
    if (v)
        __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}

SEC("xdp")
int second(void *ctx)
{
    unsigned int k = 1;
    unsigned long long *v = bpf_map_lookup_elem(&stats, &k);
    (void)ctx;
    if (v)
        __sync_fetch_and_add(v, 2);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
