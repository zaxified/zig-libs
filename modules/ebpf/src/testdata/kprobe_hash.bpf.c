/* fixture: kprobe + BTF-defined BPF_MAP_TYPE_HASH map. */
#define SEC(name) __attribute__((section(name), used))
/* The two macros libbpf's bpf_helpers.h spells the same way: a `__uint`
 * member is a POINTER TO AN ARRAY whose element count carries the value,
 * a `__type` member is a pointer to the type itself. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_HASH 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(map_flags, 0);
    __type(key, unsigned int);
    __type(value, unsigned long long);
} counts SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

SEC("kprobe/do_sys_openat2")
int count_open(void *ctx)
{
    unsigned int key = 0;
    unsigned long long *v = bpf_map_lookup_elem(&counts, &key);
    (void)ctx;
    if (v)
        __sync_fetch_and_add(v, 1);
    return 0;
}

char _license[] SEC("license") = "GPL";
