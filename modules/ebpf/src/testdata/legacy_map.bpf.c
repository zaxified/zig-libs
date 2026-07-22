/* fixture: the pre-BTF `maps` section (struct bpf_map_def). */
#define SEC(name) __attribute__((section(name), used))

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def legacy_counts SEC("maps") = {
    .type = 2,          /* BPF_MAP_TYPE_ARRAY */
    .key_size = 4,
    .value_size = 8,
    .max_entries = 16,
    .map_flags = 0,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

SEC("socket")
int sock_count(void *ctx)
{
    unsigned int key = 0;
    unsigned long long *v = bpf_map_lookup_elem(&legacy_counts, &key);
    (void)ctx;
    if (v)
        __sync_fetch_and_add(v, 1);
    return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = 0x40f00;
