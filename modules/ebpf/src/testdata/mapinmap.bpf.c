/* SPDX-License-Identifier: MIT */
/* fixture: map-in-map and prog_array. `outer` is an ARRAY_OF_MAPS whose inner
 * map definition comes from the `values` array's element type and whose first
 * two slots are pre-filled with `inner_a`/`inner_b`; `hmap` is a HASH_OF_MAPS
 * with an inner definition and no initial slots; `jumps` is a PROG_ARRAY
 * whose slot 1 holds `target`. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12
#define BPF_MAP_TYPE_HASH_OF_MAPS 13
#define XDP_PASS 2

struct inner_def {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, unsigned int);
    __type(value, unsigned long long);
};

struct inner_def inner_a SEC(".maps");
struct inner_def inner_b SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __array(values, struct inner_def);
} outer SEC(".maps") = {
    .values = { &inner_a, &inner_b },
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 16);
    __type(key, unsigned int);
    __array(values, struct inner_def);
} hmap SEC(".maps");

int target(void *ctx);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, unsigned int);
    __array(values, int(void *));
} jumps SEC(".maps") = {
    .values = { [1] = (void *)&target },
};

SEC("xdp")
int entry(void *ctx)
{
    (void)ctx;
    return XDP_PASS;
}

SEC("xdp")
int target(void *ctx)
{
    (void)ctx;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
