/* fixture: .rodata global constants reached through BPF_PSEUDO_MAP_VALUE. */
#define SEC(name) __attribute__((section(name), used))

#define XDP_DROP 1
#define XDP_PASS 2

const volatile unsigned int threshold = 42;
const volatile unsigned long long tag = 0x1122334455667788ULL;

SEC("xdp")
int filter(void *ctx)
{
    (void)ctx;
    if (threshold > 10 && tag != 0)
        return XDP_PASS;
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
