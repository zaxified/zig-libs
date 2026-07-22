/* fixture: XDP pass/drop, two program sections, no maps. */
#define SEC(name) __attribute__((section(name), used))

#define XDP_DROP 1
#define XDP_PASS 2

SEC("xdp")
int xdp_accept(void *ctx) { (void)ctx; return XDP_PASS; }

SEC("xdp/drop")
int xdp_reject(void *ctx) { (void)ctx; return XDP_DROP; }

char _license[] SEC("license") = "GPL";
