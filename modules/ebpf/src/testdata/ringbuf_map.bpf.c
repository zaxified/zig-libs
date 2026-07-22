/* fixture: BTF-defined BPF_MAP_TYPE_RINGBUF map + a tracepoint program. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_RINGBUF 27

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

static void *(*bpf_ringbuf_reserve)(void *rb, unsigned long long size,
                                    unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;

SEC("tracepoint/syscalls/sys_enter_write")
int on_write(void *ctx)
{
    unsigned long long *e = bpf_ringbuf_reserve(&events, 8, 0);
    (void)ctx;
    if (!e)
        return 0;
    *e = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
