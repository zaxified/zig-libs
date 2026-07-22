/* fixture: CO-RE field relocations (__attribute__((preserve_access_index))). */
#define SEC(name) __attribute__((section(name), used))

/* A deliberately WRONG-BY-DESIGN local view of the kernel type: `pid` sits at
 * byte 0 here and at ~2 kB in any real kernel, so a CO-RE relocation that
 * quietly did nothing is visible immediately. */
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

static unsigned long long (*bpf_get_current_task)(void) = (void *)35;

SEC("kprobe/do_sys_openat2")
int trace_pid(void *ctx)
{
    struct task_struct *t = (struct task_struct *)(long)bpf_get_current_task();
    (void)ctx;
    return t->pid + t->tgid;
}

char _license[] SEC("license") = "GPL";
