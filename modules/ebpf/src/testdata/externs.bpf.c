/* SPDX-License-Identifier: MIT */
/* fixture: externs. Kconfig variables (int, bool, tristate, string, a weak one
 * and LINUX_KERNEL_VERSION), a typed ksym variable, a typeless ksym, and two
 * kfuncs (one weak) reached through R_BPF_64_32. */
#define SEC(name) __attribute__((section(name), used))
#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))
#define __weak __attribute__((weak))

enum libbpf_tristate { TRI_NO = 0, TRI_YES = 1, TRI_MODULE = 2 };

extern unsigned int LINUX_KERNEL_VERSION __kconfig;
extern int CONFIG_HZ __kconfig;
extern _Bool CONFIG_BPF __kconfig;
extern enum libbpf_tristate CONFIG_TUN __kconfig;
extern char CONFIG_DEFAULT_HOSTNAME[16] __kconfig;
extern unsigned long long CONFIG_ZL_NOT_THERE __kconfig __weak;

extern const int bpf_prog_active __ksym;
extern const void bpf_untyped_sym __ksym __weak;

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_zl_missing_kfunc(void *p) __ksym __weak;

SEC("xdp")
int probe(void *ctx)
{
    unsigned long long acc = 0;
    (void)ctx;
    acc += LINUX_KERNEL_VERSION;
    acc += CONFIG_HZ;
    acc += CONFIG_BPF;
    acc += CONFIG_TUN;
    acc += CONFIG_DEFAULT_HOSTNAME[0];
    acc += CONFIG_ZL_NOT_THERE;
    acc += *(const int *)&bpf_prog_active;
    acc += (unsigned long long)&bpf_untyped_sym;
    bpf_rcu_read_lock();
    if (bpf_zl_missing_kfunc)
        bpf_zl_missing_kfunc((void *)0);
    return (int)acc;
}

char _license[] SEC("license") = "GPL";
