/* SPDX-License-Identifier: MIT */
/* fixture: a struct_ops map. The local `struct tcp_congestion_ops` is a subset
 * of the kernel's (loaders match members by name and size, never by position),
 * with three callbacks, a name and `.struct_ops` placement; the programs sit in
 * `struct_ops/<member>` sections. */
#define SEC(name) __attribute__((section(name), used))

struct sock;

struct tcp_congestion_ops {
    char name[16];
    unsigned int (*ssthresh)(struct sock *sk);
    unsigned int (*undo_cwnd)(struct sock *sk);
    void (*cong_avoid)(struct sock *sk, unsigned int ack, unsigned int acked);
};

SEC("struct_ops/zl_ssthresh")
unsigned int zl_ssthresh(struct sock *sk)
{
    (void)sk;
    return 2;
}

SEC("struct_ops/zl_undo_cwnd")
unsigned int zl_undo_cwnd(struct sock *sk)
{
    (void)sk;
    return 10;
}

SEC("struct_ops/zl_cong_avoid")
void zl_cong_avoid(struct sock *sk, unsigned int ack, unsigned int acked)
{
    (void)sk;
    (void)ack;
    (void)acked;
}

SEC(".struct_ops")
struct tcp_congestion_ops zl_cc = {
    .name = "zl_test",
    .ssthresh = (void *)zl_ssthresh,
    .undo_cwnd = (void *)zl_undo_cwnd,
    .cong_avoid = (void *)zl_cong_avoid,
};

SEC(".struct_ops.link")
struct tcp_congestion_ops zl_cc_link = {
    .name = "zl_link",
    .ssthresh = (void *)zl_ssthresh,
};

char _license[] SEC("license") = "GPL";
