/* SPDX-License-Identifier: MIT
 * Prints the offsets of <linux/bpf.h> that src/*.zig pins in its layout tests.
 * Run: clang tools/uapi_layout.c -o /tmp/uapi_layout && /tmp/uapi_layout */
#include <stddef.h>
#include <stdio.h>
#include <linux/bpf.h>
int main(void){
#define P(s,f) printf(#s "." #f " %zu\n", offsetof(s,f))
 P(struct bpf_prog_info, btf_id); P(struct bpf_map_info, btf_id); P(struct bpf_btf_info, btf); P(struct bpf_btf_info, kernel_btf); printf("btf_info size %zu\n", sizeof(struct bpf_btf_info));
 printf("attr size %zu\n", sizeof(union bpf_attr));
 P(union bpf_attr, query.prog_cnt); P(union bpf_attr, query.revision); P(union bpf_attr, query.link_ids);
 P(union bpf_attr, batch.count); P(union bpf_attr, batch.elem_flags); P(union bpf_attr, batch.flags); P(union bpf_attr, batch.map_fd);
 P(union bpf_attr, link_create.kprobe_multi.syms); P(union bpf_attr, link_create.kprobe_multi.cnt); P(union bpf_attr, link_create.kprobe_multi.cookies);P(union bpf_attr, link_create.kprobe_multi.flags);P(union bpf_attr, link_create.kprobe_multi.addrs);
 P(union bpf_attr, link_create.uprobe_multi.path); P(union bpf_attr, link_create.uprobe_multi.offsets); P(union bpf_attr, link_create.uprobe_multi.ref_ctr_offsets); P(union bpf_attr, link_create.uprobe_multi.cookies); P(union bpf_attr, link_create.uprobe_multi.cnt); P(union bpf_attr, link_create.uprobe_multi.flags); P(union bpf_attr, link_create.uprobe_multi.pid);
 P(union bpf_attr, link_create.tcx.relative_fd); P(union bpf_attr, link_create.tcx.expected_revision);
 P(union bpf_attr, link_create.netkit.relative_fd);P(union bpf_attr, link_create.netkit.expected_revision);
 P(union bpf_attr, link_create.flags);
 printf("prog_info btf_id ok\n");
 return 0;}
