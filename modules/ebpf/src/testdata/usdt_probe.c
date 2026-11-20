/* SPDX-License-Identifier: MIT */
/* fixture: an ELF executable carrying two SystemTap/USDT probes, the notes
 * written by hand the way <sys/sdt.h> emits them (the header is not installed
 * everywhere), one with a semaphore in `.probes`. Linked without libc so the
 * binary is a few KB:  gcc -O1 -static -nostdlib -Wl,--build-id=none -o usdt_probe usdt_probe.c */
volatile unsigned short probe_semaphore __attribute__((section(".probes")));

#define SDT_NOTE(label, prov, nm, sema, args)                                   \
    __asm__ __volatile__(                                                       \
        "990: nop\n"                                                            \
        ".pushsection .note.stapsdt,\"\",\"note\"\n"                            \
        ".balign 4\n"                                                           \
        ".4byte 992f-991f, 994f-993f, 3\n"                                      \
        "991: .asciz \"stapsdt\"\n"                                             \
        "992: .balign 4\n"                                                      \
        "993: .8byte 990b\n"                                                    \
        ".8byte _.stapsdt.base\n"                                               \
        ".8byte " sema "\n"                                                     \
        ".asciz \"" prov "\"\n"                                                 \
        ".asciz \"" nm "\"\n"                                                   \
        ".asciz \"" args "\"\n"                                                 \
        "994: .balign 4\n"                                                      \
        ".popsection\n"                                                         \
        ".ifndef _.stapsdt.base\n"                                              \
        ".pushsection .stapsdt.base,\"aG\",\"progbits\",.stapsdt.base,comdat\n" \
        ".weak _.stapsdt.base\n"                                                \
        ".hidden _.stapsdt.base\n"                                              \
        "_.stapsdt.base: .space 1\n"                                            \
        ".size _.stapsdt.base, 1\n"                                             \
        ".popsection\n"                                                         \
        ".endif\n")

void _start(void)
{
    SDT_NOTE(0, "myprov", "myprobe", "probe_semaphore", "-4@%edi 8@-8(%rbp)");
    SDT_NOTE(1, "myprov", "other", "0", "");
    __asm__ __volatile__("mov $60,%eax; xor %edi,%edi; syscall");
}
