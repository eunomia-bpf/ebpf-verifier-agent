/* === WRAPPER: compilation boilerplate === */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#ifndef __section
#define __section(name) SEC(name)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef memcpy
#define memcpy __builtin_memcpy
#endif

#ifndef memset
#define memset __builtin_memset
#endif

#ifndef memmove
#define memmove __builtin_memmove
#endif

#ifndef __constant_ntohs
#define __constant_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef __constant_htons
#define __constant_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif

#ifndef XDP_DROP
#define XDP_DROP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef XDP_TX
#define XDP_TX 3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT 4
#endif

#ifndef PIN_GLOBAL_NS
#define PIN_GLOBAL_NS 2
#endif

#ifndef csum_diff
#define csum_diff bpf_csum_diff
#endif

#ifndef skb_store_bytes
#define skb_store_bytes bpf_skb_store_bytes
#endif

#ifndef l3_csum_replace
#define l3_csum_replace bpf_l3_csum_replace
#endif

#ifndef l4_csum_replace
#define l4_csum_replace bpf_l4_csum_replace
#endif

#ifndef redirect
#define redirect bpf_redirect
#endif

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#ifndef size_key
#define size_key key_size
#endif

#ifndef size_value
#define size_value value_size
#endif

#ifndef max_elem
#define max_elem max_entries
#endif

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 map_flags;
    __u32 pinning;
};

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                                       ({                                                                                 char ____fmt[] = fmt;                                                          bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 })
#endif

/* === END WRAPPER BOILERPLATE === */

/* === ORIGINAL CODE from SO/GH post === */

Certain types of BPF programs can access packet data. The pre-4.7 way of doing it is via bpf_skb_load_bytes() helper. As the verifier got smarter, it became possible to perform "direct packet access", i.e. to access packet bytes by following pointers in the context structure. E.g:
static const struct bpf_insn prog[] = {
// BPF_PROG_TYPE_SK_REUSEPORT: gets a pointer to sk_reuseport_md (r1).
// Get packet data pointer (r2) and ensure length >= 2, goto Drop otherwise
BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1,
offsetof(struct sk_reuseport_md, data)),
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1,
offsetof(struct sk_reuseport_md, data_end)),
BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 2),
BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, /* Drop: */ +4),
// Ensure first 2 bytes are 0, goto Drop otherwise
BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_2, 0),
BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 0, /* Drop: */ +2),
// return SK_PASS
BPF_MOV32_IMM(BPF_REG_0, SK_PASS),
BPF_EXIT_INSN(),
// Drop: return SK_DROP
BPF_MOV32_IMM(BPF_REG_0, SK_DROP),
BPF_EXIT_INSN()
};
It is required to ensure that the accessed bytes are within bounds explicitly. The verifier will reject the program otherwise.
The program above loads successfully if the caller bears CAP_SYSADMIN. Supposedly, CAP_BPF should suffice as well, but it doesn't (Linux 5.13). Earlier kernels behave similarly. The verifier output follows:
Permission denied

/* === WRAPPER: added license === */
char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */
