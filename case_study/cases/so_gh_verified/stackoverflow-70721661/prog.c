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

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int offload_ifindex = 0;
    int prog_fd = -1;
    int err;

    /* If flags indicate hardware offload, supply ifindex */
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
        offload_ifindex = cfg->ifindex;

    /* Load the BPF-ELF object file and get back libbpf bpf_object */
    if (cfg->reuse_maps)
        bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
                              offload_ifindex,
                              cfg->pin_dir);
    else
        bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
    if (!bpf_obj) {
        fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
        exit(EXIT_FAIL_BPF);
    }
    /* At this point: All XDP/BPF programs from the cfg->filename have been
     * loaded into the kernel, and evaluated by the verifier. Only one of
     * these gets attached to XDP hook, the others will get freed once this
     * process exit.
     */

    if (cfg->progsec[0])
        /* Find a matching BPF prog section name */
        bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
    else
        /* Find the first program */
        bpf_prog = bpf_program__next(NULL, bpf_obj);

    if (!bpf_prog) {
        fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
        exit(EXIT_FAIL_BPF);
    }

    strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        exit(EXIT_FAIL_BPF);
    }

    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
     * is our select file-descriptor handle. Next step is attaching this FD
     * to a kernel hook point, in this case XDP net_device link-level hook.
     */
    err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
    if (err)
        exit(err);

    return bpf_obj;
}

/* === WRAPPER: added license === */
char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */
