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

// #include <bpf/bpf_helpers.h>

// struct vlan_hdr {
//  __be16 h_vlan_TCI;
//  __be16 h_vlan_encapsulated_proto;
// };

/* helper functions called from eBPF programs */
// static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
//          (void *) BPF_FUNC_trace_printk;

/* macro for printing debug info to the tracing pipe, useful just for
   debugging purposes and not recommended to use in production systems.

     use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to read debug info.
 */
// #define printt(fmt, ...)                                                   \
//             ({                                                             \
//                 char ____fmt[] = fmt;                                      \
//                 bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
//             })

SEC("xdp/xdp_ip_filter")
int xdp_ip_filter(struct xdp_md *ctx) {
    void *end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;
    __u32 ip_src, ip_dst;
    // __u64 offset;
    // __u16 eth_type;

    // struct ethhdr *eth = data;
    // offset = sizeof(struct ethhdr);

    // if (data + offset > end) {
    //     return XDP_ABORTED;
    // }
    // eth_type = eth->h_proto;

    /* handle VLAN tagged packet */
//     if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
//  struct vlan_hdr *vlan_hdr;

//  vlan_hdr = (void *)eth + offset;
//  offset += sizeof(*vlan_hdr);
//  if ((void *)eth + offset > end)
//      return 0;
//  eth_type = vlan_hdr->h_vlan_encapsulated_proto;
//    }

//     /* let's only handle IPv4 addresses */
//     if (eth_type == ntohs(ETH_P_IPV6)) {
//         return XDP_PASS;
//     }

    struct iphdr *iph;
    if (end >= data + sizeof(struct ethhdr)) {
        iph = data + sizeof(struct ethhdr);
    } else {
        return XDP_ABORTED;
    }
    // offset += sizeof(struct iphdr);
    /* make sure the bytes you want to read are within the packet's range before reading them */
    // if (iph + 1 > end) {
    //     return XDP_ABORTED;
    // }
    ip_src = iph->saddr;
    ip_dst = iph->daddr;
    __u8 proto = iph->protocol;

    if (proto == 1 || proto == 6 || proto == 17) {
        __u64 *srcMap_value, *dstMap_value, *protoMap_value, bitmap;
        srcMap_value = bpf_map_lookup_elem(&srcMap, &ip_src);
        dstMap_value = bpf_map_lookup_elem(&dstMap, &ip_dst);
        protoMap_value = bpf_map_lookup_elem(&protoMap, &proto);

        if (srcMap_value == 0) {
            __u32 default_sip = 0;
            srcMap_value = bpf_map_lookup_elem(&srcMap, &default_sip);
        }
        if (dstMap_value == 0) {
            __u32 default_dip = 0;
            dstMap_value = bpf_map_lookup_elem(&dstMap, &default_dip);
        }
        if (protoMap_value == 0) {
            __u8 default_prot = 0;
            protoMap_value = bpf_map_lookup_elem(&protoMap, &default_prot);
        }

        if (proto == 1) {
            bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value);
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp;
        }
        if (proto == 6) {
            struct tcphdr *tcph;
            if (end >= data + sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            } else {
                return XDP_ABORTED;
            }
            __u64 *sportMap_value, *dportMap_value;
            __u16 sport = tcph->source;
            __u16 dport = tcph->dest;
            sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);
            dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);

            if (sportMap_value == 0) {
                __u16 default_sport = 0;
                sportMap_value = bpf_map_lookup_elem(&sportMap, &default_sport);
            }
            if (dportMap_value == 0) {
                __u16 default_dport = 0;
                dportMap_value = bpf_map_lookup_elem(&dportMap, &default_dport);
            }

            bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp;
        }
        if (proto == 17) {
            struct udphdr *udph;
            if (end >= data + sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            } else {
                return XDP_ABORTED;
            }
            __u64 *sportMap_value, *dportMap_value;
            __u16 sport = udph->source;
            __u16 dport = udph->dest;
            sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);
            dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);

            if (sportMap_value == 0) {
                __u16 default_sport = 0;
                sportMap_value = bpf_map_lookup_elem(&sportMap, &default_sport);
            }
            if (dportMap_value == 0) {
                __u16 default_dport = 0;
                dportMap_value = bpf_map_lookup_elem(&dportMap, &default_dport);
            }

            bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp;
        }

        __u64 *actionMap_value;
        actionMap_value = bpf_map_lookup_elem(&actionMap, &bitmap);
        if (actionMap_value) {
            (*actionMap_value) = (*actionMap_value) + 1;
            bpf_map_update_elem(&actionMap, &bitmap, actionMap_value, BPF_EXIST);
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

maps.h

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
static void *(*bpf_map_update_elem)(void *map, void *key, void *value, int flags) = (void *) BPF_FUNC_map_update_elem;

#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int pinning;
    char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

enum bpf_pin_type {
    PIN_NONE = 0,
    PIN_OBJECT_NS,
    PIN_GLOBAL_NS,
    PIN_CUSTOM_NS,
};

struct bpf_map_def SEC("maps/srcMap") srcMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/dstMap") dstMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/protoMap") protoMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/sportMap") sportMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/dportMap") dportMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

struct bpf_map_def SEC("maps/actionMap") actionMap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 4194304,
    .pinning = PIN_GLOBAL_NS,
    .namespace = "globals",
};

/* === END ORIGINAL CODE === */
