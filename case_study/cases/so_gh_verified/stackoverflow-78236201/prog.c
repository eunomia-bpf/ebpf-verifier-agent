/* === WRAPPER: compilation boilerplate === */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86 1
#endif

#include <vmlinux.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef __SO_GH_VERIFIED_STDINT_TYPES
#define __SO_GH_VERIFIED_STDINT_TYPES 1
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;
typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s8 int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;
typedef __s64 int64_t;
#endif

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

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)__builtin_bswap16((__u16)(x)))
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

#ifndef ETH_HLEN
#define ETH_HLEN 14
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

#define VLAN_MAX_DEPTH 2
#define VLAN_VID_MASK 0x0fff
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

/* === WRAPPER: support copied from the tutorial includes that are not available here === */
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, XDP_ACTION_MAX);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats_map SEC(".maps");

static __always_inline int xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
    __u64 bytes = (__u64)ctx->data_end - (__u64)ctx->data;
    struct datarec *rec;

    rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec)
        return XDP_ABORTED;

    rec->rx_packets++;
    rec->rx_bytes += bytes;
    return action;
}

/* === ORIGINAL LOGIC from the post === */
struct hdr_cursor {
    void *pos;
};

struct collect_vlans {
    __u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
              h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
                                             void *data_end,
                                             struct ethhdr **ethhdr,
                                             struct collect_vlans *vlans)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    vlh = nh->pos;
    h_proto = eth->h_proto;

#pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (!proto_is_vlan(h_proto))
            break;
        if (vlh + 1 > data_end)
            break;
        h_proto = vlh->h_vlan_encapsulated_proto;
        if (vlans)
            vlans->id[i] = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
        vlh++;
    }

    nh->pos = vlh;
    return h_proto;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    if (ip6h + 1 > data_end)
        return -1;
    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;
    return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    if (hdrsize < sizeof(*iph))
        return -1;
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;
    return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmp6hdr **icmp6hdr)
{
    struct icmp6hdr *icmp6h = nh->pos;

    if (icmp6h + 1 > data_end)
        return -1;
    nh->pos = icmp6h + 1;
    *icmp6hdr = icmp6h;
    return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct icmphdr **icmphdr)
{
    struct icmphdr *icmph = nh->pos;

    if (icmph + 1 > data_end)
        return -1;
    nh->pos = icmph + 1;
    *icmphdr = icmph;
    return icmph->type;
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    __u32 action = XDP_PASS;
    struct hdr_cursor nh;
    int nh_type;

    nh.pos = data;
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == bpf_htons(ETH_P_8021Q)) {
        struct collect_vlans vlans;
        int vlan_proto = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

        if (vlan_proto < 0)
            return XDP_ABORTED;
        for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
            if (vlans.id[i] == 0)
                /* Original post had the break commented out. */
                bpf_printk("VLAN ID[%d] = %u\n", i, vlans.id[i]);
        }
    }

    if (nh_type == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6hdr;
        int ip6_next_header = parse_ip6hdr(&nh, data_end, &ip6hdr);

        if (ip6_next_header == IPPROTO_ICMPV6) {
            struct icmp6hdr *icmp6hdr;
            int icmp6_type = parse_icmp6hdr(&nh, data_end, &icmp6hdr);

            if (icmp6_type < 0)
                return XDP_ABORTED;
        }
    }

    if (nh_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *iphdr;
        int ip_next_header = parse_iphdr(&nh, data_end, &iphdr);

        if (ip_next_header == IPPROTO_ICMP) {
            struct icmphdr *icmphdr;
            int icmp_type = parse_icmphdr(&nh, data_end, &icmphdr);

            if (icmp_type < 0)
                return XDP_ABORTED;

            bpf_printk("IPv4 Header: Source Address = %x, Destination Address = %x\n",
                       bpf_ntohl(iphdr->saddr), bpf_ntohl(iphdr->daddr));
            bpf_printk("Protocol = %d\n", iphdr->protocol);
            bpf_printk("ICMP Header: Type = %d, Code = %d\n",
                       icmphdr->type, icmphdr->code);
        }
    }

    return xdp_stats_record_action(ctx, action);
}

/* === WRAPPER: added license === */
char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */
