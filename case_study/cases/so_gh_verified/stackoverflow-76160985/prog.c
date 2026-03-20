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

#define MAX_RULES 50
#define MAX_RULE_NAME 20
#define MAX_BYTE_PATTERN 11
struct filter_rule
{
char rule_name[MAX_RULE_NAME];
char byte_pattern[MAX_BYTE_PATTERN];
};
unsigned char mystrlen(const char *s, unsigned char max_len)
{
unsigned char i = 0;
if(s == NULL)
return 0;
for (i = 0; i < max_len; i++)
{
if (s[i] == '\0')
return i;
}
return i;
}
bool find_substring(const char *str, const char *search)
{
if(str != NULL && search != NULL)
{
unsigned char l1 = mystrlen(str,50);
unsigned char l2 = mystrlen(search, MAX_BYTE_PATTERN);
unsigned char i = 0, j = 0;
unsigned char flag = 0;
if(l1 == 0 || l2 == 0)
return false;
for (i = 0; i <= l1 - l2; i++)
{
for (j = i; j < i + l2; j++)
{
flag = 1;
if (str[j] != search[j - i])
{
flag = 0;
break;
}
}
if (flag == 1)
{
break;
}
}
if(flag == 1)
return true;
else
return false;
}
else
{
return false;
}
}
Here is logic of my bpf.c file:
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
struct {
__uint(type, BPF_MAP_TYPE_ARRAY);
__uint(key_size, sizeof(int));
__uint(value_size, sizeof(struct filter_rule));
__uint(max_entries, MAX_RULES);
} filter_rules SEC(".maps");
SEC("tc")
int ingress_hndlr(struct __sk_buff *ctx)
{
//Extract the TCP packet payload into buff
unsigned char buff[51] = {0};
for(int i = 0; i<tcp_payload_length && i<50; ++i)
{
buff[i] = load_byte(ctx, payload_offset+i);
//bpf_printk("%x", buff[i]);
}
unsigned int key = 0;
struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &key);
if(rule)
{
bool ret = find_substring((const char*)buff, rule->byte_pattern);
if(ret)
{
++drop_cnt;
return TC_ACT_SHOT;
}
}
}
The error I get

/* === WRAPPER: added license === */
char _license[] SEC("license") = "GPL";

/* === END ORIGINAL CODE === */
