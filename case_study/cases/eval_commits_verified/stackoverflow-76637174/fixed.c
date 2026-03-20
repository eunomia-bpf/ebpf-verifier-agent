There are two issues here. First is an off by 1 error in the loop, you need to account for the width of the read in the for loop condition:
#define KBUILD_MODNAME "xdp_nvme_drop"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
static inline int parse_ipv4(void *data, uint64_t nh_off, void *data_end) {
struct iphdr *iph = data + nh_off;
if (data + nh_off + sizeof(struct iphdr) > data_end)
return 0;
return iph->protocol;
}
static inline int parse_ipv6(void *data, uint64_t nh_off, void *data_end) {
struct ipv6hdr *ip6h = data + nh_off;
if (data + nh_off + sizeof(struct ipv6hdr) > data_end)
return 0;
return ip6h->nexthdr;
}
//static uint64_t zeroes[1024];
SEC("xdp")
int nvme_drop(struct xdp_md *ctx) {
void* data_end = (void*)(long)ctx->data_end;
void* data = (void*)(long)ctx->data;
uint64_t total = data_end-data;
struct ethhdr *eth = data;
uint16_t h_proto;
uint32_t cur = 0;
struct tcphdr *tcph;
uint32_t i;
int nbzeros = 0;
bool found = 0;
cur = sizeof(*eth);
if (data + cur > data_end)
return XDP_PASS;
h_proto = eth->h_proto;
if (h_proto == bpf_htons(ETH_P_IP)) {
h_proto = parse_ipv4(data, cur, data_end);
cur += sizeof(struct iphdr);
} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
h_proto = parse_ipv6(data, cur, data_end);
cur += sizeof(struct ipv6hdr);
} else {
return XDP_PASS;
}
if (cur > 100)
return XDP_PASS;
if (h_proto != IPPROTO_TCP)
return XDP_PASS;
if (data + cur + sizeof(*tcph) > data_end)
return XDP_PASS;
tcph = data + cur;
if (tcph->doff > 10)
return XDP_PASS;
if (data + cur + tcph->doff * 4 > data_end)
return XDP_PASS;
cur += tcph->doff * 4;
if (tcph->dest != 4420)
return XDP_PASS;
if (cur > total || cur > 100)
return XDP_PASS;
nbzeros = 0;
for (i = cur; data+i+sizeof(uint8_t) < data_end; i++) {
if (*((uint8_t*)(data+i)) == 0 && !found) {
nbzeros++;
} else {
found = true;
break;
}
}
if (found && nbzeros > 50) {
bpf_printk("found nvme pdu tail seq=%u\n", bpf_ntohs(tcph->seq));
}
return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
Once you compile and try the above you will run into the second issue which is the complexity of the code.
The sequence of 8193 jumps is too complex
That is because the verifier has to check for every possible iteration if the body of the loop is valid. But since data_end is a u32 without limits that becomes to much. What we can do to fix that is to set an upper limit for the number of iterations. like:
for (int i = 0; i < 100; i++) {
if (data + i + sizeof(uint8_t) >= data_end)
break;
if (*((uint8_t*)(data+i)) == 0 && !found) {
nbzeros++;
} else {
found = true;
break;
}
}
However, due to the way the current program is written I had a hard time modifying it. The verifier tracks which variables have been offset checked and which haven't and the current data + cur way of tracking the offset generates code that confuses the verifier. So I took the liberty to rewrite it in such a way that everything passes the verifier:
SEC("xdp")
int nvme_drop(struct xdp_md *ctx)
{
void *data_end = (void *)(long)ctx->data_end;
void *data = (void *)(long)ctx->data;
void *head = data;
struct ethhdr *eth;
struct iphdr *iph;
struct ipv6hdr *ip6h;
struct tcphdr *tcph;
uint16_t h_proto;
uint8_t *tcp_data;
int nbzeros = 0;
int i = 0;
bool found = false;
eth = head;
if ((void *)eth + sizeof(struct ethhdr) >= data_end)
return XDP_PASS;
head += sizeof(struct ethhdr);
h_proto = eth->h_proto;
switch (h_proto)
{
case bpf_htons(ETH_P_IP):
iph = head;
if ((void *)iph + sizeof(struct iphdr) >= data_end)
return XDP_PASS;
h_proto = iph->protocol;
head += iph->ihl * 4;
break;
case bpf_htons(ETH_P_IPV6):
ip6h = head;
if ((void *)ip6h + sizeof(struct ipv6hdr) >= data_end)
return XDP_PASS;
h_proto = ip6h->nexthdr;
head += sizeof(struct ipv6hdr);
break;
default:
return XDP_PASS;
}
if (h_proto != IPPROTO_TCP)
return XDP_PASS;
tcph = head;
if ((void *)tcph + sizeof(*tcph) > data_end)
return XDP_PASS;
head += sizeof(*tcph);
if (head + tcph->doff * 4 > data_end)
return XDP_PASS;
head += tcph->doff * 4;
if (tcph->dest != 4420)
return XDP_PASS;
tcp_data = head;
// 1500 is the typical MTU size
#define MAX_ITER 1500
for (i = 0; i < MAX_ITER; i++)
{
if ((void *)tcp_data + i + 1 >= data_end)
return XDP_PASS;
if (tcp_data[i] == 0)
{
nbzeros++;
continue;
}
found = true;
break;
}
if (found && nbzeros > 50)
{
bpf_printk("found nvme pdu tail seq=%u\n", bpf_ntohs(tcph->seq));
}
return XDP_PASS;
}
This should be functionally the same. In this case I chose 1500 as the max iteration count since most packets will never reach that size. Though you might need to tune that.
