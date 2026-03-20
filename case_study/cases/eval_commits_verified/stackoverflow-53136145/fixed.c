#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

Ok, so, after 3 days, more precisely 3 x 8 hrs = 24 hrs, worth of code hunting, I think I've finally found the itching problem.
The problem was in the some_inlined_func() all along, it was more tricky then challenging. I'm writing down here a code template explaining the issue, so others could see and hopefully spend less then 24 hrs of headache; I went through hell for this, so stay focused.
__alwais_inline static
int some_inlined_func(struct xdp_md *ctx, /* other non important args */)
{
if (!ctx)
return AN_ERROR_CODE;
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
struct ethhdr *eth;
struct iphdr *ipv4_hdr = NULL;
struct ipv6hdr *ipv6_hdr = NULL;
struct udphdr *udph;
uint16_t ethertype;
eth = (struct ethhdr *)data;
if (eth + 1 > data_end)
return AN_ERROR_CODE;
ethertype = __constant_ntohs(eth->h_proto);
if (ethertype == ETH_P_IP)
{
ipv4_hdr = (void *)eth + ETH_HLEN;
if (ipv4_hdr + 1 > data_end)
return AN_ERROR_CODE;
// stuff non related to the issue ...
} else if (ethertype == ETH_P_IPV6)
{
ipv6_hdr = (void *)eth + ETH_HLEN;
if (ipv6_hdr + 1 > data_end)
return AN_ERROR_CODE;
// stuff non related to the issue ...
} else
return A_RET_CODE_1;
/* here's the problem, but ... */
udph = (ipv4_hdr) ? ((void *)ipv4_hdr + sizeof(*ipv4_hdr)) :
((void *)ipv6_hdr + sizeof(*ipv6_hdr));
if (udph + 1 > data_end)
return AN_ERROR_CODE;
/* it actually breaks HERE, when dereferencing 'udph' */
uint16_t dst_port = __constant_ntohs(udph->dest);
// blablabla other stuff here unrelated to the problem ...
return A_RET_CODE_2;
}
So, why it breaks at that point? I think it's because the verifier assumes ipv6_hdr could potentially be NULL, which is utterly WRONG because if the execution ever gets to that point, that's only because either ipv4_hdr or ipv6_hdr has been set (i.e. the execution dies before this point if it's the case of neither IPv4 nor IPv6). So, apparently, the verifier isn't able to infer that. However, there's a catch, it is happy if the validity of also ipv6_hdr is explicitly checked, like this:
if (ipv4_hdr)
udph = (void *)ipv4_hdr + sizeof(*ipv4_hdr);
else if (ipv6_hdr)
udph = (void *)ipv6_hdr + sizeof(*ipv6_hdr);
else return A_RET_CODE_1; // this is redundant
It also works if we do this:
// "(ethertype == ETH_P_IP)" instead of "(ipv4_hdr)"
udph = (ethertype == ETH_P_IP) ? ((void *)ipv4_hdr + sizeof(*ipv4_hdr)) :
((void *)ipv6_hdr + sizeof(*ipv6_hdr));
So, it seems to me there's something strange about the verifier here, because it's not smart enough (maybe neither it needs to be?) to realize that if it ever gets to this point, it's only because ctx refers either an IPv4 or IPv6 packet.
How does all of this explain the complaining over return act; within the entry_point()? Simple, just bear with me. The some_inlined_func() isn't changing ctx, and its remaining args aren't used either by entry_point(). Thus, in case of returning act, as it depends on the some_inlined_func() outcome, the some_inlined_func() gets executed, with the verifier complaining at that point. But, in case of returning XDP_<whatever>, as the switch-case body, and neither the some_inlined_func(), doesn't change the internal state of the entry_point() program/function, the compiler (with O2) is smart enough to realize that there's no point in producing assembly for some_inlined_func() and the whole switch-case (that's the O2 optimization over here). Therefore, to conclude, in case of returning XDP_<whatever>, the verifier was happy as the problem actually lies into some_inlined_func() but the actual produced BPF assembly doesn't have anything of that, so the verifier didn't checked some_inlined_func() because there wasn't any in the first place. Makes sense?
Is such BPF "limitation" known? Is out there any document at all stating such known limitations? Because I didn't found any.
char _license[] SEC("license") = "GPL";
