#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("xdp")
int repro(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    (void)data;
    (void)data_end;
    TL;DR. You are hitting a corner-case of the verifier. See https://stackoverflow.com/a/70731589/6884590. Adding a bounds check on pkt_ctx->pkt_offset will fix it, as noticed by @Qeole.
    Verifier Error Explanation
    13: (bf) r1 = r7
    14: (0f) r1 += r6
    15: (bf) r2 = r1
    16: (07) r2 += 1
    ; if (data_end < data + pkt_ctx->pkt_offset + j + 1) {
    17: (2d) if r2 > r8 goto pc+14
    R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=pkt(id=2,off=0,r=0,umax_value=65535,var_off=(0x0; 0xffff)) R2_w=pkt(id=2,off=1,r=0,umax_value=65535,var_off=(0x0; 0xffff)) R3=inv253 R6=invP0 R7=pkt( id=2,off=0,r=0,umax_value=65535,var_off=(0x0; 0xffff)) R8=pkt_end(id=0,off=0,imm=0) R10=fp0 fp-8=mmmm????
    ; if (data[pkt_ctx->pkt_offset + j] == '\r') {
    18: (71) r1 = *(u8 *)(r1 +0)
    invalid access to packet, off=0 size=1, R1(id=2,off=0,r=0)
    R1 offset is outside of the packet
    The verifier is complaining because the packet access (insn. 18) is out-of-bounds. That seems unexpected because you check the packet's length (insn. 17) right before the access.
    Unfortunately, the bounds check is not even considered by the verifier because you're hitting this condition. Basically, the maximum value for R2 is too high (by 1 only for the first iteration) and the verifier thinks there's a risk of overflow.
    R2's maximum value is 65535 and its offset is 1 (for the first iteration), so the sum of both is above MAX_PACKET_OFF (65535). Considering this is an overflow risk, the verifier returns from find_good_pkt_pointers before it even updates the bounds of all packet pointers.
    Solution
    @Qeole is correct that adding a bounds check will help, although not exactly for the reason he states. By adding a bounds check on pkt_ctx->pkt_offset, R2's maximum value will be decreased and the verifier will take the packet length check into account.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
