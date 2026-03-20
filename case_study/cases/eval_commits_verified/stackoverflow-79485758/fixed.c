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
    TL;DR. You are hitting a corner-case limitation of the eBPF verifier, as explained in https://stackoverflow.com/a/70731589/6884590. You will need an extra bounds check on the packet to work around that. Your program will however likely be rejected due to its complexity afterward
    Verifier Error Explanation
    48: (69) r0 = *(u16 *)(r5 +0)
    invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)
    R5 offset is outside of the packet
    The verifier complains on the packet access because the access seems to be out of the known packet bounds. The access is at offset 0, with a size of 2 bytes. The known packet length is 0 (r=0). Hence the program is rejected.
    Maximum Packet Size Limitation
    You did check the packet bounds above, but it wasn't enough because of this corner-case limitation in the verifier:
    if (dst_reg->umax_value > MAX_PACKET_OFF ||
    dst_reg->umax_value + dst_reg->off > MAX_PACKET_OFF)
    /* Risk of overflow. For instance, ptr + (1<<63) may be less
    * than pkt_end, but that's because it's also less than pkt.
    */
    return;
    Potential Workaround
    We can see the impact in the verifier logs:
    ; if ((data + field_offset + sizeof(uint16_t)) > data_end)
    47: (2d) if r0 > r2 goto pc+36
    R0_w=pkt(id=6,off=2,r=0,umax_value=65535,var_off=(0x0; 0xffff))
    R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0)
    R3_w=inv(id=5,smin_value=-128,smax_value=1092)
    R4=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff))
    R5_w=pkt(id=6,off=0,r=0,umax_value=65535,var_off=(0x0; 0xffff))
    R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0)
    R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047)
    R10=fp0 fp-8=mmmm????
    After the comparison of R0 (packet pointer) and R2 (packet end pointer), the known packet length (range, or r=) should be set to R0's offset (off=) so 2. However, because R0's umax_value is equal to 65535 and R0's offset is equal to 2, per the above corner-case limitation, the sum is superior to MAX_PACKET_OFF (65535) and the range is therefore not updated. Hence, we end up with r=0 for R0.
    You can contrast this with the comparison of R2 and R8 on instruction 34, where the range is properly updated (r=2).
    To work around that, you will have to convince the verifier that you're pointer has a lower maximum value. The following may work:
    uint16_t *pkt_ptr = data + field_offset;
    if (pkt_ptr + 1 > data_end || pkt_ptr + 1 > MAX_PACKET_OFF)
    goto EXIT;
    x = *pkt_ptr;
    Subsequent Errors
    Even if you fix this, I strongly suspect the verifier will reject your program because your loop around the LOOK goto isn't bounded from the verifier's point of view. It is bounded by the packet size, but the length of the packets isn't known at verification time so it doesn't count for the verifier.
    To solve that, you will probably have to add a hardcoded bound on the number of iterations. If that is not enough, you may want to take a look at helpers and kfuncs to implement loops in BPF. Note that parsing gRPC with eBPF is known to be quite challenging so you will likely have to impose a bunch of limits to reach that goal.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
