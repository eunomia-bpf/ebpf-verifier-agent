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
    TL;DR. You are hitting a corner-case limitation of the verifier. Changing the end of the for loop to the following may help.
    #define MAX_PACKET_OFF 0xffff
    ...
    nh->pos += size;
    if (nh->pos > MAX_PACKET_OFF)
    return INV_RET_U32;
    if (nh->pos >= data_end)
    return INV_RET_U32;
    The full explanation is a bit long, see below.
    Verifier error explanation
    2945: (bf) r1 = r7
    2946: (07) r1 += 4
    2947: (2d) if r1 > r6 goto pc-2888
    R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1=pkt(id=68,off=30,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R2=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
    2948: (71) r1 = *(u8 *)(r7 +0)
    invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)
    R7 offset is outside of the packet
    The verifier errors because it thinks R7 is outside the packet's known bounds. It tells us you're trying to make an access of size 1B at offset 26 into the packet pointer, but the packet has a known size of 0 (r=0, for range=0).
    Maximum packet size limitation
    That's weird because you did check the packet bounds. On instruction 2947, the packet pointer R1 is compared to R6, the pointer to the end of the packet. So following that check, the known minimum size of R1 should be updated, but it remains 0 (r=0).
    That is happening because you are hitting a corner-case limitation of the verifier:
    if (dst_reg->umax_value > MAX_PACKET_OFF ||
    dst_reg->umax_value + dst_reg->off > MAX_PACKET_OFF)
    /* Risk of overflow. For instance, ptr + (1<<63) may be less
    * than pkt_end, but that's because it's also less than pkt.
    */
    return;
    As explained in the comment, this check is here to prevent overflows. Since R1's unsigned maximum value is 73851 (umax_value=73851), the condition is true and the packet's known size is not updated.
    A way to prevent this from happening might be to ensure there's an additional bounds check on R1. For example:
    #define MAX_PACKET_OFF 0xffff
    ...
    if (nh->pos + size > MAX_PACKET_OFF)
    return INV_RET_U32;
    Why is R1's unsigned maximum value so high?
    R1 comes from R7, which is initialized on those instructions:
    2934: (79) r1 = *(u64 *)(r10 -32)
    2935: (79) r2 = *(u64 *)(r10 -40)
    2936: (0f) r2 += r1
    ; if (nh->pos + size < data_end)
    2937: (57) r2 &= 65535
    2938: (bf) r7 = r8
    2939: (0f) r7 += r2
    ; if (nh->pos + size < data_end)
    2940: (3d) if r7 >= r6 goto pc-2881
    R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=0) R2_w=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7_w=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
    Two values are retrieved from the stack, at offsets -32 and -40. Those two values added hold variable size. Since size is a __u16, it is ANDed with 65535 (the maximum __u16 value). So the verifier identifies R2 has having maximum value 65535.
    When R2 is added to R7, R7's maximum value of course becomes larger than MAX_PACKET_OFF = 65535.
    Shouldn't the verifier understand that size < 516?
    The following code ensures size will never be larger than 516 (512 + 4 in the worst case):
    __u16 size = parse_sctp_chunk_size(nh->pos, data_end);
    if (size > 512)
    return INV_RET_U32;
    //Adjust for padding
    size += (size % 4) == 0 ? 0 : 4 - size % 4;
    So why is the verifier loosing track of that?
    Part of variable size is saved on the stack, at offset -32, here:
    2782: (69) r2 = *(u16 *)(r8 +2)
    2783: (dc) r2 = be16 r2
    2784: (7b) *(u64 *)(r10 -32) = r2
    ; if (size > 512)
    2785: (25) if r2 > 0x200 goto pc-2726
    R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=66,umax_value=255,var_off=(0x0; 0xff)) R2_w=inv(id=0,umax_value=512,var_off=(0x0; 0xffffffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=65,off=27,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=invP(id=0,umax_value=516,var_off=(0x0; 0xffff),s32_max_value=65535,u32_max_value=65535) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_w=mmmmmmmm fp-40=inv fp-48=pkt
    Unfortunately, the value is saved on the stack before the comparison with 512 happens. Therefore, the verifier doesn't know that the value saved on the stack is smaller than 512. We can see that because of the fp-32_w=mmmmmmmm. The ms means MISC; that is, the value could be anything from the verifier's point of view.
    I believe this limitation of the verifier was removed in recent Linux versions.
    Why does the issue only appear with 32 iterations?
    I suspect that the variable size is only saved on the stack if the program becomes really large. As long as the variable is not saved on the stack, the verifier doesn't lose track of its maximum value 516.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
