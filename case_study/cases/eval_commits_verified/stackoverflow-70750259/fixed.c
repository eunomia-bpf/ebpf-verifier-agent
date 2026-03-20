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
    TL;DR. From the verifier's point of view, ext_len is unbounded because of how it was computed. To allow you to add this value to the packet pointer, you need to add a new bound check. See below for full explanation.
    Explanation of the verifier error
    22: R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
    22: (4f) r0 |= r6
    23: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
    23: (dc) r0 = be16 r0
    24: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
    ; if (data_end < (data + ext_len)) {
    24: (0f) r5 += r0
    [...]
    math between pkt pointer and register with unbounded min value is not allowed
    The verifier rejects the program because it sees the addition of an unbounded register (R0) to a register holding the packet pointer (R5). In particular it requires R0 to have a minimum value to be added to the packet pointer. Without that, you may subtract any value from the packet pointer and read arbitrary kernel memory.
    Why is R0 unbounded?
    Before instruction 22 (r0 |= r6), R0 had bounds (umax_value=65280,var_off=(0x0; 0xff00)). R6 did as well. Unfortunately, the verifier doesn't seem to be able to track those bounds after the logic OR, and loses them. Newer kernel versions may be able to track this better.
    Why does adding a 0 minimum bound not work?
    @Qeole suggested in comments to add a minimum bounds check for 0:
    if (ext_len < 0)
    goto end;
    That probably didn't work because ext_len has type __u16 (i.e., unsigned short) so the compiler probably optimize out the check for a negative sign.
    Why does adding an upper bound check work?
    Adding an upper bound check (e.g., 30000) works because the verifier can deduce a lower signed bound from the upper unsigned bound check.
    How to solve it?
    The best way to solve this is probably to add a lower bound check as suggested by Quentin. You will however need to make the ext_len variable signed so that the compiler doesn't optimize out the bound check.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
