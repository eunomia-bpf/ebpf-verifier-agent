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
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
