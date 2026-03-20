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
    TL;DR. The verifier seems to get lost because of how the compiler optimized the code. You might be able to encourage the compiler to generate code that the verifier can track.
    Verifier Error Explanation
    28: (bf) r3 = r1
    29: (0f) r3 += r8
    ; if ((void *)(data_bytes + i + option_length + 1) > data_end)
    30: (bf) r4 = r3
    31: (07) r4 += 34
    ; if ((void *)(data_bytes + i + option_length + 1) > data_end)
    32: (2d) if r4 > r2 goto pc+278
    ; data_bytes[i + option_length] = data_bytes[i];
    33: (bf) r4 = r8
    34: (0f) r4 += r1
    ; data_bytes[i + option_length] = data_bytes[i];
    35: (71) r5 = *(u8 *)(r1 +33)
    ; data_bytes[i + option_length] = data_bytes[i];
    36: (73) *(u8 *)(r4 +33) = r5
    invalid access to packet, off=33 size=1, R4(id=10,off=33,r=0)
    R4 offset is outside of the packet
    The verifier complains that the packet access is outside the known bounds of the packet. It says you're trying to access the packet at offset 33 (off=33) with an access size of 1 byte (size=1), but the known packet size is 0 (r=0).
    Obviously, you've checked the packet size above (instructions 28--32) so that shouldn't happen. The check was done with registers r1 (data_bytes) and r8 (option_length) added into r3, copied to r4 and shifted by 34 bytes (shift_data_length). That is compared to r2, the packet's end, at instruction 32.
    After that comparison, we can see the following verifier state (which I removed above for clarity):
    R0=inv(id=0,umin_value=6,umax_value=14,var_off=(0x0; 0xe))
    R1=pkt(id=0,off=0,r=39,imm=0) R2=pkt_end(id=0,off=0,imm=0)
    R3_w=pkt(id=9,off=0,r=34,umax_value=255,var_off=(0x0; 0xff))
    R4_w=pkt(id=9,off=34,r=34,umax_value=255,var_off=(0x0; 0xff))
    R5=inv(id=1,umax_value=255,var_off=(0x0; 0xff))
    R6=inv2 R7=ctx(id=0,off=0,imm=0)
    R8_w=invP(id=2,umax_value=255,var_off=(0x0; 0xff)) R10=fp0
    We can see the range (r=) of R4 was properly updated to 34 to signify that the known packet size is 34.
    So why doesn't it work? Unfortunately, R4 is not used as is for the packet access. Instead, the whole thing is recomputed into R4 (instructions 33--34), losing what we just verified.
    Potential Solution
    I'd try to rewrite the C code like this to encourage the compiler to compute R4 only once:
    for (int i = shift_data_length - 1; i >= 0; i--) {
    char *ptr = data_bytes + option_length;
    if (ptr + i + 1 > data_end)
    return XDP_PASS;
    ptr[i] = data_bytes[i];
    }
    Note it's not guaranteed to work and you may have to tweak it further to get the compiler to generate something the verifier can handle.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
