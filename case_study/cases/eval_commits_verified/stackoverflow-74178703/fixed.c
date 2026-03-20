#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

TL;DR. When it checks the memcpy's memory access, the verifier has lost information from the previous bounds check (offset + i >= 1024) and therefore errors.
Verifier Error Explanation
193: (bf) r3 = r0
194: (0f) r3 += r1
195: (71) r3 = *(u8 *)(r3 +0)
R0=map_value(id=0,off=0,ks=4,vs=1024,umax_value=1023,var_off=(0x0; 0x3ff)) R1=invP1 R2_w=map_value(id=0,off=1,ks=4,vs=512,imm=0) R3_w=map_value(id=0,off=1,ks=4,vs=1024,umax_value=1023,var_off=(0x0; 0x3ff)) R6=map_value(id=0,off=0,ks=4,vs=32,imm=0) R7=map_value(id=0,off=0,ks=4,vs=512,imm=0) R8=inv(id=261,umin_value=2,umax_value=512,var_off=(0x0; 0x3ff)) R9=invP(id=263,umin_value=1,umax_value=1024,var_off=(0x0; 0x7ff)) R10=fp0 fp-8=mmmmm??? fp-48=????mmmm
invalid access to map value, value_size=1024 off=1024 size=1
In this output, R1 is i and R0 is b + offset.
The verifier complains that, when i=1 (i.e., r1=invP1) and offset=1023 (i.e., R0's umax_value=1023), the memory load could read outside of the 1024 bytes of the value. This is easily checked by adding R3's umax_value to R3's off to the access size (1023 + 1 + 1).
Root Cause
That seems unexpected at first sight because you did check that the memory load is bounded just before:
if (offset + i >= 1024) {
return;
}
The additions offset + i and b + offset + i are however computed separately and the bounds are therefore lost. We can see that in the verifier output where the first addition is computed at instruction 202 while the second is computed at instruction 194.
I believe this is happening because you're compiler reorganized your code to move the computation of b + offset outside the loop body.
Potential Workaround
To prevent the compiler from reorganizing code that way, you could maybe change the loop to:
dst -= offset;
for (__u32 i = offset; i < size + offset && i < 1024; ++i)
memcpy(dst + i, b + i, sizeof(__u8));
char _license[] SEC("license") = "GPL";
