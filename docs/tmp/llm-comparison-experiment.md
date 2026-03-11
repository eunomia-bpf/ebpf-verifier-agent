# LLM Comparison Experiment: Raw Log vs Structured Trace

Generated at: 2026-03-11T21:01:20+00:00

## Summary

| Condition | Cases | Root Cause Correct | Fix Direction Correct | Mean Specificity | Mean Response Tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| A: Raw log | 5 | 4 | 4 | 2.0 | 286.4 |
| B: Structured trace | 5 | 4 | 4 | 2.0 | 293.2 |

Win tally: A=3, B=2, Tie=0

## Per-Case Results

### stackoverflow-70750259

Case path: `case_study/cases/stackoverflow/stackoverflow-70750259.yaml`

Question URL: https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet

**Ground truth fix description**

```text
TL;DR. From the verifier's point of view, ext_len is unbounded because of how it was computed. To allow you to add this value to the packet pointer, you need to add a new bound check. See below for full explanation. The verifier rejects the program because it sees the addition of an unbounded register (R0) to a register holding the packet pointer (R5). In particular it requires R0 to have a minimum value to be added to the packet pointer. Without that, you may subtract any value from the packet pointer and read arbitrary kernel memory. That probably didn't work because ext_len has type __u1...
```

**Structured analysis used in Condition B**

```json
{
  "causal_chain": "Unavailable",
  "critical_transition": "BOUNDS_COLLAPSE at insn 22: R0 lost scalar bounds at insn 22: inv,id=0,umax=65280,var_off=(0x0; 0xff00) -> inv,id=0",
  "error_classification": "OBLIGE-E005 (lowering_artifact)",
  "error_line": "math between pkt pointer and register with unbounded min value is not allowed",
  "source_mapping": "if (data_end < (data + ext_len)) {"
}
```

**Condition A Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        struct server_name {
char server_name[256];
};
struct extension {
__u16 type;
__u16 len;
} __attribute__((packed));
struct sni_extension {
__u16 list_len;
__u8 type;
__u16 len;
} __attribute__((packed));
#define SERVER_NAME_EXTENSION 0
SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
char *data_end = (char *)(long)ctx->data_end;
char *data = (char *)(long)ctx->data;
if (data_end < (data + sizeof(__u16))) {
goto end;
}
__u16 extension_method_len = __bpf_htons(*(__u16 *) data);
data += sizeof(__u16);
for(int i = 0; i < extension_method_len; i += sizeof(struct extension)) { // A
if (data_end < (data + sizeof(struct extension))) {
goto end;
}
struct extension *ext = (struct extension *) data;
data += sizeof(struct extension);
if (ext->type == SERVER_NAME_EXTENSION) {
struct server_name sn;
if (data_end < (data + sizeof(struct sni_extension))) {
goto end;
}
struct sni_extension *sni = (struct sni_extension *) data;
data += sizeof(struct sni_extension);
__u16 server_name_len = __bpf_htons(sni->len);
for(int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
if (data_end < data + sn_idx) {
goto end;
}
if (sn.server_name + sizeof(struct server_name) < sn.server_name + sn_idx) {
goto end;
}
sn.server_name[sn_idx] = data[sn_idx];
}
sn.server_name[server_name_len] = 0;
goto end;
}
volatile int ext_len = __bpf_htons(ext->len);
if (ext_len < 0) {
goto end;
}
data += ext_len;
i += ext_len; // B
} // C
end:
return XDP_PASS;
}
Ignore that data does not point to the beginning of the extension length field of a TLS packet; I did not include the code for getting to this field because the above code is enough to reproduce the issue I'm seeing.

        Verifier output:
        19: R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
20: (71) r0 = *(u8 *)(r0 +3)
21: R0_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
21: (67) r0 <<= 8
22: R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
22: (4f) r0 |= r6
23: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
23: (dc) r0 = be16 r0
24: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + ext_len)) {
24: (0f) r5 += r0
last_idx 24 first_idx 12
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
math between pkt pointer and register with unbounded min value is not allowed
processed 24 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1

0: (61) r2 = *(u32 *)(r1 +4)
; char *data = (char *)(long)ctx->data;
1: (61) r1 = *(u32 *)(r1 +0)
; if (data_end < (data + EXTENSION_METHODS_LEN_FIELD_SIZE)) {
2: (bf) r0 = r1
3: (07) r0 += 2
; if (data_end < (data + EXTENSION_METHODS_LEN_FIELD_SIZE)) {
4: (2d) if r0 > r2 goto pc+37
 R0_w=pkt(id=0,off=2,r=2,imm=0) R1_w=pkt(id=0,off=0,r=2,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R10=fp0
; __u16 extension_methods_len = __bpf_htons(*(__u16 *) data);
5: (69) r1 = *(u16 *)(r1 +0)
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
6: (15) if r1 == 0x0 goto pc+35
 R0_w=pkt(id=0,off=2,r=2,imm=0) R1_w=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R2_w=pkt_end(id=0,off=0,imm=0) R10=fp0
7: (dc) r1 = be16 r1
8: (b7) r3 = 0
9: (18) r4 = 0x400000000
; if (data_end < (data + sizeof(struct extension))) {
11: (bf) r5 = r0
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+28
 R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+23
 R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; volatile int ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; volatile int ext_len = __bpf_htons(ext->len);
24: (63) *(u32 *)(r10 -4) = r0
; if (ext_len < 0) {
25: (61) r0 = *(u32 *)(r10 -4)
26: (67) r0 <<= 32
27: (c7) r0 s>>= 32
; if (ext_len < 0) {
28: (65) if r0 s> 0xffffffff goto pc+1

from 28 to 30: R0=inv(id=0,umax_value=2147483647,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5=pkt(id=0,off=6,r=6,imm=0) R6=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7=inv(id=0) R10=fp0 fp-8=mmmm????
; data += ext_len;
30: (61) r0 = *(u32 *)(r10 -4)
; i += ext_len;
31: (61) r6 = *(u32 *)(r10 -4)
; i += ext_len;
32: (0f) r3 += r6
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
33: (67) r3 <<= 32
34: (0f) r3 += r4
35: (c7) r3 s>>= 32
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
36: (7d) if r3 s>= r1 goto pc+5
 R0=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=0,smin_value=-2147483648,smax_value=2147483647) R4=inv17179869184 R5=pkt(id=0,off=6,r=6,imm=0) R6=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R7=inv(id=0) R10=fp0 fp-8=mmmm????
;
37: (67) r0 <<= 32
38: (c7) r0 s>>= 32
39: (0f) r5 += r0
last_idx 39 first_idx 36
regs=1 stack=0 before 38: (c7) r0 s>>= 32
regs=1 stack=0 before 37: (67) r0 <<= 32
regs=1 stack=0 before 36: (7d) if r3 s>= r1 goto pc+5
 R0_rw=invP(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R1_r=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_rw=inv(id=0,smin_value=-2147483648,smax_value=2147483647) R4=inv17179869184 R5_r=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R7=inv(id=0) R10=fp0 fp-8=mmmm????
parent didn't have regs=1 stack=0 marks
last_idx 35 first_idx 28
regs=1 stack=0 before 35: (c7) r3 s>>= 32
regs=1 stack=0 before 34: (0f) r3 += r4
regs=1 stack=0 before 33: (67) r3 <<= 32
regs=1 stack=0 before 32: (0f) r3 += r6
regs=1 stack=0 before 31: (61) r6 = *(u32 *)(r10 -4)
regs=1 stack=0 before 30: (61) r0 = *(u32 *)(r10 -4)
value -2147483648 makes pkt pointer be out of bounds
processed 41 insns (limit 1000000) max_states_per_insn 0 total_states 3 peak_states 3 mark_read 3

22: R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0;     0xff)) R7_w=inv(id=0) R10=fp0
22: (4f) r0 |= r6
23: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
23: (dc) r0 = be16 r0
24: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + ext_len)) {
24: (0f) r5 += r0
[...]
math between pkt pointer and register with unbounded min value is not allowed

        What is the root cause of the failure? How would you fix it?
```

**Condition A Response**

```text
The verifier is rejecting `data + ext_len` because it cannot prove `ext_len` is a bounded non-negative scalar. In this case `ext->len` is read from a `packed` struct, so Clang lowers `__bpf_htons(ext->len)` into byte loads plus shift/OR; after the `OR`, the verifier loses the `0..65535` range and treats the result as an unconstrained scalar. Making it `volatile int` makes it worse, because the spill/reload turns it into a signed 32-bit value again, so from the verifier’s point of view the offset may be negative. That is exactly what triggers “math between pkt pointer and register with unbounded min value is not allowed”.

Fix it by keeping the length unsigned, removing `volatile`, and doing an explicit bounds check before advancing the packet pointer. For example: `__u32 ext_len = bpf_ntohs(ext->len); if (ext_len > (__u32)(data_end - data)) goto end; data += ext_len; i += ext_len;`. Also remove `__attribute__((packed))` from `struct extension` if possible, since two `__u16` fields are already laid out as 4 bytes; otherwise load the 16-bit field into a temporary with a checked read instead of relying on packed-field codegen.
```

**Condition B Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        struct server_name {
char server_name[256];
};
struct extension {
__u16 type;
__u16 len;
} __attribute__((packed));
struct sni_extension {
__u16 list_len;
__u8 type;
__u16 len;
} __attribute__((packed));
#define SERVER_NAME_EXTENSION 0
SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
char *data_end = (char *)(long)ctx->data_end;
char *data = (char *)(long)ctx->data;
if (data_end < (data + sizeof(__u16))) {
goto end;
}
__u16 extension_method_len = __bpf_htons(*(__u16 *) data);
data += sizeof(__u16);
for(int i = 0; i < extension_method_len; i += sizeof(struct extension)) { // A
if (data_end < (data + sizeof(struct extension))) {
goto end;
}
struct extension *ext = (struct extension *) data;
data += sizeof(struct extension);
if (ext->type == SERVER_NAME_EXTENSION) {
struct server_name sn;
if (data_end < (data + sizeof(struct sni_extension))) {
goto end;
}
struct sni_extension *sni = (struct sni_extension *) data;
data += sizeof(struct sni_extension);
__u16 server_name_len = __bpf_htons(sni->len);
for(int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
if (data_end < data + sn_idx) {
goto end;
}
if (sn.server_name + sizeof(struct server_name) < sn.server_name + sn_idx) {
goto end;
}
sn.server_name[sn_idx] = data[sn_idx];
}
sn.server_name[server_name_len] = 0;
goto end;
}
volatile int ext_len = __bpf_htons(ext->len);
if (ext_len < 0) {
goto end;
}
data += ext_len;
i += ext_len; // B
} // C
end:
return XDP_PASS;
}
Ignore that data does not point to the beginning of the extension length field of a TLS packet; I did not include the code for getting to this field because the above code is enough to reproduce the issue I'm seeing.

        Structured analysis of the verification failure:
        - Error: math between pkt pointer and register with unbounded min value is not allowed
        - Critical state transition: BOUNDS_COLLAPSE at insn 22: R0 lost scalar bounds at insn 22: inv,id=0,umax=65280,var_off=(0x0; 0xff00) -> inv,id=0
        - Causal chain: Unavailable
        - Source mapping: if (data_end < (data + ext_len)) {
        - Error classification: OBLIGE-E005 (lowering_artifact)

        Raw verifier log (for reference):
        19: R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
20: (71) r0 = *(u8 *)(r0 +3)
21: R0_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
21: (67) r0 <<= 8
22: R0_w=inv(id=0,umax_value=65280,var_off=(0x0; 0xff00)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
22: (4f) r0 |= r6
23: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
23: (dc) r0 = be16 r0
24: R0_w=inv(id=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + ext_len)) {
24: (0f) r5 += r0
last_idx 24 first_idx 12
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
math between pkt pointer and register with unbounded min value is not allowed
processed 24 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1

0: (61) r2 = *(u32 *)(r1 +4)
; char *data = (char *)(long)ctx->data;
1: (61) r1 = *(u32 *)(r1 +0)
; if (data_end < (data + EXTENSION_METHODS_LEN_FIELD_SIZE)) {
2: (bf) r0 = r1
3: (07) r0 += 2
; if (data_end < (data + EXTENSION_METHODS_LEN_FIELD_SIZE)) {
4: (2d) if r0 > r2 goto pc+37
 R0_w=pkt(id=0,off=2,r=2,imm=0) R1_w=pkt(id=0,off=0,r=2,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R10=fp0
; __u16 extension_methods_len = __bpf_htons(*(__u16 *) data);
5: (69) r1 = *(u16 *)(r1 +0)
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
6: (15) if r1 == 0x0 goto pc+35
 R0_w=pkt(id=0,off=2,r=2,imm=0) R1_w=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R2_w=pkt_end(id=0,off=0,imm=0) R10=fp0
7: (dc) r1 = be16 r1
8: (b7) r3 = 0
9: (18) r4 = 0x400000000
; if (data_end < (data + sizeof(struct extension))) {
11: (bf) r5 = r0
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+28
 R0=pkt(id=0,off=2,r=6,imm=0) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv0 R4=inv17179869184 R5_w=pkt(id=0,off=6,r=6,imm=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8

        What is the root cause of the failure? How would you fix it?
```

**Condition B Response**

```text
Root cause: the verifier loses the bounds on `ext_len` when LLVM lowers `ext->len` into byte loads, shift, `or`, and `be16`. After `r0 |= r6`, `R0` becomes an unbounded scalar, so `data + ext_len` / `data += ext_len` is packet-pointer arithmetic with a value the verifier can no longer prove is non-negative and in range, which triggers `math between pkt pointer and register with unbounded min value is not allowed`. The `volatile int` variant makes the generated code even noisier by forcing stack spill/reload and sign extension, but the real issue is that `ext_len` is not verifier-bounded at the point you add it to `data`.

Fix: remove `volatile`, read the field as a verifier-friendly scalar, and bound it before any packet-pointer arithmetic. For example, after advancing past the extension header, use something like `int ext_len = (__s16)bpf_ntohs(ext->len); if (ext_len < 0) goto end; if (data + ext_len > data_end) goto end; data += ext_len;` or equivalently keep it unsigned but explicitly mask/cap it before the bounds check. The important part is that the verifier must see a proven lower bound and an upper bound before `data += ext_len`; also add an explicit `server_name_len < sizeof(sn.server_name)` check before writing the terminating `0`.
```

**Scoring**

| Condition | Root Cause Correct | Fix Direction Correct | Fix Specificity | Response Tokens |
| --- | ---: | ---: | ---: | ---: |
| A: Raw log | 1 | 1 | 3 | 286 |
| B: Structured trace | 1 | 1 | 3 | 315 |

### stackoverflow-78958420

Case path: `case_study/cases/stackoverflow/stackoverflow-78958420.yaml`

Question URL: https://stackoverflow.com/questions/78958420/ebpf-xdp-program-r2-offset-is-outside-of-the-packet

**Ground truth fix description**

```text
It asserts that there must at least be 254 bytes bytes in the packet after offset 62. So if you encounter a packet that is smaller than 316 bytes, the program gets aborted. This satisfies the verifier, because when the packet is larger, it can read all 254 bytes and compare with the map. What you will likely want to do is to record the length of the domain name returned by parse_dname and use it to perform the bounds check. Then prepare a zeroed out buffer of MAX_DOMAIN_SIZE bytes and copy the domain name into the buffer, up to the length of the domain name. You should end up with a buffer...
```

**Structured analysis used in Condition B**

```json
{
  "causal_chain": "insn 76 (R1): R1 was updated by `r1 += -16` and became fp,off=-16 -> propagates through insn 91 (R2), insn 111 (R0) -> fails at insn 83 (R2): invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)",
  "critical_transition": "RANGE_LOSS at insn 14: R1 lost packet range proof at insn 14: r=8 -> r=0",
  "error_classification": "OBLIGE-E001 (source_bug)",
  "error_line": "invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)",
  "source_mapping": "PARSE_FUNC_DECLARATION(ethhdr)"
}
```

**Condition A Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        @@ -198,9 +198,9 @@ int xdp_dns(struct xdp_md *ctx)
                               return XDP_ABORTED; // Return FORMERR?
                       }
                        // avoid R2 offset is outside of the packet error
                        //if (qname + MAX_DOMAIN_SIZE + 1 > c.end)
                       //      return XDP_ABORTED; // Return FORMERR?

        Verifier output:
        xdp-loader load -vvv -m skb lo xdp-dns/xdp_dns.bpf.o

  libbpf: prog 'xdp_dns': -- BEGIN PROG LOAD LOG --
Validating xdp_dns() func#0...
0: R1=ctx(off=0,imm=0) R10=fp0
; int xdp_dns(struct xdp_md *ctx)
0: (bf) r6 = r1                       ; R1=ctx(off=0,imm=0) R6_w=ctx(off=0,imm=0)
; if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
1: (18) r2 = 0xfffffff8               ; R2_w=4294967288
3: (85) call bpf_xdp_adjust_meta#54   ; R0_w=scalar()
4: (bf) r1 = r0                       ; R0_w=scalar(id=1) R1_w=scalar(id=1)
5: (b7) r0 = 2                        ; R0_w=2
; if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
6: (55) if r1 != 0x0 goto pc+81       ; R1_w=0
; c->end = (void *)(long)ctx->data_end;
7: (61) r2 = *(u32 *)(r6 +4)          ; R2_w=pkt_end(off=0,imm=0) R6_w=ctx(off=0,imm=0)
; c->end = (void *)(long)ctx->data_end;
8: (7b) *(u64 *)(r10 -8) = r2         ; R2_w=pkt_end(off=0,imm=0) R10=fp0 fp-8_w=pkt_end
; c->pos = (void *)(long)ctx->data;
9: (61) r4 = *(u32 *)(r6 +0)          ; R4_w=pkt(off=0,r=0,imm=0) R6_w=ctx(off=0,imm=0)
; md = (void *)(long)ctx->data_meta;
10: (61) r3 = *(u32 *)(r6 +8)         ; R3_w=pkt_meta(off=0,r=0,imm=0) R6_w=ctx(off=0,imm=0)
; if ((void *)(md + 1) > c.pos)
11: (bf) r1 = r3                      ; R1_w=pkt_meta(off=0,r=0,imm=0) R3_w=pkt_meta(off=0,r=0,imm=0)
12: (07) r1 += 8                      ; R1=pkt_meta(off=8,r=0,imm=0)
; if ((void *)(md + 1) > c.pos)
13: (2d) if r1 > r4 goto pc+74        ; R1=pkt_meta(off=8,r=8,imm=0) R4=pkt(off=0,r=0,imm=0)
; PARSE_FUNC_DECLARATION(ethhdr)
14: (bf) r1 = r4                      ; R1_w=pkt(off=0,r=0,imm=0) R4=pkt(off=0,r=0,imm=0)
15: (07) r1 += 14                     ; R1_w=pkt(off=14,r=0,imm=0)
; PARSE_FUNC_DECLARATION(ethhdr)
16: (2d) if r1 > r2 goto pc+71        ; R1_w=pkt(off=14,r=14,imm=0) R2=pkt_end(off=0,imm=0)
17: (15) if r4 == 0x0 goto pc+70      ; R4=pkt(off=0,r=14,imm=0)
; *eth_proto = eth->h_proto;
18: (71) r0 = *(u8 *)(r4 +12)         ; R0_w=scalar(umax=255,var_off=(0x0; 0xff)) R4=pkt(off=0,r=14,imm=0)
19: (71) r5 = *(u8 *)(r4 +13)         ; R4=pkt(off=0,r=14,imm=0) R5_w=scalar(umax=255,var_off=(0x0; 0xff))
20: (67) r5 <<= 8                     ; R5_w=scalar(umax=65280,var_off=(0x0; 0xff00))
21: (4f) r5 |= r0                     ; R0_w=scalar(umax=255,var_off=(0x0; 0xff)) R5_w=scalar()
; *eth_proto = eth->h_proto;
22: (6b) *(u16 *)(r3 +0) = r5         ; R3=pkt_meta(off=0,r=8,imm=0) R5=scalar()
; ||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
23: (15) if r5 == 0xa888 goto pc+1    ; R5=scalar()
24: (55) if r5 != 0x81 goto pc+16     ; R5=129
; PARSE_FUNC_DECLARATION(vlanhdr)
25: (bf) r6 = r4                      ; R4=pkt(off=0,r=14,imm=0) R6_w=pkt(off=0,r=14,imm=0)
26: (07) r6 += 18                     ; R6_w=pkt(off=18,r=14,imm=0)
27: (b7) r0 = 2                       ; R0_w=2
; PARSE_FUNC_DECLARATION(vlanhdr)
28: (2d) if r6 > r2 goto pc+59        ; R2=pkt_end(off=0,imm=0) R6_w=pkt(off=18,r=18,imm=0)
29: (15) if r1 == 0x0 goto pc+58      ; R1=pkt(off=14,r=18,imm=0)
; *eth_proto = vlan->encap_proto;
30: (69) r5 = *(u16 *)(r4 +16)        ; R4=pkt(off=0,r=18,imm=0) R5_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; *eth_proto = vlan->encap_proto;
31: (6b) *(u16 *)(r3 +0) = r5         ; R3=pkt_meta(off=0,r=8,imm=0) R5=scalar(umax=65535,var_off=(0x0; 0xffff))
; ||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
32: (15) if r5 == 0xa888 goto pc+2    ; R5=scalar(umax=65535,var_off=(0x0; 0xffff))
33: (bf) r1 = r6                      ; R1_w=pkt(off=18,r=18,imm=0) R6=pkt(off=18,r=18,imm=0)
34: (55) if r5 != 0x81 goto pc+6      ; R5=129
; PARSE_FUNC_DECLARATION(vlanhdr)
35: (bf) r1 = r4                      ; R1_w=pkt(off=0,r=18,imm=0) R4=pkt(off=0,r=18,imm=0)
36: (07) r1 += 22                     ; R1_w=pkt(off=22,r=18,imm=0)
; PARSE_FUNC_DECLARATION(vlanhdr)
37: (2d) if r1 > r2 goto pc+50        ; R1_w=pkt(off=22,r=22,imm=0) R2=pkt_end(off=0,imm=0)
38: (15) if r6 == 0x0 goto pc+49      ; R6=pkt(off=18,r=22,imm=0)
; *eth_proto = vlan->encap_proto;
39: (69) r5 = *(u16 *)(r4 +20)        ; R4=pkt(off=0,r=22,imm=0) R5_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; *eth_proto = vlan->encap_proto;
40: (6b) *(u16 *)(r3 +0) = r5         ; R3=pkt_meta(off=0,r=8,imm=0) R5=scalar(umax=65535,var_off=(0x0; 0xffff))
; md->ip_pos = c.pos - (void *)eth;
41: (bf) r0 = r1                      ; R0_w=pkt(off=22,r=22,imm=0) R1=pkt(off=22,r=22,imm=0)
42: (1f) r0 -= r4                     ; R0_w=scalar() R4=pkt(off=0,r=22,imm=0)
; md->ip_pos = c.pos - (void *)eth;
43: (6b) *(u16 *)(r3 +2) = r0         ; R0_w=scalar() R3=pkt_meta(off=0,r=8,imm=0)
; if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
44: (55) if r5 != 0x8 goto pc+42      ; R5=8
; PARSE_FUNC_DECLARATION(iphdr)
45: (bf) r4 = r1                      ; R1=pkt(off=22,r=22,imm=0) R4_w=pkt(off=22,r=22,imm=0)
46: (07) r4 += 20                     ; R4_w=pkt(off=42,r=22,imm=0)
47: (b7) r0 = 2                       ; R0_w=2
; PARSE_FUNC_DECLARATION(iphdr)
48: (2d) if r4 > r2 goto pc+39        ; R2=pkt_end(off=0,imm=0) R4_w=pkt(off=42,r=42,imm=0)
49: (15) if r1 == 0x0 goto pc+38      ; R1=pkt(off=22,r=42,imm=0)
; switch (ipv4->protocol) {
50: (71) r3 = *(u8 *)(r1 +9)          ; R1=pkt(off=22,r=42,imm=0) R3_w=scalar(umax=255,var_off=(0x0; 0xff))
; switch (ipv4->protocol) {
51: (55) if r3 != 0x11 goto pc+35     ; R3_w=17
; PARSE_FUNC_DECLARATION(udphdr)
52: (bf) r3 = r1                      ; R1=pkt(off=22,r=42,imm=0) R3_w=pkt(off=22,r=42,imm=0)
53: (07) r3 += 28                     ; R3_w=pkt(off=50,r=42,imm=0)
; PARSE_FUNC_DECLARATION(udphdr)
54: (2d) if r3 > r2 goto pc+33        ; R2=pkt_end(off=0,imm=0) R3_w=pkt(off=50,r=50,imm=0)
55: (15) if r4 == 0x0 goto pc+32      ; R4=pkt(off=42,r=50,imm=0)
; || !(udp->dest == __bpf_htons(DNS_PORT))
56: (69) r4 = *(u16 *)(r1 +22)        ; R1=pkt(off=22,r=50,imm=0) R4=scalar(umax=65535,var_off=(0x0; 0xffff))
; || !(dns = parse_dnshdr(&c)))
57: (55) if r4 != 0x3500 goto pc+30   ; R4=13568
; PARSE_FUNC_DECLARATION(dnshdr)
58: (bf) r4 = r1                      ; R1=pkt(off=22,r=50,imm=0) R4_w=pkt(off=22,r=50,imm=0)
59: (07) r4 += 40                     ; R4_w=pkt(off=62,r=50,imm=0)
; PARSE_FUNC_DECLARATION(dnshdr)
60: (2d) if r4 > r2 goto pc+27        ; R2=pkt_end(off=0,imm=0) R4_w=pkt(off=62,r=62,imm=0)
61: (7b) *(u64 *)(r10 -16) = r4       ; R4_w=pkt(off=62,r=62,imm=0) R10=fp0 fp-16_w=pkt
; if (!(udp = parse_udphdr(&c))
62: (15) if r3 == 0x0 goto pc+25      ; R3=pkt(off=50,r=62,imm=0)
63: (b7) r0 = 0                       ; R0_w=0
; if (dns->flags.as_bits_and_pieces.qr
64: (69) r2 = *(u16 *)(r1 +30)        ; R1=pkt(off=22,r=62,imm=0) R2_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; if (dns->flags.as_bits_and_pieces.qr
65: (57) r2 &= 128                    ; R2=scalar(umax=128,var_off=(0x0; 0x80))
; ||  dns->qdcount != __bpf_htons(1)
66: (55) if r2 != 0x0 goto pc+21      ; R2=0
; ||  dns->qdcount != __bpf_htons(1)
67: (69) r2 = *(u16 *)(r1 +32)        ; R1=pkt(off=22,r=62,imm=0) R2_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; ||  dns->ancount || dns->nscount
68: (55) if r2 != 0x100 goto pc+19    ; R2_w=256
; ||  dns->ancount || dns->nscount
69: (69) r2 = *(u16 *)(r1 +34)        ; R1=pkt(off=22,r=62,imm=0) R2_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; ||  dns->ancount || dns->nscount
70: (55) if r2 != 0x0 goto pc+17      ; R2_w=0
; ||  dns->ancount || dns->nscount
71: (69) r2 = *(u16 *)(r1 +36)        ; R1=pkt(off=22,r=62,imm=0) R2_w=scalar(umax=65535,var_off=(0x0; 0xffff))
; ||  dns->arcount >  __bpf_htons(2))
72: (55) if r2 != 0x0 goto pc+15      ; R2_w=0
; ||  dns->arcount >  __bpf_htons(2))
73: (69) r1 = *(u16 *)(r1 +38)        ; R1=scalar(umax=65535,var_off=(0x0; 0xffff))
; if (dns->flags.as_bits_and_pieces.qr
74: (25) if r1 > 0x200 goto pc+13     ; R1=scalar(umax=512,var_off=(0x0; 0x3ff))
75: (bf) r1 = r10                     ; R1_w=fp0 R10=fp0
; qname = parse_dname(&c);
76: (07) r1 += -16                    ; R1_w=fp-16
77: (85) call pc+11
reg type unsupported for arg#0 function parse_dname#26
caller:
 R6=pkt(off=18,r=62,imm=0) R10=fp0 fp-8=pkt_end fp-16=pkt
callee:
 frame1: R1_w=fp-16 R2=0 R3=pkt(off=50,r=62,imm=0) R4=pkt(off=62,r=62,imm=0) R5=8 R10=fp0
; char *parse_dname(struct cursor *c)
89: (b7) r3 = 0                       ; frame1: R3_w=0
90: (79) r4 = *(u64 *)(r1 +8)         ; frame1: R1_w=fp-16 R4_w=pkt_end(off=0,imm=0)
; __u8 *dname = c->pos;
91: (79) r2 = *(u64 *)(r1 +0)         ; frame1: R1_w=fp-16 R2_w=pkt(off=62,r=62,imm=0)
92: (18) r6 = 0x100000000000000       ; frame1: R6_w=72057594037927936
94: (bf) r5 = r2                      ; frame1: R2_w=pkt(off=62,r=62,imm=0) R5_w=pkt(off=62,r=62,imm=0)
95: (05) goto pc+5
; if (c->pos + 1 > c->end)
101: (bf) r7 = r5                     ; frame1: R5=pkt(off=62,r=62,imm=0) R7_w=pkt(off=62,r=62,imm=0)
102: (07) r7 += 1                     ; frame1: R7_w=pkt(off=63,r=62,imm=0)
103: (b7) r0 = 0                      ; frame1: R0_w=0
; if (c->pos + 1 > c->end)
104: (2d) if r7 > r4 goto pc+21       ; frame1: R4=pkt_end(off=0,imm=0) R7_w=pkt(off=63,r=63,imm=0)
; if ((o & 0xC0) == 0xC0) {
105: (71) r7 = *(u8 *)(r5 +0)         ; frame1: R5=pkt(off=62,r=63,imm=0) R7_w=scalar(umax=255,var_off=(0x0; 0xff))
; if ((o & 0xC0) == 0xC0) {
106: (bf) r0 = r7                     ; frame1: R0_w=scalar(id=2,umax=255,var_off=(0x0; 0xff)) R7_w=scalar(id=2,umax=255,var_off=(0x0; 0xff))
107: (57) r0 &= 192                   ; frame1: R0_w=scalar(umax=192,var_off=(0x0; 0xc0))
; if ((o & 0xC0) == 0xC0) {
108: (55) if r0 != 0xc0 goto pc+4     ; frame1: R0_w=192
; c->pos += 2;
109: (07) r5 += 2                     ; frame1: R5_w=pkt(off=64,r=63,imm=0)
110: (7b) *(u64 *)(r1 +0) = r5        ; frame1: R1=fp-16 R5_w=pkt(off=64,r=63,imm=0)
111: (bf) r0 = r2                     ; frame1: R0_w=pkt(off=62,r=63,imm=0) R2=pkt(off=62,r=63,imm=0)
112: (05) goto pc+13
; }
126: (95) exit
returning from callee:
 frame1: R0=pkt(off=62,r=63,imm=0) R1=fp-16 R2=pkt(off=62,r=63,imm=0) R3=0 R4=pkt_end(off=0,imm=0) R5=pkt(off=64,r=63,imm=0) R6=72057594037927936 R7=scalar(id=2,umax=255,var_off=(0x0; 0xff)) R10=fp0
to caller at 78:
 R0=pkt(off=62,r=63,imm=0) R6=pkt(off=18,r=63,imm=0) R10=fp0 fp-8=pkt_end fp-16=pkt
; qname = parse_dname(&c);
78: (bf) r2 = r0                      ; R0=pkt(off=62,r=63,imm=0) R2_w=pkt(off=62,r=63,imm=0)
79: (b7) r0 = 0                       ; R0_w=0
; if (!qname) {
80: (15) if r2 == 0x0 goto pc+7       ; R2_w=pkt(off=62,r=63,imm=0)
; if (bpf_map_lookup_elem(&domain_denylist, qname))
81: (18) r1 = 0xffff93604d4c2400      ; R1_w=map_ptr(off=0,ks=254,vs=1,imm=0)
83: (85) call bpf_map_lookup_elem#1
invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)
R2 offset is outside of the packet
processed 101 insns (limit 1000000) max_states_per_insn 0 total_states 10 peak_states 10 mark_read 8
-- END PROG LOAD LOG --
  libbpf: prog 'xdp_dns': failed to load: -13
  libbpf: failed to load object 'xdp-dns/xdp_dns.bpf.o'
 libxdp: Failed to load program xdp_dns: Permission denied
Couldn't attach XDP program on iface 'lo': Permission denied(-13)

; if (!qname) {
80: (15) if r2 == 0x0 goto pc+7       ; R2_w=pkt(off=62,r=63,imm=0)
; if (bpf_map_lookup_elem(&domain_denylist, qname))
81: (18) r1 = 0xffff93604d4c2400      ; R1_w=map_ptr(off=0,ks=254,vs=1,imm=0)
83: (85) call bpf_map_lookup_elem#1
invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)

        What is the root cause of the failure? How would you fix it?
```

**Condition A Response**

```text
The root cause is that `parse_dname()` returns `qname` as a pointer into packet data, and you pass that pointer directly to `bpf_map_lookup_elem()`. The map key size is `MAX_DOMAIN_SIZE`/254 bytes, so the verifier assumes the helper may read 254 bytes starting at `qname`. At the failure point it has only proved `qname` is valid at packet offset 62 with range 63, not that 254 bytes are available, so it rejects the helper call with `invalid access to packet, off=62 size=254`. In other words, the problem is not the single-byte reads in `parse_dname()`, but using a variable-length packet pointer as a fixed-size helper argument.

The fix is to stop using packet memory directly as the map key. Parse the domain name length, bounds-check each read while walking the DNS labels, then copy the resulting name into a zero-initialized stack buffer of fixed size `MAX_DOMAIN_SIZE` and NUL-terminate it before calling `bpf_map_lookup_elem()`. If you want a minimal verifier-only workaround, you can prove `qname + 254 <= data_end` before the helper call, but that is usually the wrong design for DNS because names are variable-length and you would still be hashing/comparing unrelated packet bytes past the actual name.
```

**Condition B Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        @@ -198,9 +198,9 @@ int xdp_dns(struct xdp_md *ctx)
                               return XDP_ABORTED; // Return FORMERR?
                       }
                        // avoid R2 offset is outside of the packet error
                        //if (qname + MAX_DOMAIN_SIZE + 1 > c.end)
                       //      return XDP_ABORTED; // Return FORMERR?

        Structured analysis of the verification failure:
        - Error: invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)
        - Critical state transition: RANGE_LOSS at insn 14: R1 lost packet range proof at insn 14: r=8 -> r=0
        - Causal chain: insn 76 (R1): R1 was updated by `r1 += -16` and became fp,off=-16 -> propagates through insn 91 (R2), insn 111 (R0) -> fails at insn 83 (R2): invalid access to packet, off=62 size=254, R2(id=0,off=62,r=63)
        - Source mapping: PARSE_FUNC_DECLARATION(ethhdr)
        - Error classification: OBLIGE-E001 (source_bug)

        Raw verifier log (for reference):
        xdp-loader load -vvv -m skb lo xdp-dns/xdp_dns.bpf.o

  libbpf: prog 'xdp_dns': -- BEGIN PROG LOAD LOG --
Validating xdp_dns() func#0...
0: R1=ctx(off=0,imm=0) R10=fp0
; int xdp_dns(struct xdp_md *ctx)
0: (bf) r6 = r1                       ; R1=ctx(off=0,imm=0) R6_w=ctx(off=0,imm=0)
; if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
1: (18) r2 = 0xfffffff8               ; R2_w=4294967288
3: (85) call bpf_xdp_adjust_meta#54   ; R0_w=scalar()
4: (bf) r1 = r0                       ; R0_w=scalar(id=1) R1_w=scalar(id=1)
5: (b7) r0 = 2                        ; R0_w=2
; if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
6: (55) if r1 != 0x0 goto pc+81       ; R1_w=0
; c->end = (void *)(long)ctx->data_end;
7: (61) r2 = *(u32 *)(r6 +4)          ; R2_w=pkt_end(off=0,imm=0) R6_w=ctx(off=0,imm=0)
; c->end = (void *)(long)ctx->data_end;
8: (7b) *(u64 *)(r10 -8) = r2         ; R2_w=pkt_end(off=0,imm=0) R10=fp0 fp-8_w=pkt_end
; c->pos = (void *)(long)ctx->data;
9: (61) r4 = *(u32 *)(r6 +0)          ; R4_w=pkt(off=0,r=0,imm=0) R6_w=ctx(off=0,imm=0)
; md = (void *)(long)ctx->data_meta;
10: (61) r3 = *(u32 *)(r6 +8)         ; R3_w=pkt_meta(off=0,r=0,imm=0) R6_w=ctx(off=0,imm=0)
; if ((void *)(md + 1) > c.pos)
11: (bf) r1 = r3                      ; R1_w=pkt_meta(off=0,r=0,imm=0) R3_w=pkt_meta(off=0,r=0,imm=0)
12: (07) r1 += 8                      ; R1=pkt_meta(off=8,r=0,imm=0)
; if ((void *)(md + 1) > c.pos)
13: (2d) if r1 > r4 goto pc+74        ; R1=pkt_meta(off=8,r=8,imm=0) R4=pkt(off=0,r=0,imm=0)
; PARSE_FUNC_DECLARATION(ethhdr)
14: (bf) r1 = r4                      ; R1_w=pkt(off=0,r=0,imm=0) R4=pkt(off=0,r=0,imm=0)
15: (07) r1 += 14                     ; R1_w=pkt(off=14,r=0,imm=0)
; PARSE_FUNC_DECLARATION(ethhdr)
16: (2d) if r1 > r2 goto pc+71        ; R1_w=pkt(off=14,r=14,imm=0) R2=pkt_end(off=0,imm=0)
17: (15) if r4 == 0x0 goto pc+70      ; R4=pkt(off=0,r=14,imm=0)
; *eth_proto = eth->h_proto;
18: (71) r0 = *(u8 *)(r4 +12)         ; R0_w=scalar(umax=255,var_off=(0x0; 0xff)) R4=pkt(off=0,r=14,imm=0)
19: (71) r5 = *(u8 *)(r4 +13)         ; R4=pkt(off=0,r=14,imm=0) R5_w=scalar(umax=255,var_off=(0x0; 0xff))
20: (67) r5 <<= 8                     ; R5_w=scalar(umax=65280,var_off=(0x0; 0xff00))
21: (4f) r5 |= r0                     ; R0_w=scalar(umax=255,var_off=(0x0; 0xff)) R5_w=scalar()
; *eth_proto = eth->h_proto;
22: (6b) *(u16 *)(r3 +0) = r5         ; R3=pkt_meta(off=0,r=8,imm=0) R5=scalar()
; ||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
23: (15) if r5 == 0xa888 goto pc+1    ; R5=scalar()
24: (55) if r5 != 0x81 goto pc+16     ; R5=129
; PARSE_FUNC_DECLARATION(vlanhdr)
25: (bf) r6 = r4                      ; R4=pkt(off=0,r=14,imm=0) R6_w=pkt(off=0,r=14,imm=0)
26: (07) r6 += 18                     ; R6_w=pkt(off=18,r=14,imm=0)
27: (b7) r0 = 2                       ; R0_w=2
; PARSE_FUNC_DECLARATION(vlanhdr)
28: (2d) if r6 > r2 goto pc+59        ; R2=pkt_end(off=0,imm=0) R6_w=pkt(off=18,r=18,imm=0)
29: (15) if r1 == 0x0 goto pc+58      ; R1=pkt(off=14,r=18,imm=0)

        What is the root cause of the failure? How would you fix it?
```

**Condition B Response**

```text
Root cause: `qname` is still a pointer into packet data when you pass it to `bpf_map_lookup_elem()`. The helper must read the full key size from that pointer, and your map key is `MAX_DOMAIN_SIZE`/254 bytes, but the verifier only knows `qname` has about 63 bytes of valid packet range left at offset 62. That is why it rejects the program with `invalid access to packet, off=62 size=254`. The `RANGE_LOSS` note in the trace is just where packet-range precision got weakened earlier; the real bug is using a packet pointer as a fixed-size map key without proving that whole key-sized region is in bounds.

Fix: do not look up the map with the packet pointer directly. Have `parse_dname()` return the domain length, verify `qname + qname_len <= c.end`, then copy at most `min(qname_len, MAX_DOMAIN_SIZE - 1)` bytes into a zero-initialized stack buffer and NUL-terminate it, and pass that stack buffer to `bpf_map_lookup_elem()`. If you keep using the packet pointer directly, you would need a check like `qname + MAX_DOMAIN_SIZE <= c.end`, but that is overly strict and will drop shorter valid packets; copying into a bounded stack key is the proper fix.
```

**Scoring**

| Condition | Root Cause Correct | Fix Direction Correct | Fix Specificity | Response Tokens |
| --- | ---: | ---: | ---: | ---: |
| A: Raw log | 1 | 1 | 2 | 304 |
| B: Structured trace | 1 | 1 | 2 | 288 |

### stackoverflow-70729664

Case path: `case_study/cases/stackoverflow/stackoverflow-70729664.yaml`

Question URL: https://stackoverflow.com/questions/70729664/need-help-in-xdp-program-failing-to-load-with-error-r7-offset-is-outside-of-the

**Ground truth fix description**

```text
The verifier errors because it thinks R7 is outside the packet's known bounds. It tells us you're trying to make an access of size 1B at offset 26 into the packet pointer, but the packet has a known size of 0 (r=0, for range=0). That's weird because you did check the packet bounds. On instruction 2947, the packet pointer R1 is compared to R6, the pointer to the end of the packet. So following that check, the known minimum size of R1 should be updated, but it remains 0 (r=0). That is happening because you are hitting a corner-case limitation of the verifier:
```

**Structured analysis used in Condition B**

```json
{
  "causal_chain": "insn 2940 (R7): R7 still carried pkt,id=68,off=26,r=0,umax=73851,var_off=(0x0; 0xffffffff) at `if r7 >= r6 goto pc-2881` -> fails at insn 2948 (R7): invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)",
  "critical_transition": "RANGE_LOSS at insn 2940: R7 lost packet range proof at insn 2940: r=27 -> r=0",
  "error_classification": "OBLIGE-E001 (source_bug)",
  "error_line": "invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)",
  "source_mapping": "if (nh->pos + size < data_end)"
}
```

**Condition A Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        #define AMF_CPUS 4
#define INV_RET_U32 4294967295
#define INV_RET_U16 65535
#define INV_RET_U8 255
#define DATA_CHUNK 0
/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
void *pos;
};
// Return the chunk type of the corresponding sctp chunk
static __always_inline __u8 parse_sctp_chunk_type(void *data, void *data_end) {
if (data + 1 > data_end)
return INV_RET_U8;
return *(__u8 *)data;
}
// Return the chunk size of the corresponding sctp chunk
static __always_inline __u16 parse_sctp_chunk_size(void *data, void *data_end) {
if (data + 4 > data_end)
return INV_RET_U16;
__u16 size = bpf_ntohs(*(__u16 *)(data + 2));
return size;
}
static __always_inline __u32 parse_sctp_hdr(struct hdr_cursor *nh,
void *data_end) {
struct sctphdr *sctph = nh->pos;
int hdrsize = sizeof(*sctph);
if (sctph + 1 > data_end)
return INV_RET_U32;
nh->pos += hdrsize;
#pragma clang loop unroll(full)
for (int i = 0; i < 16; ++i) {
__u8 type = parse_sctp_chunk_type(nh->pos, data_end);
if (type == INV_RET_U8)
return INV_RET_U32;
__u16 size = parse_sctp_chunk_size(nh->pos, data_end);
if (size > 512)
return INV_RET_U32;
//Adjust for padding
size += (size % 4) == 0 ? 0 : 4 - size % 4;
if (type == DATA_CHUNK) {
// Run logic
}
if (nh->pos + size < data_end)
nh->pos += size;
else
return INV_RET_U32;
}
return INV_RET_U32;
}
SEC("parse_sctp")
int xdp_parse_sctp(struct xdp_md *ctx) {
void *data_end = (void *)(long)ctx->data_end;
void *data = (void *)(long)ctx->data;
/* These keep track of the next header type and iterator pointer */
struct hdr_cursor nh;
__u32 nh_type, ip_type;
/* Start next header cursor position at data start */
nh.pos = data;
nh_type = parse_ethhdr(&nh, data_end);
if (bpf_ntohs(nh_type) != ETH_P_IP)
return XDP_PASS;
ip_type = parse_iphdr(&nh, data_end);
if (ip_type != IPPROTO_SCTP)
return XDP_PASS;
parse_sctp_hdr(&nh, data_end);
return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

        Verifier output:
        ; if (nh->pos + size < data_end)
2937: (57) r2 &= 65535
2938: (bf) r7 = r8
2939: (0f) r7 += r2
last_idx 2939 first_idx 2931
regs=4 stack=0 before 2938: (bf) r7 = r8
regs=4 stack=0 before 2937: (57) r2 &= 65535
regs=4 stack=0 before 2936: (0f) r2 += r1
regs=6 stack=0 before 2935: (79) r2 = *(u64 *)(r10 -40)
regs=2 stack=10 before 2934: (79) r1 = *(u64 *)(r10 -32)
regs=0 stack=18 before 2933: (6b) *(u16 *)(r8 +8) = r1
regs=0 stack=18 before 2932: (dc) r1 = be16 r1
regs=0 stack=18 before 2931: (57) r1 &= 3
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_r=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R2_w=pkt(id=65,off=37,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2835 first_idx 2828
regs=0 stack=10 before 2835: (05) goto pc+95
regs=0 stack=10 before 2834: (2d) if r2 > r6 goto pc+99
regs=0 stack=10 before 2833: (07) r2 += 11
regs=0 stack=10 before 2832: (bf) r2 = r8
regs=0 stack=10 before 2831: (73) *(u8 *)(r7 +0) = r2
regs=0 stack=10 before 2830: (47) r2 |= 4
regs=0 stack=10 before 2829: (71) r2 = *(u8 *)(r7 +0)
regs=0 stack=10 before 2828: (3d) if r2 >= r6 goto pc+3
 R0_w=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R2_rw=pkt(id=65,off=28,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2827 first_idx 2817
regs=0 stack=10 before 2827: (79) r2 = *(u64 *)(r10 -24)
regs=0 stack=10 before 2826: (61) r1 = *(u32 *)(r10 -4)
regs=0 stack=10 before 2825: (15) if r1 == 0x0 goto pc+35
regs=0 stack=10 before 2824: (69) r1 = *(u16 *)(r0 +0)
regs=0 stack=10 before 2823: (15) if r0 == 0x0 goto pc+37
regs=0 stack=10 before 2822: (85) call bpf_map_lookup_elem#1
regs=0 stack=10 before 2820: (18) r1 = 0xffffb27245d41000
regs=0 stack=10 before 2819: (07) r2 += -4
regs=0 stack=10 before 2818: (bf) r2 = r10
regs=0 stack=10 before 2817: (15) if r2 == 0xffff goto pc-2758
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R2_rw=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R3=inv(id=0,umin_value=1,umax_value=4,var_off=(0x0; 0x7)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8_r=mmmm???? fp-24_r=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2816 first_idx 2808
regs=0 stack=10 before 2816: (63) *(u32 *)(r10 -4) = r2
regs=0 stack=10 before 2815: (57) r2 &= 65535
regs=0 stack=10 before 2814: (4f) r2 |= r1
regs=0 stack=10 before 2813: (67) r2 <<= 8
regs=0 stack=10 before 2812: (71) r2 = *(u8 *)(r2 +27)
regs=0 stack=10 before 2811: (71) r1 = *(u8 *)(r2 +28)
regs=0 stack=10 before 2810: (55) if r1 != 0xa00 goto pc-2753
regs=0 stack=10 before 2809: (69) r1 = *(u16 *)(r2 +23)
regs=0 stack=10 before 2808: (2d) if r1 > r6 goto pc-2751
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=pkt(id=65,off=55,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R2_rw=pkt(id=65,off=26,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R3=inv(id=0,umin_value=1,umax_value=4,var_off=(0x0; 0x7)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8_r=mmmm???? fp-24_rw=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48_w=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2807 first_idx 2798
regs=0 stack=10 before 2807: (7b) *(u64 *)(r10 -48) = r1
regs=0 stack=10 before 2806: (07) r1 += 29
regs=0 stack=10 before 2805: (bf) r1 = r2
regs=0 stack=10 before 2804: (bf) r2 = r8
regs=0 stack=10 before 2803: (15) if r9 == 0xf goto pc+32
regs=0 stack=10 before 2802: (71) r9 = *(u8 *)(r2 +17)
regs=0 stack=10 before 2801: (7b) *(u64 *)(r10 -24) = r1
regs=0 stack=10 before 2800: (07) r1 += 2
regs=0 stack=10 before 2799: (bf) r1 = r2
regs=0 stack=10 before 2798: (2d) if r1 > r6 goto pc-2739
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=pkt(id=65,off=44,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R2_rw=pkt(id=65,off=26,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R3_w=inv(id=0,umin_value=1,umax_value=4,var_off=(0x0; 0x7)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=invP(id=0,umax_value=516,var_off=(0x0; 0xffff),s32_max_value=65535,u32_max_value=65535) R10=fp0 fp-8_r=mmmm???? fp-24=pkt fp-32_r=mmmmmmmm fp-40_rw=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2797 first_idx 2790
regs=0 stack=10 before 2797: (07) r1 += 18
regs=0 stack=10 before 2796: (bf) r1 = r2
regs=0 stack=10 before 2795: (bf) r2 = r8
regs=0 stack=10 before 2794: (55) if r1 != 0x0 goto pc+139
regs=0 stack=10 before 2793: (7b) *(u64 *)(r10 -40) = r3
regs=8 stack=0 before 2792: (1f) r3 -= r2
regs=c stack=0 before 2791: (b7) r3 = 4
regs=4 stack=0 before 2790: (15) if r2 == 0x0 goto pc+3
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=inv(id=66,umax_value=255,var_off=(0x0; 0xff)) R2_rw=invP(id=0,umax_value=3,var_off=(0x0; 0x3)) R3_w=invP0 R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=invP(id=0,umax_value=516,var_off=(0x0; 0xffff),s32_max_value=65535,u32_max_value=65535) R10=fp0 fp-8_r=mmmm???? fp-24=pkt fp-32_rw=mmmmmmmm fp-40_w=00000000 fp-48=pkt
parent didn't have regs=4 stack=0 marks
last_idx 2789 first_idx 2778
regs=4 stack=0 before 2789: (7b) *(u64 *)(r10 -40) = r3
regs=4 stack=0 before 2788: (b7) r3 = 0
regs=4 stack=0 before 2787: (57) r2 &= 3
regs=4 stack=0 before 2786: (79) r2 = *(u64 *)(r10 -32)
regs=0 stack=8 before 2785: (25) if r2 > 0x200 goto pc-2726
regs=0 stack=8 before 2784: (7b) *(u64 *)(r10 -32) = r2
regs=4 stack=0 before 2783: (dc) r2 = be16 r2
regs=5 stack=0 before 2782: (69) r2 = *(u16 *)(r8 +2)
regs=1 stack=0 before 2781: (15) if r2 == 0xff goto pc-2722
regs=1 stack=0 before 2780: (bf) r2 = r1
regs=1 stack=0 before 2779: (71) r1 = *(u8 *)(r8 +0)
regs=1 stack=0 before 2778: (2d) if r1 > r6 goto pc-2719
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=pkt(id=65,off=30,r=27,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R2_w=pkt(id=61,off=26,r=55,umin_value=20,umax_value=7800,var_off=(0x0; 0x7fffffff),s32_min_value=0,u32_max_value=2147483647) R6_r=pkt_end(id=0,off=0,imm=0) R7_rw=pkt(id=65,off=27,r=27,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_rw=pkt(id=65,off=26,r=27,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9_w=invP(id=0,umax_value=516,var_off=(0x0; 0xffff),s32_max_value=65535,u32_max_value=65535) R10=fp0 fp-8_r=mmmm???? fp-24=pkt fp-32=pkt fp-40=inv fp-48=pkt
parent already had regs=0 stack=0 marks
; if (nh->pos + size < data_end)
2940: (3d) if r7 >= r6 goto pc-2881
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=0) R2_w=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7_w=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
2941: (bf) r1 = r7
2942: (07) r1 += 1
2943: (7b) *(u64 *)(r10 -24) = r1
2944: (2d) if r1 > r6 goto pc-2885
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=pkt(id=68,off=27,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R2_w=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7_w=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24_w=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
2945: (bf) r1 = r7
2946: (07) r1 += 4
; if (type == INV_RET_U8)
2947: (2d) if r1 > r6 goto pc-2888
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1=pkt(id=68,off=30,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R2=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
2948: (71) r1 = *(u8 *)(r7 +0)
invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)
R7 offset is outside of the packet
processed 1225 insns (limit 1000000) max_states_per_insn 0 total_states 107 peak_states 107 mark_read 7

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_cpu_redirect_stream'
libbpf: failed to load object 'xdp_stream_nat_new.o'
ERR: loading BPF-OBJ file(xdp_stream_nat_new.o) (-4007): Unknown error 4007
ERR: loading file: xdp_stream_nat_new.o

2945: (bf) r1 = r7
2946: (07) r1 += 4
2947: (2d) if r1 > r6 goto pc-2888
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1=pkt(id=68,off=30,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R2=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=68,off=26,r=0,umin_value=20,umax_value=73851,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32=mmmmmmmm fp-40=inv fp-48=pkt
2948: (71) r1 = *(u8 *)(r7 +0)
invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)
R7 offset is outside of the packet

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

2782: (69) r2 = *(u16 *)(r8 +2)
2783: (dc) r2 = be16 r2
2784: (7b) *(u64 *)(r10 -32) = r2
; if (size > 512)
2785: (25) if r2 > 0x200 goto pc-2726
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=66,umax_value=255,var_off=(0x0; 0xff)) R2_w=inv(id=0,umax_value=512,var_off=(0x0; 0xffffffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=65,off=27,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8=pkt(id=65,off=26,r=30,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=invP(id=0,umax_value=516,var_off=(0x0; 0xffff),s32_max_value=65535,u32_max_value=65535) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_w=mmmmmmmm fp-40=inv fp-48=pkt

        What is the root cause of the failure? How would you fix it?
```

**Condition A Response**

```text
Root cause: this is a verifier precision loss, not a real missing bounds check. In the fully unrolled loop, `size` gets spilled to the stack before the verifier can keep the `size <= 512` fact, so when it is reloaded it is treated like a generic `__u16` with max `65535`. After `r7 = nh->pos + size`, that makes the possible packet offset exceed the verifier’s `MAX_PACKET_OFF` limit, so the later `data_end` comparison no longer restores a valid packet range. As a result `R7` reaches the load with `r=0`, and the verifier reports `R7 offset is outside of the packet`.

Fix: rewrite the advance so the verifier sees a tightly bounded scalar before it is added to the packet pointer. Keep `size` in a scalar such as `__u32`, validate and pad it first, then check it against the remaining packet length and against the packet-offset limit before doing `nh->pos += size`. A verifier-friendly pattern is to track a separate offset from `data`, ensure `size <= 516`, ensure `size <= data_end - nh->pos`, and only then advance; reducing the unroll count or using a newer kernel can also avoid this older verifier corner case.
```

**Condition B Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        #define AMF_CPUS 4
#define INV_RET_U32 4294967295
#define INV_RET_U16 65535
#define INV_RET_U8 255
#define DATA_CHUNK 0
/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
void *pos;
};
// Return the chunk type of the corresponding sctp chunk
static __always_inline __u8 parse_sctp_chunk_type(void *data, void *data_end) {
if (data + 1 > data_end)
return INV_RET_U8;
return *(__u8 *)data;
}
// Return the chunk size of the corresponding sctp chunk
static __always_inline __u16 parse_sctp_chunk_size(void *data, void *data_end) {
if (data + 4 > data_end)
return INV_RET_U16;
__u16 size = bpf_ntohs(*(__u16 *)(data + 2));
return size;
}
static __always_inline __u32 parse_sctp_hdr(struct hdr_cursor *nh,
void *data_end) {
struct sctphdr *sctph = nh->pos;
int hdrsize = sizeof(*sctph);
if (sctph + 1 > data_end)
return INV_RET_U32;
nh->pos += hdrsize;
#pragma clang loop unroll(full)
for (int i = 0; i < 16; ++i) {
__u8 type = parse_sctp_chunk_type(nh->pos, data_end);
if (type == INV_RET_U8)
return INV_RET_U32;
__u16 size = parse_sctp_chunk_size(nh->pos, data_end);
if (size > 512)
return INV_RET_U32;
//Adjust for padding
size += (size % 4) == 0 ? 0 : 4 - size % 4;
if (type == DATA_CHUNK) {
// Run logic
}
if (nh->pos + size < data_end)
nh->pos += size;
else
return INV_RET_U32;
}
return INV_RET_U32;
}
SEC("parse_sctp")
int xdp_parse_sctp(struct xdp_md *ctx) {
void *data_end = (void *)(long)ctx->data_end;
void *data = (void *)(long)ctx->data;
/* These keep track of the next header type and iterator pointer */
struct hdr_cursor nh;
__u32 nh_type, ip_type;
/* Start next header cursor position at data start */
nh.pos = data;
nh_type = parse_ethhdr(&nh, data_end);
if (bpf_ntohs(nh_type) != ETH_P_IP)
return XDP_PASS;
ip_type = parse_iphdr(&nh, data_end);
if (ip_type != IPPROTO_SCTP)
return XDP_PASS;
parse_sctp_hdr(&nh, data_end);
return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

        Structured analysis of the verification failure:
        - Error: invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)
        - Critical state transition: RANGE_LOSS at insn 2940: R7 lost packet range proof at insn 2940: r=27 -> r=0
        - Causal chain: insn 2940 (R7): R7 still carried pkt,id=68,off=26,r=0,umax=73851,var_off=(0x0; 0xffffffff) at `if r7 >= r6 goto pc-2881` -> fails at insn 2948 (R7): invalid access to packet, off=26 size=1, R7(id=68,off=26,r=0)
        - Source mapping: if (nh->pos + size < data_end)
        - Error classification: OBLIGE-E001 (source_bug)

        Raw verifier log (for reference):
        ; if (nh->pos + size < data_end)
2937: (57) r2 &= 65535
2938: (bf) r7 = r8
2939: (0f) r7 += r2
last_idx 2939 first_idx 2931
regs=4 stack=0 before 2938: (bf) r7 = r8
regs=4 stack=0 before 2937: (57) r2 &= 65535
regs=4 stack=0 before 2936: (0f) r2 += r1
regs=6 stack=0 before 2935: (79) r2 = *(u64 *)(r10 -40)
regs=2 stack=10 before 2934: (79) r1 = *(u64 *)(r10 -32)
regs=0 stack=18 before 2933: (6b) *(u16 *)(r8 +8) = r1
regs=0 stack=18 before 2932: (dc) r1 = be16 r1
regs=0 stack=18 before 2931: (57) r1 &= 3
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_r=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R2_w=pkt(id=65,off=37,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R6=pkt_end(id=0,off=0,imm=0) R7=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2835 first_idx 2828
regs=0 stack=10 before 2835: (05) goto pc+95
regs=0 stack=10 before 2834: (2d) if r2 > r6 goto pc+99
regs=0 stack=10 before 2833: (07) r2 += 11
regs=0 stack=10 before 2832: (bf) r2 = r8
regs=0 stack=10 before 2831: (73) *(u8 *)(r7 +0) = r2
regs=0 stack=10 before 2830: (47) r2 |= 4
regs=0 stack=10 before 2829: (71) r2 = *(u8 *)(r7 +0)
regs=0 stack=10 before 2828: (3d) if r2 >= r6 goto pc+3
 R0_w=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=inv(id=0,umax_value=4294967295,var_off=(0x0; 0xffffffff)) R2_rw=pkt(id=65,off=28,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=mmmm???? fp-24=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2827 first_idx 2817
regs=0 stack=10 before 2827: (79) r2 = *(u64 *)(r10 -24)
regs=0 stack=10 before 2826: (61) r1 = *(u32 *)(r10 -4)
regs=0 stack=10 before 2825: (15) if r1 == 0x0 goto pc+35
regs=0 stack=10 before 2824: (69) r1 = *(u16 *)(r0 +0)
regs=0 stack=10 before 2823: (15) if r0 == 0x0 goto pc+37
regs=0 stack=10 before 2822: (85) call bpf_map_lookup_elem#1
regs=0 stack=10 before 2820: (18) r1 = 0xffffb27245d41000
regs=0 stack=10 before 2819: (07) r2 += -4
regs=0 stack=10 before 2818: (bf) r2 = r10
regs=0 stack=10 before 2817: (15) if r2 == 0xffff goto pc-2758
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R2_rw=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R3=inv(id=0,umin_value=1,umax_value=4,var_off=(0x0; 0x7)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=55,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8_r=mmmm???? fp-24_r=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48=pkt
parent didn't have regs=0 stack=10 marks
last_idx 2816 first_idx 2808
regs=0 stack=10 before 2816: (63) *(u32 *)(r10 -4) = r2
regs=0 stack=10 before 2815: (57) r2 &= 65535
regs=0 stack=10 before 2814: (4f) r2 |= r1
regs=0 stack=10 before 2813: (67) r2 <<= 8
regs=0 stack=10 before 2812: (71) r2 = *(u8 *)(r2 +27)
regs=0 stack=10 before 2811: (71) r1 = *(u8 *)(r2 +28)
regs=0 stack=10 before 2810: (55) if r1 != 0xa00 goto pc-2753
regs=0 stack=10 before 2809: (69) r1 = *(u16 *)(r2 +23)
regs=0 stack=10 before 2808: (2d) if r1 > r6 goto pc-2751
 R0=map_value(id=0,off=0,ks=4,vs=2,imm=0) R1_rw=pkt(id=65,off=55,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R2_rw=pkt(id=65,off=26,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R3=inv(id=0,umin_value=1,umax_value=4,var_off=(0x0; 0x7)) R6_r=pkt_end(id=0,off=0,imm=0) R7_r=pkt(id=65,off=27,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R8_r=pkt(id=65,off=26,r=44,umin_value=20,umax_value=8316,var_off=(0x0; 0xffffffff)) R9_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8_r=mmmm???? fp-24_rw=pkt fp-32_r=mmmmmmmm fp-40_r=invP fp-48_w=pkt

        What is the root cause of the failure? How would you fix it?
```

**Condition B Response**

```text
The root cause is that the verifier stops trusting the chunk length by the time you do `nh->pos + size`. In the generated BPF, `size` gets spilled/reloaded across the `type == DATA_CHUNK` path, and the reload no longer carries the earlier `size <= 512` proof; by instruction 2937 it is effectively just an unconstrained 16-bit scalar again. That makes `r7 = r8 + r2` a packet pointer plus unknown offset, and the test `if (nh->pos + size < data_end)` is not enough to give `r7` a valid readable range for the next dereference, so the next `*(__u8 *)nh->pos` fails with `R7(..., r=0)`.

The fix is to restructure the parser so the verifier can keep a bounded length all the way to the cursor update. Parse the chunk header, reject invalid lengths early (`size < 4` and `size > 512`), apply padding into a local `chunk_len`, then do a single canonical bounds check like `if ((__u8 *)nh->pos + chunk_len > data_end) return ...;` before assigning `nh->pos += chunk_len`. If the `DATA_CHUNK` logic is nontrivial, move it after that bounds check or re-check `chunk_len` after the branch, so you never advance a packet pointer by a reloaded, unconstrained scalar.
```

**Scoring**

| Condition | Root Cause Correct | Fix Direction Correct | Fix Specificity | Response Tokens |
| --- | ---: | ---: | ---: | ---: |
| A: Raw log | 1 | 1 | 2 | 280 |
| B: Structured trace | 1 | 1 | 2 | 289 |

### stackoverflow-70760516

Case path: `case_study/cases/stackoverflow/stackoverflow-70760516.yaml`

Question URL: https://stackoverflow.com/questions/70760516/bpf-verifier-fails-because-of-invalid-access-to-packet

**Ground truth fix description**

```text
Now, to fix this we need to change the code so data can't exceed 65536. We do this by specifying a maximum amount of iterations(extensions) and setting the max size of each extension. I modified the program to add these constrains, I chose max 32 extensions and max 2048 bytes per extension which seems sane values (32 * 2048 = 65536), these can be changed.
```

**Structured analysis used in Condition B**

```json
{
  "causal_chain": "insn 28 (R3): R3 was updated by `r3 += r4` and became inv,id=0,umax=65535,var_off=(0x0; 0xffff) -> propagates through insn 31 (R0) -> fails at insn 14 (R0): invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)",
  "critical_transition": "BOUNDS_COLLAPSE at insn 31: R3 lost scalar bounds at insn 31: inv,id=0,umax=65535,var_off=(0x0; 0xffff) -> inv,id=0,umax=131071,var_off=(0x0; 0x1ffff)",
  "error_classification": "OBLIGE-E001 (source_bug)",
  "error_line": "invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)",
  "source_mapping": "if (ext->type == SERVER_NAME_EXTENSION) {"
}
```

**Condition A Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        struct server_name {
char server_name[256];
};
struct extension {
__u16 type;
__u16 len;
} __attribute__((packed));
struct sni_extension {
__u16 list_len;
__u8 type;
__u16 len;
} __attribute__((packed));
#define SERVER_NAME_EXTENSION 0
SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
char *data_end = (char *)(long)ctx->data_end;
char *data = (char *)(long)ctx->data;
if (data_end < (data + sizeof(__u16))) {
goto end;
}
__u16 extension_method_len = __bpf_htons(*(__u16 *) data);
data += sizeof(__u16);
for(int i = 0; i < extension_method_len; i += sizeof(struct extension)) {
if (data_end < (data + sizeof(struct extension))) {
goto end;
}
struct extension *ext = (struct extension *) data;
data += sizeof(struct extension);
///////////////////// (A) ////////////////////
if (data_end < ((char *) ext) + sizeof(struct extension)) {
goto end;
}
if (ext->type == SERVER_NAME_EXTENSION) { // Error happens here
struct server_name sn;
if (data_end < (data + sizeof(struct sni_extension))) {
goto end;
}
struct sni_extension *sni = (struct sni_extension *) data;
data += sizeof(struct sni_extension);
__u16 server_name_len = __bpf_htons(sni->len);
for(int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
if (data_end < data + sn_idx) {
goto end;
}
if (sn.server_name + sizeof(struct server_name) < sn.server_name + sn_idx) {
goto end;
}
sn.server_name[sn_idx] = data[sn_idx];
}
sn.server_name[server_name_len] = 0;
goto end;
}
__u16 ext_len = __bpf_htons(ext->len);
if (ext_len > 30000) {
goto end;
}
if (data_end < data + ext_len) {
goto end;
}
data += ext_len;
i += ext_len;
}
end:
return XDP_PASS;
}
Ignore that data does not point to the beginning of the extension length field of a TLS packet; I did not include the code for getting to this field because the above code is enough to reproduce the issue I'm seeing.
Here is the end of the error log when I attempt to load this program. The error at the end happens at if (ext->type == SERVER_NAME_EXTENSION) {:
from 31 to 12: R0_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {

        Verifier output:
        from 31 to 12: R0_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=14,off=58,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=14,off=58,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=15,off=62,r=0,umax_value=45000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=62,r=0,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=15,off=62,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=66,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=15,off=62,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=66,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=66,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=16,off=66,r=0,umax_value=48000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=64,umax_value=48064,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=16,off=66,r=0,umax_value=48000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=16,off=66,r=70,umax_value=48000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=64,umax_value=48064,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=16,off=70,r=70,umax_value=48000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=16,off=66,r=70,umax_value=48000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=64,umax_value=48064,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=16,off=70,r=70,umax_value=48000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=64,umax_value=48064,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=16,off=70,r=70,umax_value=48000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=17,off=70,r=0,umax_value=51000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=68,umax_value=51068,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=17,off=70,r=0,umax_value=51000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=17,off=70,r=74,umax_value=51000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=68,umax_value=51068,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=17,off=74,r=74,umax_value=51000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=17,off=70,r=74,umax_value=51000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=68,umax_value=51068,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=17,off=74,r=74,umax_value=51000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=68,umax_value=51068,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=17,off=74,r=74,umax_value=51000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0=pkt(id=18,off=74,r=0,umax_value=54000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=0,umin_value=72,umax_value=54072,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5=pkt(id=18,off=74,r=0,umax_value=54000,var_off=(0x0; 0xffffffff)) R6=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0=pkt(id=18,off=74,r=78,umax_value=54000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=0,umin_value=72,umax_value=54072,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=18,off=78,r=78,umax_value=54000,var_off=(0x0; 0xffffffff)) R6=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0=pkt(id=18,off=74,r=78,umax_value=54000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=0,umin_value=72,umax_value=54072,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=18,off=78,r=78,umax_value=54000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=0,umin_value=72,umax_value=54072,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=18,off=78,r=78,umax_value=54000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=19,off=78,r=0,umax_value=57000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=76,umax_value=57076,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=19,off=78,r=0,umax_value=57000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=19,off=78,r=82,umax_value=57000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=76,umax_value=57076,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=19,off=82,r=82,umax_value=57000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=19,off=78,r=82,umax_value=57000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=76,umax_value=57076,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=19,off=82,r=82,umax_value=57000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=76,umax_value=57076,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=19,off=82,r=82,umax_value=57000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=20,off=82,r=0,umax_value=60000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=80,umax_value=60080,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=20,off=82,r=0,umax_value=60000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=20,off=82,r=86,umax_value=60000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=80,umax_value=60080,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=20,off=86,r=86,umax_value=60000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=20,off=82,r=86,umax_value=60000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=80,umax_value=60080,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=20,off=86,r=86,umax_value=60000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=80,umax_value=60080,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=20,off=86,r=86,umax_value=60000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=21,off=86,r=0,umax_value=63000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=84,umax_value=63084,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=21,off=86,r=0,umax_value=63000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=21,off=86,r=90,umax_value=63000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=84,umax_value=63084,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=21,off=90,r=90,umax_value=63000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=21,off=86,r=90,umax_value=63000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=84,umax_value=63084,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=21,off=90,r=90,umax_value=63000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=84,umax_value=63084,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=21,off=90,r=90,umax_value=63000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=22,off=90,r=0,umax_value=66000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=88,umax_value=66088,var_off=(0x0; 0x1ffff),s32_min_value=0,s32_max_value=131071,u32_max_value=131071) R4=inv17179869184 R5_w=pkt(id=22,off=90,r=0,umax_value=66000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=22,off=90,r=0,umax_value=66000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=88,umax_value=66088,var_off=(0x0; 0x1ffff),s32_min_value=0,s32_max_value=131071,u32_max_value=131071) R4=inv17179869184 R5_w=pkt(id=22,off=94,r=0,umax_value=66000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)
R0 offset is outside of the packet
processed 477 insns (limit 1000000) max_states_per_insn 4 total_states 9 peak_states 9 mark_read 2

        What is the root cause of the failure? How would you fix it?
```

**Condition A Response**

```text
Root cause: the verifier is not complaining about that single `ext->type` read by itself; it is complaining because your loop keeps advancing `data` by a variable `ext_len`, so after enough iterations the possible packet offset of `data` grows beyond the verifier's tracked packet-range window (roughly `0xffff` / 64 KiB). At that point the range proof collapses (`R0(..., r=0)` in the log), so the earlier `data_end < data + sizeof(struct extension)` check no longer gives the verifier a safe byte to read, and `ext->type` becomes an invalid packet access.

Fix: keep the cursor provably below that limit for the whole loop. In practice, add hard bounds on both the number of extensions and the maximum `ext_len` so the total walked distance can never exceed about 65535 bytes, or parse with an explicit bounded 16-bit offset and rebuild `ext = base + off` each iteration. A simple fix is to choose sane caps such as `MAX_EXTENSIONS = 32` and `MAX_EXT_LEN = 2048`, reject anything larger, and keep the per-iteration bounds checks before every dereference.
```

**Condition B Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        struct server_name {
char server_name[256];
};
struct extension {
__u16 type;
__u16 len;
} __attribute__((packed));
struct sni_extension {
__u16 list_len;
__u8 type;
__u16 len;
} __attribute__((packed));
#define SERVER_NAME_EXTENSION 0
SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
char *data_end = (char *)(long)ctx->data_end;
char *data = (char *)(long)ctx->data;
if (data_end < (data + sizeof(__u16))) {
goto end;
}
__u16 extension_method_len = __bpf_htons(*(__u16 *) data);
data += sizeof(__u16);
for(int i = 0; i < extension_method_len; i += sizeof(struct extension)) {
if (data_end < (data + sizeof(struct extension))) {
goto end;
}
struct extension *ext = (struct extension *) data;
data += sizeof(struct extension);
///////////////////// (A) ////////////////////
if (data_end < ((char *) ext) + sizeof(struct extension)) {
goto end;
}
if (ext->type == SERVER_NAME_EXTENSION) { // Error happens here
struct server_name sn;
if (data_end < (data + sizeof(struct sni_extension))) {
goto end;
}
struct sni_extension *sni = (struct sni_extension *) data;
data += sizeof(struct sni_extension);
__u16 server_name_len = __bpf_htons(sni->len);
for(int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
if (data_end < data + sn_idx) {
goto end;
}
if (sn.server_name + sizeof(struct server_name) < sn.server_name + sn_idx) {
goto end;
}
sn.server_name[sn_idx] = data[sn_idx];
}
sn.server_name[server_name_len] = 0;
goto end;
}
__u16 ext_len = __bpf_htons(ext->len);
if (ext_len > 30000) {
goto end;
}
if (data_end < data + ext_len) {
goto end;
}
data += ext_len;
i += ext_len;
}
end:
return XDP_PASS;
}
Ignore that data does not point to the beginning of the extension length field of a TLS packet; I did not include the code for getting to this field because the above code is enough to reproduce the issue I'm seeing.
Here is the end of the error log when I attempt to load this program. The error at the end happens at if (ext->type == SERVER_NAME_EXTENSION) {:
from 31 to 12: R0_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {

        Structured analysis of the verification failure:
        - Error: invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)
        - Critical state transition: BOUNDS_COLLAPSE at insn 31: R3 lost scalar bounds at insn 31: inv,id=0,umax=65535,var_off=(0x0; 0xffff) -> inv,id=0,umax=131071,var_off=(0x0; 0x1ffff)
        - Causal chain: insn 28 (R3): R3 was updated by `r3 += r4` and became inv,id=0,umax=65535,var_off=(0x0; 0xffff) -> propagates through insn 31 (R0) -> fails at insn 14 (R0): invalid access to packet, off=90 size=1, R0(id=22,off=90,r=0)
        - Source mapping: if (ext->type == SERVER_NAME_EXTENSION) {
        - Error classification: OBLIGE-E001 (source_bug)

        Raw verifier log (for reference):
        from 31 to 12: R0_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=58,r=0,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=14,off=58,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8
17: (4f) r7 |= r6
; if (ext->type == SERVER_NAME_EXTENSION) {
18: (15) if r7 == 0x0 goto pc+13
 R0_w=pkt(id=14,off=58,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; __u16 ext_len = __bpf_htons(ext->len);
19: (71) r6 = *(u8 *)(r0 +2)
20: (71) r0 = *(u8 *)(r0 +3)
21: (67) r0 <<= 8
22: (4f) r0 |= r6
23: (dc) r0 = be16 r0
; if (ext_len > 3000) {
24: (25) if r0 > 0xbb8 goto pc+7
 R0_w=inv(id=0,umax_value=3000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=56,umax_value=42056,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=14,off=62,r=62,umax_value=42000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
25: (0f) r5 += r0
last_idx 25 first_idx 31
regs=1 stack=0 before 24: (25) if r0 > 0xbb8 goto pc+7
regs=1 stack=0 before 23: (dc) r0 = be16 r0
regs=1 stack=0 before 22: (4f) r0 |= r6
regs=41 stack=0 before 21: (67) r0 <<= 8
regs=41 stack=0 before 20: (71) r0 = *(u8 *)(r0 +3)
regs=40 stack=0 before 19: (71) r6 = *(u8 *)(r0 +2)
26: (0f) r3 += r0
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
27: (67) r3 <<= 32
28: (0f) r3 += r4
29: (c7) r3 s>>= 32
30: (bf) r0 = r5
; for(int i = 0; i < extension_methods_len; i += sizeof(struct extension)) {
31: (6d) if r1 s> r3 goto pc-20

from 31 to 12: R0_w=pkt(id=15,off=62,r=0,umax_value=45000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=62,r=0,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (data_end < (data + sizeof(struct extension))) {
12: (07) r5 += 4
; if (data_end < (data + sizeof(struct extension))) {
13: (2d) if r5 > r2 goto pc+18
 R0_w=pkt(id=15,off=62,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R1=inv(id=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umin_value=60,umax_value=45060,var_off=(0x0; 0xffff),s32_min_value=0,s32_max_value=65535,u32_max_value=65535) R4=inv17179869184 R5_w=pkt(id=15,off=66,r=66,umax_value=45000,var_off=(0x0; 0xffffffff)) R6_w=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R7_w=inv(id=0) R10=fp0
; if (ext->type == SERVER_NAME_EXTENSION) {
14: (71) r6 = *(u8 *)(r0 +0)
15: (71) r7 = *(u8 *)(r0 +1)
16: (67) r7 <<= 8

        What is the root cause of the failure? How would you fix it?
```

**Condition B Response**

```text
Root cause: the bad access is caused by the loop state, not by `ext->type` alone. You advance `data` and `i` by a variable `ext_len` on each iteration, but the verifier cannot prove a tight upper bound on the total accumulated advance; once that running offset can exceed about 64 KiB, the scalar bounds widen (`0xffff` to `0x1ffff` in your log), the packet pointer loses its proven range, and the next read of `ext->type` is rejected as `invalid access to packet`.

Fix: make the extension walk statically bounded. Cap both the number of extensions and the maximum allowed `ext_len` so the worst-case total cursor advance stays within 65536 bytes; for example, a fixed loop limit such as 32 extensions and `ext_len <= 2048`, with `data + sizeof(*ext) <= data_end` before reading the header and `data + ext_len <= data_end` before skipping payload. Also clamp `server_name_len` to `< sizeof(sn.server_name)` before copying and before writing the trailing `0`, since that is a separate bound you also need to prove.
```

**Scoring**

| Condition | Root Cause Correct | Fix Direction Correct | Fix Specificity | Response Tokens |
| --- | ---: | ---: | ---: | ---: |
| A: Raw log | 1 | 1 | 2 | 264 |
| B: Structured trace | 1 | 1 | 2 | 254 |

### stackoverflow-79485758

Case path: `case_study/cases/stackoverflow/stackoverflow-79485758.yaml`

Question URL: https://stackoverflow.com/questions/79485758/invalid-access-to-packet-while-parsing-packet-in-an-ebpf-program

**Ground truth fix description**

```text
The verifier complains on the packet access because the access seems to be out of the known packet bounds. The access is at offset 0, with a size of 2 bytes. The known packet length is 0 (r=0). Hence the program is rejected. You did check the packet bounds above, but it wasn't enough because of this corner-case limitation in the verifier: than pkt_end, but that's because it's also less than pkt.
```

**Structured analysis used in Condition B**

```json
{
  "causal_chain": "insn 46 (R0): R0 was updated by `r0 += 2` and became map_value,id=0,off=0 -> propagates through insn 0 (R6), insn 11 (R2) -> fails at insn 48 (R5): invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)",
  "critical_transition": "RANGE_LOSS at insn 36: R5 lost packet range proof at insn 36: r=2 -> r=0",
  "error_classification": "OBLIGE-E001 (source_bug)",
  "error_line": "invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)",
  "source_mapping": "x = *((uint16_t*) (data + field_offset));"
}
```

**Condition A Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        SEC("classifier")
int find_grpc(struct __sk_buff *skb){
if(skb == NULL) {
goto EXIT;
}
context_key_t key = CONTEXT_KEY;
context_data_t * ctx = bpf_map_lookup_elem(&context_map,&key);
void *data_end = (void*)(__u64)skb->data_end;
void *data = (void *)(__u64)skb->data;
if(ctx==NULL) {
goto EXIT;
}
if(ctx->action_index >= MAX_ACTION_LIST) {
goto EXIT;
}
find_grpc_t *args = (find_grpc_t*)&(ctx->action_argument[ctx->action_index].find_grpc_args);
if(args==NULL) {
goto EXIT;
}
unsigned int flag = 0;
if (args->offset > 100)
{
goto EXIT;
}
if (ctx->payload_offset > MAX_PAYLOAD_OFFSET)
{
goto EXIT;
}
unsigned short field_offset = ctx->payload_offset + args->offset;
char len = 0;
uint16_t x;
if (args->field_index > MAX_IDS)
{
goto EXIT;
}
unsigned short toBeFound = args->field_id[args->field_index];
LOOK:
if ((data + field_offset + sizeof(uint16_t)) > data_end)
{
goto EXIT;
}
x = *((uint16_t*) (data + field_offset));
char y = (x & GRPC_ID_MASK) >> GRPC_ID_SHIFT;
len = x & GRPC_LEN_MASK;
if (len > 32)
{
goto EXIT;
}
if (y == toBeFound)
{
goto FOUND;
}
field_offset += len;
goto LOOK;
FOUND:
// some logic on finding the required attribute in the payload
EXIT:
return TC_ACT_OK;
}
#endif
In the above code, the verifier complains by saying that I am trying to access an offset which is outside the packet at the following line in code (where I try to dereference a pointer at an offset inside the packet)
x = *((uint16_t*) (off));
As can be seen in the code above, I do check for bounds just above that particular line. Any reason why I might be seeing this error even though I have check for packet bounds?

        Verifier output:
        libbpf: load bpf program failed: Permission denied
libbpf: -- BEGIN DUMP LOG ---
libbpf:
; int find_grpc(struct __sk_buff *skb){
0: (bf) r6 = r1
; if(skb == NULL) {
1: (15) if r6 == 0x0 goto pc+82
 R1=ctx(id=0,off=0,imm=0) R6_w=ctx(id=0,off=0,imm=0) R10=fp0
2: (b7) r1 = 0
; context_key_t key = CONTEXT_KEY;
3: (63) *(u32 *)(r10 -4) = r1
last_idx 3 first_idx 0
regs=2 stack=0 before 2: (b7) r1 = 0
4: (bf) r2 = r10
;
5: (07) r2 += -4
; context_data_t * ctx = bpf_map_lookup_elem(&context_map,&key);
6: (18) r1 = 0xffff97d362338000
8: (85) call bpf_map_lookup_elem#1
9: (bf) r7 = r0
; void *data = (void *)(__u64)skb->data;
10: (61) r1 = *(u32 *)(r6 +76)
; void *data_end = (void*)(__u64)skb->data_end;
11: (61) r2 = *(u32 *)(r6 +80)
; if(ctx==NULL) {
12: (15) if r7 == 0x0 goto pc+71
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if(ctx->action_index >= MAX_ACTION_LIST) {
13: (69) r5 = *(u16 *)(r7 +6)
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if(ctx->action_index >= MAX_ACTION_LIST) {
14: (25) if r5 > 0x1f goto pc+69
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R5_w=inv(id=0,umax_value=31,var_off=(0x0; 0x1f)) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if (args->offset > 100)
15: (27) r5 *= 584
; find_grpc_t *args = (find_grpc_t*)&(ctx->action_argument[ctx->action_index].find_grpc_args);
16: (bf) r4 = r7
17: (07) r4 += 272
; if (args->offset > 100)
18: (bf) r3 = r4
19: (0f) r3 += r5
last_idx 19 first_idx 9
regs=20 stack=0 before 18: (bf) r3 = r4
regs=20 stack=0 before 17: (07) r4 += 272
regs=20 stack=0 before 16: (bf) r4 = r7
regs=20 stack=0 before 15: (27) r5 *= 584
regs=20 stack=0 before 14: (25) if r5 > 0x1f goto pc+69
regs=20 stack=0 before 13: (69) r5 = *(u16 *)(r7 +6)
20: (69) r8 = *(u16 *)(r3 +0)
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4_w=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5_w=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if (args->offset > 100)
21: (25) if r8 > 0x64 goto pc+62
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=inv(id=0,umax_value=100,var_off=(0x0; 0x7f)) R10=fp0 fp-8=mmmm????
; if (ctx->payload_offset > MAX_PAYLOAD_OFFSET)
22: (69) r3 = *(u16 *)(r7 +2)
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=inv(id=0,umax_value=100,var_off=(0x0; 0x7f)) R10=fp0 fp-8=mmmm????
; if (ctx->payload_offset > MAX_PAYLOAD_OFFSET)
23: (25) if r3 > 0x3c0 goto pc+60
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umax_value=960,var_off=(0x0; 0x3ff)) R4=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=inv(id=0,umax_value=100,var_off=(0x0; 0x7f)) R10=fp0 fp-8=mmmm????
; if (args->field_index > MAX_IDS)
24: (0f) r4 += r5
last_idx 24 first_idx 21
regs=20 stack=0 before 23: (25) if r3 > 0x3c0 goto pc+60
regs=20 stack=0 before 22: (69) r3 = *(u16 *)(r7 +2)
regs=20 stack=0 before 21: (25) if r8 > 0x64 goto pc+62
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4_rw=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5_rw=invP(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7_rw=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8_rw=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R10=fp0 fp-8=mmmm????
parent didn't have regs=20 stack=0 marks
last_idx 20 first_idx 9
regs=20 stack=0 before 20: (69) r8 = *(u16 *)(r3 +0)
regs=20 stack=0 before 19: (0f) r3 += r5
regs=20 stack=0 before 18: (bf) r3 = r4
regs=20 stack=0 before 17: (07) r4 += 272
regs=20 stack=0 before 16: (bf) r4 = r7
regs=20 stack=0 before 15: (27) r5 *= 584
regs=20 stack=0 before 14: (25) if r5 > 0x1f goto pc+69
regs=20 stack=0 before 13: (69) r5 = *(u16 *)(r7 +6)
25: (69) r0 = *(u16 *)(r4 +14)
 R0_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umax_value=960,var_off=(0x0; 0x3ff)) R4_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R5=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=inv(id=0,umax_value=100,var_off=(0x0; 0x7f)) R10=fp0 fp-8=mmmm????
; if (args->field_index > MAX_IDS)
26: (25) if r0 > 0x5 goto pc+57
 R0_w=inv(id=0,umax_value=5,var_off=(0x0; 0x7)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=0,umax_value=960,var_off=(0x0; 0x3ff)) R4_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R5=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=inv(id=0,umax_value=100,var_off=(0x0; 0x7f)) R10=fp0 fp-8=mmmm????
; unsigned short field_offset = ctx->payload_offset + args->offset;
27: (0f) r3 += r8
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
28: (bf) r8 = r3
29: (57) r8 &= 65535
30: (bf) r5 = r1
31: (0f) r5 += r8
last_idx 31 first_idx 21
regs=100 stack=0 before 30: (bf) r5 = r1
regs=100 stack=0 before 29: (57) r8 &= 65535
regs=100 stack=0 before 28: (bf) r8 = r3
regs=8 stack=0 before 27: (0f) r3 += r8
regs=108 stack=0 before 26: (25) if r0 > 0x5 goto pc+57
regs=108 stack=0 before 25: (69) r0 = *(u16 *)(r4 +14)
regs=108 stack=0 before 24: (0f) r4 += r5
regs=108 stack=0 before 23: (25) if r3 > 0x3c0 goto pc+60
regs=108 stack=0 before 22: (69) r3 = *(u16 *)(r7 +2)
regs=100 stack=0 before 21: (25) if r8 > 0x64 goto pc+62
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_rw=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4_rw=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5_rw=invP(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7_rw=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8_rw=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R10=fp0 fp-8=mmmm????
parent didn't have regs=100 stack=0 marks
last_idx 20 first_idx 9
regs=100 stack=0 before 20: (69) r8 = *(u16 *)(r3 +0)
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
32: (bf) r8 = r5
33: (07) r8 += 2
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
34: (2d) if r8 > r2 goto pc+49
 R0=inv(id=0,umax_value=5,var_off=(0x0; 0x7)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R5=pkt(id=3,off=0,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
35: (67) r0 <<= 1
36: (0f) r4 += r0
last_idx 36 first_idx 34
regs=1 stack=0 before 35: (67) r0 <<= 1
regs=1 stack=0 before 34: (2d) if r8 > r2 goto pc+49
 R0_rw=invP(id=0,umax_value=5,var_off=(0x0; 0x7)) R1=pkt(id=0,off=0,r=0,imm=0) R2_r=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4_rw=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R5_w=pkt(id=3,off=0,r=0,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8_rw=pkt(id=3,off=2,r=0,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
parent didn't have regs=1 stack=0 marks
last_idx 33 first_idx 21
regs=1 stack=0 before 33: (07) r8 += 2
regs=1 stack=0 before 32: (bf) r8 = r5
regs=1 stack=0 before 31: (0f) r5 += r8
regs=1 stack=0 before 30: (bf) r5 = r1
regs=1 stack=0 before 29: (57) r8 &= 65535
regs=1 stack=0 before 28: (bf) r8 = r3
regs=1 stack=0 before 27: (0f) r3 += r8
regs=1 stack=0 before 26: (25) if r0 > 0x5 goto pc+57
regs=1 stack=0 before 25: (69) r0 = *(u16 *)(r4 +14)
37: (69) r4 = *(u16 *)(r4 +4)
 R0_w=inv(id=0,umax_value=10,var_off=(0x0; 0xe)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18114,var_off=(0x0; 0xfffe),s32_max_value=65534,u32_max_value=65534) R5=pkt(id=3,off=0,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
38: (05) goto pc+9
; x = *((uint16_t*) (data + field_offset));
48: (69) r0 = *(u16 *)(r5 +0)
; if (len > 32)
49: (bf) r5 = r0
50: (67) r5 <<= 56
51: (c7) r5 s>>= 32
; if (len > 32)
52: (65) if r5 s> 0x20000000 goto pc+31
 R0=inv(id=4,umax_value=65535,var_off=(0x0; 0xffff)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R5=inv(id=0,smin_value=-2147483648,smax_value=536870912,umax_value=18446744073692774400,var_off=(0x0; 0xffffffffff000000),u32_max_value=-16777216) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
; char y = (x & GRPC_ID_MASK) >> GRPC_ID_SHIFT;
53: (57) r0 &= 61440
54: (77) r0 >>= 12
; if (y == toBeFound)
55: (5d) if r0 != r4 goto pc-17

from 55 to 39: R0_w=inv(id=0,umax_value=15,var_off=(0x0; 0xf)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=inv(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R5=inv(id=0,smin_value=-2147483648,smax_value=536870912,umax_value=18446744073692774400,var_off=(0x0; 0xffffffffff000000),u32_max_value=-16777216) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
;
39: (c7) r5 s>>= 24
40: (0f) r3 += r5
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
41: (bf) r0 = r3
42: (57) r0 &= 65535
43: (bf) r5 = r1
44: (0f) r5 += r0
last_idx 44 first_idx 52
regs=1 stack=0 before 43: (bf) r5 = r1
regs=1 stack=0 before 42: (57) r0 &= 65535
regs=1 stack=0 before 41: (bf) r0 = r3
regs=8 stack=0 before 40: (0f) r3 += r5
regs=28 stack=0 before 39: (c7) r5 s>>= 24
regs=28 stack=0 before 55: (5d) if r0 != r4 goto pc-17
regs=28 stack=0 before 54: (77) r0 >>= 12
regs=28 stack=0 before 53: (57) r0 &= 61440
regs=28 stack=0 before 52: (65) if r5 s> 0x20000000 goto pc+31
 R0_rw=inv(id=4,umax_value=65535,var_off=(0x0; 0xffff)) R1_r=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_r=invP(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4_rw=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R5_rw=invP(id=0,smin_value=-2147483648,smax_value=2130706432,umax_value=18446744073692774400,var_off=(0x0; 0xffffffffff000000),u32_max_value=-16777216) R6_r=ctx(id=0,off=0,imm=0) R7_r=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8_r=mmmm????
parent didn't have regs=28 stack=0 marks
last_idx 51 first_idx 34
regs=28 stack=0 before 51: (c7) r5 s>>= 32
regs=28 stack=0 before 50: (67) r5 <<= 56
regs=28 stack=0 before 49: (bf) r5 = r0
regs=9 stack=0 before 48: (69) r0 = *(u16 *)(r5 +0)
regs=8 stack=0 before 38: (05) goto pc+9
regs=8 stack=0 before 37: (69) r4 = *(u16 *)(r4 +4)
regs=8 stack=0 before 36: (0f) r4 += r0
regs=8 stack=0 before 35: (67) r0 <<= 1
regs=8 stack=0 before 34: (2d) if r8 > r2 goto pc+49
 R0_rw=invP(id=0,umax_value=5,var_off=(0x0; 0x7)) R1_r=pkt(id=0,off=0,r=0,imm=0) R2_r=pkt_end(id=0,off=0,imm=0) R3_rw=invP(id=2,umax_value=1060,var_off=(0x0; 0x7ff)) R4_rw=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R5_rw=pkt(id=3,off=0,r=0,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R6_r=ctx(id=0,off=0,imm=0) R7_r=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8_rw=pkt(id=3,off=2,r=0,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8_r=mmmm????
parent didn't have regs=8 stack=0 marks
last_idx 33 first_idx 21
regs=8 stack=0 before 33: (07) r8 += 2
regs=8 stack=0 before 32: (bf) r8 = r5
regs=8 stack=0 before 31: (0f) r5 += r8
regs=8 stack=0 before 30: (bf) r5 = r1
regs=8 stack=0 before 29: (57) r8 &= 65535
regs=8 stack=0 before 28: (bf) r8 = r3
regs=8 stack=0 before 27: (0f) r3 += r8
regs=108 stack=0 before 26: (25) if r0 > 0x5 goto pc+57
regs=108 stack=0 before 25: (69) r0 = *(u16 *)(r4 +14)
regs=108 stack=0 before 24: (0f) r4 += r5
regs=108 stack=0 before 23: (25) if r3 > 0x3c0 goto pc+60
regs=108 stack=0 before 22: (69) r3 = *(u16 *)(r7 +2)
regs=100 stack=0 before 21: (25) if r8 > 0x64 goto pc+62
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_rw=pkt(id=0,off=0,r=0,imm=0) R2_rw=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4_rw=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5_rw=invP(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6_r=ctx(id=0,off=0,imm=0) R7_rw=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8_rw=invP(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R10=fp0 fp-8_r=mmmm????
parent already had regs=100 stack=0 marks
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
45: (bf) r0 = r5
46: (07) r0 += 2
; if ((data + field_offset + sizeof(uint16_t)) > data_end)
47: (2d) if r0 > r2 goto pc+36
 R0_w=pkt(id=6,off=2,r=0,umax_value=65535,var_off=(0x0; 0xffff)) R1=pkt(id=0,off=0,r=0,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3_w=inv(id=5,smin_value=-128,smax_value=1092) R4=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R5_w=pkt(id=6,off=0,r=0,umax_value=65535,var_off=(0x0; 0xffff)) R6=ctx(id=0,off=0,imm=0) R7=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R8=pkt(id=3,off=2,r=2,umax_value=1060,var_off=(0x0; 0x7ff),s32_max_value=2047,u32_max_value=2047) R10=fp0 fp-8=mmmm????
; x = *((uint16_t*) (data + field_offset));
48: (69) r0 = *(u16 *)(r5 +0)
invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)
R5 offset is outside of the packet
processed 88 insns (limit 1000000) max_states_per_insn 0 total_states 8 peak_states 8 mark_read 5

48: (69) r0 = *(u16 *)(r5 +0)
invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)
R5 offset is outside of the packet

        What is the root cause of the failure? How would you fix it?
```

**Condition A Response**

```text
Root cause: the verifier loses the packet-range proof on the loop back-edge, not on the first access. `len` is declared as `char`, so `len = x & GRPC_LEN_MASK` truncates the field and can become negative after sign extension; then `field_offset += len` is applied to an `unsigned short`, which can wrap. After that, the verifier can no longer prove that `data + field_offset` is still within the packet window `[data, data_end)`. Your check only proves the pointer is not past `data_end`; it does not prove it did not move before `data`, so the dereference is rejected as `R5(..., r=0)`.

Fix: make the cursor monotonic and unsigned so the verifier can keep the proof across iterations. Use `__u16`/`__u32` for `len` and `field_offset` instead of `char`/`unsigned short`, reject `len == 0`, keep `len` bounded (`if (len > 32) goto EXIT;`), and re-check bounds after each increment. In practice, something like `__u32 off = ctx->payload_offset + args->offset; __u16 len;` and then `if (data + off + sizeof(__u16) > data_end) goto EXIT; x = *(__u16 *)(data + off); len = x & GRPC_LEN_MASK; if (!len || len > 32) goto EXIT; off += len;` is the pattern the verifier accepts much more reliably.
```

**Condition B Prompt**

```text
You are an eBPF expert. The following BPF program fails verification.

        Source code:
        SEC("classifier")
int find_grpc(struct __sk_buff *skb){
if(skb == NULL) {
goto EXIT;
}
context_key_t key = CONTEXT_KEY;
context_data_t * ctx = bpf_map_lookup_elem(&context_map,&key);
void *data_end = (void*)(__u64)skb->data_end;
void *data = (void *)(__u64)skb->data;
if(ctx==NULL) {
goto EXIT;
}
if(ctx->action_index >= MAX_ACTION_LIST) {
goto EXIT;
}
find_grpc_t *args = (find_grpc_t*)&(ctx->action_argument[ctx->action_index].find_grpc_args);
if(args==NULL) {
goto EXIT;
}
unsigned int flag = 0;
if (args->offset > 100)
{
goto EXIT;
}
if (ctx->payload_offset > MAX_PAYLOAD_OFFSET)
{
goto EXIT;
}
unsigned short field_offset = ctx->payload_offset + args->offset;
char len = 0;
uint16_t x;
if (args->field_index > MAX_IDS)
{
goto EXIT;
}
unsigned short toBeFound = args->field_id[args->field_index];
LOOK:
if ((data + field_offset + sizeof(uint16_t)) > data_end)
{
goto EXIT;
}
x = *((uint16_t*) (data + field_offset));
char y = (x & GRPC_ID_MASK) >> GRPC_ID_SHIFT;
len = x & GRPC_LEN_MASK;
if (len > 32)
{
goto EXIT;
}
if (y == toBeFound)
{
goto FOUND;
}
field_offset += len;
goto LOOK;
FOUND:
// some logic on finding the required attribute in the payload
EXIT:
return TC_ACT_OK;
}
#endif
In the above code, the verifier complains by saying that I am trying to access an offset which is outside the packet at the following line in code (where I try to dereference a pointer at an offset inside the packet)
x = *((uint16_t*) (off));
As can be seen in the code above, I do check for bounds just above that particular line. Any reason why I might be seeing this error even though I have check for packet bounds?

        Structured analysis of the verification failure:
        - Error: invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)
        - Critical state transition: RANGE_LOSS at insn 36: R5 lost packet range proof at insn 36: r=2 -> r=0
        - Causal chain: insn 46 (R0): R0 was updated by `r0 += 2` and became map_value,id=0,off=0 -> propagates through insn 0 (R6), insn 11 (R2) -> fails at insn 48 (R5): invalid access to packet, off=0 size=2, R5(id=6,off=0,r=0)
        - Source mapping: x = *((uint16_t*) (data + field_offset));
        - Error classification: OBLIGE-E001 (source_bug)

        Raw verifier log (for reference):
        libbpf: load bpf program failed: Permission denied
libbpf: -- BEGIN DUMP LOG ---
libbpf:
; int find_grpc(struct __sk_buff *skb){
0: (bf) r6 = r1
; if(skb == NULL) {
1: (15) if r6 == 0x0 goto pc+82
 R1=ctx(id=0,off=0,imm=0) R6_w=ctx(id=0,off=0,imm=0) R10=fp0
2: (b7) r1 = 0
; context_key_t key = CONTEXT_KEY;
3: (63) *(u32 *)(r10 -4) = r1
last_idx 3 first_idx 0
regs=2 stack=0 before 2: (b7) r1 = 0
4: (bf) r2 = r10
;
5: (07) r2 += -4
; context_data_t * ctx = bpf_map_lookup_elem(&context_map,&key);
6: (18) r1 = 0xffff97d362338000
8: (85) call bpf_map_lookup_elem#1
9: (bf) r7 = r0
; void *data = (void *)(__u64)skb->data;
10: (61) r1 = *(u32 *)(r6 +76)
; void *data_end = (void*)(__u64)skb->data_end;
11: (61) r2 = *(u32 *)(r6 +80)
; if(ctx==NULL) {
12: (15) if r7 == 0x0 goto pc+71
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if(ctx->action_index >= MAX_ACTION_LIST) {
13: (69) r5 = *(u16 *)(r7 +6)
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if(ctx->action_index >= MAX_ACTION_LIST) {
14: (25) if r5 > 0x1f goto pc+69
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R5_w=inv(id=0,umax_value=31,var_off=(0x0; 0x1f)) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????
; if (args->offset > 100)
15: (27) r5 *= 584
; find_grpc_t *args = (find_grpc_t*)&(ctx->action_argument[ctx->action_index].find_grpc_args);
16: (bf) r4 = r7
17: (07) r4 += 272
; if (args->offset > 100)
18: (bf) r3 = r4
19: (0f) r3 += r5
last_idx 19 first_idx 9
regs=20 stack=0 before 18: (bf) r3 = r4
regs=20 stack=0 before 17: (07) r4 += 272
regs=20 stack=0 before 16: (bf) r4 = r7
regs=20 stack=0 before 15: (27) r5 *= 584
regs=20 stack=0 before 14: (25) if r5 > 0x1f goto pc+69
regs=20 stack=0 before 13: (69) r5 = *(u16 *)(r7 +6)
20: (69) r8 = *(u16 *)(r3 +0)
 R0=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R1_w=pkt(id=0,off=0,r=0,imm=0) R2_w=pkt_end(id=0,off=0,imm=0) R3_w=map_value(id=0,off=272,ks=4,vs=19096,umax_value=18104,var_off=(0x0; 0x7ff8),s32_max_value=32760,u32_max_value=32760) R4_w=map_value(id=0,off=272,ks=4,vs=19096,imm=0) R5_w=inv(id=0,umax_value=18104,var_off=(0x0; 0x7ff8)) R6=ctx(id=0,off=0,imm=0) R7_w=map_value(id=0,off=0,ks=4,vs=19096,imm=0) R10=fp0 fp-8=mmmm????

        What is the root cause of the failure? How would you fix it?
```

**Condition B Response**

```text
Root cause: the verifier loses the packet-range proof on the looped path, not on the first read. `field_offset` is carried through the loop as an `unsigned short`, and you update it with `len`, where `len` is a plain `char` (signed on BPF/clang targets). After `field_offset += len`, the verifier must consider negative/backward movement and 16-bit truncation/wrap, so on the next iteration `data + field_offset` becomes effectively an arbitrary 16-bit packet offset. At that point, `if (data + field_offset + 2 > data_end)` is no longer enough for the verifier to conclude the dereference is safe, because the pointer could also have wrapped or ended up before `data`, so the load sees `R5(...,r=0)` and is rejected.

Fix: make the loop-carried offset and length unsigned wider scalars, and keep them explicitly bounded each iteration. Use `__u32` or `int` for `field_offset` and `len` (not `char` / `unsigned short`), extract `len` into an unsigned type, check `len <= 32`, update `field_offset` with that unsigned value, and then re-check bounds before every read with a fresh pointer, e.g. `__u8 *p = data + field_offset; if (p + sizeof(__u16) > data_end) goto EXIT; x = *(__u16 *)p;`. That gives the verifier a monotonic, non-wrapping offset and preserves the range proof.
```

**Scoring**

| Condition | Root Cause Correct | Fix Direction Correct | Fix Specificity | Response Tokens |
| --- | ---: | ---: | ---: | ---: |
| A: Raw log | 0 | 0 | 1 | 298 |
| B: Structured trace | 0 | 0 | 1 | 320 |

## Analysis

Across these five cases, the structured-trace prompt did not improve aggregate correctness. Both conditions reached 4/5 root-cause accuracy and 4/5 fix-direction accuracy, while Condition B was slightly longer on average (293.2 vs 286.4 approximate tokens).

Structured trace helped most on: stackoverflow-78958420 (fixed-size map-key read from packet memory), stackoverflow-70760516 (long loop with 64 KiB accumulated offset growth). In these cases the synthesized bullets made the key invariant easier to state concisely.

Raw log was better on: stackoverflow-70750259 (unbounded `ext_len` / bounds-collapse case), stackoverflow-70729664 (loop/backtracking range-loss case), stackoverflow-79485758 (corner-case packet-range loss on looped cursor arithmetic). The raw log already exposed enough signal, and in one loop/range-loss case the trace summary hid the MAX_PACKET_OFF-style corner case rather than clarifying it.

Cases where neither prompt got the real fix: stackoverflow-79485758 (corner-case packet-range loss on looped cursor arithmetic). The failure mode there appears to need a more faithful MAX_PACKET_OFF / verifier-corner-case summary than the current trace prompt provides.
