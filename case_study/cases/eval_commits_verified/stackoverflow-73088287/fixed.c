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
    The issue is in those lines:
    for (__u32 i = 0; i < MTU && payload + i + 1 <= data_end; i++) {
    fd -> buf[i] = payload[i];
    }
    This is a common problem: the compiler probably[1] computed and stored payload + i + 1 and payload[i] in two different registers.
    Let's say the first is in R5 and the second in R6. When the compiler compared R5 to data_end, it understands that there's a new upper bound data_end for R5, but it's not smart enough to understand what that means for i. So when it then computes R6, it can't infer any upper bound for that new register.
    Adding a bounds check on i solves it. The bounds check on payload + i + 1 may be unnecessary.
    [1] - We would need the full verifier logs to confirm.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
