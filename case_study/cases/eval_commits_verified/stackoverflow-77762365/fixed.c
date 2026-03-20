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
    TL;DR. The verifier is not yet smart enough to use event->len + read < MAX_READ_CONTENT_LENGTH.
    Explanation
    For the verifier to confirm that bpf_probe_read_user(&event->content[A], B, ...); is safe, it would need to remember that A + B < value_size. That's what you are trying to guarantee with:
    if (event->len + read < MAX_READ_CONTENT_LENGTH)
    Unfortunately, the verifier is currently unable to understand and retain such relations between variables (A and B or event->len and read in this example). The only exception is a special case for the pointer to the packet's end (ctx->data_end) in case of networking BPF programs.
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
