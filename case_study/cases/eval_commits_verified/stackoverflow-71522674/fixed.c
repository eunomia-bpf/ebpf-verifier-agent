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
    {
        if (tcph + 1 > data_end)
            return XDP_DROP;

        tcp_len = tcph->doff * 4;

        if (tcp_len < sizeof(*tcph))
            return XDP_DROP;
        if ((void *)tcph + tcp_len > data_end)
            return XDP_DROP;

        value = bpf_csum_diff(0, 0, (void *)tcph, tcp_len, 0);
        if (value == 0) return XDP_DROP;

        return XDP_PASS;
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
