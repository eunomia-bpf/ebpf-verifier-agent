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
    // get return value (is the length of data read)
        let ret_value_len: i32 = match ctx.ret() {
            Some(ret) => ret,
            None => return 0
        };
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
