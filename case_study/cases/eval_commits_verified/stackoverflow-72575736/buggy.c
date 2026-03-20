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
    #[xdp]
    unsafe fn xdp_test(ctx: XdpContext) -> XdpResult {
        let data = ctx.data()?;
        let start = ctx.data_start();
        let off = data.offset();
        let end = ctx.data_end();

        /* Ensuring an upper bound for off doesn't make any difference
        if off > 50 {
            return XdpResult::Err(OutOfBounds);
        }
        */

        let mut address = start + off;
        for i in 0..500 {
            address = start + off + i;
            if address <= start || address >= end {
                break;
            }

            // This line (packet access) fails on kernel 5.10, but works fine on 5.13
            let byte = *(address as *const u8);
            // Just so the packet read above doesn't get optimized away
            printk!("%u", byte as u32);
        }

        Ok(XdpAction::Pass)
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
