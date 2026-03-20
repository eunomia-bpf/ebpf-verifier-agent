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
    bpf_name: true,
        bpf_probe_read_kernel: true,
        bpf_perf_link: true,
        bpf_global_data: true,
        bpf_cookie: true,
        cpumap_prog_id: true,
        devmap_prog_id: true,
        prog_info_map_ids: true,
        prog_info_gpl_compatible: true,
        btf: Some(
            BtfFeatures {
                btf_func: true,
                btf_func_global: true,
                btf_datasec: true,
                btf_float: true,
                btf_decl_tag: true,
                btf_type_tag: true,
                btf_enum64: true,
            },
        ),
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
