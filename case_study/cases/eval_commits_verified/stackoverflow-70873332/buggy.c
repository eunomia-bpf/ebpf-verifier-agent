#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct packet_context {
    __u16 pkt_offset;
};

struct bpf_map_def SEC("maps") context_table = {
   .type = BPF_MAP_TYPE_ARRAY,
   .key_size = sizeof(__u32),
   .value_size = sizeof(struct packet_context),
   .max_entries = 1,
};

SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
    char *data_end = (char *)(long)ctx->data_end;
    char *data = (char *)(long)ctx->data;
    __u32 index = 0;
    struct packet_context *pkt_ctx = (struct packet_context *) bpf_map_lookup_elem(&context_table, &index);

    if (pkt_ctx == NULL) {
        goto end;
    }

    __u32 length = 0;

    for (__u16 j = 0; j < 253; j++) {
        if (data_end < data + pkt_ctx->pkt_offset + j + 1) {
            goto end;
        }

        if (data[pkt_ctx->pkt_offset + j] == '\r') {
            break;
        }

        length++;
    }

    bpf_printk("%d", length);

end:
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
