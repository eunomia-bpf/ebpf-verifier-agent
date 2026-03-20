#define BUFFER_SIZE (1<<20)
#define MTU 1500

struct my_buffer {
    __u32 len;
    char buf[BUFFER_SIZE + 5];
};
struct bpf_map_def SEC("maps") map_my_buffer = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct my_buffer),
    .max_entries = 1,
};

SEC("WriteBuffer")
int WriteBuffer_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (payload >= data_end) return XDP_PASS;

    unsigned int zero = 0;
    struct my_buffer *fd = bpf_map_lookup_elem(&map_my_buffer, &zero);
    if (!fd) return XDP_PASS; // can't find the context...

    __u32 data_len = data_end - (void *)payload;
    if (data_len > MTU) return XDP_PASS;

    for (__u32 i = 0; i < MTU && payload + i + 1 <= data_end; i++) {
        fd -> buf[i] = payload[i];
    }

    return XDP_DROP;
}
char _license[] SEC("license") = "GPL";
