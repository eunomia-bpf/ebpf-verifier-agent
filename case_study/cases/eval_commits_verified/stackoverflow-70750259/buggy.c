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
char _license[] SEC("license") = "GPL";
