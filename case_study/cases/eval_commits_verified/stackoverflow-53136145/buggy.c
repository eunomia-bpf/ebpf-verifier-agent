SEC("entry_point_prog")
int entry_point(struct xdp_md *ctx)
{
    int act = XDP_DROP;
    int rc, i = 0;
    struct global_vars *globals;
    struct ip_addr addr = {};
    struct some_key key = {};
    void *temp;

    globals = bpf_map_lookup_elem(&globals_map, &i);
    if (!globals)
        return XDP_ABORTED;

    rc = some_inlined_func(ctx, &key);

    addr = key.dst_ip;
    temp = bpf_map_lookup_elem(&some_map, &addr);

    switch(rc)
    {
    case 0:
        if(temp)
        {
            // no rocket science here ...
        } else
            act = XDP_PASS;
        break;
    default:
        break;
    }

    return act;  // this gives the error
    //return XDP_<whatever>;  // this works fine
}
char _license[] SEC("license") = "GPL";
