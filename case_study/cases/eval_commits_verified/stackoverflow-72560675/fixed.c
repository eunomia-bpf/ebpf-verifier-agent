#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

struct read_enter_ctx {
        unsigned long long unused;
        int __syscall_nr;
        //unsigned int padding;
        unsigned long fd;
        char* buf;
        size_t count;
};

struct read_exit_ctx {
        unsigned long long unused;
        int __syscall_nr;
        long ret;
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, int);
        __type(value, void*);
} saved_read_ctx SEC(".maps");

#define HEAP_BUFFER_SIZE (2 * 1024)

struct heap_buffer {
        char buf[HEAP_BUFFER_SIZE];
};

/* This is the temporary storage - 'heap', used to copy userspace buffers */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, int);
        __type(value, struct heap_buffer);
} heap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct read_enter_ctx *ctx)
{
        int zero = 0;
        void *p = ctx->buf;

        bpf_map_update_elem(&saved_read_ctx, &zero, &p, BPF_ANY);
        return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct read_exit_ctx *ctx)
{
        char *map_buf;
        void **ubuf;
        int zero = 0;
        unsigned long min;

        ubuf = bpf_map_lookup_elem(&saved_read_ctx, &zero);
        if (!ubuf)
                return 0;

        if (ctx->ret <= 0)
                return 0;

        map_buf = bpf_map_lookup_elem(&heap, &zero);
        if (!map_buf) {
                return 0;
        }

        min = MIN(ctx->ret, HEAP_BUFFER_SIZE);
        min &= 0xffff;
        //min = 16;  // verifier is happy once I uncomment this line
#if 1

        // this is where things go bad
        if (bpf_probe_read_user(map_buf, min, *ubuf)) {
                return 0;
        }
#endif
        return 0;
}

char _license[] SEC("license") = "GPL";
