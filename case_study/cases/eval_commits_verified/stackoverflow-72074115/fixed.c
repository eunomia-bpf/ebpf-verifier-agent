#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

Thank you for all the answers.
A friend of mine told me that I should verify it by:
if(v[shift]){
...
}
He told me that I should judge whether the corresponding position of the array exists, rather than directly judge the size of the "shift".
I modified it like this, and the program did pass the verification.
char _license[] SEC("license") = "GPL";
