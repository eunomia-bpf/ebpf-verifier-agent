#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * cbrt(x) MSB values for x MSB values in [0..63].
 * Precomputed then refined by hand - Willy Tarreau
 *
 * For x in [0..63],
 *   v = cbrt(x << 18) - 1
 *   cbrt(x) = (v[x] + 10) >> 6
 */
static const __u8 v[] = {
/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
};

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static __always_inline __u32 cubic_root(__u64 a)
{
    __u32 x=0, b, shift;

    if (a < 64) {
        /* a in [0..63] */
        return ((__u32)v[(__u32)a] + 35) >> 6;
    }

    b = fls64(a);
    b = ((b * 84) >> 8) - 1;
    shift = (a >> (b * 3));

    /* it is needed for verifier's bound check on v */
    if (shift >= 64){
        return 0;
    }else{
        x = ((__u32)(((__u32)v[shift] + 10) << b)) >> 6;

        /*
        * Newton-Raphson iteration
        *                         2
        * x    = ( 2 * x  +  a / x  ) / 3
        *  k+1          k         k
        */
        x = (2 * x + (__u32)div64_u64(a, (__u64)x * (__u64)(x - 1)));
        x = ((x * 341) >> 10);
    }
    return x;
}
char _license[] SEC("license") = "GPL";
