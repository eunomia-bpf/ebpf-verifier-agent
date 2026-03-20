// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Facebook */

#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define ITER_HELPERS						\
	  __imm(bpf_iter_num_new),				\
	  __imm(bpf_iter_num_next),				\
	  __imm(bpf_iter_num_destroy)

SEC("?raw_tp")
__failure __msg("expected uninitialized iter_num as arg #0")
int double_create_fail(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"
		/* (attempt to) create iterator again */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"
		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common
	);

	return 0;
}

int zero;
